package hako

import (
	"bufio"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/listener"
	"github.com/TokenPLS/Hako/tunnel"
)

// The App's idea of the current mode was a snapshot from the last time it asked, and that was
// correct for exactly as long as it was the only writer. Opening PATCH /configs added a second
// one: a dashboard on another device can now switch mode, and nothing tells the App.
//
// The consuming lane fixed two refresh points and stopped at the third on purpose: "user is
// looking at the home screen while somebody else switches mode" can only be solved by polling,
// and polling a value that changes zero times on a typical day costs every day for a benefit
// measured in seconds. Their read is right, and the fix belongs here -- tunnel.SetMode is where
// both writers converge, so one seam covers both.
//
// The stream sends the CURRENT mode on connect before any change. Without that, a subscriber
// that attaches after a switch believes whatever it last knew, which is the same staleness one
// layer down -- and it would only show up in the same rare situation nobody can reproduce.
func TestModeStreamSendsCurrentModeThenEveryChange(t *testing.T) {
	previous := tunnel.Mode()
	t.Cleanup(func() { tunnel.SetMode(previous) })
	tunnel.SetMode(tunnel.Rule)

	port := freeLoopbackPort(t)
	addr := "127.0.0.1:" + port
	path := shortClashSocketPath(t)
	cfg := controllerConfig(t, addr)
	if err := startControlPlane(cfg, path); err != nil {
		t.Fatalf("startControlPlane: %v", err)
	}
	t.Cleanup(func() { stopClashAPI(path) })

	connection, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("dial the controller: %v", err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := connection.Write([]byte("GET /hako/v1/mode HTTP/1.1\r\nHost: localhost\r\n\r\n")); err != nil {
		t.Fatalf("request the mode stream: %v", err)
	}

	reader := bufio.NewReader(connection)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read the response head: %v", err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}
	nextMode := func(what string) string {
		t.Helper()
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("read %s: %v", what, err)
			}
			line = strings.TrimSpace(line)
			if line == "" || !strings.HasPrefix(line, "{") {
				continue // chunked framing between payloads
			}
			var payload struct {
				Mode     string `json:"mode"`
				AllowLan bool   `json:"allow-lan"`
			}
			if err := json.Unmarshal([]byte(line), &payload); err != nil {
				t.Fatalf("decode %s from %q: %v", what, line, err)
			}
			return payload.Mode
		}
	}

	if mode := nextMode("the mode on connect"); mode != "rule" {
		t.Fatalf("the stream opened with %q, not the mode the tunnel is actually in", mode)
	}

	tunnel.SetMode(tunnel.Global)
	if mode := nextMode("the mode after a change"); mode != "global" {
		t.Errorf("after SetMode(Global) the stream said %q; a dashboard switching mode has to "+
			"reach the App without it polling", mode)
	}
}

// allow-lan travels on the same stream, and it needs the push more than mode does: it has three
// writers -- the app's permission gate, hub/executor applying a parsed configuration, and the
// controller's PATCH -- so a snapshot is blind to two of them. The consuming lane measured that
// mode and allow-lan are the only two of PATCH's eleven writable values it displays as live
// state, which is why the payload carries exactly these.
func TestAllowLanChangesTravelOnTheSameStream(t *testing.T) {
	previousMode, previousLan := tunnel.Mode(), listener.AllowLan()
	t.Cleanup(func() {
		tunnel.SetMode(previousMode)
		listener.SetAllowLan(previousLan)
	})
	tunnel.SetMode(tunnel.Rule)
	listener.SetAllowLan(false)

	port := freeLoopbackPort(t)
	addr := "127.0.0.1:" + port
	path := shortClashSocketPath(t)
	cfg := controllerConfig(t, addr)
	if err := startControlPlane(cfg, path); err != nil {
		t.Fatalf("startControlPlane: %v", err)
	}
	t.Cleanup(func() { stopClashAPI(path) })

	connection, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("dial the controller: %v", err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := connection.Write([]byte("GET /hako/v1/mode HTTP/1.1\r\nHost: localhost\r\n\r\n")); err != nil {
		t.Fatalf("request the stream: %v", err)
	}
	reader := bufio.NewReader(connection)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read the response head: %v", err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}
	next := func(what string) (string, bool) {
		t.Helper()
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("read %s: %v", what, err)
			}
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "{") {
				continue
			}
			var payload struct {
				Mode     string `json:"mode"`
				AllowLan bool   `json:"allow-lan"`
			}
			if err := json.Unmarshal([]byte(line), &payload); err != nil {
				t.Fatalf("decode %s from %q: %v", what, line, err)
			}
			return payload.Mode, payload.AllowLan
		}
	}

	if mode, lan := next("the snapshot on connect"); mode != "rule" || lan {
		t.Fatalf("the stream opened with mode=%q allow-lan=%v, not what is running", mode, lan)
	}

	listener.SetAllowLan(true)
	mode, lan := next("the snapshot after allow-lan changed")
	if !lan {
		t.Error("turning allow-lan on did not reach the stream; it has three writers and a " +
			"snapshot is blind to two of them")
	}
	// The pair travels together, so a subscriber never has to merge two partial messages.
	if mode != "rule" {
		t.Errorf("the allow-lan message carried mode=%q, so the pair came apart", mode)
	}
}

// The seam is in tunnel because that is where both writers arrive. A hook installed at the two
// call sites instead would be the failure this batch already made twice -- two paths each
// having to remember -- and the one nobody would notice is the controller's, because it is the
// path no test drives by default.
func TestModeObserverFiresForEveryWriterNotJustTheAppsOwnRoute(t *testing.T) {
	previous := tunnel.Mode()
	t.Cleanup(func() {
		tunnel.SetModeObserver(nil)
		tunnel.SetMode(previous)
	})

	seen := make(chan tunnel.TunnelMode, 4)
	tunnel.SetModeObserver(func(mode tunnel.TunnelMode) { seen <- mode })

	tunnel.SetMode(tunnel.Direct)
	select {
	case mode := <-seen:
		if mode != tunnel.Direct {
			t.Fatalf("observer saw %v, want Direct", mode)
		}
	case <-time.After(time.Second):
		t.Fatal("tunnel.SetMode did not reach the observer")
	}

	// Installing nil has to stop it, or a test that leaves one behind changes the next one.
	tunnel.SetModeObserver(nil)
	tunnel.SetMode(tunnel.Rule)
	select {
	case mode := <-seen:
		t.Fatalf("observer still fired with %v after being cleared", mode)
	case <-time.After(100 * time.Millisecond):
	}
}
