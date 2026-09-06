package hako

import (
	"bufio"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/config"
	"github.com/TokenPLS/Hako/hub/executor"
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

// A hot reload used to put THREE messages on the stream for one change of mode: new, old, new.
// The middle two are upstream's parser talking to itself -- config.ParseRawConfig applies the
// candidate's general section for the duration of the parse (geodata loading depends on it)
// and rolls it back before returning, and both steps go through tunnel.SetMode, where the seam
// listens. On a device the consuming lane saw the home-screen selector bounce on every switch,
// and its mode-change handler ran the connected-global enforcement against a core that was still
// reloading. The contract they asked for and the one pinned here: one apply publishes at most
// once, and only after the mode is really applied.
func TestReloadPublishesTheModeOnceAndOnlyAfterItIsReallyApplied(t *testing.T) {
	if err := Setup(testOptions(t)); err != nil {
		t.Fatal(err)
	}
	previous := tunnel.Mode()
	t.Cleanup(func() { tunnel.SetMode(previous) })
	// An earlier test may have cleared the seam; the publisher has to be listening for this
	// test to say anything about it.
	installRuntimeSwitchSeams()
	tunnel.SetMode(tunnel.Direct)

	stream, unsubscribe := subscribeRuntimeSwitches()
	defer unsubscribe()

	cfg, err := parseConfigForIOS(`
mode: rule
dns:
  enable: true
  nameserver: [223.5.5.5]
rules:
  - MATCH,DIRECT
`, false)
	if err != nil {
		t.Fatalf("parseConfigForIOS: %v", err)
	}
	// Parsing is not applying. Whatever the parser did to the live mode on the way, it put it
	// back before returning, and none of that is anybody's business.
	if live := tunnel.Mode(); live != tunnel.Direct {
		t.Fatalf("live mode after a parse = %v, want the unchanged Direct", live)
	}
	select {
	case switches := <-stream:
		t.Fatalf("parsing alone published %+v; nothing was applied yet", switches)
	default:
	}

	executor.ApplyConfig(cfg, true)

	select {
	case switches := <-stream:
		if switches.Mode != "rule" {
			t.Fatalf("the apply published mode %q, want rule", switches.Mode)
		}
	default:
		t.Fatal("applying the configuration published nothing")
	}
	select {
	case switches := <-stream:
		t.Fatalf("a second message %+v followed the apply", switches)
	default:
	}
}

// CheckConfig parses a candidate against the running core -- the App calls it on save -- and
// the parser's temporary apply happens there too, with no real apply to follow. Before the fix
// a validation of a configuration whose mode differed from the live one published a bounce
// (candidate's mode, then the live one again) for something that never happened.
func TestCheckConfigPublishesNothingOnTheModeStream(t *testing.T) {
	if err := Setup(testOptions(t)); err != nil {
		t.Fatal(err)
	}
	previous := tunnel.Mode()
	t.Cleanup(func() { tunnel.SetMode(previous) })
	installRuntimeSwitchSeams()
	tunnel.SetMode(tunnel.Direct)

	stream, unsubscribe := subscribeRuntimeSwitches()
	defer unsubscribe()

	if err := CheckConfig(`
mode: global
dns:
  enable: true
  nameserver: [223.5.5.5]
rules:
  - MATCH,DIRECT
`); err != nil {
		t.Fatalf("CheckConfig: %v", err)
	}
	if live := tunnel.Mode(); live != tunnel.Direct {
		t.Fatalf("CheckConfig changed the live mode to %v", live)
	}
	select {
	case switches := <-stream:
		t.Fatalf("validating a candidate published %+v", switches)
	default:
	}
}

// The mute above is a window around one call, so it only holds while every parse this binding
// performs goes through parseRawConfigQuietly. A second way in -- config.ParseRawConfig used
// anywhere else, any of upstream's wrappers that reach it (config.Parse, executor.Parse /
// ParseWithPath / ParseWithBytes, hub.Parse), under an alias, as a method value handed around,
// through a dot-import, or from a new production subpackage -- would put the parser's temporary
// apply back on the stream, and the behavioural tests would not notice unless the new path
// happened to be the one they drive. So the source is read: every non-test file under this
// module, imports resolved by their unquoted path, and any REFERENCE to a watched symbol (not
// just a direct call -- a method value is a call the AST cannot see) counts. Dot-importing a
// watched package is refused outright, because it makes references unattributable.
func TestEveryParseInThisPackageGoesThroughTheQuietOne(t *testing.T) {
	entryPoints := map[string]map[string]bool{
		"github.com/TokenPLS/Hako/config":       {"ParseRawConfig": true, "Parse": true},
		"github.com/TokenPLS/Hako/hub/executor": {"Parse": true, "ParseWithPath": true, "ParseWithBytes": true},
		"github.com/TokenPLS/Hako/hub":          {"Parse": true},
	}
	references := map[string][]string{}
	fileSet := token.NewFileSet()
	err := filepath.WalkDir(".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if name := entry.Name(); name != "." && (strings.HasPrefix(name, ".") || name == "testdata" || name == "harness" || name == "apple") {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fileSet, path, nil, 0)
		if err != nil {
			return err
		}
		imported := map[string]string{}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return err
			}
			name := importPath[strings.LastIndex(importPath, "/")+1:]
			if spec.Name != nil {
				name = spec.Name.Name
				if name == "." {
					if _, watched := entryPoints[importPath]; watched {
						references["DOT-IMPORT"] = append(references["DOT-IMPORT"], path+":"+importPath)
					}
					continue
				}
			}
			imported[name] = importPath
		}
		ast.Inspect(file, func(n ast.Node) bool {
			selector, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkgIdent, ok := selector.X.(*ast.Ident)
			if !ok {
				return true
			}
			if names, watched := entryPoints[imported[pkgIdent.Name]]; watched && names[selector.Sel.Name] {
				position := fileSet.Position(selector.Pos())
				references[position.Filename] = append(references[position.Filename], imported[pkgIdent.Name]+"."+selector.Sel.Name)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk the module: %v", err)
	}
	if len(references) != 1 || len(references["mode_stream_route.go"]) != 1 ||
		references["mode_stream_route.go"][0] != "github.com/TokenPLS/Hako/config.ParseRawConfig" {
		t.Fatalf("parse entry points are referenced from %v; the only reference allowed is config.ParseRawConfig inside parseRawConfigQuietly (mode_stream_route.go), once", references)
	}
}

// Positive control for the arithmetic below: one config.ParseRawConfig writes the mode exactly
// twice -- once applying the candidate's general for the parse, once rolling it back -- and
// nothing else in the parse reaches tunnel.SetMode. The publisher counts on that number to tell
// the parser's own writes from anybody else's; if upstream ever changes it, this is the test
// that says so, and the constant next to the publisher is what moves.
func TestOneParseWritesTheModeExactlyTwice(t *testing.T) {
	previous := tunnel.Mode()
	t.Cleanup(func() {
		installRuntimeSwitchSeams()
		tunnel.SetMode(previous)
	})
	tunnel.SetMode(tunnel.Direct)
	var writes []tunnel.TunnelMode
	tunnel.SetModeObserver(func(mode tunnel.TunnelMode) { writes = append(writes, mode) })

	raw, err := config.UnmarshalRawConfig([]byte("mode: rule\ndns:\n  enable: true\n  nameserver: [223.5.5.5]\nrules:\n  - MATCH,DIRECT\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := config.ParseRawConfig(raw); err != nil {
		t.Fatalf("ParseRawConfig: %v", err)
	}
	if len(writes) != parserModeWritesPerParse || writes[0] != tunnel.Rule || writes[1] != tunnel.Direct {
		t.Fatalf("one parse wrote the mode %v; want exactly [rule direct] (%d writes)", writes, parserModeWritesPerParse)
	}
}

// The window mutes everything, and the parser's two writes are all it should be muting. When
// somebody else wrote inside the window -- the controller's PATCH, the App's own mode switch
// landing while a provider refresh is parsing -- that write must not vanish: upstream's rollback
// may have undone it (a race upstream loses), the parse may fail so no apply follows, or it may
// land after the rollback and simply be live. In every one of those a subscriber holding an
// optimistic copy is only corrected by hearing the live value once. So when the window closes
// having muted more than the parser's own writes, the publisher sends the live snapshot once.
func TestAWriteMutedInsideTheWindowIsPublishedWhenTheWindowCloses(t *testing.T) {
	previous := tunnel.Mode()
	t.Cleanup(func() { tunnel.SetMode(previous) })
	installRuntimeSwitchSeams()
	tunnel.SetMode(tunnel.Direct)
	stream, unsubscribe := subscribeRuntimeSwitches()
	defer unsubscribe()

	// A parse whose window sees one write that is not the parser's.
	_, err := parseRawConfigQuietlyWith(func() { tunnel.SetMode(tunnel.Global) }, "mode: rule\ndns:\n  enable: true\n  nameserver: [223.5.5.5]\nrules:\n  - MATCH,DIRECT\n")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// Upstream's rollback overwrote the foreign write; the live value is Direct again, and that
	// is what the closing window must say -- once.
	select {
	case switches := <-stream:
		if switches.Mode != "direct" {
			t.Fatalf("the closing window published %q, want the live value direct", switches.Mode)
		}
	default:
		t.Fatal("a write muted inside the window was never made good when the window closed")
	}
	select {
	case switches := <-stream:
		t.Fatalf("second message %+v after the window closed", switches)
	default:
	}

	// And a plain parse -- the parser's own two writes and nothing else -- still publishes nothing.
	if _, err := parseRawConfigQuietlyWith(nil, "mode: rule\ndns:\n  enable: true\n  nameserver: [223.5.5.5]\nrules:\n  - MATCH,DIRECT\n"); err != nil {
		t.Fatalf("parse: %v", err)
	}
	select {
	case switches := <-stream:
		t.Fatalf("a plain parse published %+v", switches)
	default:
	}
}

// parseRawConfigQuietlyWith parses through the quiet path and, when given, performs one foreign
// write from inside the window: right after the parser's temporary apply and before its rollback.
func parseRawConfigQuietlyWith(insideWindow func(), yaml string) (*config.Config, error) {
	raw, err := config.UnmarshalRawConfig([]byte(yaml))
	if err != nil {
		return nil, err
	}
	if insideWindow != nil {
		// The parser's own observer sequence is [apply, rollback]; hooking the seam lets the
		// foreign write land between them, which is the interleaving that matters.
		previous := tunnel.Mode()
		fired := false
		tunnel.SetModeObserver(func(mode tunnel.TunnelMode) {
			publishRuntimeSwitches()
			if !fired && mode != previous {
				fired = true
				insideWindow()
			}
		})
		defer installRuntimeSwitchSeams()
	}
	return parseRawConfigQuietly(raw)
}

// A muted write must never be left behind once the last parse is out. The two-atomic version
// of the window could: a foreign notification read "window open", was preempted, and counted
// itself after the closing parse had already reckoned up and reset -- the count sat at one, and
// the write it stood for was never spoken. Under the lock that residue is impossible, and this
// test looks for it after hammering the bookkeeping. The stand-in parser publishes twice, as the
// real parser's apply and rollback would; nothing here calls tunnel.SetMode, so upstream's
// unsynchronised mode variable is only ever read, and the race detector is watching the window
// itself.
func TestTheWindowNeverLeavesAMutedWriteBehind(t *testing.T) {
	installRuntimeSwitchSeams()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			publishRuntimeSwitches()
		}
	}()
	for i := 0; i < 500; i++ {
		_, _ = insideParseWindow(func() (*config.Config, error) {
			publishRuntimeSwitches()
			publishRuntimeSwitches()
			return nil, nil
		})
	}
	close(stop)
	wg.Wait()

	parseWindow.Lock()
	defer parseWindow.Unlock()
	if parseWindow.inFlight != 0 || parseWindow.parses != 0 || parseWindow.muted != 0 {
		t.Fatalf("bookkeeping left behind after every window closed: inFlight=%d parses=%d muted=%d",
			parseWindow.inFlight, parseWindow.parses, parseWindow.muted)
	}
}
