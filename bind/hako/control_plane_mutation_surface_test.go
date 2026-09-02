package hako

import (
	"bufio"
	"net"
	"net/http"
	"strings"
	"testing"
)

// PUT /configs is upstream's "replace the running configuration" endpoint, and
// it is the one path into the core that does not go through this tree's Apple
// normalization: hub/route/configs.go:407 updateConfigs calls
// executor.ParseWithBytes and then executor.ApplyConfig directly, so
// normalizeRawConfigForApple -- and with it repairApplePacketTunnelDNS, the
// dns.enable repair and everything else in that pipeline -- never runs.
//
// It is closed here, because hub/route/configs.go:40 registers it only when
// !embedMode and bind/hako/clash_api.go:107 sets embed mode on. That is a real
// invariant with real consequences (a PUT of `dns.enable: false` would put the
// extension's state -- DefaultService nil, every hijacked query
// SERVFAIL -- while the App still shows the profile it thinks is running), and
// until now nothing was watching it. Flipping SetEmbedMode for an unrelated
// reason, or an upstream change to that default, would restore the bypass in
// silence.
//
// Raised by the macOS lane while reviewing, where it turned up as a
// candidate hole and turned out to be a closed door with no lock on it.
//
// The gate is behavioural on purpose: it asks the running control plane rather
// than reading the source, so it stays true through any refactor that keeps the
// endpoint shut and goes red the moment one opens it.
func TestTheControlPlaneServesNoConfigReplacementEndpoint(t *testing.T) {
	path := shortClashSocketPath(t)
	withSetupClashAPIPath(t, path)
	if err := startControlPlane(plainConfig(t), path); err != nil {
		t.Fatalf("startControlPlane: %v", err)
	}
	t.Cleanup(func() { stopClashAPI(path) })

	ask := func(method, target, body string) int {
		t.Helper()
		conn, err := net.Dial("unix", path)
		if err != nil {
			t.Fatalf("dial the App Group socket: %v", err)
		}
		defer conn.Close()
		var reader *strings.Reader
		if body != "" {
			reader = strings.NewReader(body)
		}
		var request *http.Request
		if reader != nil {
			request, err = http.NewRequest(method, "http://hako"+target, reader)
		} else {
			request, err = http.NewRequest(method, "http://hako"+target, nil)
		}
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		if err := request.Write(conn); err != nil {
			t.Fatalf("write request: %v", err)
		}
		response, err := http.ReadResponse(bufio.NewReader(conn), request)
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		_ = response.Body.Close()
		return response.StatusCode
	}

	// Positive control first. Without it a 404 below proves nothing -- a socket
	// that answers nothing at all looks exactly the same.
	if status := ask(http.MethodGet, "/configs", ""); status != http.StatusOK {
		t.Fatalf("GET /configs answered %d, want 200 -- the control plane is not live, so this test measures nothing", status)
	}

	// PUT only, and the narrowing is evidence rather than taste. The first
	// version of this gate treated any non-404 on /configs as the replacement
	// surface being open, and PATCH answered 204 -- which looked like a finding
	// and was the predicate being too wide. PATCH is patchConfigs
	// (hub/route/configs.go:336), which decodes into configSchema: a fixed
	// allowlist of general/tun settings with no dns member at all, so the body
	// below decodes to an all-nil struct and changes nothing. Whether PATCH's
	// own allowlist should reach the core unnormalized is a separate question
	// that hub/route/configs.go:36-39 already reasons about; it is not this
	// invariant.
	status := ask(http.MethodPut, "/configs", `{"dns":{"enable":false}}`)
	if status != http.StatusNotFound && status != http.StatusMethodNotAllowed {
		t.Errorf("PUT /configs answered %d -- the config-replacement surface is open. It bypasses "+
			"normalizeRawConfigForApple entirely (hub/route/configs.go:407 parses upstream and applies "+
			"directly), so a payload with dns.enable false reaches the core unrepaired and every hijacked "+
			"query answers SERVFAIL while the App still shows the profile it thinks is running. "+
			"Keep route.SetEmbedMode(true) in clash_api.go, or run the payload through the Apple pipeline first.",
			status)
	}
}
