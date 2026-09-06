package hako

import (
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// external-ui was opened on the ground that upstream honours it and the platform permits it.
// Honouring it turned out to mean half of what upstream does: hub/hub.go:60-63 applyRoute runs
// two statements, SetUIPath then ReCreateServer, and only the second was ported. So the core
// downloaded the dashboard exactly as configured -- the six seconds a user waits on first start
// -- stored it, and then served nothing, because hub/route/server.go:159 only mounts /ui when
// the package-level uiPath is non-empty and hub.go:62 is its only assignment in the tree.
//
// A user who wrote external-ui paid the download and got 404. That is worse than either whole
// answer: doing both, or doing neither.
//
// The order is load-bearing and is the reason this is one function rather than two calls in two
// paths. router() reads uiPath while it builds the route table, so SetUIPath after
// ReCreateServer configures the NEXT server. That is the same shape as the defect this file's
// neighbour pins -- the second call decides -- and it is why the two statements now live
// together in recreateControlPlane instead of being remembered separately.
func TestExternalUIIsActuallyServedAndNotJustDownloaded(t *testing.T) {
	options := testOptions(t)
	options.BasePath = shortSocketDirectory(t)
	if err := Setup(options); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// The dashboard the containing app materialises into the container, standing in for the one
	// AutoDownloadUI would fetch. Relative, because C.Path.Resolve puts a relative external-ui
	// under the home directory -- which is what makes an absolute desktop path fail upstream's
	// own safe-path check.
	uiDirectory := filepath.Join(options.WorkingPath, "ui")
	if err := os.MkdirAll(uiDirectory, 0o755); err != nil {
		t.Fatalf("create the dashboard directory: %v", err)
	}
	const marker = "<title>hako dashboard</title>"
	if err := os.WriteFile(filepath.Join(uiDirectory, "index.html"), []byte(marker), 0o644); err != nil {
		t.Fatalf("write the dashboard: %v", err)
	}

	port := freeLoopbackPort(t)
	addr := "127.0.0.1:" + port
	cfg, err := parseConfigForIOS(`
external-controller: `+addr+`
external-ui: ui
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`, true)
	if err != nil {
		t.Fatalf("parse the fixture: %v", err)
	}

	if err := startControlPlane(cfg, ClashAPIPath()); err != nil {
		t.Fatalf("startControlPlane: %v", err)
	}
	t.Cleanup(func() { stopClashAPI(ClashAPIPath()) })

	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Get("http://" + addr + "/ui/index.html")
	if err != nil {
		t.Fatalf("GET /ui/index.html: %v", err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)

	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET /ui/index.html = %d, want 200. The configuration named a dashboard and this "+
			"core downloads it; serving it is the other half of the same field", response.StatusCode)
	}
	if !strings.Contains(string(body), marker) {
		t.Errorf("/ui/index.html served %q, which is not the dashboard in the container", string(body))
	}
}

// A configuration that never names external-ui must not mount anything, because uiPath is a
// package-level variable: set once by any configuration, it would otherwise outlive it and serve
// a previous run's directory to the next one.
func TestNoDashboardIsMountedWhenTheConfigurationNamesNone(t *testing.T) {
	options := testOptions(t)
	options.BasePath = shortSocketDirectory(t)
	if err := Setup(options); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	port := freeLoopbackPort(t)
	addr := "127.0.0.1:" + port
	cfg, err := parseConfigForIOS(`
external-controller: `+addr+`
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`, true)
	if err != nil {
		t.Fatalf("parse the fixture: %v", err)
	}

	if err := startControlPlane(cfg, ClashAPIPath()); err != nil {
		t.Fatalf("startControlPlane: %v", err)
	}
	t.Cleanup(func() { stopClashAPI(ClashAPIPath()) })

	// Reachability first, so a 404 cannot come from a listener that never started -- the shape
	// that let a controller "pass" while nothing was bound.
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("the controller is not listening at %s: %v", addr, err)
	}
	_ = conn.Close()

	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Get("http://" + addr + "/ui/index.html")
	if err != nil {
		t.Fatalf("GET /ui/index.html: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusOK {
		t.Error("a configuration with no external-ui served a dashboard anyway; uiPath is a " +
			"package global and something left it set from another configuration")
	}
}
