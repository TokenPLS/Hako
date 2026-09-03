package hako

import (
	"os"
	"testing"

	"github.com/sirupsen/logrus"
)

// A config with a selector group so SelectProxy has something to switch.
const groupYAML = `
mode: rule
log-level: info
dns:
  enable: true
  nameserver:
    - 8.8.8.8
proxies:
  - {name: a, type: socks5, server: 127.0.0.1, port: 1080}
  - {name: b, type: socks5, server: 127.0.0.1, port: 1081}
proxy-groups:
  - name: pick
    type: select
    proxies: [a, b]
  - name: auto
    type: url-test
    url: "https://www.gstatic.com/generate_204"
    interval: 300
    proxies: [a, b]
rules:
  - MATCH,pick
`

func TestControlActions(t *testing.T) {
	t.Cleanup(func() { logrus.SetOutput(os.Stdout) })
	if err := Setup(testOptions(t)); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	svc, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	if err := svc.Start(groupYAML); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Select a member of the group.
	if err := SelectProxy("pick", "b"); err != nil {
		t.Fatalf("SelectProxy: %v", err)
	}
	// Selecting a non-member fails.
	if err := SelectProxy("pick", "nope"); err == nil {
		t.Fatal("selecting a non-member should fail")
	}
	// A non-group name is rejected.
	if err := SelectProxy("a", "b"); err == nil {
		t.Fatal("selecting on a non-group should fail")
	}
	// An unknown group is rejected.
	if err := SelectProxy("ghost", "b"); err == nil {
		t.Fatal("unknown group should fail")
	}

	// Unfix hands an automatic group back to its own measurement. `pick`
	// is a Selector, which the kernel's own route refuses to unfix
	// (hub/route/proxies.go:155-160): nothing resumes on a manual group.
	if err := UnfixProxy("pick"); err == nil {
		t.Fatal("unfixing a selector should fail like the kernel route does")
	}
	if err := UnfixProxy("auto"); err != nil {
		t.Fatalf("UnfixProxy: %v", err)
	}
	// Releasing an unpinned group is a no-op, not an error, matching
	// ForceSet("") semantics.
	if err := UnfixProxy("auto"); err != nil {
		t.Fatalf("UnfixProxy twice: %v", err)
	}
	if err := UnfixProxy("ghost"); err == nil {
		t.Fatal("unknown group should fail")
	}
	if err := UnfixProxy("a"); err == nil {
		t.Fatal("a plain node should fail")
	}

	// URLTest on an unknown proxy returns the -1 sentinel (no panic).
	if d := URLTest("ghost", ""); d != -1 {
		t.Fatalf("URLTest(unknown) = %d, want -1", d)
	}

	// Connection teardown is safe with no live connections.
	if CloseConnection("does-not-exist") {
		t.Fatal("CloseConnection on unknown id should return false")
	}
	CloseAllConnections() // must not panic
}
