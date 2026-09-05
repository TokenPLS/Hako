package hako

import (
	"os"
	"strings"
	"testing"
	"time"

	C "github.com/TokenPLS/Hako/constant"
	"github.com/TokenPLS/Hako/log"
	"github.com/TokenPLS/Hako/tunnel"
	"github.com/sirupsen/logrus"
)

// . A remote provider the app could not download at activation used to be a
// refusal at three layers; a subscription with dozens of rule-set links then held
// the app for minutes while it tried. Now the definition rides through as written,
// the core starts it empty and fetches it in the background, and the app can hand
// in a payload it fetched through the tunnel.

const remoteProviderYAML = `
mode: rule
log-level: info
dns:
  enable: true
  enhanced-mode: fake-ip
  nameserver:
    - 8.8.8.8
proxies:
  - name: probe
    type: socks5
    server: 127.0.0.1
    port: 1080
rule-providers:
  ads:
    type: http
    behavior: domain
    format: yaml
    url: https://example.invalid/ads.yaml
    interval: 86400
rules:
  - RULE-SET,ads,REJECT
  - MATCH,probe
`

func TestRemoteProviderWithAUsableURLIsAcceptedAtEveryLayer(t *testing.T) {
	if err := Setup(testOptions(t)); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if err := CheckConfig(remoteProviderYAML); err != nil {
		t.Fatalf("CheckConfig refused a remote provider: %v", err)
	}
	// No resource map: the app downloaded nothing. The definition must survive whole.
	out, err := FinalizeForIOS(remoteProviderYAML, "")
	if err != nil {
		t.Fatalf("FinalizeForIOS: %v", err)
	}
	for _, want := range []string{"type: http", "https://example.invalid/ads.yaml", "interval: 86400"} {
		if !strings.Contains(out.Value, want) {
			t.Fatalf("finalized configuration lost %q:\n%s", want, out.Value)
		}
	}
	// With a staged copy the rewrite to file stands exactly as before.
	staged, err := FinalizeForIOS(remoteProviderYAML, `{"providerPaths":{"ads":"/data/providers/ads.yaml"}}`)
	if err != nil {
		t.Fatalf("FinalizeForIOS with a staged copy: %v", err)
	}
	if !strings.Contains(staged.Value, "type: file") || strings.Contains(staged.Value, "example.invalid") {
		t.Fatalf("a staged provider must still become a file provider:\n%s", staged.Value)
	}
}

func TestPlanNamesTheCoreFetchForRemoteProviders(t *testing.T) {
	plan := planOf(t, remoteProviderYAML)
	if len(plan.Errors) != 0 {
		t.Fatalf("the plan refused a remote provider: %+v", plan.Errors)
	}
	for _, notice := range plan.Notices {
		if strings.HasPrefix(notice, "rule-providers: ") && strings.Contains(notice, "downloaded by the core in the background") {
			return
		}
	}
	t.Fatalf("no core-fetch notice for rule-providers in %+v", plan.Notices)
}

func TestRemoteProviderWithAUsableURLStartsEmptyAndIsFetchedLater(t *testing.T) {
	t.Cleanup(func() { logrus.SetOutput(os.Stdout) })
	options := testOptions(t)
	if err := Setup(options); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	C.SetHomeDir(options.WorkingPath)
	// The core's own log stream, not logrus: the deferral line is what tells a
	// reader the empty provider is expected, and it must not read as a failure.
	subscription := log.Subscribe()
	t.Cleanup(func() { log.UnSubscribe(subscription) })
	seen := make(chan string, 1)
	go func() {
		deadline := time.After(10 * time.Second)
		for {
			select {
			case event, open := <-subscription:
				if !open {
					seen <- ""
					return
				}
				if strings.Contains(event.Payload, "provider ads") && (strings.Contains(event.Payload, "deferred") || strings.Contains(event.Payload, "error")) {
					seen <- event.Payload
					return
				}
			case <-deadline:
				seen <- ""
				return
			}
		}
	}()
	svc, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })

	started := time.Now()
	if err := svc.Start(remoteProviderYAML); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if elapsed := time.Since(started); elapsed > 10*time.Second {
		t.Fatalf("Start took %s with an unreachable remote provider; the download must not sit on the Start path", elapsed)
	}
	provider, ok := tunnel.RuleProviders()["ads"]
	if !ok {
		t.Fatalf("the remote provider is not part of the running configuration")
	}
	if provider.Count() != 0 {
		t.Fatalf("a provider nobody has fetched yet holds %d rules", provider.Count())
	}
	if line := <-seen; !strings.Contains(line, "deferred") {
		t.Fatalf("the log must say the load was deferred, not that it failed; got %q", line)
	}

	// The app fetched it through the tunnel and hands it in. The live provider
	// applies it and keeps a copy where the next start will find it.
	payload := []byte("payload:\n  - ads.example.com\n  - '+.tracker.example.net'\n")
	if err := svc.sideUpdateProvider("rule", "ads", payload); err != nil {
		t.Fatalf("side update over the http vehicle: %v", err)
	}
	if provider.Count() != 2 {
		t.Fatalf("after the side update the provider holds %d rules, want 2", provider.Count())
	}
	stored := C.Path.GetPathByHash("rules", "https://example.invalid/ads.yaml")
	if _, err := os.Stat(stored); err != nil {
		t.Fatalf("the side-updated payload was not stored at the vehicle path %s: %v", stored, err)
	}
	if err := svc.sideUpdateProvider("rule", "nope", payload); err == nil {
		t.Fatalf("an unknown provider must still be refused")
	}
}
