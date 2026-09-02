package hako

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TokenPLS/Hako/config"
	C "github.com/TokenPLS/Hako/constant"
	"github.com/sirupsen/logrus"
)

// The extension stages every file-backed provider at tunnel start: 413ms of an
// 865ms cold start on a 56-provider subscription, inside a fifty-megabyte
// budget, while the reader watches a spinner. The App already holds those same
// bytes -- it downloaded them -- so the work can happen there instead, once per
// revision, where the reader is already waiting on the network.
//
// That only holds if both processes produce the same product. These tests pin
// the contract: identical inputs, byte-identical staged files and manifest, and
// an extension start that serves them without reading a provider.

const publishTestProxy = "proxies:\n" +
	"  - name: a\n    type: ss\n    server: 1.2.3.4\n    port: 443\n" +
	"    cipher: aes-128-gcm\n    password: x\n    interface-name: en0\n"

const publishTestRule = "payload:\n  - DOMAIN-SUFFIX,example.com\n  - PROCESS-NAME,Mail\n"

func publishTestConfig(t *testing.T, home string) string {
	t.Helper()
	proxyPath := filepath.Join(home, "published-proxy.yaml")
	rulePath := filepath.Join(home, "published-rule.yaml")
	if err := os.WriteFile(proxyPath, []byte(publishTestProxy), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rulePath, []byte(publishTestRule), 0o600); err != nil {
		t.Fatal(err)
	}
	return "" +
		"dns:\n  enable: true\n  nameserver: [8.8.8.8]\n" +
		"proxy-providers:\n  air:\n    type: file\n    path: " + proxyPath + "\n" +
		"rule-providers:\n  ads:\n    type: file\n    behavior: classical\n" +
		"    format: yaml\n    path: " + rulePath + "\n" +
		"proxy-groups:\n  - name: G\n    type: select\n    use: [air]\n" +
		"rules:\n  - RULE-SET,ads,G\n  - MATCH,DIRECT\n"
}

func stagedTree(t *testing.T, home string) map[string]string {
	t.Helper()
	root := filepath.Join(home, providerRuntimeDirectoryName)
	tree := map[string]string{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		payload, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		relative, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		tree[relative] = string(payload)
		return nil
	})
	if err != nil {
		t.Fatalf("walk staged tree: %v", err)
	}
	return tree
}

func capturePublishLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var logBuffer bytes.Buffer
	logrus.SetOutput(&logBuffer)
	t.Cleanup(func() { logrus.SetOutput(os.Stdout) })
	return &logBuffer
}

// One line at the end of a publish says where the products landed and what
// the verdicts were. It exists because a staging tree written under an
// unexpected home directory took a night to find; with this line the answer
// is the first thing the log says.
func TestPublishLogsWhereItWroteAndTheVerdictCounts(t *testing.T) {
	options := testOptions(t)
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	home := options.WorkingPath
	C.SetHomeDir(home)
	// IP-CIDR runs fine on every Apple profile (nothing strips it), and the
	// domain strategy cannot store it, so this set is a genuine
	// notCompilable -- unlike the shared fixture's PROCESS-NAME, which iOS
	// strips before the compiler ever sees it.
	rulePath := filepath.Join(home, "published-cidr.yaml")
	if err := os.WriteFile(rulePath,
		[]byte("payload:\n  - DOMAIN-SUFFIX,example.com\n  - IP-CIDR,10.0.0.0/8,no-resolve\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	content := "" +
		"dns:\n  enable: true\n  nameserver: [8.8.8.8]\n" +
		"rule-providers:\n  cidr:\n    type: file\n    behavior: classical\n" +
		"    format: yaml\n    path: " + rulePath + "\n" +
		"rules:\n  - RULE-SET,cidr,DIRECT\n  - MATCH,DIRECT\n"
	logBuffer := capturePublishLog(t)

	if err := StageProvidersForPublish(content, RuntimeProfileIOSPacketTunnel, true); err != nil {
		t.Fatalf("StageProvidersForPublish: %v", err)
	}

	logged := logBuffer.String()
	if !strings.Contains(logged, stagedProviderParentDirectory()) {
		t.Fatalf("publish log never names the destination directory %q:\n%s", stagedProviderParentDirectory(), logged)
	}
	for _, want := range []string{"compiled=0", "notCompilable=0", "keptSource=1"} {
		if !strings.Contains(logged, want) {
			t.Fatalf("publish log misses %q:\n%s", want, logged)
		}
	}
}

func TestPublishLogsEvenWhenNothingIsFileBacked(t *testing.T) {
	options := testOptions(t)
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	C.SetHomeDir(options.WorkingPath)
	logBuffer := capturePublishLog(t)

	content := "dns:\n  enable: true\n  nameserver: [8.8.8.8]\nrules:\n  - MATCH,DIRECT\n"
	if err := StageProvidersForPublish(content, RuntimeProfileIOSPacketTunnel, true); err != nil {
		t.Fatalf("StageProvidersForPublish: %v", err)
	}

	logged := logBuffer.String()
	if !strings.Contains(logged, stagedProviderParentDirectory()) ||
		!strings.Contains(logged, "compiled=0") {
		t.Fatalf("a publish that staged nothing must still say where it would have written and that every count is zero:\n%s", logged)
	}
}

// The App runs outside the Network Extension, and three policy fields turn on
// that very boolean -- networkExtension, requirePacketTunnelDNS,
// repairPacketTunnelDNS. Staging for "this process" would therefore fingerprint
// differently from the extension and miss every entry, so the publish entry
// names the profile it is staging FOR rather than reading the one it runs in.
func TestPublishStagesForTheProfileTheExtensionWillRun(t *testing.T) {
	options := testOptions(t)
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	home := options.WorkingPath
	C.SetHomeDir(home)
	content := publishTestConfig(t, home)

	if err := StageProvidersForPublish(content, RuntimeProfileIOSPacketTunnel, false); err != nil {
		t.Fatalf("StageProvidersForPublish: %v", err)
	}
	published := stagedTree(t, home)
	if len(published) < 3 {
		t.Fatalf("publish staged %d files, want a manifest and two providers", len(published))
	}

	manifestName := providerRuntimeManifestName
	raw, exists := published[manifestName]
	if !exists {
		t.Fatalf("publish wrote no manifest; %d files staged", len(published))
	}
	var manifest stagedProviderManifest
	if err := json.Unmarshal([]byte(raw), &manifest); err != nil {
		t.Fatalf("decode published manifest: %v", err)
	}
	extensionPolicy := runtimePolicyFor(runtimeProfileIOSPacketTunnel, true)
	if manifest.Policy != stagedPolicyFingerprint(extensionPolicy) {
		t.Fatal("published manifest carries the App's policy, so the extension will miss every entry")
	}
}

// Same inputs, same product. If the two processes could disagree by a single
// byte the manifest would not be a cache, it would be a correctness bug that
// only shows up on the device.
func TestPublishAndExtensionStagingAgreeByteForByte(t *testing.T) {
	options := testOptions(t)
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	home := options.WorkingPath
	C.SetHomeDir(home)
	content := publishTestConfig(t, home)

	if err := StageProvidersForPublish(content, RuntimeProfileIOSPacketTunnel, false); err != nil {
		t.Fatalf("StageProvidersForPublish: %v", err)
	}
	byPublish := stagedTree(t, home)

	// Wipe and let the extension path build the same thing from the same source.
	if err := os.RemoveAll(filepath.Join(home, providerRuntimeDirectoryName)); err != nil {
		t.Fatal(err)
	}
	raw, err := config.UnmarshalRawConfig([]byte(content))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stageProviderRuntime(raw, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true), false); err != nil {
		t.Fatalf("stageProviderRuntime: %v", err)
	}
	byExtension := stagedTree(t, home)

	if len(byPublish) != len(byExtension) {
		t.Fatalf("published %d files, extension staged %d", len(byPublish), len(byExtension))
	}
	for name, publishedPayload := range byPublish {
		extensionPayload, exists := byExtension[name]
		if !exists {
			t.Fatalf("the extension did not produce %q", name)
		}
		if publishedPayload != extensionPayload {
			t.Fatalf("%q differs between publish and extension staging", name)
		}
	}
}

// The whole point: after a publish, the extension's own staging pass reads no
// provider file at all. The cost line is the witness -- every entry a hit,
// nothing read, nothing decoded.
func TestExtensionReadsNoProviderAfterAPublish(t *testing.T) {
	options := testOptions(t)
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	home := options.WorkingPath
	C.SetHomeDir(home)
	content := publishTestConfig(t, home)

	if err := StageProvidersForPublish(content, RuntimeProfileIOSPacketTunnel, false); err != nil {
		t.Fatalf("StageProvidersForPublish: %v", err)
	}

	raw, err := config.UnmarshalRawConfig([]byte(content))
	if err != nil {
		t.Fatal(err)
	}
	startupProbing.Store(true)
	defer startupProbing.Store(false)
	before := len(StartupPhaseTrace())
	if _, err := stageProviderRuntime(raw, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true), false); err != nil {
		t.Fatalf("stageProviderRuntime after publish: %v", err)
	}
	trace := StartupPhaseTrace()[before:]
	if !bytes.Contains([]byte(trace), []byte("hit=2")) {
		t.Fatalf("expected both providers served from the publish, trace = %q", trace)
	}
	if !bytes.Contains([]byte(trace), []byte("read=0/")) {
		t.Fatalf("the extension still read provider files after a publish, trace = %q", trace)
	}
}

// A publish for one profile must not silently serve another. The macOS packet
// tunnel keeps PROCESS-NAME rules the iOS one strips, so a shared staging would
// hand one platform the other's rules.
func TestAPublishForAnotherProfileIsNotServed(t *testing.T) {
	options := testOptions(t)
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	home := options.WorkingPath
	C.SetHomeDir(home)
	content := publishTestConfig(t, home)

	if err := StageProvidersForPublish(content, RuntimeProfileMacOSPacketTunnel, false); err != nil {
		t.Fatalf("StageProvidersForPublish: %v", err)
	}
	raw, err := config.UnmarshalRawConfig([]byte(content))
	if err != nil {
		t.Fatal(err)
	}
	startupProbing.Store(true)
	defer startupProbing.Store(false)
	before := len(StartupPhaseTrace())
	if _, err := stageProviderRuntime(raw, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true), false); err != nil {
		t.Fatal(err)
	}
	trace := StartupPhaseTrace()[before:]
	if !bytes.Contains([]byte(trace), []byte("hit=0")) {
		t.Fatalf("a macOS publish was served to an iOS packet tunnel, trace = %q", trace)
	}
}

// An unreadable rule set is not a reason to refuse an import. Upstream stages
// it, fails to load it, logs that, and keeps every other rule; was
// written after refusing one cost a reader twenty-six working rule sets. The
// publish path inherits that ruling, not a stricter one.
func TestPublishDoesNotRefuseAnUnreadableRuleSet(t *testing.T) {
	options := testOptions(t)
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	home := options.WorkingPath
	C.SetHomeDir(home)
	proxyPath := filepath.Join(home, "published-proxy.yaml")
	if err := os.WriteFile(proxyPath, []byte(publishTestProxy), 0o600); err != nil {
		t.Fatal(err)
	}
	// format: mrs over an HTML error page -- the exact shape of the incident.
	brokenPath := filepath.Join(home, "broken-rule.mrs")
	if err := os.WriteFile(brokenPath, []byte("<!DOCTYPE html><html>404</html>"), 0o600); err != nil {
		t.Fatal(err)
	}
	content := "" +
		"dns:\n  enable: true\n  nameserver: [8.8.8.8]\n" +
		"proxy-providers:\n  air:\n    type: file\n    path: " + proxyPath + "\n" +
		"rule-providers:\n  broken:\n    type: file\n    behavior: domain\n" +
		"    format: mrs\n    path: " + brokenPath + "\n" +
		"proxy-groups:\n  - name: G\n    type: select\n    use: [air]\n" +
		"rules:\n  - MATCH,DIRECT\n"

	if err := StageProvidersForPublish(content, RuntimeProfileIOSPacketTunnel, false); err != nil {
		t.Fatalf("an unreadable rule set must not fail the publish: %v", err)
	}
	staged := stagedTree(t, home)
	if _, exists := staged[providerRuntimeManifestName]; !exists {
		t.Fatal("publish wrote no manifest for a configuration with one unreadable rule set")
	}
}
