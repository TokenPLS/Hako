package hako

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TokenPLS/Hako/config"
)

// A1 removed the stripping of all ten owner-metadata kinds, on the finding that upstream keeps
// them and evaluates them against empty metadata. That finding was about EVALUATION, and it is
// right for nine of the ten. UID is different for a reason A1 never checked: upstream refuses
// to CONSTRUCT it off linux/android/darwin (rules/common/uid.go), so on GOOS=ios the rule does
// not evaluate to false -- config.Parse returns an error and the whole configuration fails to
// start.
//
// The tests that were supposed to catch this could not: they run on the host, which is darwin,
// and darwin is on upstream's allow-list. A green `UID,0,REJECT` on this machine says nothing
// about the platform the code ships to. That blind spot is why this test reads upstream's
// source for the list instead of restating it.
func TestOurUIDPlatformListStillMatchesUpstream(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "rules", "common", "uid.go"))
	if err != nil {
		t.Fatalf("read upstream uid rule: %v", err)
	}
	body := string(source)
	if !strings.Contains(body, `runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "darwin"`) {
		t.Fatalf("the UID constructor's platform list changed; re-read it and update " +
			"uidRuleConstructible. This core strips UID exactly where upstream cannot build it, " +
			"and that correspondence is the only thing keeping a config from failing to start")
	}
	for goos, want := range map[string]bool{
		"linux": true, "android": true, "darwin": true,
		"ios": false, "windows": false, "freebsd": false,
	} {
		if got := uidRuleConstructible(goos); got != want {
			t.Errorf("uidRuleConstructible(%q) = %v, want %v", goos, got, want)
		}
	}
}

// The regression, stated as the user sees it: a subscription written for Android carries a UID
// rule; on iOS it used to run with that rule stripped, and after A1 it stopped starting at all.
func TestAUIDRuleDoesNotStopAnIOSConfigurationFromStarting(t *testing.T) {
	raw := mustUnmarshalRaw(t, `
rules:
  - DOMAIN,first.example,DIRECT
  - UID,501,REJECT
  - MATCH,DIRECT
`)
	normalizeRawConfigForApple(raw, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true))

	for _, rule := range raw.Rule {
		if strings.HasPrefix(rule, "UID,") {
			t.Fatalf("UID survived normalize for an iOS packet tunnel: %v -- upstream's "+
				"constructor will refuse it and the whole configuration will fail to parse", raw.Rule)
		}
	}
	if len(raw.Rule) != 2 || raw.Rule[0] != "DOMAIN,first.example,DIRECT" {
		t.Fatalf("the executable rules did not survive in order: %v", raw.Rule)
	}
}

// A1's fix stays: the other nine kinds are still kept, because their constructors accept every
// platform and upstream evaluates them against empty metadata.
func TestTheOtherNineKindsAreStillKeptOnIOS(t *testing.T) {
	// All nine, by name, in the order RULE-KIND-AVAILABILITY.json lists them -- the macOS lane
	// asked for the full set because its client cannot measure this offline and keys its own
	// copy on these names.
	raw := mustUnmarshalRaw(t, `
rules:
  - PROCESS-NAME,curl,REJECT
  - PROCESS-NAME-REGEX,^cu.*,REJECT
  - PROCESS-NAME-WILDCARD,cu*,REJECT
  - PROCESS-PATH,/usr/bin/curl,REJECT
  - PROCESS-PATH-REGEX,^/usr/bin/.*,REJECT
  - PROCESS-PATH-WILDCARD,/usr/bin/*,REJECT
  - IN-USER,alice,REJECT
  - SOURCE-APP-SIGNING-ID,com.example.app,REJECT
  - SOURCE-APP-TEAM-ID,ABCDE12345,REJECT
  - MATCH,DIRECT
`)
	before := append([]string(nil), raw.Rule...)
	normalizeRawConfigForApple(raw, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true))
	if len(raw.Rule) != len(before) {
		t.Fatalf("a kind whose constructor accepts every platform was stripped: %v", raw.Rule)
	}
	for i := range before {
		if raw.Rule[i] != before[i] {
			t.Fatalf("rule %d changed or moved: %q -> %q", i, before[i], raw.Rule[i])
		}
	}
	for _, kind := range ownerMetadataRuleKinds {
		if kind == "UID" {
			continue
		}
		if !strings.Contains(strings.Join(raw.Rule, "|"), kind+",") {
			t.Fatalf("%s is one of the nine kept kinds but is not in the fixture -- the test no longer covers the set it claims", kind)
		}
	}
}

// macOS builds as GOOS=darwin, which upstream allows, so nothing is stripped there.
func TestUIDSurvivesOnMacOSWhereUpstreamCanBuildIt(t *testing.T) {
	raw := mustUnmarshalRaw(t, `
rules:
  - UID,501,REJECT
  - MATCH,DIRECT
`)
	normalizeRawConfigForApple(raw, runtimePolicyFor(runtimeProfileMacOSPacketTunnel, true))
	if len(raw.Rule) != 2 {
		t.Fatalf("UID was stripped on macOS, where upstream builds it fine: %v", raw.Rule)
	}
}

// A logic rule carrying a UID branch cannot be kept either: rules/logic/logic.go parsePayload
// returns on the first branch that fails to construct, so one UID branch fails the whole rule
// and with it the configuration. Dropping the rule loses its executable branches -- the exact
// harm A1 fixed -- so it is dropped and REPORTED rather than dropped quietly.
func TestALogicRuleCarryingUIDIsDroppedAndReportedOnIOS(t *testing.T) {
	const document = `
rules:
  - OR,((UID,501),(DOMAIN-SUFFIX,bank.example)),REJECT
  - OR,((PROCESS-NAME,evil),(DOMAIN-SUFFIX,other.example)),REJECT
  - MATCH,DIRECT
`
	raw := mustUnmarshalRaw(t, document)
	normalizeRawConfigForApple(raw, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true))

	joined := strings.Join(raw.Rule, "|")
	if strings.Contains(joined, "UID,501") {
		t.Fatalf("the UID-bearing logic rule survived: %v", raw.Rule)
	}
	if !strings.Contains(joined, "PROCESS-NAME,evil") {
		t.Fatalf("a logic rule with no UID branch was dropped too; A1's fix regressed: %v", raw.Rule)
	}
}

// And the whole thing has to actually parse, which is the property that broke.
func TestAnIOSConfigurationWithUIDRulesParses(t *testing.T) {
	const document = `
proxies: []
proxy-groups: []
rules:
  - UID,501,REJECT
  - OR,((UID,0),(DOMAIN-SUFFIX,bank.example)),REJECT
  - DOMAIN,keep.example,DIRECT
  - MATCH,DIRECT
`
	if _, err := config.Parse([]byte(document)); err != nil {
		t.Fatalf("fixture is wrong, not the code: upstream on this host rejected it: %v", err)
	}
	if _, err := parseConfigForIOS(document, true); err != nil {
		t.Fatalf("an iOS parse of a configuration carrying UID rules failed: %v", err)
	}
}

// UID was found by a consumer, on a device, after it shipped to main. The class it belongs to
// is "a rule constructor that refuses a platform", and the reason nobody here caught it is
// structural: these tests run on darwin, which upstream allows, so the failure is invisible on
// the only machine that runs them.
//
// This is that class turned into a gate. It does not try to be clever about what a new gate
// would mean -- it just refuses to let one arrive unnoticed. Today the set is exactly one
// file; if an upstream bump adds another, somebody has to look at it and decide whether iOS
// needs the same treatment, and this is the line that makes them look.
func TestNoNewPlatformGatedRuleConstructorArrivesUnnoticed(t *testing.T) {
	known := map[string]string{
		"rules/common/uid.go": "handled: stripUnconstructibleUIDRules removes UID where upstream " +
			"cannot build it, and the platform list is checked against this file above",
	}

	root := filepath.Join("..", "..", "rules")
	found := make(map[string]bool)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if strings.Contains(string(body), "runtime.GOOS") {
			relative := filepath.ToSlash(strings.TrimPrefix(path, filepath.Join("..", "..")+string(filepath.Separator)))
			found[relative] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk rules/: %v", err)
	}
	if len(found) == 0 {
		t.Fatal("no runtime.GOOS found anywhere under rules/, which cannot be right -- " +
			"uid.go has one. The scan is broken, and a broken scan passes silently")
	}

	for file := range found {
		if _, isKnown := known[file]; !isKnown {
			t.Errorf("%s gates on runtime.GOOS and nothing here handles it. A rule constructor "+
				"that refuses a platform does not evaluate to false -- it fails config.Parse for "+
				"the WHOLE configuration, so a user's file stops starting. Decide whether this "+
				"kind needs the same treatment as UID, then add it here with the reason", file)
		}
	}
	for file := range known {
		if !found[file] {
			t.Errorf("%s no longer gates on runtime.GOOS; if upstream dropped the restriction, "+
				"the strip in uid_construction_gate.go is now stricter than upstream and should go", file)
		}
	}
}
