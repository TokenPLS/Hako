package hako

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TokenPLS/Hako/config"
	C "github.com/TokenPLS/Hako/constant"
)

// Rule sets ride into the runtime as MRS, compiled once in the App process.
//
// A text rule set holds four representations of the same table at once while it loads —
// measured on device, one 616 KB table takes the extension from 25 MiB to within sight of
// the 50 MiB ceiling, and the user's fourteen together account for 32 MiB of it. The same
// table as MRS costs a fifth. So publishing compiles (the App has the bytes and the
// memory), staging rewrites the three values that must agree — path, format, behavior —
// in the one function both processes run, and the verdict travels in the staged manifest.
//
// The compiler is the official path: CompileRuleProvider calls the same ConvertToMrs the
// `mihomo convert-ruleset` CLI is built on, so artifacts are byte-compatible with what
// meta-rules-dat distributes.
//
// A set that cannot compile is staged EMPTY instead of being stripped: RULE-SET
// references can hide inside AND()/OR()/NOT() and sub-rules, where removing the provider
// leaves a fatal dangling name, while an empty set simply matches nothing — the zero-byte
// deliberate-staging precedent, reused. The ruling's words: not refused at start, the
// runtime just does not carry it.

func compileStagingHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	C.SetHomeDir(home)
	return home
}

// Sources live inside the container: staging refuses anything outside it
// (providerSourceContained), which is what the App does in production -- it
// publishes into the App Group and points providers at those files.
func writeRuleSource(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(C.Path.HomeDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func rawWithRuleProvider(path, behavior, format string) *config.RawConfig {
	raw := &config.RawConfig{}
	raw.RuleProvider = map[string]map[string]any{
		"reject": {
			"type": "file", "path": path,
			"behavior": behavior, "format": format,
		},
	}
	return raw
}

func manifestEntry(t *testing.T, home, kind, name string) string {
	t.Helper()
	entries := readManifest(t, home)
	entry, ok := entries[providerRuntimeKey(kind, name)]
	if !ok {
		t.Fatalf("no manifest entry for %s %s", kind, name)
	}
	return string(entry)
}

func TestPublishCompilesADomainRuleSetToMrs(t *testing.T) {
	home := compileStagingHome(t)
	source := writeRuleSource(t, "reject.txt", "example.com\n+.example.org\n")
	raw := rawWithRuleProvider(source, "domain", "text")

	runtime, err := stageProviderRuntime(raw, currentRuntimePolicy(true), true)
	if err != nil {
		t.Fatalf("stage with compile: %v", err)
	}
	defer runtime.close()

	entry := manifestEntry(t, home, "rule", "reject")
	if !strings.Contains(entry, `"compileVerdict":"compiled"`) {
		t.Fatalf("no compiled verdict in manifest entry: %s", entry)
	}
	if !strings.Contains(entry, `"compiledBehavior":"domain"`) {
		t.Fatalf("no compiled behavior in manifest entry: %s", entry)
	}

	// The three values must agree, or the core reads the artifact under the
	// wrong strategy: the definition now names the artifact.
	definition := raw.RuleProvider["reject"]
	if definition["format"] != "mrs" {
		t.Fatalf("definition format is %v, artifact is mrs", definition["format"])
	}
	if definition["behavior"] != "domain" {
		t.Fatalf("definition behavior is %v", definition["behavior"])
	}
	staged, err := os.ReadFile(definition["path"].(string))
	if err != nil {
		t.Fatal(err)
	}
	// The artifact is real MRS by the core's own reader, not by file extension.
	count, err := ProviderEntryCountForIOS("rule", "domain", "mrs", staged)
	if err != nil {
		t.Fatalf("staged artifact is not readable MRS: %v", err)
	}
	if count != 2 {
		t.Fatalf("artifact carries %d rules, source had 2", count)
	}
}

// The shape a real subscription publishes: classical behavior, YAML format, a
// payload: header — and nothing but domain rules under it. It must compile as
// domain, and the payload: line must not be mistaken for a rule.
func TestClassicalYamlOfPureDomainsCompilesAsDomain(t *testing.T) {
	home := compileStagingHome(t)
	source := writeRuleSource(t, "openai.yaml",
		"payload:\n  - DOMAIN,openai.com\n  - DOMAIN-SUFFIX,chatgpt.com\n")
	raw := rawWithRuleProvider(source, "classical", "yaml")

	runtime, err := stageProviderRuntime(raw, currentRuntimePolicy(true), true)
	if err != nil {
		t.Fatalf("stage with compile: %v", err)
	}
	defer runtime.close()

	entry := manifestEntry(t, home, "rule", "reject")
	if !strings.Contains(entry, `"compileVerdict":"compiled"`) {
		t.Fatalf("pure-domain classical yaml did not compile: %s", entry)
	}
	definition := raw.RuleProvider["reject"]
	if definition["behavior"] != "domain" || definition["format"] != "mrs" {
		t.Fatalf("classical→domain rewrite missing: behavior=%v format=%v",
			definition["behavior"], definition["format"])
	}
}

func TestUncompilableClassicalIsStagedEmptyNotStripped(t *testing.T) {
	home := compileStagingHome(t)
	source := writeRuleSource(t, "mixed.yaml",
		"payload:\n  - DOMAIN-KEYWORD,ads\n  - DOMAIN,example.com\n")
	raw := rawWithRuleProvider(source, "classical", "yaml")

	runtime, err := stageProviderRuntime(raw, currentRuntimePolicy(true), true)
	if err != nil {
		t.Fatalf("stage with compile: %v", err)
	}
	defer runtime.close()

	entry := manifestEntry(t, home, "rule", "reject")
	if !strings.Contains(entry, `"compileVerdict":"notCompilable"`) {
		t.Fatalf("no verdict for the uncompilable set: %s", entry)
	}
	if !strings.Contains(entry, `"compileReason"`) {
		t.Fatalf("no reason for the reader: %s", entry)
	}

	// Not stripped, staged empty: the provider stays declared so RULE-SET
	// references — including ones inside logic rules — never dangle, and an
	// empty set matches nothing.
	definition := raw.RuleProvider["reject"]
	if definition["behavior"] != "classical" || definition["format"] != "yaml" {
		t.Fatalf("uncompilable definition was rewritten: %v", definition)
	}
	staged, err := os.Stat(definition["path"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if staged.Size() != 0 {
		t.Fatalf("uncompilable set was staged with %d bytes; the runtime must not carry it", staged.Size())
	}
}

// The extension never compiles; it must still serve the artifact — the
// three-value rewrite lives on the reuse path too, in the same function.
func TestExtensionServesTheCompiledArtifactWithoutCompiling(t *testing.T) {
	compileStagingHome(t)
	source := writeRuleSource(t, "reject.txt", "example.com\n")

	published, err := stageProviderRuntime(
		rawWithRuleProvider(source, "domain", "text"), currentRuntimePolicy(true), true)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	published.close()

	raw := rawWithRuleProvider(source, "domain", "text")
	runtime, err := stageProviderRuntime(raw, currentRuntimePolicy(true), false)
	if err != nil {
		t.Fatalf("extension stage: %v", err)
	}
	defer runtime.close()

	definition := raw.RuleProvider["reject"]
	if definition["format"] != "mrs" {
		t.Fatalf("reuse path did not rewrite format: %v — the core would read MRS bytes as text", definition["format"])
	}
	staged, err := os.ReadFile(definition["path"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ProviderEntryCountForIOS("rule", "domain", "mrs", staged); err != nil {
		t.Fatalf("reuse path serves a file that is not the artifact: %v", err)
	}
}

// Without compile and without a prior publish, today's behavior — byte for
// byte. An accelerator, never a requirement.
func TestNotYetCompiledStaysOnTheTextPath(t *testing.T) {
	home := compileStagingHome(t)
	source := writeRuleSource(t, "reject.txt", "example.com\n")
	raw := rawWithRuleProvider(source, "domain", "text")

	runtime, err := stageProviderRuntime(raw, currentRuntimePolicy(true), false)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	defer runtime.close()

	entry := manifestEntry(t, home, "rule", "reject")
	if strings.Contains(entry, "compileVerdict") {
		t.Fatalf("a set nobody compiled carries a verdict: %s", entry)
	}
	definition := raw.RuleProvider["reject"]
	if definition["format"] != "text" {
		t.Fatalf("text path was rewritten without an artifact: %v", definition["format"])
	}
	staged, err := os.ReadFile(definition["path"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if string(staged) != "example.com\n" {
		t.Fatal("staged bytes stopped matching the published source")
	}
}

// An edited source outlives its verdict: the record is rebuilt, and with no
// compiler in this process the set rides as text until the next publish.
func TestSourceChangeDropsTheVerdict(t *testing.T) {
	home := compileStagingHome(t)
	source := filepath.Join(home, "reject.txt")
	if err := os.WriteFile(source, []byte("example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	published, err := stageProviderRuntime(
		rawWithRuleProvider(source, "domain", "text"), currentRuntimePolicy(true), true)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	published.close()

	if err := os.WriteFile(source, []byte("example.com\nexample.net\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	raw := rawWithRuleProvider(source, "domain", "text")
	runtime, err := stageProviderRuntime(raw, currentRuntimePolicy(true), false)
	if err != nil {
		t.Fatalf("extension stage: %v", err)
	}
	defer runtime.close()

	entry := manifestEntry(t, home, "rule", "reject")
	if strings.Contains(entry, "compileVerdict") {
		t.Fatalf("a stale verdict survived a source edit: %s", entry)
	}
	definition := raw.RuleProvider["reject"]
	if definition["format"] != "text" {
		t.Fatalf("stale artifact still served after the source changed: %v", definition["format"])
	}
}

// A real subscription line carries inline comments; the comment must not ride
// into the artifact as part of the domain — finding 3 of the adversarial
// real one silently stopped matching.
func TestInlineCommentsDoNotPoisonTheCompiledDomains(t *testing.T) {
	compileStagingHome(t)
	source := writeRuleSource(t, "ads.yaml",
		"payload:\n  - DOMAIN,example.com # exact\n  - DOMAIN-SUFFIX,ads.com # 广告\n")
	raw := rawWithRuleProvider(source, "classical", "yaml")

	runtime, err := stageProviderRuntime(raw, currentRuntimePolicy(true), true)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.close()

	staged, err := os.ReadFile(raw.RuleProvider["reject"]["path"].(string))
	if err != nil {
		t.Fatal(err)
	}
	count, err := ProviderEntryCountForIOS("rule", "domain", "mrs", staged)
	if err != nil || count != 2 {
		t.Fatalf("artifact count=%d err=%v, want exactly the 2 real domains", count, err)
	}
	if bytes.Contains(staged, []byte("广告")) || bytes.Contains(staged, []byte(" #")) {
		t.Fatal("comment text rode into the compiled artifact")
	}
}

// -- compiledRuleSetsOnly / keptSource ---------------------------------------
//
// is an iOS memory problem, not a macOS one. The policy bit says whose
// problem it is. iOS packet tunnels stage the refusal EMPTY (the 50 MiB
// ceiling is real); macOS keeps the source online and pays the parse, which
// is exactly what upstream does. The wire vocabulary is locked three ways:
// compiled | notCompilable | keptSource.

func TestCompiledRuleSetsOnlyFollowsTheProfile(t *testing.T) {
	if !runtimePolicyFor(runtimeProfileIOSPacketTunnel, true).compiledRuleSetsOnly {
		t.Fatal("the iOS packet tunnel must run compiled rule sets only; a refused compile stages empty there")
	}
	if runtimePolicyFor(runtimeProfileMacOSPacketTunnel, true).compiledRuleSetsOnly {
		t.Fatal("the macOS packet tunnel must keep refused sources online; upstream capability is the ruling")
	}
	if runtimePolicyFor(runtimeProfileMacOSApplication, false).compiledRuleSetsOnly {
		t.Fatal("the macOS application profile must keep refused sources online")
	}
}

func TestMacOSKeepsTheSourceWhenTheCompilerRefuses(t *testing.T) {
	home := compileStagingHome(t)
	// PROCESS-NAME resolves on the macOS packet tunnel (nothing strips it)
	// and the domain strategy cannot store it: a genuine refusal with no
	// stripping, so the verbatim path must serve the published bytes.
	content := "payload:\n  - DOMAIN,example.com\n  - PROCESS-NAME,Mail\n"
	source := writeRuleSource(t, "procs.yaml", content)
	raw := rawWithRuleProvider(source, "classical", "yaml")

	runtime, err := stageProviderRuntime(raw,
		runtimePolicyFor(runtimeProfileMacOSPacketTunnel, true), true)
	if err != nil {
		t.Fatalf("stage with compile: %v", err)
	}
	defer runtime.close()

	entry := manifestEntry(t, home, "rule", "reject")
	if !strings.Contains(entry, `"compileVerdict":"keptSource"`) {
		t.Fatalf("macOS refusal did not record keptSource: %s", entry)
	}
	if !strings.Contains(entry, `"compileReason"`) {
		t.Fatalf("keptSource must carry the reason exactly as notCompilable does: %s", entry)
	}

	// The definition still names the source strategy — the set rides as text.
	definition := raw.RuleProvider["reject"]
	if definition["behavior"] != "classical" || definition["format"] != "yaml" {
		t.Fatalf("keptSource definition was rewritten: %v", definition)
	}
	staged, err := os.ReadFile(definition["path"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if string(staged) != content {
		t.Fatalf("keptSource staged %d bytes that differ from the published source", len(staged))
	}
	// The sentinel the client side asserts too: keptSource rows carry bytes.
	if len(staged) == 0 {
		t.Fatal("keptSource staged empty; that is notCompilable's shape, not this one's")
	}
}

func TestMacOSKeepsThePreparedCopyWhenStrippingPreceded(t *testing.T) {
	home := compileStagingHome(t)
	// SOURCE-APP-SIGNING-ID needs an audit token no packet tunnel has, so the
	// macOS profile strips it; IP-CIDR stays and refuses the compile. The
	// runtime copy must be the PREPARED bytes: stripped of what cannot
	// execute, still carrying everything that can.
	source := writeRuleSource(t, "mixed.yaml",
		"payload:\n  - DOMAIN,example.com\n  - SOURCE-APP-SIGNING-ID,com.example.app\n  - IP-CIDR,10.0.0.0/8\n")
	raw := rawWithRuleProvider(source, "classical", "yaml")

	runtime, err := stageProviderRuntime(raw,
		runtimePolicyFor(runtimeProfileMacOSPacketTunnel, true), true)
	if err != nil {
		t.Fatalf("stage with compile: %v", err)
	}
	defer runtime.close()

	entry := manifestEntry(t, home, "rule", "reject")
	if !strings.Contains(entry, `"compileVerdict":"keptSource"`) {
		t.Fatalf("stripped-then-refused set did not record keptSource: %s", entry)
	}
	if !strings.Contains(entry, `"metadataNoops"`) {
		t.Fatalf("the stripping must stay recorded for replay: %s", entry)
	}
	staged, err := os.ReadFile(raw.RuleProvider["reject"]["path"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(staged), "SOURCE-APP-SIGNING-ID") {
		t.Fatal("the staged copy still carries a rule this profile cannot execute")
	}
	if !strings.Contains(string(staged), "IP-CIDR") {
		t.Fatal("the staged copy lost IP-CIDR, which executes fine here — keptSource must keep capability, not just bytes")
	}
}

func TestIOSStillStagesTheRefusalEmpty(t *testing.T) {
	home := compileStagingHome(t)
	source := writeRuleSource(t, "procs.yaml",
		"payload:\n  - DOMAIN,example.com\n  - IP-CIDR,10.0.0.0/8\n")
	raw := rawWithRuleProvider(source, "classical", "yaml")

	runtime, err := stageProviderRuntime(raw,
		runtimePolicyFor(runtimeProfileIOSPacketTunnel, true), true)
	if err != nil {
		t.Fatalf("stage with compile: %v", err)
	}
	defer runtime.close()

	entry := manifestEntry(t, home, "rule", "reject")
	if !strings.Contains(entry, `"compileVerdict":"notCompilable"`) {
		t.Fatalf("iOS refusal changed vocabulary: %s", entry)
	}
	staged, err := os.Stat(raw.RuleProvider["reject"]["path"].(string))
	if err != nil {
		t.Fatal(err)
	}
	// The other half of the sentinel: notCompilable rows carry no bytes.
	if staged.Size() != 0 {
		t.Fatalf("iOS staged %d bytes for a refused set; the 50 MiB ceiling is why this profile stages empty", staged.Size())
	}
}

func TestKeptSourceHitsTheCacheOnRepublish(t *testing.T) {
	compileStagingHome(t)
	source := writeRuleSource(t, "procs.yaml",
		"payload:\n  - DOMAIN,example.com\n  - PROCESS-NAME,Mail\n")
	policy := runtimePolicyFor(runtimeProfileMacOSPacketTunnel, true)

	first, err := stageProviderRuntime(rawWithRuleProvider(source, "classical", "yaml"), policy, true)
	if err != nil {
		t.Fatalf("first publish: %v", err)
	}
	firstPath := ""
	for _, entry := range first.entries {
		firstPath = entry.runtimePath
	}
	first.close()
	before, err := os.Stat(firstPath)
	if err != nil {
		t.Fatal(err)
	}

	second, err := stageProviderRuntime(rawWithRuleProvider(source, "classical", "yaml"), policy, true)
	if err != nil {
		t.Fatalf("second publish: %v", err)
	}
	defer second.close()
	after, err := os.Stat(firstPath)
	if err != nil {
		t.Fatal(err)
	}
	// A verdict-carrying record must hit; a keptSource that restages on every
	// compile-enabled publish is the re-stage loop the hit gate exists to end.
	if !os.SameFile(before, after) {
		t.Fatal("keptSource was restaged on an identical republish; the recorded verdict must satisfy the hit gate")
	}
}

// -- the upgrade path: a refused set must stay empty on iOS even when the
// extension restages it ----------------------------------------------------
//
// Found by adversarial review of this batch: a providerStagingLogicVersion
// bump (or any manifest invalidation) voids the recorded notCompilable
// verdict, the client does not republish for a core upgrade (publish rides
// only on activation), and the extension restages with compileRuleSets=false
// -- which used to hardlink the refused SOURCE back online. The empty-set
// safety ruling silently became a text load, on the one profile whose memory
// ceiling is why the ruling exists, and jetsam would restart into the same
// state. The refusal judgement is cheap (a line scan, no artifact), so the
// extension applies it too.

func TestExtensionStagesARefusedSetEmptyWithoutCompiling(t *testing.T) {
	home := compileStagingHome(t)
	source := writeRuleSource(t, "mixed.yaml",
		"payload:\n  - DOMAIN,example.com\n  - IP-CIDR,10.0.0.0/8\n")
	raw := rawWithRuleProvider(source, "classical", "yaml")

	// No prior manifest: exactly the post-upgrade state.
	runtime, err := stageProviderRuntime(raw,
		runtimePolicyFor(runtimeProfileIOSPacketTunnel, true), false)
	if err != nil {
		t.Fatalf("extension stage: %v", err)
	}
	defer runtime.close()

	entry := manifestEntry(t, home, "rule", "reject")
	if !strings.Contains(entry, `"compileVerdict":"notCompilable"`) {
		t.Fatalf("the extension restaged a refused set without the verdict: %s", entry)
	}
	staged, err := os.Stat(raw.RuleProvider["reject"]["path"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if staged.Size() != 0 {
		t.Fatalf("the extension put %d bytes of a refused set back online; the empty-set ruling must survive a manifest invalidation", staged.Size())
	}
}

func TestExtensionRefusalMatchesTheCompilerVerdict(t *testing.T) {
	content := "payload:\n  - DOMAIN,example.com\n  - IP-CIDR,10.0.0.0/8\n"
	policy := runtimePolicyFor(runtimeProfileIOSPacketTunnel, true)

	compileStagingHome(t)
	source := writeRuleSource(t, "mixed.yaml", content)
	published, err := stageProviderRuntime(rawWithRuleProvider(source, "classical", "yaml"), policy, true)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	published.close()
	compilerEntry := manifestEntry(t, C.Path.HomeDir(), "rule", "reject")

	extensionHome := compileStagingHome(t)
	extensionSource := writeRuleSource(t, "mixed.yaml", content)
	restaged, err := stageProviderRuntime(rawWithRuleProvider(extensionSource, "classical", "yaml"), policy, false)
	if err != nil {
		t.Fatalf("extension stage: %v", err)
	}
	defer restaged.close()
	extensionEntry := manifestEntry(t, extensionHome, "rule", "reject")

	// Same verdict AND same reason: the two judgements are one code path, or
	// they will drift and the extension will empty a set the App can compile.
	for _, want := range []string{`"compileVerdict":"notCompilable"`, `"compileReason"`} {
		if !strings.Contains(compilerEntry, want) || !strings.Contains(extensionEntry, want) {
			t.Fatalf("verdicts diverged:\ncompiler:  %s\nextension: %s", compilerEntry, extensionEntry)
		}
	}
	reasonOf := func(entry string) string {
		var record stagedProviderRecord
		if err := json.Unmarshal([]byte(entry), &record); err != nil {
			t.Fatalf("decode entry: %v", err)
		}
		return record.CompileReason
	}
	if compilerReason, extensionReason := reasonOf(compilerEntry), reasonOf(extensionEntry); compilerReason != extensionReason {
		t.Fatalf("reasons diverged: compiler=%q extension=%q", compilerReason, extensionReason)
	}
}

// Stripping precedes the judgement, exactly as it precedes the compiler: a
// set whose unstorable rules are the ones iOS strips anyway (PROCESS-NAME
// here) compiles clean after preparation, so the extension must not empty it
// off the RAW bytes. Caught by TestRuleProviderRuntimeStripsMetadataNoops...
// during this batch — kept as its own pin because that test's subject is
// mutation, not this judgement.
func TestExtensionJudgesThePreparedCopyNotTheRawSource(t *testing.T) {
	home := compileStagingHome(t)
	source := writeRuleSource(t, "procs.yaml",
		"payload:\n  - PROCESS-NAME,curl\n  - DOMAIN,example.com\n")
	raw := rawWithRuleProvider(source, "classical", "yaml")

	runtime, err := stageProviderRuntime(raw,
		runtimePolicyFor(runtimeProfileIOSPacketTunnel, true), false)
	if err != nil {
		t.Fatalf("extension stage: %v", err)
	}
	defer runtime.close()

	entry := manifestEntry(t, home, "rule", "reject")
	if strings.Contains(entry, "compileVerdict") {
		t.Fatalf("the extension judged the raw bytes; after stripping this set is pure domains and the App will compile it: %s", entry)
	}
	staged, err := os.ReadFile(raw.RuleProvider["reject"]["path"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(staged), "DOMAIN,example.com") {
		t.Fatalf("the executable rule was lost from the staged copy: %q", staged)
	}
}

func TestExtensionKeepsCompilableSetsOnTheTextPath(t *testing.T) {
	home := compileStagingHome(t)
	source := writeRuleSource(t, "pure.yaml",
		"payload:\n  - DOMAIN,example.com\n  - DOMAIN-SUFFIX,example.org\n")
	raw := rawWithRuleProvider(source, "classical", "yaml")

	runtime, err := stageProviderRuntime(raw,
		runtimePolicyFor(runtimeProfileIOSPacketTunnel, true), false)
	if err != nil {
		t.Fatalf("extension stage: %v", err)
	}
	defer runtime.close()

	// Compilable means the App will compile it later; the extension neither
	// compiles nor empties it -- the accelerator contract, unchanged.
	entry := manifestEntry(t, home, "rule", "reject")
	if strings.Contains(entry, "compileVerdict") {
		t.Fatalf("the extension judged a compilable set: %s", entry)
	}
	staged, err := os.Stat(raw.RuleProvider["reject"]["path"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if staged.Size() == 0 {
		t.Fatal("a compilable set was emptied; the extension may only empty what the compiler would refuse")
	}
}

func TestMacOSExtensionStillRidesRefusedSetsAsText(t *testing.T) {
	home := compileStagingHome(t)
	source := writeRuleSource(t, "procs.yaml",
		"payload:\n  - DOMAIN,example.com\n  - PROCESS-NAME,Mail\n")
	raw := rawWithRuleProvider(source, "classical", "yaml")

	runtime, err := stageProviderRuntime(raw,
		runtimePolicyFor(runtimeProfileMacOSPacketTunnel, true), false)
	if err != nil {
		t.Fatalf("extension stage: %v", err)
	}
	defer runtime.close()

	entry := manifestEntry(t, home, "rule", "reject")
	if strings.Contains(entry, "compileVerdict") {
		t.Fatalf("a macOS extension restage judged a set; source-online needs no verdict here: %s", entry)
	}
	staged, err := os.Stat(raw.RuleProvider["reject"]["path"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if staged.Size() == 0 {
		t.Fatal("macOS emptied a refused set; keeping the source online is this profile's ruling")
	}
}

// A start served from the cache must say keptSource exactly as loudly as the
// staging that did the work — the established replay rule, extended to the
// third verdict.
func TestKeptSourceReplaysOnACachedStart(t *testing.T) {
	compileStagingHome(t)
	source := writeRuleSource(t, "procs.yaml",
		"payload:\n  - DOMAIN,example.com\n  - PROCESS-NAME,Mail\n")
	policy := runtimePolicyFor(runtimeProfileMacOSPacketTunnel, true)

	first, err := stageProviderRuntime(rawWithRuleProvider(source, "classical", "yaml"), policy, true)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	first.close()

	logBuffer := capturePublishLog(t)
	second, err := stageProviderRuntime(rawWithRuleProvider(source, "classical", "yaml"), policy, false)
	if err != nil {
		t.Fatalf("cached start: %v", err)
	}
	defer second.close()

	if !strings.Contains(logBuffer.String(), "kept as source") {
		t.Fatalf("the cached start stayed silent about keptSource; silence here is indistinguishable from a compiled set:\n%s", logBuffer.String())
	}
}

// The deferral contract: the client classifies by this exported prefix, so the
// prefix reaching the wire is load-bearing, not cosmetic.
func TestCompiledSideUpdateRefusalCarriesTheDeferredPrefix(t *testing.T) {
	entry := providerRuntimeEntry{compiled: true, sideUpdateSafe: true}
	_ = entry
	err := fmt.Errorf("%sthis rule set runs compiled; the update applies at the next activation", SideUpdateDeferredPrefix)
	if !strings.HasPrefix(err.Error(), SideUpdateDeferredPrefix) {
		t.Fatal("unreachable")
	}
	if !strings.HasPrefix(SideUpdateDeferredPrefix, "hako: side update deferred: ") {
		t.Fatalf("the exported prefix moved: %q — the client classifies by it", SideUpdateDeferredPrefix)
	}
}
