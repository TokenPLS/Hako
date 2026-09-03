package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestStripHakoSuffix(t *testing.T) {
	cases := map[string]string{
		"1.19.28":          "1.19.28",
		"1.19.28-hako.1":   "1.19.28",
		"1.19.28-hako.42":  "1.19.28",
		"1.19.29":          "1.19.29",
		"1.20.0-hako.3-rc": "1.20.0", // any -hako... is stripped
	}
	for in, want := range cases {
		if got := stripHakoSuffix(in); got != want {
			t.Errorf("stripHakoSuffix(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSDKTagPattern(t *testing.T) {
	valid := []string{"v1.19.28-hako.1", "v12.0.3-hako.42"}
	invalid := []string{
		"1.19.28-hako.1", "v1.19.28", "v1.19.28-hako.0",
		"v1.19.28-hako.1-rc", "v1.19-hako.1", "release",
	}
	for _, tag := range valid {
		if !sdkTagPattern.MatchString(tag) {
			t.Errorf("valid SDK tag rejected: %s", tag)
		}
	}
	for _, tag := range invalid {
		if sdkTagPattern.MatchString(tag) {
			t.Errorf("invalid SDK tag accepted: %s", tag)
		}
	}
}

func TestInternalBuildTagIsOptIn(t *testing.T) {
	if got := effectiveBaseTags(false, true); got != baseTags {
		t.Fatalf("release tags = %q, want %q", got, baseTags)
	}
	if got := effectiveBaseTags(true, true); got != baseTags+",hako_internal" {
		t.Fatalf("internal tags = %q", got)
	}
	if got := effectiveBaseTags(false, false); got != baseTagsNoQUIC {
		t.Fatalf("no-QUIC tags = %q", got)
	}
	if got := effectiveBaseTags(true, false); got != baseTagsNoQUIC+",hako_internal" {
		t.Fatalf("internal no-QUIC tags = %q", got)
	}
}

func TestDefaultAppleTargetIncludesTVOS17(t *testing.T) {
	if got, want := appleBindTarget, "ios,iossimulator,macos,tvos,tvossimulator"; got != want {
		t.Fatalf("default Apple target = %q, want %q", got, want)
	}
	if got, want := tvosVersion, "17.0"; got != want {
		t.Fatalf("tvOS deployment target = %q, want %q", got, want)
	}
}

func TestAppleBuildPlanSerializesEveryArchitecture(t *testing.T) {
	plans := appleSerialBuildPlan()
	var targets []string
	for _, plan := range plans {
		if len(plan.targets) == 0 {
			t.Fatalf("slice %q has no architecture targets", plan.name)
		}
		for _, target := range plan.targets {
			if strings.Contains(target, ",") || !strings.Contains(target, "/") {
				t.Fatalf("target %q is not one platform/architecture", target)
			}
			targets = append(targets, target)
		}
	}
	want := []string{
		"ios/arm64",
		"iossimulator/arm64",
		"iossimulator/amd64",
		"macos/arm64",
		"macos/amd64",
		"tvos/arm64",
		"tvossimulator/arm64",
		"tvossimulator/amd64",
	}
	if strings.Join(targets, ",") != strings.Join(want, ",") {
		t.Fatalf("serial targets = %v, want %v", targets, want)
	}
}

func TestFrameworkMetadataComparisonIgnoresOnlyTheBinary(t *testing.T) {
	root := t.TempDir()
	left := filepath.Join(root, "left", "Hako.framework")
	right := filepath.Join(root, "right", "Hako.framework")
	for _, framework := range []string{left, right} {
		if err := os.MkdirAll(filepath.Join(framework, "Versions", "A", "Headers"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(
			filepath.Join(framework, "Versions", "A", "Headers", "Hako.h"),
			[]byte("same header"),
			0o644,
		); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(left, "Versions", "A", "Hako"), []byte("arm64"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(right, "Versions", "A", "Hako"), []byte("x86_64"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := compareFrameworkMetadata(left, right); err != nil {
		t.Fatalf("architecture-only binary difference was rejected: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(right, "Versions", "A", "Headers", "Hako.h"),
		[]byte("drifted header"),
		0o644,
	); err != nil {
		t.Fatal(err)
	}
	if err := compareFrameworkMetadata(left, right); err == nil {
		t.Fatal("architecture metadata drift was accepted")
	}
}

func TestVerifyAppleBuildInfoRequiresFiveMatchingSlices(t *testing.T) {
	artifact := filepath.Join(t.TempDir(), "Hako.xcframework")
	expected := []byte(`{"schema":1,"sourceRevision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
	slices := []string{
		"ios-arm64",
		"ios-arm64_x86_64-simulator",
		"macos-arm64_x86_64",
		"tvos-arm64",
		"tvos-arm64_x86_64-simulator",
	}
	for _, slice := range slices {
		resourceDirectory := filepath.Join(
			artifact,
			slice,
			"Hako.framework",
			"Versions",
			"A",
			"Resources",
		)
		if err := os.MkdirAll(resourceDirectory, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(
			filepath.Join(resourceDirectory, buildInfoResourceName),
			expected,
			0o644,
		); err != nil {
			t.Fatal(err)
		}
	}
	if err := verifyAppleBuildInfo(artifact, expected, len(appleSerialBuildPlan())); err != nil {
		t.Fatal(err)
	}
	drifted := filepath.Join(
		artifact,
		"tvos-arm64",
		"Hako.framework",
		"Versions",
		"A",
		"Resources",
		buildInfoResourceName,
	)
	if err := os.WriteFile(drifted, []byte("drifted"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyAppleBuildInfo(artifact, expected, len(appleSerialBuildPlan())); err == nil {
		t.Fatal("slice-specific build provenance drift was accepted")
	}
}

func TestFinalizeXCFrameworkAddsPrivacyManifestAndNormalizesConstructors(t *testing.T) {
	root := t.TempDir()
	manifest := []byte("privacy-manifest")
	manifestPath := filepath.Join(root, privacyManifestRelativePath)
	if err := os.MkdirAll(filepath.Dir(manifestPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, manifest, 0o644); err != nil {
		t.Fatal(err)
	}

	artifact := filepath.Join(root, "Hako.xcframework")
	header := strings.Join([]string{
		"@interface HakoNetworkQualityTest : NSObject",
		"- (nullable instancetype)init;",
		"@end",
		"@interface HakoSTUNTest : NSObject",
		"- (nullable instancetype)init;",
		"@end",
	}, "\n")
	for _, slice := range []string{
		"ios-arm64",
		"ios-arm64_x86_64-simulator",
		"macos-arm64_x86_64",
		"tvos-arm64",
		"tvos-arm64_x86_64-simulator",
	} {
		base := filepath.Join(artifact, slice, "Hako.framework", "Versions", "A")
		if err := os.MkdirAll(filepath.Join(base, "Headers"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(base, "Resources"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(base, "Headers", "Hako.objc.h"), []byte(header), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	buildInfo := []byte(`{"schema":1,"sourceRevision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
	if err := finalizeXCFramework(root, artifact, buildInfo); err != nil {
		t.Fatal(err)
	}
	for _, slice := range []string{
		"ios-arm64",
		"ios-arm64_x86_64-simulator",
		"macos-arm64_x86_64",
		"tvos-arm64",
		"tvos-arm64_x86_64-simulator",
	} {
		base := filepath.Join(artifact, slice, "Hako.framework", "Versions", "A")
		gotManifest, err := os.ReadFile(filepath.Join(base, "Resources", "PrivacyInfo.xcprivacy"))
		if err != nil {
			t.Fatal(err)
		}
		if string(gotManifest) != string(manifest) {
			t.Fatalf("%s privacy manifest = %q", slice, gotManifest)
		}
		gotBuildInfo, err := os.ReadFile(filepath.Join(base, "Resources", buildInfoResourceName))
		if err != nil {
			t.Fatal(err)
		}
		if string(gotBuildInfo) != string(buildInfo) {
			t.Fatalf("%s build info = %q", slice, gotBuildInfo)
		}
		gotHeader, err := os.ReadFile(filepath.Join(base, "Headers", "Hako.objc.h"))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(gotHeader), "nullable instancetype)init;") {
			t.Fatalf("%s retained conflicting nullable initializer", slice)
		}
		if got := strings.Count(string(gotHeader), "nonnull instancetype)init;"); got != 2 {
			t.Fatalf("%s normalized initializer count = %d, want 2", slice, got)
		}
	}
}

// coreVersion must reject a nearest tag that is not a v-prefixed
// semver, instead of silently injecting garbage as the core version.
func TestParseCoreVersion(t *testing.T) {
	ok := map[string]string{
		"v1.19.28\n":        "1.19.28",
		"v1.19.28-hako.3\n": "1.19.28",
		"1.19.28":           "1.19.28",
	}
	for in, want := range ok {
		got, err := parseCoreVersion(in)
		if err != nil || got != want {
			t.Errorf("parseCoreVersion(%q) = %q, %v; want %q, nil", in, got, err, want)
		}
	}
	for _, in := range []string{"", "Meta", "beta-3", "v1.19", "random-tag", "v1.19.28.1"} {
		if got, err := parseCoreVersion(in); err == nil {
			t.Errorf("parseCoreVersion(%q) = %q, nil; want error", in, got)
		}
	}
}

func TestEncodeAppleBuildInfo(t *testing.T) {
	revision := strings.Repeat("a", 40)
	encoded, err := encodeAppleBuildInfo(
		revision,
		false,
		"dev-aaaaaaaa",
		"1.19.28",
		baseTags,
		notMacosTags,
		"go1.26.6",
		false,
		false,
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	var info struct {
		Schema              int      `json:"schema"`
		SourceRevision      string   `json:"sourceRevision"`
		SourceDirty         bool     `json:"sourceDirty"`
		SDKVersion          string   `json:"sdkVersion"`
		MihomoCoreVersion   string   `json:"mihomoCoreVersion"`
		BuildTags           []string `json:"buildTags"`
		BuildTagsNotMacos   []string `json:"buildTagsNotMacos"`
		GoToolchain         string   `json:"goToolchain"`
		HTTP3NetworkQuality bool     `json:"http3NetworkQuality"`
		InternalDiagnostics bool     `json:"internalDiagnostics"`
		DebugBuild          bool     `json:"debugBuild"`
	}
	if err := json.Unmarshal(encoded, &info); err != nil {
		t.Fatal(err)
	}
	if info.Schema != 2 || info.SourceRevision != revision || info.SourceDirty ||
		info.SDKVersion != "dev-aaaaaaaa" || info.MihomoCoreVersion != "1.19.28" ||
		!info.HTTP3NetworkQuality || info.InternalDiagnostics || info.DebugBuild {
		t.Fatalf("build info = %#v", info)
	}
	wantTags := []string{"cmfa", "with_gvisor", "with_quic"}
	if strings.Join(info.BuildTags, ",") != strings.Join(wantTags, ",") {
		t.Fatalf("build tags = %v, want %v", info.BuildTags, wantTags)
	}
	// The non-macOS slices are compiled with one more tag than the base set, through
	// gomobile's -tags-not-macos. A provenance record that names only the base set describes
	// the macOS slice and misdescribes the other four; the exact invocation is what "binds
	// this binary to the exact build mode" has to mean.
	if strings.Join(info.BuildTagsNotMacos, ",") != "with_low_memory" {
		t.Fatalf("build tags (not macOS) = %v, want [with_low_memory]", info.BuildTagsNotMacos)
	}
	// The standard library is part of what was built, and it is the part govulncheck's std
	// findings are about; without the toolchain in the record, a scan of the delivered
	// artifact has to guess which Go built it.
	if info.GoToolchain != "go1.26.6" {
		t.Fatalf("go toolchain = %q, want go1.26.6", info.GoToolchain)
	}
	if _, err := encodeAppleBuildInfo("short", false, "dev", "1.19.28", baseTags, notMacosTags, "go1.26.6", false, false, true); err == nil {
		t.Fatal("invalid source revision was accepted")
	}
	if _, err := encodeAppleBuildInfo(revision, false, "dev", "1.19.28", baseTags, notMacosTags, "", false, false, true); err == nil {
		t.Fatal("an empty toolchain was accepted; the record would not say what built it")
	}
	if _, err := encodeAppleBuildInfo(revision, false, "dev", "1.19.28", baseTags, notMacosTags, "1.26.6", false, false, true); err == nil {
		t.Fatal("a toolchain that is not a go version string was accepted")
	}
}

// goToolchainVersion asks the go command itself, from inside the bind module, so the answer
// honours that module's toolchain line -- the same resolution gomobile's go build performs.
func TestGoToolchainVersionReadsTheBindModuleToolchain(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	version, err := goToolchainVersion(root)
	if err != nil {
		t.Fatalf("goToolchainVersion: %v", err)
	}
	if !goVersionPattern.MatchString(version) {
		t.Fatalf("go toolchain %q does not look like a go version", version)
	}
	goMod, err := os.ReadFile(filepath.Join(root, bindModuleDir, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(goMod), "\n") {
		if pinned, ok := strings.CutPrefix(line, "toolchain "); ok {
			if version != strings.TrimSpace(pinned) {
				t.Fatalf("go toolchain %q is not the module's pinned %q; the record would name a "+
					"toolchain other than the one gomobile builds with", version, pinned)
			}
			return
		}
	}
	t.Skip("bind module pins no toolchain; only the shape was checked")
}

func TestGitSourceStateDetectsTrackedAndUntrackedChanges(t *testing.T) {
	root := t.TempDir()
	runGit := func(arguments ...string) string {
		t.Helper()
		command := exec.Command("git", arguments...)
		command.Dir = root
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v: %s", arguments, err, output)
		}
		return strings.TrimSpace(string(output))
	}
	runGit("init", "-q")
	runGit("config", "user.name", "Hako Test")
	runGit("config", "user.email", "hako@example.invalid")
	if err := os.WriteFile(filepath.Join(root, "tracked.txt"), []byte("clean"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit("add", "tracked.txt")
	runGit("commit", "-q", "-m", "initial")
	wantRevision := runGit("rev-parse", "HEAD")
	revision, dirty, err := gitSourceState(root)
	if err != nil {
		t.Fatal(err)
	}
	if revision != wantRevision || dirty {
		t.Fatalf("clean state = revision %q dirty=%v", revision, dirty)
	}
	if err := os.WriteFile(filepath.Join(root, "tracked.txt"), []byte("modified"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, dirty, err = gitSourceState(root)
	if err != nil {
		t.Fatal(err)
	}
	if !dirty {
		t.Fatal("tracked source change was not detected")
	}
	runGit("checkout", "--", "tracked.txt")
	if err := os.WriteFile(filepath.Join(root, "untracked.txt"), []byte("dirty"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, dirty, err = gitSourceState(root)
	if err != nil {
		t.Fatal(err)
	}
	if !dirty {
		t.Fatal("untracked source change was not detected")
	}
}

// sdkVersion must fail when more than one release tag points at HEAD
// rather than silently choosing one, enforcing the exactly-one-tag rule.
func TestSelectSDKVersion(t *testing.T) {
	if got, err := selectSDKVersion("v1.19.28-hako.2\n", "abc1234"); err != nil || got != "v1.19.28-hako.2" {
		t.Errorf("one tag: got %q, %v; want v1.19.28-hako.2", got, err)
	}
	if got, err := selectSDKVersion("", "abc1234"); err != nil || got != "dev-abc1234" {
		t.Errorf("no tag: got %q, %v; want dev-abc1234", got, err)
	}
	if got, err := selectSDKVersion("some-other-tag\n", ""); err != nil || got != "dev" {
		t.Errorf("no valid tag, no sha: got %q, %v; want dev", got, err)
	}
	if got, err := selectSDKVersion("v1.19.28-hako.2\nv1.19.28-hako.3\n", "abc1234"); err == nil {
		t.Errorf("multiple tags: got %q, nil; want error", got)
	}
}

// Two clean builds of the same revision produced five archives that differed only in the
// `__.SYMDEF SORTED` member's timestamp -- Apple's ar/ranlib/libtool stamp the symbol table
// with the current time -- so "the artifact checksum is reproducible" (CORE-RELEASE-GOAL §6)
// was false while every object inside was identical. cctools honour ZERO_AR_DATE, and the
// Go linker's own archive step already zeroes the object timestamps, so this one variable is
// the difference between "same objects" and "same bytes" (measured: two c-archive builds with
// -trimpath -buildid= differ without it and are byte-identical with it).
func TestBuildEnvZeroesArchiveDates(t *testing.T) {
	found := false
	for _, entry := range buildEnv() {
		if entry == "ZERO_AR_DATE=1" {
			found = true
		}
	}
	if !found {
		t.Fatal("buildEnv does not set ZERO_AR_DATE=1; the static archives will carry the build time")
	}
}

// xcodebuild -create-xcframework orders AvailableLibraries by something that is not the
// argument order and not stable across runs (measured: tvos-arm64 first in one delivery), which
// makes the root Info.plist the second source of checksum drift. Sorting by LibraryIdentifier
// is a canonical form the loader does not care about and a diff reader does.
func TestCanonicalizeXCFrameworkPlistSortsTheLibraries(t *testing.T) {
	root := t.TempDir()
	plist := filepath.Join(root, "Info.plist")
	unsorted := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>AvailableLibraries</key>
	<array>
		<dict>
			<key>LibraryIdentifier</key>
			<string>tvos-arm64</string>
			<key>LibraryPath</key>
			<string>Hako.framework</string>
		</dict>
		<dict>
			<key>LibraryIdentifier</key>
			<string>ios-arm64</string>
			<key>LibraryPath</key>
			<string>Hako.framework</string>
		</dict>
		<dict>
			<key>LibraryIdentifier</key>
			<string>macos-arm64_x86_64</string>
			<key>LibraryPath</key>
			<string>Hako.framework</string>
		</dict>
	</array>
	<key>CFBundlePackageType</key>
	<string>XFWK</string>
	<key>XCFrameworkFormatVersion</key>
	<string>1.0</string>
</dict>
</plist>
`
	if err := os.WriteFile(plist, []byte(unsorted), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := canonicalizeXCFrameworkPlist(root); err != nil {
		t.Fatalf("canonicalizeXCFrameworkPlist: %v", err)
	}
	first, err := os.ReadFile(plist)
	if err != nil {
		t.Fatal(err)
	}
	text := string(first)
	ios := strings.Index(text, "<string>ios-arm64</string>")
	macos := strings.Index(text, "<string>macos-arm64_x86_64</string>")
	tvos := strings.Index(text, "<string>tvos-arm64</string>")
	if ios < 0 || macos < 0 || tvos < 0 || !(ios < macos && macos < tvos) {
		t.Fatalf("libraries are not sorted by identifier:\n%s", text)
	}
	if !strings.Contains(text, "<key>XCFrameworkFormatVersion</key>") ||
		!strings.Contains(text, "<string>XFWK</string>") {
		t.Fatalf("canonicalization lost keys:\n%s", text)
	}
	// Idempotent: a second pass is a no-op, byte for byte -- otherwise it is a
	// transformation, not a canonical form.
	if err := canonicalizeXCFrameworkPlist(root); err != nil {
		t.Fatalf("second canonicalizeXCFrameworkPlist: %v", err)
	}
	second, err := os.ReadFile(plist)
	if err != nil {
		t.Fatal(err)
	}
	if string(second) != text {
		t.Fatal("canonicalization is not idempotent")
	}
}
