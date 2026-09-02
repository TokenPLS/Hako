// Command build_libbox drives `gomobile bind` to produce Hako.xcframework
// from the bind/hako nested module.
//
// Flag organization mirrors sing-box cmd/internal/build_libbox. Single source
// of truth for the bind flag set.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var sdkTagPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+-hako\.[1-9][0-9]*$`)
var sourceRevisionPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

// coreVersionPattern validates the mihomo core version after the leading "v"
// and any "-hako.N" suffix are stripped, so a stray non-semver tag cannot be
// injected into constant.Version.
var coreVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)

var (
	target        string
	output        string
	debugBuild    bool
	internalBuild bool
	withoutQUIC   bool
	slices        string
)

type appleSlicePlan struct {
	name    string
	targets []string
}

const (
	bindModuleDir               = "bind/hako"
	privacyManifestRelativePath = "cmd/build_libbox/PrivacyInfo.xcprivacy"
	buildInfoResourceName       = "HakoBuildInfo.json"
	appleBindTarget             = "ios,iossimulator,macos,tvos,tvossimulator"
	iosVersion                  = "15.0"
	macosVersion                = "13.0"
	tvosVersion                 = "17.0"

	// Base tags apply to every slice; with_low_memory is added via
	// -tags-not-macos so the macOS slice keeps full-size buffers (spec
	// `-tags-not-macos=with_low_memory`, fork build.go:323).
	baseTags       = "with_gvisor,cmfa,with_quic"
	baseTagsNoQUIC = "with_gvisor,cmfa"
	notMacosTags   = "with_low_memory"
)

func init() {
	flag.StringVar(&target, "target", "apple", "bind target: apple = "+appleBindTarget+", or an explicit gomobile target list")
	flag.StringVar(&output, "output", "Hako.xcframework", "output xcframework path (relative to repo root)")
	flag.BoolVar(&debugBuild, "debug", false, "keep symbols and build ids")
	flag.BoolVar(&internalBuild, "internal", false, "compile internal-only diagnostics and keep symbols")
	flag.BoolVar(&withoutQUIC, "without-quic", false, "exclude HTTP/3 Network Quality support")
	flag.StringVar(&slices, "slices", "", "build only these Apple slices (comma separated); "+
		"names "+strings.Join(appleSliceNames(), ", ")+", groups "+strings.Join(appleSliceGroupNames(), ", ")+
		"; empty means every slice")
}

func main() {
	flag.Parse()

	root, err := os.Getwd()
	if err != nil {
		fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, bindModuleDir, "go.mod")); err != nil {
		fatal(fmt.Errorf("run from the repository root (missing %s/go.mod): %w", bindModuleDir, err))
	}

	bindTarget := target
	if target == "apple" {
		bindTarget = appleBindTarget
	}

	version, err := coreVersion(root)
	if err != nil {
		fatal(err)
	}
	sdk, err := sdkVersion(root)
	if err != nil {
		fatal(err)
	}
	revision, dirty, err := gitSourceState(root)
	if err != nil {
		fatal(err)
	}

	outPath := output
	if !filepath.IsAbs(outPath) {
		outPath = filepath.Join(root, output)
	}

	ldflags := "-X github.com/TokenPLS/Hako/constant.Version=" + version
	if !debugBuild && !internalBuild {
		ldflags += " -s -w -buildid="
	}
	buildTags := effectiveBaseTags(internalBuild, !withoutQUIC)
	toolchain, err := goToolchainVersion(root)
	if err != nil {
		fatal(err)
	}
	buildInfo, err := encodeAppleBuildInfo(
		revision,
		dirty,
		sdk,
		version,
		buildTags,
		notMacosTags,
		toolchain,
		debugBuild,
		internalBuild,
		!withoutQUIC,
	)
	if err != nil {
		fatal(err)
	}

	if target == "apple" {
		if err := buildAppleSerial(root, outPath, buildInfo); err != nil {
			fatal(err)
		}
	} else {
		args := []string{
			"bind", "-v",
			"-target", bindTarget,
			"-o", outPath,
			"-iosversion=" + iosVersion,
			"-macosversion=" + macosVersion,
			"-tvosversion=" + tvosVersion,
			"-tags", buildTags,
			"-tags-not-macos=" + notMacosTags,
			"-trimpath",
			"-buildvcs=false",
			"-ldflags", ldflags,
			".",
		}

		gomobile, err := findTool("gomobile")
		if err != nil {
			fatal(err)
		}

		cmd := exec.Command(gomobile, args...)
		cmd.Dir = filepath.Join(root, bindModuleDir)
		cmd.Env = buildEnv()
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		fmt.Fprintf(os.Stderr, "build_libbox: core version %s (SDK %s)\nbuild_libbox: (cd %s && %s %s)\n",
			version, sdk, bindModuleDir, gomobile, strings.Join(args, " "))
		if err := cmd.Run(); err != nil {
			fatal(err)
		}
		if err := finalizeXCFramework(root, outPath, buildInfo); err != nil {
			fatal(err)
		}
	}

	slices, err := filepath.Glob(filepath.Join(outPath, "*-*"))
	if err != nil || len(slices) == 0 {
		fatal(fmt.Errorf("no slices found in %s", outPath))
	}
	fmt.Fprintf(os.Stderr, "build_libbox: %s slices:\n", outPath)
	for _, s := range slices {
		fmt.Fprintf(os.Stderr, "  %s\n", filepath.Base(s))
	}
}

func appleSerialBuildPlan() []appleSlicePlan {
	return []appleSlicePlan{
		{name: "ios-device", targets: []string{"ios/arm64"}},
		{name: "ios-simulator", targets: []string{"iossimulator/arm64", "iossimulator/amd64"}},
		{name: "macos", targets: []string{"macos/arm64", "macos/amd64"}},
		{name: "tvos-device", targets: []string{"tvos/arm64"}},
		{name: "tvos-simulator", targets: []string{"tvossimulator/arm64", "tvossimulator/amd64"}},
	}
}

// buildAppleSerial prevents the sagernet gomobile fork from launching one
// gobind and one Go archive build per Apple platform/architecture in parallel.
// Each child invocation receives exactly one platform/architecture. Frameworks
// for the same simulator/macOS variant are checked and lipo-merged only after
// both thin builds have completed.
// appleSliceGroups lets a caller ask for a platform instead of spelling out its slices.
// iOS and macOS have to be independently packageable: their Core capabilities now differ
// (PROCESS-NAME/-PATH rules execute on a macOS Packet Tunnel and are stripped on iOS), and
// each consuming app pins the SDK through its own lock file, so the two platforms are
// versioned and rolled forward separately.
func appleSliceGroups() map[string][]string {
	return map[string][]string{
		"ios":   {"ios-device", "ios-simulator"},
		"macos": {"macos"},
		"tvos":  {"tvos-device", "tvos-simulator"},
	}
}

func appleSliceNames() []string {
	plans := appleSerialBuildPlan()
	names := make([]string, 0, len(plans))
	for _, plan := range plans {
		names = append(names, plan.name)
	}
	return names
}

func appleSliceGroupNames() []string {
	groups := appleSliceGroups()
	names := make([]string, 0, len(groups))
	for name := range groups {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// selectAppleSlices resolves the -slices request against the build plan.
//
// Fail-closed on an unknown name rather than skipping it: a typo would otherwise produce an
// xcframework silently missing a platform, which is far worse than a build error because the
// artifact still looks valid and only breaks at the consumer.
func selectAppleSlices(request string, plans []appleSlicePlan) ([]appleSlicePlan, error) {
	request = strings.TrimSpace(request)
	if request == "" {
		return plans, nil
	}
	groups := appleSliceGroups()
	wanted := make(map[string]bool)
	for _, token := range strings.Split(request, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		if expanded, ok := groups[token]; ok {
			for _, name := range expanded {
				wanted[name] = true
			}
			continue
		}
		known := false
		for _, plan := range plans {
			if plan.name == token {
				known = true
				break
			}
		}
		if !known {
			return nil, fmt.Errorf("unknown Apple slice %q; slices are %s, groups are %s",
				token, strings.Join(appleSliceNames(), ", "), strings.Join(appleSliceGroupNames(), ", "))
		}
		wanted[token] = true
	}
	if len(wanted) == 0 {
		return nil, fmt.Errorf("-slices %q selected nothing", request)
	}
	// Plan order is preserved so a partial artifact assembles its slices in the same order
	// as the full one.
	selected := make([]appleSlicePlan, 0, len(wanted))
	for _, plan := range plans {
		if wanted[plan.name] {
			selected = append(selected, plan)
		}
	}
	return selected, nil
}

func buildAppleSerial(root, outPath string, expectedBuildInfo []byte) error {
	if !strings.HasSuffix(outPath, ".xcframework") {
		return fmt.Errorf("Apple output %q must end in .xcframework", outPath)
	}
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate build_libbox executable: %w", err)
	}
	workRoot, err := os.MkdirTemp("", "hako-apple-serial-")
	if err != nil {
		return fmt.Errorf("create serial Apple build directory: %w", err)
	}
	defer os.RemoveAll(workRoot)

	selected, err := selectAppleSlices(slices, appleSerialBuildPlan())
	if err != nil {
		return err
	}
	if len(selected) != len(appleSerialBuildPlan()) {
		names := make([]string, 0, len(selected))
		for _, plan := range selected {
			names = append(names, plan.name)
		}
		fmt.Fprintf(os.Stderr, "build_libbox: PARTIAL Apple artifact, slices: %s\n", strings.Join(names, ", "))
	}

	var assembledFrameworks []string
	for _, plan := range selected {
		var thinFrameworks []string
		for _, thinTarget := range plan.targets {
			thinRoot := filepath.Join(
				workRoot,
				strings.NewReplacer("/", "-", ",", "-").Replace(thinTarget),
			)
			thinOutput := filepath.Join(thinRoot, "Hako.xcframework")
			if err := os.MkdirAll(thinRoot, 0o755); err != nil {
				return fmt.Errorf("create %s build directory: %w", thinTarget, err)
			}
			arguments := []string{"-target", thinTarget, "-output", thinOutput}
			if debugBuild {
				arguments = append(arguments, "-debug")
			}
			if internalBuild {
				arguments = append(arguments, "-internal")
			}
			if withoutQUIC {
				arguments = append(arguments, "-without-quic")
			}
			fmt.Fprintf(os.Stderr, "build_libbox: serial Apple target %s\n", thinTarget)
			command := exec.Command(executable, arguments...)
			command.Dir = root
			command.Env = os.Environ()
			command.Stdout = os.Stdout
			command.Stderr = os.Stderr
			if err := command.Run(); err != nil {
				return fmt.Errorf("build %s: %w", thinTarget, err)
			}
			frameworks, err := filepath.Glob(
				filepath.Join(thinOutput, "*-*", "Hako.framework"),
			)
			if err != nil || len(frameworks) != 1 {
				return fmt.Errorf("%s produced %d frameworks, want 1", thinTarget, len(frameworks))
			}
			thinFrameworks = append(thinFrameworks, frameworks[0])
		}

		framework := thinFrameworks[0]
		if len(thinFrameworks) > 1 {
			for _, candidate := range thinFrameworks[1:] {
				if err := compareFrameworkMetadata(framework, candidate); err != nil {
					return fmt.Errorf("%s architecture metadata mismatch: %w", plan.name, err)
				}
			}
			fatRoot := filepath.Join(workRoot, "fat", plan.name)
			framework = filepath.Join(fatRoot, "Hako.framework")
			if err := os.MkdirAll(fatRoot, 0o755); err != nil {
				return fmt.Errorf("create %s assembly directory: %w", plan.name, err)
			}
			if err := runStreamingCommand(exec.Command("ditto", thinFrameworks[0], framework)); err != nil {
				return fmt.Errorf("copy %s framework: %w", plan.name, err)
			}
			lipoArguments := []string{"lipo"}
			for _, thinFramework := range thinFrameworks {
				lipoArguments = append(
					lipoArguments,
					filepath.Join(thinFramework, "Versions", "A", "Hako"),
				)
			}
			lipoArguments = append(
				lipoArguments,
				"-create", "-output", filepath.Join(framework, "Versions", "A", "Hako"),
			)
			if err := runStreamingCommand(exec.Command("xcrun", lipoArguments...)); err != nil {
				return fmt.Errorf("merge %s architectures: %w", plan.name, err)
			}
		}
		assembledFrameworks = append(assembledFrameworks, framework)
	}

	if err := os.RemoveAll(outPath); err != nil {
		return fmt.Errorf("remove previous Apple output: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return fmt.Errorf("create Apple output directory: %w", err)
	}
	arguments := []string{"-create-xcframework"}
	for _, framework := range assembledFrameworks {
		arguments = append(arguments, "-framework", framework)
	}
	arguments = append(arguments, "-output", outPath)
	if err := runStreamingCommand(exec.Command("xcodebuild", arguments...)); err != nil {
		return fmt.Errorf("assemble Apple XCFramework: %w", err)
	}
	if err := canonicalizeXCFrameworkPlist(outPath); err != nil {
		return err
	}
	if err := verifyAppleBuildInfo(outPath, expectedBuildInfo, len(selected)); err != nil {
		return err
	}
	return nil
}

// canonicalizeXCFrameworkPlist rewrites the XCFramework's root Info.plist with AvailableLibraries
// sorted by LibraryIdentifier. xcodebuild -create-xcframework emits them in an order that is
// neither the argument order nor stable across runs, so two builds of the same revision could
// differ in this one file after every archive inside them matched. plistlib writes dictionary
// keys sorted, so the result is a canonical form: running it twice is a byte-level no-op.
func canonicalizeXCFrameworkPlist(artifact string) error {
	plist := filepath.Join(artifact, "Info.plist")
	script := `import plistlib, sys
path = sys.argv[1]
with open(path, "rb") as handle:
    root = plistlib.load(handle)
libraries = root.get("AvailableLibraries")
if not isinstance(libraries, list):
    raise SystemExit("XCFramework Info.plist has no AvailableLibraries array")
root["AvailableLibraries"] = sorted(libraries, key=lambda item: item.get("LibraryIdentifier", ""))
with open(path, "wb") as handle:
    plistlib.dump(root, handle, sort_keys=True)
`
	command := exec.Command("python3", "-c", script, plist)
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("canonicalize XCFramework Info.plist: %w", err)
	}
	return nil
}

func runStreamingCommand(command *exec.Cmd) error {
	command.Env = buildEnv()
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	return command.Run()
}

func compareFrameworkMetadata(left, right string) error {
	leftMetadata, err := frameworkMetadata(left)
	if err != nil {
		return err
	}
	rightMetadata, err := frameworkMetadata(right)
	if err != nil {
		return err
	}
	if len(leftMetadata) != len(rightMetadata) {
		return fmt.Errorf("metadata entry count %d != %d", len(leftMetadata), len(rightMetadata))
	}
	for name, leftDigest := range leftMetadata {
		if rightDigest, ok := rightMetadata[name]; !ok || rightDigest != leftDigest {
			return fmt.Errorf("metadata differs at %s", name)
		}
	}
	return nil
}

func frameworkMetadata(root string) (map[string]string, error) {
	metadata := make(map[string]string)
	err := filepath.WalkDir(root, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, current)
		if err != nil {
			return err
		}
		if relative == "." || relative == filepath.Join("Versions", "A", "Hako") {
			return nil
		}
		if entry.IsDir() {
			metadata[relative] = "directory"
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			target, err := os.Readlink(current)
			if err != nil {
				return err
			}
			metadata[relative] = "symlink:" + target
			return nil
		}
		contents, err := os.ReadFile(current)
		if err != nil {
			return err
		}
		metadata[relative] = fmt.Sprintf("file:%x", sha256.Sum256(contents))
		return nil
	})
	if err != nil {
		return nil, err
	}
	return metadata, nil
}

// verifyAppleBuildInfo requires one build-info resource per slice the build was ASKED for,
// not one per slice in the full plan. Comparing against the full plan would fail every
// partial artifact; comparing against "at least one" would let a slice go missing silently,
// which is the failure this whole check exists to prevent.
func verifyAppleBuildInfo(artifact string, expected []byte, wantSlices int) error {
	paths, err := filepath.Glob(filepath.Join(
		artifact,
		"*-*",
		"Hako.framework",
		"Versions",
		"A",
		"Resources",
		buildInfoResourceName,
	))
	if err != nil {
		return fmt.Errorf("enumerate Apple build info: %w", err)
	}
	if len(paths) != wantSlices {
		return fmt.Errorf("Apple build info count is %d, want %d", len(paths), wantSlices)
	}
	for _, path := range paths {
		actual, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		if !bytes.Equal(actual, expected) {
			return fmt.Errorf("Apple build info differs at %s", path)
		}
	}
	return nil
}

// finalizeXCFramework adds the Apple distribution metadata that gomobile does
// not generate and tightens two constructor annotations that are known to be
// non-nil. The latter removes a clang conflict with NSObject's nonnull init
// without changing the conservative nullability of the exported C functions
// that existing Swift clients already consume as optionals.
func finalizeXCFramework(root, artifact string, buildInfo []byte) error {
	manifest, err := os.ReadFile(filepath.Join(root, privacyManifestRelativePath))
	if err != nil {
		return fmt.Errorf("read SDK privacy manifest: %w", err)
	}
	slices, err := filepath.Glob(filepath.Join(artifact, "*-*"))
	if err != nil {
		return fmt.Errorf("enumerate XCFramework slices: %w", err)
	}
	if len(slices) == 0 {
		return fmt.Errorf("no slices found in %s", artifact)
	}
	oldInitializer := []byte("- (nullable instancetype)init;")
	newInitializer := []byte("- (nonnull instancetype)init;")
	for _, slice := range slices {
		framework := filepath.Join(slice, "Hako.framework", "Versions", "A")
		headerPath := filepath.Join(framework, "Headers", "Hako.objc.h")
		header, err := os.ReadFile(headerPath)
		if err != nil {
			return fmt.Errorf("read %s public header: %w", filepath.Base(slice), err)
		}
		if count := bytes.Count(header, oldInitializer); count != 2 {
			return fmt.Errorf("%s nullable constructor count is %d, want 2", filepath.Base(slice), count)
		}
		header = bytes.ReplaceAll(header, oldInitializer, newInitializer)
		if err := os.WriteFile(headerPath, header, 0o644); err != nil {
			return fmt.Errorf("write %s public header: %w", filepath.Base(slice), err)
		}
		manifestPath := filepath.Join(framework, "Resources", "PrivacyInfo.xcprivacy")
		if err := os.MkdirAll(filepath.Dir(manifestPath), 0o755); err != nil {
			return fmt.Errorf("create %s resource directory: %w", filepath.Base(slice), err)
		}
		if err := os.WriteFile(manifestPath, manifest, 0o644); err != nil {
			return fmt.Errorf("write %s privacy manifest: %w", filepath.Base(slice), err)
		}
		buildInfoPath := filepath.Join(framework, "Resources", buildInfoResourceName)
		if err := os.WriteFile(buildInfoPath, buildInfo, 0o644); err != nil {
			return fmt.Errorf("write %s build info: %w", filepath.Base(slice), err)
		}
	}
	return nil
}

// appleBuildInfo is the provenance record every slice carries, identical across slices.
//
// Schema 2 adds the two facts schema 1 left out of "the exact build mode": the tags the
// non-macOS slices are compiled with beyond the base set (gomobile's -tags-not-macos, so the
// iOS/tvOS slices carry with_low_memory and the macOS slice does not -- one record, both
// facts, still identical in every slice), and the Go toolchain that built it, which is the
// standard library the binary links and the version a vulnerability scan of the artifact has
// to be pinned to.
type appleBuildInfo struct {
	Schema              int      `json:"schema"`
	SourceRevision      string   `json:"sourceRevision"`
	SourceDirty         bool     `json:"sourceDirty"`
	SDKVersion          string   `json:"sdkVersion"`
	MihomoCoreVersion   string   `json:"mihomoCoreVersion"`
	GoToolchain         string   `json:"goToolchain"`
	BuildTags           []string `json:"buildTags"`
	BuildTagsNotMacos   []string `json:"buildTagsNotMacos"`
	DebugBuild          bool     `json:"debugBuild"`
	InternalDiagnostics bool     `json:"internalDiagnostics"`
	HTTP3NetworkQuality bool     `json:"http3NetworkQuality"`
}

// goVersionPattern is what `go env GOVERSION` answers for a release toolchain.
var goVersionPattern = regexp.MustCompile(`^go[0-9]+\.[0-9]+(\.[0-9]+)?([a-z]+[0-9]+)?$`)

func splitBuildTags(tags string) []string {
	buildTags := strings.FieldsFunc(tags, func(character rune) bool {
		return character == ',' || character == ' '
	})
	sort.Strings(buildTags)
	uniqueTags := buildTags[:0]
	for _, tag := range buildTags {
		if len(uniqueTags) == 0 || uniqueTags[len(uniqueTags)-1] != tag {
			uniqueTags = append(uniqueTags, tag)
		}
	}
	if uniqueTags == nil {
		return []string{}
	}
	return uniqueTags
}

func encodeAppleBuildInfo(
	revision string,
	dirty bool,
	sdk string,
	core string,
	tags string,
	tagsNotMacos string,
	toolchain string,
	debug bool,
	internal bool,
	http3 bool,
) ([]byte, error) {
	if !sourceRevisionPattern.MatchString(revision) {
		return nil, fmt.Errorf("source revision must be a full lowercase Git revision")
	}
	if strings.TrimSpace(sdk) == "" || strings.TrimSpace(core) == "" {
		return nil, fmt.Errorf("SDK and core versions are required")
	}
	if !goVersionPattern.MatchString(toolchain) {
		return nil, fmt.Errorf("go toolchain %q is not a go version (want the form go1.26.6)", toolchain)
	}
	payload := appleBuildInfo{
		Schema:              2,
		SourceRevision:      revision,
		SourceDirty:         dirty,
		SDKVersion:          sdk,
		MihomoCoreVersion:   core,
		GoToolchain:         toolchain,
		BuildTags:           splitBuildTags(tags),
		BuildTagsNotMacos:   splitBuildTags(tagsNotMacos),
		DebugBuild:          debug,
		InternalDiagnostics: internal,
		HTTP3NetworkQuality: http3,
	}
	encoded, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode Apple build info: %w", err)
	}
	return append(encoded, '\n'), nil
}

// goToolchainVersion is the Go that builds the bind module: `go env GOVERSION` asked from inside
// that module, so a toolchain line in its go.mod is honoured the way gomobile's own go build
// honours it. Asked from anywhere else it would answer with whatever go is on PATH.
func goToolchainVersion(root string) (string, error) {
	command := exec.Command("go", "env", "GOVERSION")
	command.Dir = filepath.Join(root, bindModuleDir)
	command.Env = buildEnv()
	output, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("read the bind module's go toolchain: %w", err)
	}
	version := strings.TrimSpace(string(output))
	if !goVersionPattern.MatchString(version) {
		return "", fmt.Errorf("go env GOVERSION answered %q, not a go version", version)
	}
	return version, nil
}

func gitSourceState(root string) (string, bool, error) {
	revisionCommand := exec.Command("git", "rev-parse", "HEAD")
	revisionCommand.Dir = root
	revisionOutput, err := revisionCommand.Output()
	if err != nil {
		return "", false, fmt.Errorf("read source revision: %w", err)
	}
	revision := strings.TrimSpace(string(revisionOutput))
	if !sourceRevisionPattern.MatchString(revision) {
		return "", false, fmt.Errorf("source revision is not a full lowercase Git revision")
	}
	statusCommand := exec.Command("git", "status", "--porcelain", "--untracked-files=normal")
	statusCommand.Dir = root
	statusOutput, err := statusCommand.Output()
	if err != nil {
		return "", false, fmt.Errorf("read source status: %w", err)
	}
	entries := dirtySourceEntries(statusOutput)
	// Untracked files count, and that is deliberate: an untracked .go file in this tree is
	// compiled into the artifact, so a build made over one is genuinely not reproducible from
	// the revision alone. What was NOT deliberate is that the answer was a bare bool. A whole
	// round of builds recorded sourceDirty=true because a DerivedData directory sat at the repo
	// root, and nobody could tell, because "dirty" named nothing. package_release.sh refuses a
	// formal SDK on that flag, so whether a release could be packaged came down to whether
	// somebody had happened to delete a temporary directory.
	//
	// The flag stays exactly as strict. It just says what it saw now, which is the difference
	// between a build you fix in ten seconds and one you find out about a round later.
	if len(entries) > 0 {
		fmt.Fprintf(os.Stderr, "build_libbox: source tree is dirty, so this artifact records sourceDirty=true\n")
		fmt.Fprintf(os.Stderr, "build_libbox: a formal SDK cannot be packaged from it (scripts/package_release.sh)\n")
		for _, entry := range entries {
			fmt.Fprintf(os.Stderr, "  %s\n", entry)
		}
	}
	return revision, len(entries) != 0, nil
}

// dirtySourceEntries splits git's porcelain output into one line per path, dropping blank ones.
// Returned rather than counted so the caller can name them.
func dirtySourceEntries(statusOutput []byte) []string {
	trimmed := bytes.TrimSpace(statusOutput)
	if len(trimmed) == 0 {
		return nil
	}
	lines := strings.Split(string(trimmed), "\n")
	entries := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		entries = append(entries, strings.TrimSpace(line))
	}
	return entries
}

func effectiveBaseTags(internal bool, includeQUIC bool) string {
	tags := baseTags
	if !includeQUIC {
		tags = baseTagsNoQUIC
	}
	if internal {
		return tags + ",hako_internal"
	}
	return tags
}

// coreVersion is the mihomo core version injected into constant.Version, so
// HakoVersion() always reports the upstream core (e.g. "1.19.28") — NOT the
// SDK release. It is the latest tag minus the leading "v" and any "-hako.N"
// SDK suffix: a release cut from tag "v1.19.28-hako.3" still reports
// "1.19.28".
func coreVersion(root string) (string, error) {
	cmd := exec.Command("git", "describe", "--tags", "--abbrev=0", "--match", "v*")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git describe: %w", err)
	}
	return parseCoreVersion(string(out))
}

// parseCoreVersion strips the leading "v" and any "-hako.N" SDK suffix from a
// git tag, then validates the remainder is a plain semver — rejecting a nearest
// non-semver tag rather than injecting it as the core version.
func parseCoreVersion(describeOut string) (string, error) {
	v := stripHakoSuffix(strings.TrimPrefix(strings.TrimSpace(describeOut), "v"))
	if !coreVersionPattern.MatchString(v) {
		return "", fmt.Errorf("core version %q from git tag is not a valid semver; check the nearest v* tag", v)
	}
	return v, nil
}

// stripHakoSuffix removes the SDK-release "-hako.N" suffix, leaving the core
// mihomo version.
func stripHakoSuffix(tag string) string {
	if i := strings.Index(tag, "-hako"); i >= 0 {
		return tag[:i]
	}
	return tag
}

// sdkVersion is an exact SDK tag at HEAD, never the nearest ancestor tag.
// Non-release builds are labeled with their commit rather than impersonating
// an older release.
func sdkVersion(root string) (string, error) {
	tagCmd := exec.Command("git", "tag", "--points-at", "HEAD")
	tagCmd.Dir = root
	tagOut, _ := tagCmd.Output() // empty on error -> dev fallback in selectSDKVersion

	short := exec.Command("git", "rev-parse", "--short", "HEAD")
	short.Dir = root
	shortOut, _ := short.Output()

	return selectSDKVersion(string(tagOut), strings.TrimSpace(string(shortOut)))
}

// selectSDKVersion returns the single SDK release tag at HEAD, a dev-<sha> label
// when none is present, or an error when more than one release tag points at
// HEAD — enforcing the exactly-one-tag release rule.
func selectSDKVersion(tagOutput, shortSHA string) (string, error) {
	var matches []string
	for _, tag := range strings.Fields(tagOutput) {
		if sdkTagPattern.MatchString(tag) {
			matches = append(matches, tag)
		}
	}
	switch len(matches) {
	case 0:
		if shortSHA != "" {
			return "dev-" + shortSHA, nil
		}
		return "dev", nil
	case 1:
		return matches[0], nil
	default:
		return "", fmt.Errorf("multiple SDK release tags point at HEAD (%s); exactly one v*-hako.N is required", strings.Join(matches, ", "))
	}
}

// findTool locates gomobile/gobind, preferring PATH then GOPATH/bin.
func findTool(name string) (string, error) {
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}
	gopath, err := exec.Command("go", "env", "GOPATH").Output()
	if err == nil {
		p := filepath.Join(strings.TrimSpace(string(gopath)), "bin", name)
		if _, statErr := os.Stat(p); statErr == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s not found in PATH or GOPATH/bin (install gomobile)", name)
}

// buildEnv augments the environment so the build works on machines where
// xcode-select points at CommandLineTools and gobind is only in GOPATH/bin.
func buildEnv() []string {
	env := os.Environ()
	if os.Getenv("DEVELOPER_DIR") == "" {
		sel, err := exec.Command("xcode-select", "-p").Output()
		const xcodeDev = "/Applications/Xcode.app/Contents/Developer"
		if err == nil && !strings.Contains(string(sel), "Xcode.app") {
			if _, statErr := os.Stat(xcodeDev); statErr == nil {
				env = append(env, "DEVELOPER_DIR="+xcodeDev)
			}
		}
	}
	if gopath, err := exec.Command("go", "env", "GOPATH").Output(); err == nil {
		gobin := filepath.Join(strings.TrimSpace(string(gopath)), "bin")
		env = append(env, "PATH="+gobin+string(os.PathListSeparator)+os.Getenv("PATH"))
	}
	// Apple's ar/ranlib/libtool stamp the archive symbol table (`__.SYMDEF SORTED`) with the
	// current time, and cctools honour this variable to write zero instead. The Go linker
	// already zeroes the object members it hands to ar, so this is the one remaining source
	// of checksum drift between two clean builds of the same revision (measured: identical
	// members, differing archives, until this was set). lipo and xcodebuild ignore it.
	env = append(env, "ZERO_AR_DATE=1")
	return env
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "build_libbox:", err)
	os.Exit(1)
}
