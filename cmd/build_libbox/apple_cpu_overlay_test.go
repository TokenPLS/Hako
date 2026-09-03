package main

import (
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Go's internal/cpu never detects ARM64 features on GOOS=ios: cpu_arm64_other.go
// (`arm64 && ... && (!darwin || ios)`) has an empty osInit, so HasAES/HasPMULL/HasSHA2
// stay false and every AES-GCM byte of a vmess/TLS stream goes through the pure-Go
// path -- 24% of the packet tunnel's CPU under load on 2026-09-02.
// macOS (`darwin && !ios`) sets them from the M1 baseline. The overlay says the same
// thing for iOS: every arm64 Apple SoC since A7 has the ARMv8.0 crypto extensions.

func TestAppleCPUOverlayStatesOnlyTheAppleTruths(t *testing.T) {
	root := repoRoot(t)
	source := appleCPUOverlaySource(root)
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, source, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("overlay source must parse as Go: %v", err)
	}
	var found bool
	for _, group := range file.Comments {
		for _, c := range group.List {
			if constraint.IsGoBuild(c.Text) {
				expr, err := constraint.Parse(c.Text)
				if err != nil {
					t.Fatalf("build constraint: %v", err)
				}
				found = true
				tags := func(tag string) bool { return tag == "arm64" || tag == "ios" }
				if !expr.Eval(tags) {
					t.Fatalf("constraint %q must select arm64 && ios", c.Text)
				}
				darwin := func(tag string) bool { return tag == "arm64" || tag == "darwin" }
				if expr.Eval(darwin) {
					t.Fatalf("constraint %q must not select macOS, which detects features itself", c.Text)
				}
			}
		}
	}
	if !found {
		t.Fatal("overlay source carries no build constraint")
	}
	set := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, lhs := range assign.Lhs {
			sel, ok := lhs.(*ast.SelectorExpr)
			if !ok {
				continue
			}
			if ident, ok := sel.X.(*ast.Ident); !ok || ident.Name != "ARM64" {
				continue
			}
			rhs, ok := assign.Rhs[i].(*ast.Ident)
			if !ok || rhs.Name != "true" {
				t.Fatalf("ARM64.%s must be assigned the literal true, not %T", sel.Sel.Name, assign.Rhs[i])
			}
			set[sel.Sel.Name] = true
		}
		return true
	})
	want := map[string]bool{"HasAES": true, "HasPMULL": true, "HasSHA1": true, "HasSHA2": true}
	for name := range want {
		if !set[name] {
			t.Errorf("ARM64.%s must be set: every arm64 Apple SoC since A7 has it", name)
		}
	}
	for name := range set {
		if !want[name] {
			t.Errorf("ARM64.%s must not be asserted: iOS 15 still runs A9 and tvOS 17 the A8 Apple TV HD, neither has ARMv8.1 atomics or the SHA-512/SHA-3 extensions", name)
		}
	}
}

func TestAppleCPUOverlayReplacesTheSilentFile(t *testing.T) {
	root := repoRoot(t)
	goroot := t.TempDir()
	silent := filepath.Join(goroot, "src", "internal", "cpu", "cpu_arm64_other.go")
	if err := os.MkdirAll(filepath.Dir(silent), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(silent, []byte("//go:build arm64 && !linux && !freebsd && !android && (!darwin || ios) && !openbsd\n\npackage cpu\n\nfunc osInit() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	jsonPath, err := writeAppleCPUOverlay(root, goroot, dir)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	wantKey := `"` + filepath.Join(goroot, "src", "internal", "cpu", "cpu_arm64_other.go") + `"`
	if !strings.Contains(text, wantKey) {
		t.Fatalf("overlay must replace the file whose osInit is empty on iOS; got %s", text)
	}
	if !strings.Contains(text, `"`+appleCPUOverlaySource(root)+`"`) {
		t.Fatalf("overlay must point at the repository's replacement source; got %s", text)
	}
}

func TestAppleCPUOverlayCompilesForIOSAndLeavesMacOSAlone(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go not on PATH")
	}
	root := repoRoot(t)
	goroot := strings.TrimSpace(runOutput(t, goBinary, "env", "GOROOT"))
	jsonPath, err := writeAppleCPUOverlay(root, goroot, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range [][2]string{{"ios", "arm64"}, {"darwin", "arm64"}} {
		cmd := exec.Command(goBinary, "build", "-overlay="+jsonPath, "internal/cpu", "crypto/aes")
		cmd.Env = append(os.Environ(), "GOOS="+target[0], "GOARCH="+target[1], "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s/%s with the overlay: %v\n%s", target[0], target[1], err, out)
		}
	}
}

func TestGoShimInjectsTheOverlayOnlyWhereGoCompiles(t *testing.T) {
	dir := t.TempDir()
	fakeGo := filepath.Join(dir, "real-go")
	if err := os.WriteFile(fakeGo, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	shimDir, err := writeGoShim(dir, fakeGo, "/tmp/overlay.json")
	if err != nil {
		t.Fatal(err)
	}
	shim := filepath.Join(shimDir, "go")
	cases := map[string][]string{
		"build":   {"build", "-trimpath", "-o", "out", "."},
		"install": {"install", "golang.org/x/mobile/cmd/gobind"},
		"list":    {"list", "-json", "."},
		"env":     {"env", "GOROOT"},
		"version": {"version"},
		"mod":     {"mod", "download"},
	}
	overlayJSON := filepath.Join(dir, "overlay.json")
	shimDir, err = writeGoShim(dir, fakeGo, overlayJSON)
	if err != nil {
		t.Fatal(err)
	}
	shim = filepath.Join(shimDir, "go")
	for name, args := range cases {
		out := runOutput(t, shim, args...)
		lines := strings.Split(strings.TrimSpace(out), "\n")
		injected := len(lines) > 1 && lines[1] == "-overlay="+overlayJSON
		switch name {
		case "build", "install", "list":
			if !injected {
				t.Errorf("%s: the overlay must ride right behind the subcommand; got %q", name, lines)
			}
			if lines[0] != args[0] || lines[len(lines)-1] != args[len(args)-1] {
				t.Errorf("%s: the rest of the arguments must pass through unchanged; got %q", name, lines)
			}
		default:
			if injected || strings.Contains(out, "-overlay") {
				t.Errorf("%s: a subcommand that compiles nothing must not see the overlay; got %q", name, lines)
			}
		}
	}
	marks, err := os.ReadFile(overlayJSON + ".injected")
	if err != nil {
		t.Fatalf("the shim must leave a mark for every injection, so a build log can prove it was used: %v", err)
	}
	if got := strings.Count(string(marks), "\n"); got != 3 {
		t.Fatalf("expected 3 injections marked (build, install, list), got %d: %q", got, marks)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}

func runOutput(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return string(out)
}

func TestAppleOverlayToolchainIsResolvedUnderTheBuildsOwnPath(t *testing.T) {
	// The resolver used to ask the host go with the ambient PATH while gomobile ran
	// under buildEnv(), which prepends GOPATH/bin. On a shell without GOPATH/bin the
	// two disagreed: the resolver saw the module-cache download and refused, while the
	// build would have used the real installation on the augmented PATH.
	root := repoRoot(t)
	env := buildEnv()
	// Decide availability before asking anything inside bind/hako: that first question
	// downloads the pin when it is absent, and a unit test does not get to spend 311 MB.
	pin := pinnedToolchainLine(t, root)
	hostVersion := hostGoVersion(t)
	if !pinnedToolchainAvailable(pin, hostVersion, func(name string) (string, error) { return lookPathIn(env, name) }) {
		t.Skipf("bind/hako pins %s and this machine has %s with no %s wrapper on the build PATH; the resolver would download the pin (install it: go install golang.org/dl/%s@latest && %s download)", pin, hostVersion, pin, pin, pin)
	}
	chosen, err := appleOverlayToolchain(root, env)
	if err != nil {
		t.Fatalf("the overlay toolchain must resolve under the build's own environment: %v", err)
	}
	modcache := goEnvIn(t, root, env, "GOMODCACHE")
	if strings.HasPrefix(chosen, modcache+string(os.PathSeparator)) {
		t.Fatalf("overlay GOROOT %q is inside GOMODCACHE, where go build refuses overlays", chosen)
	}
	if _, err := os.Stat(filepath.Join(chosen, "src", "internal", "cpu", "cpu_arm64_other.go")); err != nil {
		t.Fatalf("overlay GOROOT %q does not hold the file the overlay replaces: %v", chosen, err)
	}
	if got := goEnvIn(t, root, env, "GOROOT"); got != chosen {
		t.Fatalf("the overlay names %q but the build compiles under %q", chosen, got)
	}
}

func goEnvIn(t *testing.T, root string, env []string, name string) string {
	t.Helper()
	out, err := goInBindModule(root, env, "env", name)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// pinnedToolchainLine reads the `toolchain goX.Y.Z` line of bind/hako's go.mod.
func pinnedToolchainLine(t *testing.T, root string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, bindModuleDir, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "toolchain ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "toolchain "))
		}
	}
	t.Fatal("bind/hako/go.mod has no toolchain line")
	return ""
}

// hostGoVersion is the host go's own version, asked with GOTOOLCHAIN=local so the
// question itself cannot trigger a switch or a download.
func hostGoVersion(t *testing.T) string {
	t.Helper()
	cmd := exec.Command("go", "env", "GOVERSION")
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

// lookPathIn resolves an executable against the PATH inside env, not the test's. The
// last PATH entry wins, which is what exec does with a duplicated variable -- buildEnv
// appends its augmented PATH after the inherited one.
func lookPathIn(env []string, name string) (string, error) {
	path := ""
	for _, entry := range env {
		if strings.HasPrefix(entry, "PATH=") {
			path = strings.TrimPrefix(entry, "PATH=")
		}
	}
	if path == "" {
		return exec.LookPath(name)
	}
	for _, dir := range filepath.SplitList(path) {
		candidate := filepath.Join(dir, name)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return candidate, nil
		}
	}
	return "", exec.ErrNotFound
}

// A toolchain the go command downloaded into the module cache cannot carry an overlay,
// and the error has to name the fix without naming a private document.
func TestModuleCacheToolchainIsRefusedWithAnActionableError(t *testing.T) {
	_, err := requireOverlayableGOROOT("/u/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.6.darwin-arm64", "/u/go/pkg/mod", "go1.26.6")
	if err == nil {
		t.Fatal("a module-cache GOROOT must be refused; go build ignores nothing here, it errors, and shipping software AES silently is worse")
	}
	message := err.Error()
	for _, want := range []string{"golang.org/dl/go1.26.6", "download"} {
		if !strings.Contains(message, want) {
			t.Errorf("the error must carry the command that fixes it; %q lacks %q", message, want)
		}
	}
	// This error is a string literal in a file the public export ships, and the export's
	// leak gates refuse any reference to an internal document. Assert the shape rather
	// than the name -- naming the document here would trip the same gates this guards.
	if doc := regexp.MustCompile(`[A-Za-z0-9_-]+\.md`).FindString(message); doc != "" {
		t.Errorf("a string literal that ships publicly must not point at a document: %q", doc)
	}
	if strings.Contains(message, "docs"+"/") {
		t.Error("a string literal that ships publicly must not carry a repository documentation path")
	}
	goroot, err := requireOverlayableGOROOT("/opt/homebrew/Cellar/go/1.26.6/libexec", "/u/go/pkg/mod", "go1.26.6")
	if err != nil || goroot != "/opt/homebrew/Cellar/go/1.26.6/libexec" {
		t.Fatalf("a GOROOT outside the module cache is usable as it is: %q %v", goroot, err)
	}
}

// A build that bypassed the overlay compiles and links without complaint, so the
// overlay carries a symbol of its own that the finished slice can be asked for.
func TestAppleCPUOverlayCarriesAMarkerTheLinkerKeeps(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, appleCPUOverlaySource(root), nil, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	var marker *ast.FuncDecl
	var osInit *ast.FuncDecl
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		switch fn.Name.Name {
		case appleCPUOverlayMarkerSymbol:
			marker = fn
		case "osInit":
			osInit = fn
		}
	}
	if marker == nil {
		t.Fatalf("overlay must define %s", appleCPUOverlayMarkerSymbol)
	}
	noinline := false
	if marker.Doc != nil {
		for _, c := range marker.Doc.List { // Doc.Text() strips //go: directives, so read the raw lines
			if c.Text == "//go:noinline" {
				noinline = true
			}
		}
	}
	if !noinline {
		t.Fatal("the marker must be //go:noinline, or the compiler inlines it away and the symbol never exists")
	}
	if osInit == nil {
		t.Fatal("overlay must define osInit")
	}
	called := false
	ast.Inspect(osInit, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == appleCPUOverlayMarkerSymbol {
				called = true
			}
		}
		return true
	})
	if !called {
		t.Fatal("osInit must call the marker, or the linker drops it as unreachable")
	}
}

func TestAppleCPUOverlayMarkerVerdict(t *testing.T) {
	withMarker := "0000000000001000 t _internal/cpu." + appleCPUOverlayMarkerSymbol + "\n0000000000002000 t _internal/cpu.osInit\n"
	without := "0000000000002000 t _internal/cpu.osInit\n"
	if err := verifyAppleCPUOverlayMarker("ios-arm64", withMarker); err != nil {
		t.Errorf("ios slice with the marker must pass: %v", err)
	}
	if err := verifyAppleCPUOverlayMarker("ios-arm64", without); err == nil {
		t.Error("an ios slice without the marker was built past the overlay and must fail")
	}
	if err := verifyAppleCPUOverlayMarker("macos-arm64_x86_64", without); err != nil {
		t.Errorf("macOS detects features itself and must not carry the marker: %v", err)
	}
	if err := verifyAppleCPUOverlayMarker("macos-arm64_x86_64", withMarker); err == nil {
		t.Error("a macOS slice carrying the iOS overlay means the constraint leaked and must fail")
	}
	// The overlay is arm64-only; an x86_64 simulator slice detects AES through cpuid and
	// must neither need nor carry the marker.
	if err := verifyAppleCPUOverlayMarker("ios-x86_64-simulator", without); err != nil {
		t.Errorf("an x86_64 simulator slice has no arm64 code to overlay: %v", err)
	}
	if err := verifyAppleCPUOverlayMarker("ios-x86_64-simulator", withMarker); err == nil {
		t.Error("an x86_64 slice carrying the arm64 overlay means the constraint leaked and must fail")
	}
	if err := verifyAppleCPUOverlayMarker("ios-arm64_x86_64-simulator", withMarker); err != nil {
		t.Errorf("the fat simulator slice holds arm64 and must carry the marker: %v", err)
	}
	if err := verifyAppleCPUOverlayMarker("tvos-arm64", without); err == nil {
		t.Error("tvOS is GOOS=ios on arm64 and must carry the marker")
	}
}

// nm prints only the host architecture of a universal binary unless asked for all of
// them, so the verdict on the fat simulator slices would follow the build machine's CPU.
func TestSliceSymbolsAreReadForEveryArchitecture(t *testing.T) {
	args := sliceSymbolArgs("/x/Hako.framework/Hako")
	if !slicesContain(args, "-arch") {
		t.Fatalf("nm must be asked for every architecture of a universal binary: %v", args)
	}
	if !slicesContain(args, "all") {
		t.Fatalf("the architecture selector must be `all`: %v", args)
	}
}

// The xcframework holds more than slices (Info.plist, and whatever a signing or
// packaging step leaves next to them); the rest of build_libbox enumerates slices as
// "*-*" and this verdict must agree with it rather than hard-failing on a stray entry.
func TestOnlySliceDirectoriesAreJudged(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"ios-arm64", "macos-arm64_x86_64", "_CodeSignature", "dSYMs"} {
		if err := os.MkdirAll(filepath.Join(dir, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "Info.plist"), []byte("<plist/>"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := xcframeworkSliceDirs(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ios-arm64", "macos-arm64_x86_64"}
	if len(got) != len(want) {
		t.Fatalf("slice enumeration must match the rest of build_libbox (\"*-*\"): got %v, want %v", got, want)
	}
	for i := range want {
		if filepath.Base(got[i]) != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func slicesContain(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

// go build ignores an overlay key that names a file which does not exist. The day
// upstream fixes iOS feature detection it will likely retire cpu_arm64_other.go for
// the iOS family, and the overlay would then add a second osInit and die inside
// internal/cpu with a redeclaration error that names nothing about this mechanism.
func TestOverlayRefusesAGOROOTWithoutTheFileItReplaces(t *testing.T) {
	root := repoRoot(t)
	goroot := t.TempDir() // no src/internal/cpu/cpu_arm64_other.go here
	_, err := writeAppleCPUOverlay(root, goroot, t.TempDir())
	if err == nil {
		t.Fatal("a GOROOT without cpu_arm64_other.go must be refused before the build, not discovered as a redeclaration deep in internal/cpu")
	}
	if !strings.Contains(err.Error(), "cpu_arm64_other.go") || !strings.Contains(err.Error(), "retire") {
		t.Fatalf("the error must name the missing file and say the overlay may have outlived upstream: %v", err)
	}
}

// Asking the go command anything inside bind/hako makes it honour the module's
// toolchain line, and when that toolchain is not installed it downloads it -- 311 MB --
// before answering. A unit test must find out whether the pin is available without
// paying that, and skip with its own reason when it is not, rather than either
// downloading or hiding a resolver failure behind a skip.
func TestPinnedToolchainAvailabilityIsDecidedWithoutADownload(t *testing.T) {
	lookPath := func(name string) (string, error) {
		if name == "go1.26.6" {
			return "/u/go/bin/go1.26.6", nil
		}
		return "", exec.ErrNotFound
	}
	if !pinnedToolchainAvailable("go1.26.6", "go1.26.5", lookPath) {
		t.Fatal("a goX.Y.Z wrapper on PATH means the go command will use it instead of downloading")
	}
	if !pinnedToolchainAvailable("go1.26.6", "go1.26.6", func(string) (string, error) { return "", exec.ErrNotFound }) {
		t.Fatal("a host go at the pinned version needs no switch at all")
	}
	if !pinnedToolchainAvailable("go1.26.6", "go1.27.1", func(string) (string, error) { return "", exec.ErrNotFound }) {
		t.Fatal("a host go newer than the pin satisfies the toolchain line without a switch")
	}
	if pinnedToolchainAvailable("go1.26.6", "go1.26.5", func(string) (string, error) { return "", exec.ErrNotFound }) {
		t.Fatal("an older host go with no wrapper on PATH means the go command would download the pin")
	}
}

// The resolver used to spawn go three times for three answers it can get in one.
func TestGoEnvAnswersComeFromOneSpawn(t *testing.T) {
	env := parseGoEnvLines("GOROOT=/x/go\nGOMODCACHE=/x/mod\nGOVERSION=go1.26.6\n", []string{"GOROOT", "GOMODCACHE", "GOVERSION"})
	if env["GOROOT"] != "/x/go" || env["GOMODCACHE"] != "/x/mod" || env["GOVERSION"] != "go1.26.6" {
		t.Fatalf("one `go env A B C` call answers all three: %v", env)
	}
	if _, err := goEnvValues(parseGoEnvLines("GOROOT=/x/go\n", []string{"GOROOT", "GOMODCACHE"}), "GOROOT", "GOMODCACHE"); err == nil {
		t.Fatal("a missing answer must be an error, not an empty string that later passes a prefix check")
	}
}

// The overlay replaces the whole file, so a future toolchain that keeps the file name
// but gives it real iOS detection would be silently overwritten while the marker still
// passes. The replaced file must be the one the overlay was written for: the constraint
// that selects iOS and nothing but an empty osInit.
func TestOverlayRefusesAReplacedFileThatHasGrownLogic(t *testing.T) {
	root := repoRoot(t)
	goroot := t.TempDir()
	silent := filepath.Join(goroot, "src", "internal", "cpu", "cpu_arm64_other.go")
	if err := os.MkdirAll(filepath.Dir(silent), 0o755); err != nil {
		t.Fatal(err)
	}
	grown := "//go:build arm64 && !linux && !freebsd && !android && (!darwin || ios) && !openbsd\n\npackage cpu\n\nfunc osInit() {\n\tARM64.HasAES = sysctlEnabled([]byte(\"hw.optional.arm.FEAT_AES\\x00\"))\n}\n"
	if err := os.WriteFile(silent, []byte(grown), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := writeAppleCPUOverlay(root, goroot, t.TempDir()); err == nil {
		t.Fatal("a cpu_arm64_other.go whose osInit does something must not be overlaid away")
	} else if !strings.Contains(err.Error(), "osInit") {
		t.Fatalf("the refusal must say what changed: %v", err)
	}
	narrowed := "//go:build arm64 && !linux && !freebsd && !android && !darwin && !openbsd\n\npackage cpu\n\nfunc osInit() {}\n"
	if err := os.WriteFile(silent, []byte(narrowed), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := writeAppleCPUOverlay(root, goroot, t.TempDir()); err == nil {
		t.Fatal("a constraint that no longer selects iOS means the toolchain handles iOS elsewhere; the overlay must step aside")
	}
}

// GNU nm on PATH takes different flags; the slice verdict must use the SDK's nm.
func TestSliceSymbolsUseTheSDKsNM(t *testing.T) {
	name, args := sliceSymbolCommand("/x/Hako.framework/Hako")
	if name != "xcrun" || len(args) < 2 || args[0] != "nm" {
		t.Fatalf("the verdict must run the SDK's nm through xcrun, got %s %v", name, args)
	}
}
