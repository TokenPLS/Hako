package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Go's internal/cpu never detects ARM64 features on GOOS=ios (cpu_arm64_other.go has
// an empty osInit), so the crypto packages take their pure-Go paths on every iPhone,
// iPad and Apple TV slice. The fix is a build-time overlay of that one file. gomobile
// sets GOFLAGS itself for every platform it builds, which discards a GOFLAGS=-overlay
// from the caller, so the overlay rides in through a `go` shim placed first on PATH:
// it adds -overlay to the subcommands that compile code and passes everything else
// through untouched.

const appleCPUOverlayRelativeSource = "cmd/build_libbox/overlay/internal_cpu_arm64_ios.go.src"

// appleCPUOverlayMarkerSymbol is the function the overlay defines so that a finished
// slice can prove it was compiled in; nm shows it as internal/cpu.<symbol>.
const appleCPUOverlayMarkerSymbol = "hakoAppleCPUOverlayMarker"

// requireOverlayableGOROOT refuses a GOROOT the go command downloaded into the module
// cache: `go build` rejects an overlay of any file beneath GOMODCACHE, so the pinned
// version has to be installed for real. The error carries the command that fixes it.
func requireOverlayableGOROOT(goroot, modcache, version string) (string, error) {
	if modcache != "" && strings.HasPrefix(goroot, filepath.Clean(modcache)+string(os.PathSeparator)) {
		return "", fmt.Errorf("the bind module pins %s and this machine only has it as a module-cache download under %s; go build refuses to overlay files beneath GOMODCACHE, so the Apple slices cannot be built at all. Install it for real: go install golang.org/dl/%s@latest && %s download", version, modcache, version, version)
	}
	return goroot, nil
}

// goInBindModule runs the go command inside bind/hako with the build's environment, so
// the answer reflects the toolchain the bind module's build will actually use. The
// child's stderr rides on the error; "exit status 1" alone explains nothing.
func goInBindModule(root string, env []string, args ...string) (string, error) {
	cmd := exec.Command("go", args...)
	cmd.Dir = filepath.Join(root, bindModuleDir)
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && len(exit.Stderr) > 0 {
			return "", fmt.Errorf("go %s in %s: %w: %s", strings.Join(args, " "), bindModuleDir, err, strings.TrimSpace(string(exit.Stderr)))
		}
		return "", fmt.Errorf("go %s in %s: %w", strings.Join(args, " "), bindModuleDir, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// parseGoEnvLines reads the `go env NAME...` output, one answer per line in the order
// asked, into a map. GOVERSION is a plain value; `go env` never quotes here.
func parseGoEnvLines(output string, names []string) map[string]string {
	values := map[string]string{}
	lines := strings.Split(strings.TrimRight(output, "\n"), "\n")
	for i, name := range names {
		if i < len(lines) {
			line := lines[i]
			// `go env` prints bare values when asked for names; tolerate KEY=value too.
			if strings.HasPrefix(line, name+"=") {
				line = strings.TrimPrefix(line, name+"=")
			}
			values[name] = strings.TrimSpace(line)
		}
	}
	return values
}

// goEnvValues returns the named values or an error naming the first one that is empty:
// an unanswered GOMODCACHE would make the module-cache check pass by accident.
func goEnvValues(values map[string]string, names ...string) ([]string, error) {
	out := make([]string, 0, len(names))
	for _, name := range names {
		v, ok := values[name]
		if !ok || v == "" {
			return nil, fmt.Errorf("go env gave no %s", name)
		}
		out = append(out, v)
	}
	return out, nil
}

// pinnedToolchainAvailable decides, without spawning anything that could download,
// whether the go command will find the bind module's pinned toolchain: the host go is
// already at or past the pin, or a goX.Y.Z wrapper for it is on PATH (which the go
// command consults before downloading). hostVersion and pin are "goX.Y.Z" strings.
func pinnedToolchainAvailable(pin, hostVersion string, lookPath func(string) (string, error)) bool {
	if compareGoVersions(hostVersion, pin) >= 0 {
		return true
	}
	_, err := lookPath(pin)
	return err == nil
}

// compareGoVersions orders two "goX.Y.Z" strings numerically; anything unparsable
// sorts lowest so it never counts as satisfying a pin.
func compareGoVersions(a, b string) int {
	parse := func(v string) [3]int {
		var out [3]int
		v = strings.TrimPrefix(v, "go")
		v = strings.SplitN(v, "-", 2)[0] // "go1.27rc1" style suffixes are not release pins
		for i, part := range strings.SplitN(v, ".", 3) {
			n := 0
			for _, r := range part {
				if r < '0' || r > '9' {
					break
				}
				n = n*10 + int(r-'0')
			}
			out[i] = n
		}
		return out
	}
	x, y := parse(a), parse(b)
	for i := range x {
		if x[i] != y[i] {
			if x[i] < y[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// appleOverlayToolchain reports the GOROOT the overlay must be keyed on: the one the
// bind module's build compiles under, asked with the environment that build will use.
// Asking with the ambient environment instead is how the first version disagreed with
// itself -- buildEnv prepends GOPATH/bin, where the real installation of a pinned
// toolchain lives, and the go command searches that same PATH before downloading one.
func appleOverlayToolchain(root string, env []string) (string, error) {
	names := []string{"GOROOT", "GOMODCACHE", "GOVERSION"}
	output, err := goInBindModule(root, env, append([]string{"env"}, names...)...)
	if err != nil {
		return "", err
	}
	values, err := goEnvValues(parseGoEnvLines(output, names), names...)
	if err != nil {
		return "", err
	}
	return requireOverlayableGOROOT(values[0], values[1], values[2])
}

// verifyAppleCPUOverlayMarker judges one slice by its nm output: the iOS family must
// carry the marker, macOS must not (its own darwin file detects features).
func verifyAppleCPUOverlayMarker(slice, nmOutput string) error {
	present := strings.Contains(nmOutput, "internal/cpu."+appleCPUOverlayMarkerSymbol)
	// The overlay is constrained to arm64 && ios: the iOS family on arm64 must carry it,
	// and nothing else may -- macOS detects features itself, x86_64 slices through cpuid.
	iosFamily := strings.HasPrefix(slice, "ios") || strings.HasPrefix(slice, "tvos")
	wantsMarker := iosFamily && strings.Contains(slice, "arm64")
	switch {
	case wantsMarker && !present:
		return fmt.Errorf("slice %s was built past the cpu overlay: internal/cpu.%s is missing, so AES-GCM runs in software on it", slice, appleCPUOverlayMarkerSymbol)
	case !wantsMarker && present:
		return fmt.Errorf("slice %s carries the arm64 iOS cpu overlay marker; the overlay's build constraint leaked", slice)
	}
	return nil
}

// sliceSymbolArgs is the nm argument list for one slice binary. `-arch all` is not
// optional: nm prints only the host architecture of a universal binary, so without it
// the verdict on the fat simulator slices would follow the build machine's CPU.
func sliceSymbolArgs(binary string) []string {
	return []string{"-arch", "all", "-a", binary}
}

// sliceSymbolCommand runs the SDK's nm through xcrun: a GNU nm first on PATH takes
// different flags and would fail the verdict on a machine that never built anything wrong.
func sliceSymbolCommand(binary string) (string, []string) {
	return "xcrun", append([]string{"nm"}, sliceSymbolArgs(binary)...)
}

// requireSilentFeatureFile checks that the file the overlay replaces is still the one it
// was written for: a build constraint that selects the iOS family, and an osInit that
// does nothing. The overlay replaces the whole file, so a toolchain that gives this path
// real iOS detection would otherwise be overwritten in silence while the marker still
// passes; either change means the overlay needs a human to look again.
func requireSilentFeatureFile(path string) error {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return fmt.Errorf("apple cpu overlay: %s no longer parses as the file the overlay was written for: %w", filepath.Base(path), err)
	}
	selectsIOS := false
	for _, group := range file.Comments {
		for _, c := range group.List {
			if !constraint.IsGoBuild(c.Text) {
				continue
			}
			expr, err := constraint.Parse(c.Text)
			if err != nil {
				return fmt.Errorf("apple cpu overlay: %s build constraint: %w", filepath.Base(path), err)
			}
			// GOOS=ios satisfies both the ios and the darwin tags; evaluate the way
			// the go command would for an iOS build.
			if expr.Eval(func(tag string) bool { return tag == "arm64" || tag == "ios" || tag == "darwin" }) {
				selectsIOS = true
			}
		}
	}
	if !selectsIOS {
		return fmt.Errorf("apple cpu overlay: %s no longer selects arm64 && ios, so this toolchain handles iOS elsewhere; retire the overlay after reading what it does now", filepath.Base(path))
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "osInit" {
			continue
		}
		if fn.Body == nil || len(fn.Body.List) == 0 {
			return nil
		}
		return fmt.Errorf("apple cpu overlay: %s now has an osInit that does something on iOS; the overlay would overwrite it, so it needs a human to compare before it is applied again", filepath.Base(path))
	}
	return fmt.Errorf("apple cpu overlay: %s defines no osInit; the toolchain has changed shape, retire or rewrite the overlay", filepath.Base(path))
}

// xcframeworkSliceDirs lists the slice directories, the way the rest of build_libbox
// does: an xcframework also holds Info.plist and whatever a packaging step leaves
// beside the slices, and none of that is a slice to judge.
func xcframeworkSliceDirs(xcframework string) ([]string, error) {
	matches, err := filepath.Glob(filepath.Join(xcframework, "*-*"))
	if err != nil {
		return nil, err
	}
	dirs := make([]string, 0, len(matches))
	for _, match := range matches {
		info, err := os.Stat(match) // Stat, not DirEntry: a symlinked slice is still a slice
		if err != nil {
			return nil, err
		}
		if info.IsDir() {
			dirs = append(dirs, match)
		}
	}
	return dirs, nil
}

// verifyAppleCPUOverlayInXCFramework runs nm over every slice binary of the finished
// xcframework and applies verifyAppleCPUOverlayMarker; one bad slice fails the build.
func verifyAppleCPUOverlayInXCFramework(xcframework string) error {
	sliceDirs, err := xcframeworkSliceDirs(xcframework)
	if err != nil {
		return err
	}
	checked := 0
	for _, sliceDir := range sliceDirs {
		slice := filepath.Base(sliceDir)
		binary, err := appleSliceBinary(sliceDir)
		if err != nil {
			return err
		}
		name, args := sliceSymbolCommand(binary)
		out, err := exec.Command(name, args...).Output()
		if err != nil {
			return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
		}
		if err := verifyAppleCPUOverlayMarker(slice, string(out)); err != nil {
			return err
		}
		checked++
	}
	if checked == 0 {
		return fmt.Errorf("no slices found under %s", xcframework)
	}
	fmt.Fprintf(os.Stderr, "build_libbox: apple cpu overlay marker verified in %d slice(s)\n", checked)
	return nil
}

// appleSliceBinary finds the framework binary inside one xcframework slice directory.
func appleSliceBinary(sliceDir string) (string, error) {
	for _, candidate := range []string{
		filepath.Join(sliceDir, "Hako.framework", "Hako"),
		filepath.Join(sliceDir, "Hako.framework", "Versions", "A", "Hako"),
	} {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("no Hako framework binary under %s", sliceDir)
}

// appleCPUOverlaySource is the repository file whose content replaces
// $GOROOT/src/internal/cpu/cpu_arm64_other.go.
func appleCPUOverlaySource(root string) string {
	return filepath.Join(root, filepath.FromSlash(appleCPUOverlayRelativeSource))
}

// writeAppleCPUOverlay writes the -overlay JSON for GOROOT into dir and returns its path.
func writeAppleCPUOverlay(root, goroot, dir string) (string, error) {
	source := appleCPUOverlaySource(root)
	if _, err := os.Stat(source); err != nil {
		return "", fmt.Errorf("apple cpu overlay source: %w", err)
	}
	replaced := filepath.Join(goroot, "src", "internal", "cpu", "cpu_arm64_other.go")
	// go build ignores a key that names no file. If the toolchain no longer has this
	// one, upstream has most likely given the iOS family its own detection file, and
	// the overlay's osInit would collide with it -- time to retire the overlay, not
	// to let internal/cpu report a redeclaration.
	if _, err := os.Stat(replaced); err != nil {
		return "", fmt.Errorf("apple cpu overlay: %s is missing from GOROOT %s; the toolchain may detect ARM64 features on iOS itself now, in which case retire the overlay (%w)", "cpu_arm64_other.go", goroot, err)
	}
	if err := requireSilentFeatureFile(replaced); err != nil {
		return "", err
	}
	payload, err := json.Marshal(map[string]map[string]string{"Replace": {replaced: source}})
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "apple-cpu-overlay.json")
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// goShimCompilingSubcommands are the go subcommands that read -overlay; every other
// subcommand (env, version, mod, ...) rejects the flag and must not see it.
var goShimCompilingSubcommands = []string{"build", "install", "list", "test", "vet", "run"}

// writeGoShim writes a `go` executable into dir/bin that execs realGo with the overlay
// injected after a compiling subcommand, and returns that bin directory.
func writeGoShim(dir, realGo, overlayJSON string) (string, error) {
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return "", err
	}
	var script strings.Builder
	script.WriteString("#!/bin/sh\n")
	script.WriteString("# Hako build shim: hands go build the internal/cpu overlay for the iOS family.\n")
	script.WriteString("real=" + shellQuote(realGo) + "\n")
	script.WriteString("overlay=" + shellQuote(overlayJSON) + "\n")
	script.WriteString("case \"$1\" in\n")
	script.WriteString("  " + strings.Join(goShimCompilingSubcommands, "|") + ")\n")
	script.WriteString("    sub=\"$1\"; shift\n")
	script.WriteString("    printf '%s\\n' \"$sub\" >> \"$overlay.injected\"\n")
	script.WriteString("    exec \"$real\" \"$sub\" \"-overlay=$overlay\" \"$@\"\n")
	script.WriteString("    ;;\n")
	script.WriteString("  *)\n")
	script.WriteString("    exec \"$real\" \"$@\"\n")
	script.WriteString("    ;;\n")
	script.WriteString("esac\n")
	shim := filepath.Join(binDir, "go")
	if err := os.WriteFile(shim, []byte(script.String()), 0o755); err != nil {
		return "", err
	}
	return binDir, nil
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// withAppleCPUOverlay returns env with a go shim first on PATH so that every go build
// gomobile runs for an Apple slice compiles internal/cpu from the overlay. The returned
// cleanup reports how many go invocations went through the shim and removes it; it must
// be called on every path out, including the failing ones, because that count is the
// only evidence that the overlay was offered to the build at all.
func withAppleCPUOverlay(env []string, root string) (_ []string, cleanup func(), err error) {
	realGo, err := exec.LookPath("go")
	if err != nil {
		return nil, nil, err
	}
	goroot, err := appleOverlayToolchain(root, env)
	if err != nil {
		return nil, nil, err
	}
	dir, err := os.MkdirTemp("", "hako-apple-cpu-overlay-")
	if err != nil {
		return nil, nil, err
	}
	shimWritten := false
	cleanup = func() {
		// The temp dir goes away with the build, so the proof that gomobile's go
		// invocations went through the shim is printed before it does. A shim that
		// was never written cannot have been bypassed, so nothing is claimed then.
		if shimWritten {
			if marks, err := os.ReadFile(filepath.Join(dir, "apple-cpu-overlay.json.injected")); err == nil {
				fmt.Fprintf(os.Stderr, "build_libbox: apple cpu overlay rode into %d go invocation(s)\n", strings.Count(string(marks), "\n"))
			} else {
				fmt.Fprintln(os.Stderr, "build_libbox: apple cpu overlay rode into 0 go invocations -- the shim was never used")
			}
		}
		_ = os.RemoveAll(dir)
	}
	overlayJSON, err := writeAppleCPUOverlay(root, goroot, dir)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	binDir, err := writeGoShim(dir, realGo, overlayJSON)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	shimWritten = true
	fmt.Fprintf(os.Stderr, "build_libbox: apple cpu overlay %s via %s\n", overlayJSON, filepath.Join(binDir, "go"))
	out := make([]string, 0, len(env)+1)
	pathSeen := false
	for _, entry := range env {
		if strings.HasPrefix(entry, "PATH=") {
			out = append(out, "PATH="+binDir+string(os.PathListSeparator)+strings.TrimPrefix(entry, "PATH="))
			pathSeen = true
			continue
		}
		out = append(out, entry)
	}
	if !pathSeen {
		out = append(out, "PATH="+binDir)
	}
	return out, cleanup, nil
}

// isAppleBindTarget reports whether a gomobile bind target is one of the Apple family.
func isAppleBindTarget(target string) bool {
	for _, item := range strings.Split(target, ",") {
		switch strings.SplitN(strings.TrimSpace(item), "/", 2)[0] {
		case "ios", "iossimulator", "macos", "maccatalyst", "tvos", "tvossimulator":
		default:
			return false
		}
	}
	return target != ""
}
