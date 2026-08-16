// Command package_licenses emits the complete license inventory for every Go
// module linked into the Apple binding. Release packaging uses this inventory
// instead of a hand-maintained representative dependency list.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

const productionTags = "with_gvisor,with_low_memory,cmfa,with_quic"

type goModule struct {
	Path    string    `json:"Path"`
	Version string    `json:"Version"`
	Dir     string    `json:"Dir"`
	Main    bool      `json:"Main"`
	Replace *goModule `json:"Replace"`
}

type goPackage struct {
	Module *goModule `json:"Module"`
}

type licenseEntry struct {
	Module      string        `json:"module"`
	Version     string        `json:"version,omitempty"`
	Replacement string        `json:"replacement,omitempty"`
	Files       []licenseFile `json:"files"`
}

type licenseFile struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

type licenseIndex struct {
	Schema  int            `json:"schema"`
	Modules []licenseEntry `json:"modules"`
}

func main() {
	var output string
	var clientResource string
	flag.StringVar(&output, "output", "dist/THIRD_PARTY_LICENSES", "output directory relative to the repository root")
	flag.StringVar(&clientResource, "client-resource", "",
		"path of a separately maintained acknowledgements list this command does not write; "+
			"named in the success report so a caller cannot mistake one for the other")
	flag.Parse()

	root, err := os.Getwd()
	if err != nil {
		fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "bind", "hako", "go.mod")); err != nil {
		fatal(errors.New("run package_licenses from the repository root"))
	}
	if !filepath.IsAbs(output) {
		output = filepath.Join(root, output)
	}
	if err := packageLicenses(root, output); err != nil {
		fatal(err)
	}
	reportWhatWasAndWasNotWritten(os.Stderr, output, clientResource)
}

// reportWhatWasAndWasNotWritten prints where the inventory went, and -- when the caller names
// one -- the separately maintained list people reach for this command hoping to regenerate.
//
// The second half is a property of a particular repository layout, not of this command, so it
// arrives through -client-resource rather than being compiled in. A build with no such list must
// not invent a sentence about one: a plausible sentence naming a path that does not exist fails
// the same way silence does, one level up.
//
// Until now this command succeeded in silence. Someone bumping the SDK ran it expecting the
// client's acknowledgements to be regenerated, got exit 0 and no output, and nearly moved on --
// while the file they actually needed sat untouched, because it is a manual double-pin
// (AGENTS.md: HakoSDK.lock.json's coreRevision must start with the version credited here, which
// AcknowledgementsTests asserts).
//
// A silent success is worse than an error for exactly this reason: nothing distinguishes "did
// the thing you meant" from "did a different thing correctly". The tool knows which one it did,
// so it says.
func reportWhatWasAndWasNotWritten(out io.Writer, output, clientResource string) {
	fmt.Fprintf(out, "package_licenses: wrote the linked-module inventory to %s\n", output)
	if clientResource == "" {
		return
	}
	fmt.Fprintf(out, "package_licenses: this does NOT update %s\n", clientResource)
	fmt.Fprintf(out, "package_licenses: that one is a manual pin -- its github.com/TokenPLS/Hako "+
		"version is the first 12 characters of HakoSDK.lock.json's coreRevision, and "+
		"AcknowledgementsTests fails when they disagree\n")
}

func packageLicenses(root, output string) error {
	modules, err := linkedModules(filepath.Join(root, "bind", "hako"))
	if err != nil {
		return err
	}
	if err := os.RemoveAll(output); err != nil {
		return fmt.Errorf("clear license output: %w", err)
	}
	if err := os.MkdirAll(output, 0o755); err != nil {
		return fmt.Errorf("create license output: %w", err)
	}

	index := licenseIndex{Schema: 1}
	for _, module := range modules {
		// A slice and a loop rather than the obvious `a || b`, because the OSS
		// export rewrites both of these paths to the same public module name.
		// As `||` that collapses to `x || x` and `go vet` rejects it as a
		// redundant or; as a map or a switch, duplicate keys and duplicate cases
		// are outright compile errors. Identical slice entries are legal and
		// silent, so the export cannot break this file by doing its job.
		selfModules := []string{
			"github.com/TokenPLS/Hako",
			"github.com/TokenPLS/Hako",
		}
		isSelf := false
		for _, self := range selfModules {
			if module.Path == self {
				isSelf = true
				break
			}
		}
		if module.Main || isSelf {
			continue // The repository root LICENSE covers Hako and its mihomo fork.
		}
		source := module.Dir
		replacement := ""
		if module.Replace != nil {
			replacement = module.Replace.Path
			if module.Replace.Version != "" {
				replacement += "@" + module.Replace.Version
			}
			if module.Replace.Dir != "" {
				source = module.Replace.Dir
			}
		}
		files, err := discoverLicenseFiles(source)
		if err != nil {
			return fmt.Errorf("%s: %w", module.Path, err)
		}
		if len(files) == 0 {
			return fmt.Errorf("linked module %s has no root LICENSE/COPYING/NOTICE/COPYRIGHT file", module.Path)
		}

		destination := filepath.Join(output, safeModuleDirectory(module.Path))
		if err := os.MkdirAll(destination, 0o755); err != nil {
			return fmt.Errorf("create license directory for %s: %w", module.Path, err)
		}
		entry := licenseEntry{Module: module.Path, Version: module.Version, Replacement: replacement}
		for _, sourceFile := range files {
			name, err := filepath.Rel(source, sourceFile)
			if err != nil || name == "." || strings.HasPrefix(name, "..") {
				return fmt.Errorf("resolve %s license path: %w", module.Path, err)
			}
			name = filepath.ToSlash(name)
			destinationFile := filepath.Join(destination, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(destinationFile), 0o755); err != nil {
				return fmt.Errorf("create license subdirectory for %s: %w", module.Path, err)
			}
			sum, err := copyAndHash(sourceFile, destinationFile)
			if err != nil {
				return fmt.Errorf("copy %s license %s: %w", module.Path, name, err)
			}
			entry.Files = append(entry.Files, licenseFile{Name: name, SHA256: sum})
		}
		index.Modules = append(index.Modules, entry)
	}
	if len(index.Modules) == 0 {
		return errors.New("linked module license inventory is empty")
	}
	payload, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return fmt.Errorf("encode license index: %w", err)
	}
	payload = append(payload, '\n')
	if err := os.WriteFile(filepath.Join(output, "INDEX.json"), payload, 0o644); err != nil {
		return fmt.Errorf("write license index: %w", err)
	}
	return nil
}

func linkedModules(moduleDir string) ([]goModule, error) {
	cmd := exec.Command("go", "list", "-deps", "-json", "-tags="+productionTags, ".")
	cmd.Dir = moduleDir
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("open go list output: %w", err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start go list: %w", err)
	}
	decoder := json.NewDecoder(stdout)
	unique := make(map[string]goModule)
	for {
		var pkg goPackage
		if err := decoder.Decode(&pkg); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			_ = cmd.Wait()
			return nil, fmt.Errorf("decode go list: %w", err)
		}
		if pkg.Module != nil {
			unique[pkg.Module.Path] = *pkg.Module
		}
	}
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("go list linked modules: %w", err)
	}
	modules := make([]goModule, 0, len(unique))
	for _, module := range unique {
		modules = append(modules, module)
	}
	sort.Slice(modules, func(i, j int) bool { return modules[i].Path < modules[j].Path })
	return modules, nil
}

func discoverLicenseFiles(directory string) ([]string, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("read module root: %w", err)
	}
	var files []string
	for _, entry := range entries {
		if entry.IsDir() || !isLicenseFile(entry.Name()) {
			continue
		}
		files = append(files, filepath.Join(directory, entry.Name()))
	}
	sort.Strings(files)
	if len(files) != 0 {
		return files, nil
	}
	// Some cryptography modules carry separate license texts beside each
	// linked package instead of at module root. Preserve those relative paths.
	err = filepath.WalkDir(directory, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == directory {
			return nil
		}
		if entry.IsDir() {
			if strings.HasPrefix(entry.Name(), ".") || entry.Name() == "vendor" || entry.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if isLicenseFile(entry.Name()) {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk module root: %w", err)
	}
	sort.Strings(files)
	return files, nil
}

func isLicenseFile(name string) bool {
	upper := strings.ToUpper(name)
	for _, prefix := range []string{"LICENSE", "LICENCE", "COPYING", "NOTICE", "COPYRIGHT"} {
		if strings.HasPrefix(upper, prefix) {
			return true
		}
	}
	return false
}

func safeModuleDirectory(module string) string {
	replacer := strings.NewReplacer("/", "__", "\\", "__", ":", "_", "@", "_")
	return replacer.Replace(module)
}

func copyAndHash(source, destination string) (string, error) {
	in, err := os.Open(source)
	if err != nil {
		return "", err
	}
	defer in.Close()
	out, err := os.OpenFile(destination, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(out, hash), in)
	closeErr := out.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "package_licenses:", err)
	os.Exit(1)
}
