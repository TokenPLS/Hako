package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDiscoverLicenseFiles(t *testing.T) {
	directory := t.TempDir()
	for _, name := range []string{"LICENSE", "NOTICE.md", "copying.txt", "README.md"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	files, err := discoverLicenseFiles(directory)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, file := range files {
		names = append(names, filepath.Base(file))
	}
	want := []string{"LICENSE", "NOTICE.md", "copying.txt"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("license files = %v, want %v", names, want)
	}
}

func TestDiscoverLicenseFilesFallsBackToPackageLicenses(t *testing.T) {
	directory := t.TempDir()
	if err := os.MkdirAll(filepath.Join(directory, "crypto"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "crypto", "LICENSE"), []byte("license"), 0o644); err != nil {
		t.Fatal(err)
	}
	files, err := discoverLicenseFiles(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || filepath.Base(files[0]) != "LICENSE" {
		t.Fatalf("fallback license files = %v", files)
	}
}

func TestSafeModuleDirectory(t *testing.T) {
	if got, want := safeModuleDirectory("github.com/example/module/v2"), "github.com__example__module__v2"; got != want {
		t.Fatalf("safeModuleDirectory = %q, want %q", got, want)
	}
}
