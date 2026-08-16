package hako

import (
	"fmt"
	"io"
	"os"
	"strings"
)

func readBoundedRegularFile(path string, maximumBytes int64, label string) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("hako: %s path is empty", label)
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("hako: stat %s: %w", label, err)
	}
	if !before.Mode().IsRegular() {
		return nil, fmt.Errorf("hako: %s is not a regular file", label)
	}
	if before.Size() <= 0 || before.Size() > maximumBytes {
		return nil, fmt.Errorf("hako: %s size is invalid", label)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("hako: open %s: %w", label, err)
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("hako: stat opened %s: %w", label, err)
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, fmt.Errorf("hako: %s changed while opening", label)
	}
	payload, err := io.ReadAll(io.LimitReader(file, maximumBytes+1))
	if err != nil {
		return nil, fmt.Errorf("hako: read %s: %w", label, err)
	}
	if int64(len(payload)) != after.Size() || len(payload) == 0 || int64(len(payload)) > maximumBytes {
		return nil, fmt.Errorf("hako: %s size changed while reading", label)
	}
	return payload, nil
}
