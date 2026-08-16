package fswatch

import (
	"errors"
	"os"
	"testing"
	"time"
)

func TestNewWatcherRejectsInvalidOptions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		options Options
	}{
		{name: "missing path", options: Options{Callback: func(string) {}}},
		{name: "missing callback", options: Options{Path: []string{"/tmp/config.yaml"}}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			watcher, err := NewWatcher(test.options)
			if !errors.Is(err, os.ErrInvalid) {
				t.Fatalf("NewWatcher() error = %v, want os.ErrInvalid", err)
			}
			if watcher != nil {
				t.Fatal("NewWatcher() returned a watcher for invalid options")
			}
		})
	}
}

func TestWatcherIsInert(t *testing.T) {
	t.Parallel()

	called := make(chan string, 1)
	watcher, err := NewWatcher(Options{
		Path:     []string{"/tmp/config.yaml"},
		Callback: func(path string) { called <- path },
	})
	if err != nil {
		t.Fatalf("NewWatcher() error = %v", err)
	}
	if err := watcher.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := watcher.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	select {
	case path := <-called:
		t.Fatalf("no-op watcher invoked callback for %q", path)
	case <-time.After(20 * time.Millisecond):
	}
}
