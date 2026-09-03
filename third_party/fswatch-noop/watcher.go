// Package fswatch preserves the github.com/metacubex/fswatch API while
// deliberately disabling filesystem observation for Hako's Apple binding.
package fswatch

import (
	"os"
	"time"
)

const DefaultWaitTimeout = 100 * time.Millisecond

// Logger matches the upstream logging contract.
type Logger interface {
	Error(args ...any)
}

// Options matches the upstream watcher construction contract.
type Options struct {
	Path        []string
	Direct      bool
	Callback    func(path string)
	WaitTimeout time.Duration
	Logger      Logger
}

// Watcher is inert. Apple configuration revisions are immutable and are
// activated through an explicit provider reload instead of file observation.
type Watcher struct{}

// NewWatcher validates the same required options as the upstream package.
func NewWatcher(options Options) (*Watcher, error) {
	if len(options.Path) == 0 || options.Callback == nil {
		return nil, os.ErrInvalid
	}
	return &Watcher{}, nil
}

// Start intentionally does not allocate a descriptor or launch a goroutine.
func (*Watcher) Start() error {
	return nil
}

// Close is a no-op because Start owns no resources.
func (*Watcher) Close() error {
	return nil
}
