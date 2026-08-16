//go:build !with_low_memory

package net

import (
	"io"

	"github.com/metacubex/sing/common/bufio"
)

func relayCopy(destination io.Writer, source io.Reader) (int64, error) {
	return bufio.Copy(destination, source)
}
