//go:build tools

package hako

// Keeps github.com/sagernet/gomobile in this module's graph: gobind-generated
// glue imports its bind packages at bind time (same trick as sing-box's
// cmd/internal/build_libbox blank import).
import (
	_ "github.com/sagernet/gomobile/bind"
	_ "github.com/sagernet/gomobile/bind/objc"
)
