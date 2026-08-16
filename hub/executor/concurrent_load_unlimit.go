//go:build (386 || amd64 || arm64 || arm64be) && !(darwin && arm64) && !ios

package executor

import "math"

const concurrentCount = math.MaxInt
