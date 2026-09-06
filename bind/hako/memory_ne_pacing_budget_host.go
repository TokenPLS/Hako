//go:build !ios

package hako

// See memory_ne_pacing_budget.go; macOS and host builds keep the Go runtime
// defaults on purpose.
const buildIsNEBudgetedPlatform = false
