//go:build (darwin && arm64) || ios

package executor

// Provider loading is bounded on Apple hardware, and the reason is the budget
// rather than the chip.
//
// Upstream picks this constant by architecture: arm64 gets math.MaxInt, on the
// reasoning that a 64-bit machine can afford to parse every provider at once
// and finish sooner. A phone is arm64 and does not share that premise. An iOS
// packet tunnel gets fifty megabytes for the whole extension — the kernel's
// own number, logged by runningboardd as "Memory Limits: active 50 inactive
// 50" — and unbounded concurrency spends it on transient parse buffers that
// exist only while the providers load.
//
// Measured on an iPhone 13 mini with a profile carrying fifty-three rule
// providers and three subscriptions: the extension was killed at exactly 3200
// pages, per-process-limit, having exceeded the cap by 34784 bytes. Loaded
// steadily those same rule sets retain 4.3 MiB. Nothing about the profile is
// large; the peak was.
//
// Five is upstream's own answer for the architectures it considers
// constrained, so this is their number applied on their reasoning, not a new
// one invented here.
const concurrentCount = 5
