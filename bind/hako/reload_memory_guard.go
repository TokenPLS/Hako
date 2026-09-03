package hako

import (
	"fmt"
	"math"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/TokenPLS/Hako/config"
	C "github.com/TokenPLS/Hako/constant"
)

// A hot reload is a full ParseRawConfig + ApplyConfig on top of the running core: the new
// configuration is built whole while the old one is still serving, and only then swapped.
// On a desktop that is the safe design. Inside a Network Extension it meets a wall: the
// process is killed at 50 MiB of phys_footprint with no signal, no crash report and no
// shutdown line -- the tunnel just stops. On a device a profile running at 31.5 MiB was
// measured 116 ms into a reload at 43.3 MiB and still climbing, and then gone; the same
// configuration cold-starts in a second and lives at 31 MiB. What died was not the
// configuration but the sum: one core plus most of a second one. The App then read the
// silence as a stalled extension, retried against a dead process for five seconds, tore the
// tunnel down and started it again -- seven to nine seconds without a network per edit,
// thirty-three at the worst.
//
// So the second core is not built when it would not fit. Before parsing, the judge reads the
// process's remaining headroom and estimates what building one more core costs; if that does
// not fit, Reload returns a refusal the App can act on -- the same shape as the refusal for a
// reload that would change the live tun -- and the App restarts the extension cleanly instead.
// The estimate is deliberately biased high: a wrong refusal costs a one-second restart, a
// wrong acceptance costs the death above, and the two are not the same size.

const (
	reloadAccepted      = "accepted"
	reloadRefusedMemory = "memory"
	reloadUnmeasured    = "unmeasured"

	// One core is what the running configuration occupies above the process's baseline; a
	// reload builds one more of about that size, plus what parsing allocates and lets go of
	// before the swap -- geosite decoding, rule compilation, provider loading -- and whatever
	// the collector has not returned yet. That transient is not measured, so it is bought
	// with a factor: building costs twice a core. On the 50 MiB wall with a 7.7 MiB baseline
	// that admits profiles running below about 22 MiB and refuses the rest, which brackets
	// the two profiles that were measured (14 MiB reloads daily; 31.5 MiB died). If the OOM
	// evidence ever shows a reload that was accepted still dying in the parse, this is the
	// number to raise.
	reloadBuildCostSafetyFactor = 2.0

	// What a provider file becomes is much bigger than the file. This tree measured a 4.7 MB
	// domain rule-set taking an iOS extension from 25 MiB to its 50 MiB ceiling inside
	// Initial -- the raw file, a pointer trie, a full copy of the domains and the succinct
	// set all live at once (hub/executor/executor.go, the comment above Initial) -- at least
	// 25 MiB out of 4.7 MB, which is 5.3x and more if the megabytes were decimal. Six covers
	// the measurement with margin on its high side; like the core factor, it is the number to
	// raise if the OOM evidence ever shows an accepted reload dying in a provider build.
	providerPayloadCostFactor = 6.0
)

// reloadMemoryReading is what the judge sees: the headroom this process has left, its
// footprint now, its footprint before the running configuration was parsed, and what a zero
// headroom means on this platform.
type reloadMemoryReading struct {
	AvailableBytes int64
	FootprintBytes int64
	BaselineBytes  int64
	// CurrentProviderBytes and CandidateProviderBytes are the sizes of the files behind the
	// running configuration's providers and the candidate's (providerPayloadBytes). The text of
	// a configuration is not the whole candidate: a subscription can grow from small to 16 MiB
	// under an unchanged YAML, and providers are read and prepared before the parse.
	CurrentProviderBytes   int64
	CandidateProviderBytes int64
	// ZeroMeansExhausted is the platform's reading of a zero from os_proc_available_memory.
	// Apple's header: "0 is returned if the calling process is not an app, or the calling
	// process exceeds its memory limit." On a macOS host that is the first clause -- no wall,
	// nothing to judge; in an iOS or tvOS extension, where the same call answers positive
	// numbers all day, it is the second: at or over the limit, and a second core is the surest
	// way to be killed. GOOS tells the two apart at build time (zeroHeadroomMeansExhausted).
	ZeroMeansExhausted bool
}

// zeroHeadroomMeansExhausted is true in the iOS/tvOS builds (GOOS=ios), where a zero from
// os_proc_available_memory is "exceeds its memory limit", and false on darwin, where the same
// zero is "not an app". A variable rather than a constant so the judge's service-level test can
// exercise both meanings on one host.
var zeroHeadroomMeansExhausted = runtime.GOOS == "ios"

// reloadMemoryVerdict is the judge's answer, in numbers rather than a sentence, so the
// diagnostics can carry it and a reader can redo the arithmetic.
type reloadMemoryVerdict struct {
	Reason         string `json:"reason"`
	NeededBytes    int64  `json:"neededBytes,omitempty"`
	AvailableBytes int64  `json:"availableBytes,omitempty"`
	FootprintBytes int64  `json:"footprintBytes,omitempty"`
	AtUnix         int64  `json:"atUnix,omitempty"`
}

// The readers behind the judge, as variables so a test can hand it a device's numbers: the
// test process has no wall, and os_proc_available_memory answers 0 or -1 there.
var (
	readAvailableMemoryForReload = availableMemory
	readFootprintForReload       = physFootprint
)

// judgeReloadMemory decides whether building one more core fits in the headroom.
//
// A strictly positive headroom is a reading. A zero is a reading only where the platform says
// it means "exceeds its memory limit" (ZeroMeansExhausted): then nothing fits, and the judge
// refuses even without a footprint to estimate from -- there is nothing to estimate, and nothing
// is what fits. Elsewhere a zero is "not an app" and -1 is "no such symbol"; judging on those
// would refuse reloads on platforms that have no wall. Without a footprint reading there is
// otherwise nothing to estimate from, so nothing to refuse on. A baseline that is missing or
// implausible counts as zero, which makes the whole footprint one core -- the high side, on
// purpose.
//
// The estimate scales up with the candidate's size relative to the running configuration
// (a subscription update growing is the ordinary case) and never down: a smaller file can
// still pull larger providers.
func judgeReloadMemory(reading reloadMemoryReading, currentLength, candidateLength int) reloadMemoryVerdict {
	verdict := reloadMemoryVerdict{
		Reason:         reloadUnmeasured,
		AvailableBytes: reading.AvailableBytes,
		FootprintBytes: reading.FootprintBytes,
		AtUnix:         time.Now().Unix(),
	}
	if reading.AvailableBytes == 0 && reading.ZeroMeansExhausted {
		verdict.Reason = reloadRefusedMemory
		verdict.NeededBytes = reading.FootprintBytes
		if verdict.NeededBytes <= 0 {
			verdict.NeededBytes = 1
		}
		return verdict
	}
	if reading.AvailableBytes <= 0 || reading.FootprintBytes <= 0 {
		return verdict
	}
	oneCore := reading.FootprintBytes
	if reading.BaselineBytes > 0 && reading.BaselineBytes < reading.FootprintBytes {
		oneCore = reading.FootprintBytes - reading.BaselineBytes
	}
	needed := float64(oneCore) * reloadBuildCostSafetyFactor
	if currentLength > 0 && candidateLength > currentLength {
		needed *= float64(candidateLength) / float64(currentLength)
	}
	// Provider payload growth on top, counted twice: the raw file and what it is prepared
	// into both sit in memory before the swap. Shrinkage is not credited.
	if growth := reading.CandidateProviderBytes - reading.CurrentProviderBytes; growth > 0 {
		needed += float64(growth) * providerPayloadCostFactor
	}
	verdict.NeededBytes = int64(math.Ceil(needed))
	if verdict.NeededBytes > reading.AvailableBytes {
		verdict.Reason = reloadRefusedMemory
	} else {
		verdict.Reason = reloadAccepted
	}
	return verdict
}

// judgeReloadAgainstTheCeiling is the service's call into the judge, made under s.mu before
// the candidate is parsed. It records the verdict for the diagnostics either way.
//
// The headroom is read twice on purpose. The first read only asks whether there is a wall at
// all; when there is one, the collector is asked to return what it holds
// (debug.FreeOSMemory) before the second read, so that Go's retained heap does not count
// against the reload -- that is memory the process could give back and will, and counting
// it would refuse reloads that fit. On a platform with no reading the collector is left alone.
func (s *BoxService) judgeReloadAgainstTheCeiling(candidate string) reloadMemoryVerdict {
	reading := reloadMemoryReading{
		AvailableBytes:     readAvailableMemoryForReload(),
		ZeroMeansExhausted: zeroHeadroomMeansExhausted,
	}
	if reading.AvailableBytes > 0 || (reading.AvailableBytes == 0 && reading.ZeroMeansExhausted) {
		debug.FreeOSMemory()
		reading.AvailableBytes = readAvailableMemoryForReload()
		reading.FootprintBytes = readFootprintForReload()
		reading.BaselineBytes = s.startFootprintBytes
		reading.CurrentProviderBytes = s.providerBytes
		reading.CandidateProviderBytes = providerPayloadBytes(candidate)
	}
	// Remembered for the success path: a committed reload adopts this as the new current
	// figure instead of decoding the same 4 MiB-bounded text a second time. Negative marks
	// "not computed" (no wall on this platform), which the success path re-measures.
	s.candidateProviderBytes = -1
	if reading.AvailableBytes > 0 || (reading.AvailableBytes == 0 && reading.ZeroMeansExhausted) {
		s.candidateProviderBytes = reading.CandidateProviderBytes
	}
	verdict := judgeReloadMemory(reading, s.configLength, len(candidate))
	s.reloadVerdict = verdict
	return verdict
}

// reloadMemoryRefusal is the sentence the App receives. The tail is the same as the tun
// refusal's so a consumer that branches on it restarts for both; the token in parentheses
// says which. Needed is rounded up and available down, so the numbers err the same way the
// judge does.
func reloadMemoryRefusal(verdict reloadMemoryVerdict) error {
	const mebibyte = 1 << 20
	return fmt.Errorf("hako: reload refused (memory): need ~%d MiB, have %d MiB; restart the appex instead",
		(verdict.NeededBytes+mebibyte-1)/mebibyte, verdict.AvailableBytes/mebibyte)
}

// providerPayloadBytes is the size of the files behind a configuration's providers, resolved
// the way upstream resolves them: the declared path, or for an http provider without one the
// hashed default under the home directory. It is a floor: unreadable YAML, a provider without a
// resolvable file, or a file that is not there count zero. Only the sizes are read; nothing is
// opened, and nothing about the providers' contents leaves this function.
func providerPayloadBytes(configContent string) int64 {
	raw, err := config.UnmarshalRawConfig([]byte(configContent))
	if err != nil {
		return 0
	}
	var total int64
	// Keys with the pipeline's own precedence: canonicalizeProviderDefinitionKeys lets a key
	// that is already lowercase always win -- a mixed-case duplicate never overwrites it -- so
	// when `path:` is present that is the file the provider will load, whatever a `Path:`
	// beside it says. Between several mixed-case variants with no lowercase key the pipeline's
	// resolution is map order; the estimator cannot be more deterministic than what it
	// estimates, so it takes every variant's file and charges the largest -- over-counting is
	// the safe side of a nondeterminism that lives upstream of it.
	variants := func(provider map[string]any, key string) []string {
		if value, ok := provider[key].(string); ok {
			return []string{value}
		}
		var values []string
		for k, v := range provider {
			if strings.ToLower(k) == key {
				if value, ok := v.(string); ok {
					values = append(values, value)
				}
			}
		}
		return values
	}
	sizeOf := func(path string) int64 {
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			return info.Size()
		}
		return 0
	}
	count := func(kind string, providers map[string]map[string]any) {
		for _, provider := range providers {
			var largest int64
			// A DECLARED path decides, whatever its file holds: the pipeline reads the
			// explicit path exclusively when one exists, and a zero-byte file is a valid
			// provider by contract (a 404'd subscription writes an empty file and the set
			// starts empty). Falling through to the url on "size zero" would charge whatever
			// stale download sits at the url's hashed cache location -- a phantom refusal.
			// The url location is the payload only when no path is declared at all.
			if paths := variants(provider, "path"); len(paths) > 0 {
				for _, path := range paths {
					if size := sizeOf(C.Path.Resolve(path)); size > largest {
						largest = size
					}
				}
			} else {
				for _, url := range variants(provider, "url") {
					if size := sizeOf(C.Path.GetPathByHash(kind, url)); size > largest {
						largest = size
					}
				}
			}
			total += largest
		}
	}
	count("proxies", raw.ProxyProvider)
	count("rules", raw.RuleProvider)
	return total
}
