package hako

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	C "github.com/TokenPLS/Hako/constant"
	P "github.com/TokenPLS/Hako/constant/provider"
	"github.com/TokenPLS/Hako/rules/provider"
)

// RuleProviderCompileResult is what one compile attempt did, and when it did
// nothing, why.
//
// Not an error: a rule set that cannot be compiled is a normal, permanent
// property of that rule set, and the profile it belongs to still runs. The
// caller writes the reason down and keeps the source.
type RuleProviderCompileResult struct {
	// Compiled reports whether an artifact was written.
	Compiled bool
	// Behavior the artifact was written with. A classical list of nothing but
	// domains compiles as "domain"; the caller must rewrite the provider to
	// match, or the core will read the artifact under the wrong strategy.
	Behavior string
	// Rules carried into the artifact, so the caller can log a summary and a
	// gate can compare it against the source.
	Rules int
	// Reason names what stopped the compile, in the words a reader can act on.
	// Empty when Compiled is true.
	Reason string
}

// CompileRuleProvider turns a downloaded rule set into the compact form the
// core reads in milliseconds, when that rule set can make the trip.
//
// A `text` or `yaml` list is source material: the core parses every line on
// every start, and for a large set that is tens of megabytes of scaffolding
// held for the life of the process. The MRS form is the parsed result — 1.4
// MiB of domains become 0.4 MiB on disk, 76ms and +60.8 MiB to compile once
// against 3ms and +11.4 MiB to read back (measured on this module against a
// 111,803-line list).
//
// Three answers, and only the first writes anything:
//   - `domain` or `ipcidr` source: compiled.
//   - `classical` holding nothing but DOMAIN and DOMAIN-SUFFIX: compiled as
//     `domain`, because those two are exactly what that strategy holds.
//   - anything else: left alone, with a reason. `classical` has no compact
//     representation, so a set with a keyword, an address or a logical rule
//     stays source and pays the parse. Saying so is the point — the cost is
//     then visible instead of silently absent.
func CompileRuleProvider(sourcePath, behavior, format, outputPath string) (*RuleProviderCompileResult, error) {
	// Both paths are checked even though today's only caller passes container
	// paths it built itself: this is an exported gomobile entry, and an export
	// with no containment check is one caller away from being an
	// arbitrary-read/write primitive. The write goes through
	// writeRuntimeProviderFile for the same reason -- os.WriteFile follows a
	// symlink planted at the destination and leaves a truncated file behind on
	// failure.
	home := C.Path.HomeDir()
	if !providerSourceContained(sourcePath, home) {
		return nil, bridgeSafeError(errors.New("hako: rule provider source is outside this app's container"))
	}
	if !providerSourceContained(outputPath, home) {
		return nil, bridgeSafeError(errors.New("hako: compiled rule provider destination is outside this app's container"))
	}
	source, err := readBoundedRegularFile(sourcePath, int64(maximumProviderResourceBytes), "rule provider")
	if err != nil {
		return nil, bridgeSafeError(fmt.Errorf("hako: read rule provider: %w", err))
	}
	result := compileRuleProviderPayload(source, behavior, format)
	if result.Reason != "" {
		return &RuleProviderCompileResult{Reason: result.Reason}, nil
	}
	if err := writeRuntimeProviderFile(outputPath, result.artifact); err != nil {
		return nil, bridgeSafeError(fmt.Errorf("hako: write compiled rule provider: %w", err))
	}
	return &RuleProviderCompileResult{
		Compiled: true,
		Behavior: result.Behavior,
		Rules:    result.Rules,
	}, nil
}

// ruleProviderCompilation is the bytes-level answer: what staging consumes
// directly, with the artifact still in memory. Reason is exclusive with the
// rest, and it is the reader-facing sentence the manifest will carry.
type ruleProviderCompilation struct {
	artifact []byte
	Behavior string
	Rules    int
	Reason   string
}

func compileRuleProviderPayload(source []byte, behavior, format string) ruleProviderCompilation {
	normalizedFormat := strings.ToLower(strings.TrimSpace(format))
	if normalizedFormat == "mrs" {
		return ruleProviderCompilation{Reason: "already compiled"}
	}

	targetBehavior := strings.ToLower(strings.TrimSpace(behavior))
	payload := source
	switch targetBehavior {
	case "domain", "ipcidr":
	case "classical":
		domains, reason := domainsFromClassical(source)
		if reason != "" {
			return ruleProviderCompilation{Reason: reason}
		}
		payload = []byte(strings.Join(domains, "\n") + "\n")
		targetBehavior = "domain"
		normalizedFormat = "text"
	default:
		return ruleProviderCompilation{Reason: fmt.Sprintf("unknown behavior %q", behavior)}
	}

	parsedBehavior, err := ruleBehavior(targetBehavior)
	if err != nil {
		return ruleProviderCompilation{Reason: err.Error()}
	}
	parsedFormat, err := ruleFormat(normalizedFormat)
	if err != nil {
		return ruleProviderCompilation{Reason: err.Error()}
	}

	var compiled bytes.Buffer
	if err := provider.ConvertToMrs(
		payload, parsedBehavior, parsedFormat, &compiled,
	); err != nil {
		// A set the converter refuses is one this core cannot compile; the
		// profile still runs on the source, so this is a reason, not a fault.
		return ruleProviderCompilation{Reason: fmt.Sprintf("cannot compile: %v", err)}
	}

	count, err := ProviderEntryCountForIOS("rule", targetBehavior, "mrs", compiled.Bytes())
	if err != nil {
		// Written but unreadable is worse than not written: the caller would
		// point the provider at an artifact the core refuses at startup.
		return ruleProviderCompilation{Reason: fmt.Sprintf("artifact unreadable: %v", err)}
	}

	return ruleProviderCompilation{
		artifact: compiled.Bytes(),
		Behavior: targetBehavior,
		Rules:    count,
	}
}

// domainsFromClassicalReason answers only the refusal, for callers that want to
// know whether a set compiles without building anything from it.
func domainsFromClassicalReason(source []byte) (int, string) {
	return classicalDomainScan(source, nil)
}

// domainsFromClassical reads a classical list and answers with the domain
// lines it holds, or with the first rule kind that cannot be one.
//
// DOMAIN and DOMAIN-SUFFIX are what the domain strategy stores — a suffix is
// its `+.` form. Everything else in the classical vocabulary (keywords,
// addresses, ports, processes, logical rules) has no place in it, and a set
// holding one of them keeps its own behavior.
func domainsFromClassical(source []byte) ([]string, string) {
	var domains []string
	if _, reason := classicalDomainScan(source, func(domain string) {
		domains = append(domains, domain)
	}); reason != "" {
		return nil, reason
	}
	return domains, ""
}

// classicalDomainScan is the one scanner both the compiler and the cheap
// refusal judgement run, so the two can never drift: it streams the classical
// list, hands each storable domain to emit (nil to only judge), and answers
// how many it saw plus the refusal reason, "" when the set compiles.
func classicalDomainScan(source []byte, emit func(string)) (int, string) {
	count := 0
	for index, raw := range strings.Split(string(source), "\n") {
		lineNumber := index + 1
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		// A payload list may arrive as YAML sequence items.
		line = strings.TrimSpace(strings.TrimPrefix(line, "- "))
		line = strings.Trim(line, `'"`)
		if line == "" {
			continue
		}
		// A YAML rule set is `payload:` followed by sequence items, and may
		// open with a document marker. Neither is a rule; refusing on them
		// declared every real-world YAML classical set uncompilable.
		if line == "payload:" || line == "---" {
			continue
		}
		// An inline comment is not part of the rule. mihomo's YAML parser strips
		// these; a scanner that keeps them compiles the comment into the domain
		// and the real one silently stops matching.
		if i := strings.Index(line, " #"); i >= 0 {
			line = strings.TrimSpace(line[:i])
			if line == "" {
				continue
			}
		}
		kind, value, found := strings.Cut(line, ",")
		if !found {
			// Never the line's bytes. A provider path is subscription-authored
			// and this reason travels into the manifest and the product log, so
			// echoing content turns a mis-pointed path into a working read
			// oracle -- the same rule provider_resource.go states for the
			// sibling path ("record only the index, never the entry text").
			// The position and length are what a reader needs to find it.
			return count, fmt.Sprintf("line %d is not a classical rule (%d bytes)", lineNumber, len(line))
		}
		kind = strings.ToUpper(strings.TrimSpace(kind))
		value = strings.TrimSpace(value)
		// A trailing policy or no-resolve is not part of the domain.
		if cut := strings.Index(value, ","); cut >= 0 {
			value = strings.TrimSpace(value[:cut])
		}
		switch kind {
		case "DOMAIN":
			if emit != nil {
				emit(value)
			}
			count++
		case "DOMAIN-SUFFIX":
			if emit != nil {
				emit("+." + value)
			}
			count++
		default:
			return count, fmt.Sprintf(
				"holds %s, which the domain strategy cannot store", kind,
			)
		}
	}
	if count == 0 {
		return 0, "no domain rules"
	}
	return count, ""
}

func ruleBehavior(name string) (P.RuleBehavior, error) {
	switch name {
	case "domain":
		return P.Domain, nil
	case "ipcidr":
		return P.IPCIDR, nil
	case "classical":
		return P.Classical, nil
	default:
		return P.Domain, fmt.Errorf("unknown behavior %q", name)
	}
}

func ruleFormat(name string) (P.RuleFormat, error) {
	switch name {
	case "", "yaml":
		return P.YamlRule, nil
	case "text":
		return P.TextRule, nil
	case "mrs":
		return P.MrsRule, nil
	default:
		return P.YamlRule, fmt.Errorf("unknown format %q", name)
	}
}
