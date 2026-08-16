package hako

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/TokenPLS/Hako/adapter"
	proxyprovider "github.com/TokenPLS/Hako/adapter/provider"
	"github.com/TokenPLS/Hako/common/convert"
	"github.com/TokenPLS/Hako/component/age"
	P "github.com/TokenPLS/Hako/constant/provider"
	rules "github.com/TokenPLS/Hako/rules"
	rulecommon "github.com/TokenPLS/Hako/rules/common"
	ruleprovider "github.com/TokenPLS/Hako/rules/provider"
	"gopkg.in/yaml.v3"
)

const maximumProviderResourceBytes = 16 * 1024 * 1024

// DecryptAgeForIOS uses mihomo's pinned age implementation without installing
// a process-global key. The caller owns key retrieval and plaintext lifetime.
func DecryptAgeForIOS(payload []byte, secretKey string) ([]byte, error) {
	if len(payload) == 0 || len(payload) > maximumProviderResourceBytes {
		return nil, fmt.Errorf("hako: encrypted provider size is invalid")
	}
	if len(secretKey) == 0 || len(secretKey) > 64*1024 {
		return nil, fmt.Errorf("hako: age secret key size is invalid")
	}
	if !bytes.HasPrefix(payload, []byte(age.FileHeader)) {
		return nil, fmt.Errorf("hako: provider is not age armored")
	}
	if err := age.VeritySecretKeys(secretKey); err != nil {
		return nil, fmt.Errorf("hako: invalid age secret key: %w", err)
	}
	plaintext, err := age.DecryptBytes(payload, secretKey)
	if err != nil {
		return nil, fmt.Errorf("hako: decrypt age provider: %w", err)
	}
	if len(plaintext) == 0 || len(plaintext) > maximumProviderResourceBytes {
		return nil, fmt.Errorf("hako: decrypted provider size is invalid")
	}
	return plaintext, nil
}

// ValidateProviderForIOS opens the exact payload shape the Core will consume
// after the immutable revision is published. This keeps malformed remote
// resources from passing config-only preflight and failing at service start.
func ValidateProviderForIOS(kind, behavior, format string, payload []byte) error {
	if len(payload) == 0 || len(payload) > maximumProviderResourceBytes {
		return fmt.Errorf("hako: provider payload size is invalid")
	}
	if bytes.HasPrefix(payload, []byte(age.FileHeader)) {
		return fmt.Errorf("hako: encrypted provider was not decrypted")
	}
	switch kind {
	case "rule":
		parsedBehavior, err := P.ParseBehavior(behavior)
		if err != nil {
			return fmt.Errorf("hako: provider behavior: %w", err)
		}
		parsedFormat, err := P.ParseRuleFormat(format)
		if err != nil {
			return fmt.Errorf("hako: provider format: %w", err)
		}
		if parsedFormat == P.MrsRule {
			if err := validateMRSForIOS(payload, parsedBehavior); err != nil {
				return fmt.Errorf("hako: validate rule provider: %w", err)
			}
			return nil
		}
		if parsedBehavior == P.Classical && parsedFormat != P.MrsRule {
			if err := validateClassicalProvider(payload, parsedFormat); err != nil {
				return err
			}
			return nil
		}
		if err := ruleprovider.ConvertToMrs(payload, parsedBehavior, parsedFormat, io.Discard); err != nil {
			if isUpstreamEmptyRuleError(err) {
				return nil
			}
			return fmt.Errorf("hako: validate rule provider: %w", err)
		}
		return nil
	case "proxy":
		// The standalone client pre-fetch check parses every node so the App can
		// reject a malformed subscription. Runtime staging instead defers
		// parseability (and the provider filter that scopes it) to mihomo.
		_, _, err := sanitizeProxyProviderPayloadForIOS(format, payload, true)
		return err
	default:
		return fmt.Errorf("hako: unknown provider kind %q", kind)
	}
}

// upstreamEmptyRuleMessage is what ConvertToMrs returns for a rule set that
// parsed cleanly but holds nothing (rules/provider/mrs_converter.go:21-23). It is
// an inline errors.New with no sentinel, so matching the text is the only hook;
// TestUpstreamEmptyRuleErrorTextIsUnchanged fails loudly if an upstream bump
// rewords it.
const upstreamEmptyRuleMessage = "empty rule"

// isUpstreamEmptyRuleError separates "this payload holds no rules" from "this
// payload is broken".
//
// domain and ipcidr providers are validated by running them through
// ConvertToMrs, which is a WRITER and refuses to serialise an empty set. The
// loader a running config uses has no such rule: rulesParse hands back a
// zero-rule strategy and mihomo starts. Treating the writer's precondition as a
// read-time verdict made an empty domain list a config that would not launch on
// iOS while it launched everywhere else -- the same defect already fixed for
// classical, on the behaviour that sees it more often.
func isUpstreamEmptyRuleError(err error) bool {
	return err != nil && err.Error() == upstreamEmptyRuleMessage
}

// ProviderEntryCountForIOS returns the entry count for a payload the iOS provider
// pipeline can consume. Counting shares the parser used by validation, so a
// payload that cannot be parsed produces an error rather than a number.
//
// What it does NOT promise, since the docstring used to and no longer can: for
// `format: mrs` the number is the file's own header field, returned verbatim and
// unbounded, because upstream treats that field the same way (it reaches Count()
// and nothing else). A corrupt MRS can therefore report a negative or absurd
// tally.
//
// The docstring used to justify that by tracing the consumers ("ProviderMaterializer stores
// it, ProvidersView renders it into a status string"). Those consumers do not exist: the
// consuming lane swept the whole export surface on 2026-08-09 and found zero references to
// this function or to providerEntryCount anywhere in apple/. The reasoning was sound and the
// premise was invented, which is the worse of the two failures -- a reader would have trusted
// the tolerance conclusion because the chain looked traced.
//
// What can be said without inventing anything: nothing in this repository consumes the
// return value, so no allocation is sized from it today. If a caller ever does size something
// from it, bound it there -- this function returns the file's own claim, not a measurement.
func ProviderEntryCountForIOS(kind, behavior, format string, payload []byte) (int, error) {
	if len(payload) == 0 || len(payload) > maximumProviderResourceBytes {
		return 0, fmt.Errorf("hako: provider payload size is invalid")
	}
	if bytes.HasPrefix(payload, []byte(age.FileHeader)) {
		return 0, fmt.Errorf("hako: encrypted provider was not decrypted")
	}
	switch kind {
	case "rule":
		parsedBehavior, err := P.ParseBehavior(behavior)
		if err != nil {
			return 0, fmt.Errorf("hako: provider behavior: %w", err)
		}
		parsedFormat, err := P.ParseRuleFormat(format)
		if err != nil {
			return 0, fmt.Errorf("hako: provider format: %w", err)
		}
		if parsedFormat == P.MrsRule {
			return inspectMRSForIOS(payload, parsedBehavior)
		}
		if parsedBehavior == P.Classical {
			_, count, _, err := sanitizeClassicalProviderPayloadForIOS(payload, parsedFormat)
			if err != nil {
				return 0, err
			}
			return count, nil
		}
		var encoded bytes.Buffer
		if err := ruleprovider.ConvertToMrs(payload, parsedBehavior, parsedFormat, &encoded); err != nil {
			if isUpstreamEmptyRuleError(err) {
				return 0, nil
			}
			return 0, fmt.Errorf("hako: count rule provider: %w", err)
		}
		return inspectMRSForIOS(encoded.Bytes(), parsedBehavior)
	case "proxy":
		if err := ValidateProviderForIOS(kind, behavior, format, payload); err != nil {
			return 0, err
		}
		var document proxyprovider.ProxySchema
		if err := yaml.Unmarshal(payload, &document); err != nil {
			proxies, convertErr := convert.ConvertsV2Ray(payload)
			if convertErr != nil {
				return 0, fmt.Errorf("hako: count proxy provider: %w", convertErr)
			}
			document.Proxies = proxies
		}
		return len(document.Proxies), nil
	default:
		return 0, fmt.Errorf("hako: unknown provider kind %q", kind)
	}
}

func parseAndCloseProviderOutbound(mapping map[string]any, parse func(map[string]any) (io.Closer, error)) error {
	outbound, err := parse(mapping)
	if err != nil {
		return err
	}
	if outbound == nil {
		return fmt.Errorf("parsed outbound is nil")
	}
	if err := outbound.Close(); err != nil {
		return fmt.Errorf("close parsed outbound: %w", err)
	}
	return nil
}

func validateClassicalProvider(payload []byte, format P.RuleFormat) error {
	_, _, _, err := sanitizeClassicalProviderPayloadForIOS(payload, format)
	return err
}

// providerNoopReason distinguishes why a classical rule-provider entry was
// dropped from the private runtime copy so the diagnostic log line is accurate.
type providerNoopReason int

const (
	// providerNoopMetadataUnavailable marks a PROCESS/UID/IN-USER metadata rule
	// the Network Extension cannot evaluate (stripped; it would match nothing).
	providerNoopMetadataUnavailable providerNoopReason = iota
	// providerNoopRuleUnsupported marks an entry this pinned core cannot parse or
	// does not support (e.g. a newer rule keyword). It is skipped to match
	// upstream classicalStrategy.Insert's warn-and-continue rather than failing
	// the whole provider.
	providerNoopRuleUnsupported
)

type providerMetadataNoop struct {
	kind   string
	index  int
	reason providerNoopReason
}

type providerEgressNoop struct {
	field string
	index int
}

// sanitizeProxyProviderPayloadForIOS produces the private runtime bytes Hako may
// hand mihomo. The mandatory Network-Extension guards -- the egress-override strip
// (interface-name, routing-mark, ...) and the unsafe-runtime-option / embedded-DNS
// rejection -- always run over EVERY node, because mihomo, not Hako, decides which
// nodes a provider's filter keeps, so any node left in the copy could become the
// live node and must already be egress-safe.
//
// parseNodes decides who owns parseability. The standalone client pre-fetch check
// (ValidateProviderForIOS) passes true and parses every node so the App can reject a
// malformed subscription. Runtime staging passes false: it does NOT parse nodes,
// deferring to mihomo, which applies the provider's filter BEFORE adapter.ParseProxy
// and treats a parse failure as non-fatal (hub/executor loadProvider logs it and
// keeps running). That is how a node this pinned core cannot parse stops failing the
// whole provider when the filter excludes it -- upstream's own filter-before-parse,
// not a second filter decode inside Hako. Hako must NOT re-decode the filter to
// discover survivors itself: its decode is independent of mihomo's, and a
// pathological config (case-variant duplicate filter keys resolved by the structure
// decoder's nondeterministic case-insensitive fallback) could make the two disagree
// and strand the provider empty or falsely reject a valid config.
func sanitizeProxyProviderPayloadForIOS(format string, payload []byte, parseNodes bool) ([]byte, []providerEgressNoop, error) {
	if format != "" && format != "yaml" {
		return nil, nil, fmt.Errorf("hako: proxy provider format %q is unsupported", format)
	}
	var document proxyprovider.ProxySchema
	if err := yaml.Unmarshal(payload, &document); err != nil {
		proxies, convertErr := convert.ConvertsV2Ray(payload)
		if convertErr != nil {
			return nil, nil, fmt.Errorf("hako: parse proxy provider: %w; convert share links: %v", err, convertErr)
		}
		document.Proxies = proxies
	}
	if len(document.Proxies) == 0 {
		return nil, nil, fmt.Errorf("hako: proxy provider payload is empty")
	}
	stripped := make([]providerEgressNoop, 0, 2)
	seenFields := make(map[string]struct{})
	for index, proxy := range document.Proxies {
		if field, reason := unsafeOutboundRuntimeOption(proxy); field != "" {
			return nil, nil, fmt.Errorf("hako: proxy provider item %d %s: %s", index, field, reason)
		}
		if outboundEmbeddedDNSHasFragment(proxy) {
			return nil, nil, fmt.Errorf("hako: proxy provider item %d uses an ignored L3 outbound nested DNS fragment", index)
		}
		for _, field := range outboundEgressOverrideFields(proxy) {
			delete(proxy, field)
			if _, seen := seenFields[field]; !seen {
				seenFields[field] = struct{}{}
				stripped = append(stripped, providerEgressNoop{field: field, index: index})
			}
		}
		if !parseNodes {
			// Runtime staging leaves parseability (and the filter that scopes it) to
			// mihomo. A filtered-out node this core cannot parse is never reached by
			// mihomo's filter-before-parse, and a filter-passing parse error is
			// non-fatal at load.
			continue
		}
		name, _ := proxy["name"].(string)
		typeName, _ := proxy["type"].(string)
		if strings.TrimSpace(name) == "" || strings.TrimSpace(typeName) == "" {
			return nil, nil, fmt.Errorf("hako: proxy provider item %d lacks name or type", index)
		}
		if err := parseAndCloseProviderOutbound(proxy, func(mapping map[string]any) (io.Closer, error) {
			return adapter.ParseProxy(mapping)
		}); err != nil {
			return nil, nil, fmt.Errorf("hako: proxy provider item %d: %w", index, err)
		}
	}
	if len(stripped) == 0 {
		return payload, nil, nil
	}
	sanitized, err := yaml.Marshal(document)
	if err != nil {
		return nil, nil, fmt.Errorf("hako: encode proxy provider: %w", err)
	}
	return sanitized, stripped, nil
}

// sanitizeClassicalProviderPayloadForIOS returns the exact private runtime
// bytes Hako may give mihomo. Metadata rules have no Apple packet-tunnel input,
// so removing the entire rule is the only faithful no-op: all executable rules
// retain their relative order and provider matching falls through normally.
// The caller owns the returned bytes; the published provider is never changed.
// stageClassicalProviderPayloadForApple removes only what this profile cannot
// evaluate, and asks nothing else of the bytes.
//
// The platform-required part is a prefix test: PROCESS/UID/SOURCE-APP rules
// have no input inside an Apple packet tunnel, so a rule naming one matches
// nothing and removing it is the only faithful no-op. That is cheap.
//
// What used to sit beside it was not. Every entry was handed to rules.ParseRule
// -- built into a rule to discover whether it would build, then discarded --
// and the ones that failed were removed from the staged copy. Upstream does the
// same work again at load and reaches the same verdict: classicalStrategy.Insert
// (rules/provider/classical_strategy.go:41) warns and continues on exactly
// these entries, keeping the rest. So the removal changed nothing a reader can
// observe -- a skipped rule and an absent rule both match nothing -- while
// costing 253ms of a 413ms staging pass across twenty-one rule sets on a
// 2026-08-05 device trace, the single largest item in it.
//
// Counting keeps the expensive answer, in sanitizeClassicalProviderPayloadForApple
// below, because the figure the App shows at import has to mean rules that will
// actually run.
func stageClassicalProviderPayloadForApple(
	payload []byte, format P.RuleFormat, capability appleProcessMetadataCapability,
) ([]byte, []providerMetadataNoop, error) {
	entries, err := classicalProviderEntries(payload, format)
	if err != nil {
		return nil, nil, err
	}
	kept := make([]string, 0, len(entries))
	stripped := make([]providerMetadataNoop, 0)
	seenKinds := make(map[string]struct{})
	for index, entry := range entries {
		if kind := unavailableMetadataRuleKind(entry, capability); kind != "" {
			if _, seen := seenKinds[kind]; !seen {
				stripped = append(stripped, providerMetadataNoop{
					kind: kind, index: index, reason: providerNoopMetadataUnavailable,
				})
				seenKinds[kind] = struct{}{}
			}
			continue
		}
		kept = append(kept, entry)
	}
	if len(stripped) == 0 {
		// The exact original bytes, so the staged copy stays a hard link to the
		// published revision instead of a second copy of every rule set.
		return payload, nil, nil
	}
	sanitized, err := encodeClassicalProviderEntriesForIOS(kept, format)
	if err != nil {
		return nil, nil, err
	}
	return sanitized, stripped, nil
}

func sanitizeClassicalProviderPayloadForIOS(payload []byte, format P.RuleFormat) ([]byte, int, []providerMetadataNoop, error) {
	return sanitizeClassicalProviderPayloadForApple(payload, format, appleProcessMetadataCapability{})
}

// sanitizeClassicalProviderPayloadForApple is the profile-aware form. A profile
// that trusts process metadata (the macOS Transparent Proxy, which does receive
// process identity) KEEPS PROCESS/UID/IN-USER rules instead of stripping them,
// but an entry this pinned core cannot parse or support is still skipped rather
// than failing the whole provider -- upstream classicalStrategy.Insert
// warn-and-continue, matching the Network-Extension path.
func sanitizeClassicalProviderPayloadForApple(payload []byte, format P.RuleFormat, capability appleProcessMetadataCapability) ([]byte, int, []providerMetadataNoop, error) {
	entries, err := classicalProviderEntries(payload, format)
	if err != nil {
		return nil, 0, nil, err
	}
	kept := make([]string, 0, len(entries))
	stripped := make([]providerMetadataNoop, 0)
	seenKinds := make(map[string]struct{})
	for index, entry := range entries {
		if kind := unavailableMetadataRuleKind(entry, capability); kind != "" {
			if _, seen := seenKinds[kind]; !seen {
				stripped = append(stripped, providerMetadataNoop{kind: kind, index: index, reason: providerNoopMetadataUnavailable})
				seenKinds[kind] = struct{}{}
			}
			continue
		}
		if err := validateClassicalEntryForApple(entry, index, capability); err != nil {
			// Upstream classicalStrategy.Insert warn-skips an entry it cannot parse
			// or support and keeps the rest. Failing the whole provider here would
			// refuse the entire subscription (and block the config from starting)
			// over one stale or malformed line, so drop just this entry and go on.
			// Record only the index -- never the entry text, which for a malformed
			// rule can be a bare domain (privacy) or carry control characters (log
			// injection).
			stripped = append(stripped, providerMetadataNoop{index: index, reason: providerNoopRuleUnsupported})
			continue
		}
		kept = append(kept, entry)
	}
	if len(stripped) == 0 {
		return payload, len(kept), nil, nil
	}
	sanitized, err := encodeClassicalProviderEntriesForIOS(kept, format)
	if err != nil {
		return nil, 0, nil, err
	}
	return sanitized, len(kept), stripped, nil
}

func encodeClassicalProviderEntriesForIOS(entries []string, format P.RuleFormat) ([]byte, error) {
	switch format {
	case P.YamlRule:
		encoded, err := yaml.Marshal(struct {
			Payload []string `yaml:"payload"`
		}{Payload: entries})
		if err != nil {
			return nil, fmt.Errorf("hako: encode classical provider: %w", err)
		}
		return encoded, nil
	case P.TextRule:
		if len(entries) == 0 {
			return []byte("# all Apple-unavailable metadata rules were stripped\n"), nil
		}
		return []byte(strings.Join(entries, "\n") + "\n"), nil
	default:
		return nil, fmt.Errorf("hako: classical provider does not support this format")
	}
}

// classicalPayloadHeadPresent mirrors the one condition under which upstream's
// parser refuses a classical body outright.
//
// `rulesParse` walks the buffer looking for a newline; when it reaches a final
// chunk that has none, it returns ErrNoPayload if it has not yet found a
// `payload:`/`rules:` head (rules/provider/provider.go:186-199). So the error is
// reachable only for a buffer that does NOT end in a newline -- `payload:\n`
// and `payload: []\n` both parse fine and simply yield zero rules, while bare
// `payload:` does not parse at all.
//
// Written as that condition rather than as "does the document contain the key",
// because the naive form rejects `payload: []\n`, which upstream accepts.
func classicalPayloadHeadPresent(payload []byte) bool {
	if bytes.HasSuffix(payload, []byte("\n")) {
		return true
	}
	lastNewline := bytes.LastIndexByte(payload, '\n')
	if lastNewline < 0 {
		return false
	}
	var probe map[string]any
	if err := yaml.Unmarshal(payload[:lastNewline+1], &probe); err != nil {
		return false
	}
	_, hasPayload := probe["payload"]
	_, hasRules := probe["rules"]
	return hasPayload || hasRules
}

func classicalProviderEntries(payload []byte, format P.RuleFormat) ([]string, error) {
	var entries []string
	switch format {
	case P.YamlRule:
		// Both spellings, because upstream's own RulePayload carries both
		// (rules/provider/provider.go:26-33) and its parser feeds whichever is
		// present to the strategy. Reading only `payload:` made a `rules:`-keyed
		// provider look empty: with the empty-payload rejection in place that was a
		// loud refusal, and without it the metadata strip below silently ran over
		// nothing and returned the caller's bytes unchanged.
		var document struct {
			Payload []string `yaml:"payload"`
			Rules   []string `yaml:"rules"`
		}
		if err := yaml.Unmarshal(payload, &document); err != nil {
			return nil, fmt.Errorf("hako: parse classical provider: %w", err)
		}
		entries = append(append([]string(nil), document.Payload...), document.Rules...)
		// Upstream distinguishes "the list is empty" from "there is no list".
		// `rulesParse` finds the head by scanning LINES, so a buffer whose last
		// chunk has no trailing newline never registers one and it returns
		// ErrNoPayload (rules/provider/provider.go:186-199): `payload:\n` parses to
		// zero rules, bare `payload:` does not parse at all. Preflight has to make
		// the same distinction -- exists so a provider error surfaces here
		// rather than after the active revision pointer has flipped -- so a body
		// carrying neither key is refused while an empty list is not.
		if entries == nil && !classicalPayloadHeadPresent(payload) {
			return nil, fmt.Errorf(
				"hako: classical provider has no payload or rules field")
		}
	case P.TextRule:
		scanner := bufio.NewScanner(bytes.NewReader(payload))
		for scanner.Scan() {
			entry := strings.TrimSpace(scanner.Text())
			if entry != "" && !strings.HasPrefix(entry, "#") {
				entries = append(entries, entry)
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("hako: scan classical provider: %w", err)
		}
	default:
		return nil, fmt.Errorf("hako: classical provider does not support this format")
	}
	// No empty-payload rejection. Upstream's parser
	// (rules/provider/provider.go:175-266) skips blank and comment lines and then
	// falls out of its loop into `strategy.FinishInsert(); return strategy, nil`,
	// so a provider with a `payload:` head and nothing under it is a provider with
	// zero rules -- it matches nothing and the configuration runs. Refusing it
	// here stopped the whole configuration from starting on iOS over a list that
	// happened to be empty this week, which providers legitimately are: a category
	// cleared upstream, a file not filled in yet, a subscription returning nothing
	// for one list. The encoder below already handles the empty case for both
	// formats, so nothing downstream needed the guarantee either.
	return entries, nil
}

func validateClassicalEntriesForIOS(entries []string) error {
	for index, entry := range entries {
		if err := validateClassicalEntryForIOS(entry, index); err != nil {
			return err
		}
	}
	return nil
}

func validateClassicalEntryForIOS(entry string, index int) error {
	return validateClassicalEntryForApple(entry, index, appleProcessMetadataCapability{})
}

func validateClassicalEntryForApple(entry string, index int, capability appleProcessMetadataCapability) error {
	tp, rulePayload, target, params := rulecommon.ParseRulePayload(entry, false)
	{
		kind := unavailableMetadataRuleKind(entry, capability)
		if kind == "" && isUnavailableMetadataRuleType(tp, capability) {
			kind = strings.ToUpper(strings.TrimSpace(tp))
		}
		if kind != "" {
			return fmt.Errorf("hako: classical provider item %d uses metadata rule %s, which this profile cannot resolve", index, kind)
		}
	}
	switch tp {
	case "MATCH", "RULE-SET", "SUB-RULE":
		return fmt.Errorf("hako: classical provider item %d uses unsupported type %s", index, tp)
	}
	if _, err := rules.ParseRule(tp, rulePayload, target, params, nil); err != nil {
		return fmt.Errorf("hako: classical provider item %d: %w", index, err)
	}
	return nil
}

// InspectProviderForIOS answers both questions the App asks about a payload —
// can the core read it, and how many entries does it hold — from one parse.
//
// They used to be two entry points and two parses of the same bytes. For a text
// rule set that means running the whole conversion twice, measured at 76 ms and
// a 55.3 MiB peak for a 111,803-line list, and a reader's profile carried 53
// providers. Switching profiles paid for all of it twice over.
//
// A payload that cannot be read has no count, so the pair collapses cleanly: an
// error here is the same error validation used to report, and callers keep
// treating a rule set they cannot read as a warning and a proxy set as fatal.
func InspectProviderForIOS(kind, behavior, format string, payload []byte) (int, error) {
	count, err := ProviderEntryCountForIOS(kind, behavior, format, payload)
	if err == nil {
		return count, nil
	}
	// Both entry points reached the same parse — validateMRSForIOS and
	// validateClassicalProvider are one-line wrappers over the functions the
	// count uses — so the only thing lost by dropping one call is the sentence
	// the reader was shown. Keep that sentence: it is what appears in the log
	// beside "cannot be read by this core".
	message := err.Error()
	switch {
	case strings.HasPrefix(message, "hako: count rule provider: "):
		return 0, fmt.Errorf("hako: validate rule provider: %s",
			strings.TrimPrefix(message, "hako: count rule provider: "))
	case kind == "rule" && !strings.HasPrefix(message, "hako: "):
		return 0, fmt.Errorf("hako: validate rule provider: %w", err)
	}
	return 0, err
}

// ConvertProxiesForIOS turns share links or a base64 v2ray subscription body
// into a mihomo `proxies:` document.
//
// The core has always been able to read this shape — a proxy provider whose
// payload is share links is converted at load time (see convertProxies above).
// What the client could not do was see the result: the only exported surface
// returned a count, so a pasted link could be stored but never shown or
// edited. This hands back the parsed proxies so the node editor can be filled
// in and the reader can correct it before anything is saved.
func ConvertProxiesForIOS(payload []byte) (*StringBox, error) {
	if len(payload) == 0 || len(payload) > maximumProviderResourceBytes {
		return nil, fmt.Errorf("hako: proxy payload size is invalid")
	}
	proxies, err := convert.ConvertsV2Ray(payload)
	if err != nil {
		return nil, fmt.Errorf("hako: convert proxies: %w", err)
	}
	if len(proxies) == 0 {
		return nil, fmt.Errorf("hako: no proxies in payload")
	}
	encoded, err := yaml.Marshal(map[string]any{"proxies": proxies})
	if err != nil {
		return nil, fmt.Errorf("hako: encode proxies: %w", err)
	}
	return WrapString(string(encoded)), nil
}
