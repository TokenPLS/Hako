package hako

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/TokenPLS/Hako/config"
	"github.com/TokenPLS/Hako/dns"
)

const resourcePlanSchemaVersion = 4

type planProvider struct {
	Name                  string              `json:"name"`
	Kind                  string              `json:"kind"` // "proxy" | "rule"
	ResourceKey           string              `json:"resourceKey"`
	Behavior              string              `json:"behavior"`
	Type                  string              `json:"type"`
	URL                   string              `json:"url"`
	Path                  string              `json:"path"`
	Format                string              `json:"format"`
	Headers               map[string][]string `json:"headers"`
	Proxy                 string              `json:"proxy"`
	MaximumBytes          int64               `json:"maximumBytes"`
	UpdateIntervalSeconds int64               `json:"updateIntervalSeconds"`
}
type planGeo struct {
	Kind         string `json:"kind"`
	URL          string `json:"url"`
	Format       string `json:"format"`
	Path         string `json:"path"`
	MaximumBytes int64  `json:"maximumBytes"`
}
type planError struct {
	Field  string `json:"field"`
	Reason string `json:"reason"`
}
type planResources struct {
	SchemaVersion int            `json:"schemaVersion"`
	Providers     []planProvider `json:"providers"`
	Geodata       []planGeo      `json:"geodata"`
	Notices       []string       `json:"notices"`
	Errors        []planError    `json:"errors"`
}

var unsupportedTunIntentKeys = []string{
	"auto-redirect", "auto-redirect-input-mark", "auto-redirect-output-mark",
	"auto-redirect-iproute2-fallback-rule-index",
	"include-interface", "exclude-interface",
	"include-uid", "exclude-uid", "include-uid-range", "exclude-uid-range",
	"include-android-user", "include-package", "exclude-package",
	"include-mac-address", "exclude-mac-address",
	"exclude-src-port", "exclude-dst-port", "exclude-src-port-range", "exclude-dst-port-range",
	"iproute2-table-index", "iproute2-rule-index",
}

// PlanResourcesForIOS keeps its signature and its result schema: three
// notice-only UI callers depend on both (ProfilesView:2139/:2579,
// ProfileCenterView:773). It is now a thin wrapper so the parse it performs is
// the same one a full activation reuses for projections.
func PlanResourcesForIOS(mergedYAML string) (*StringBox, error) {
	doc, err := NewConfigDocument(mergedYAML)
	if err != nil {
		return nil, err
	}
	defer doc.Close()
	return doc.PlanResourcesJSON()
}

// PlanResourcesJSON is the existing plan logic reading the handle's views.
// The projection is deliberately NOT part of this result: the plan result has
// a 16 MiB ceiling (validateConfigurationJSONResult below), and a projection
// pushing a legal plan past it would turn "slower" into "activation fails";
// ask ProjectionJSON on the same handle instead.
func (d *ConfigDocument) PlanResourcesJSON() (*StringBox, error) {
	views, err := d.snapshot()
	if err != nil {
		return nil, err
	}
	root := views.root
	raw := views.raw
	res := planResources{
		SchemaVersion: resourcePlanSchemaVersion,
		Providers:     []planProvider{},
		Geodata:       []planGeo{},
		Notices:       []string{},
		Errors:        []planError{},
	}

	// providers
	proxyProviders, proxyErrors, proxyNotices := httpProviders(root, "proxy-providers", "proxy")
	ruleProviders, ruleErrors, ruleNotices := httpProviders(root, "rule-providers", "rule")
	res.Notices = append(res.Notices, proxyNotices...)
	res.Notices = append(res.Notices, ruleNotices...)
	res.Providers = append(res.Providers, proxyProviders...)
	res.Providers = append(res.Providers, ruleProviders...)
	res.Errors = append(res.Errors, proxyErrors...)
	res.Errors = append(res.Errors, ruleErrors...)

	// Geodata is planned from typed RawConfig so mihomo defaults and
	// geodata-mode select the same URL/format/path that ParseRawConfig will
	// consume. Guessing from a URL extension is incorrect: geodata-mode=false
	// requires the MMDB URL and geoip.metadb, not GeoIP.dat.
	geodata, geoErrors := planGeodata(raw)
	res.Geodata = append(res.Geodata, geodata...)
	res.Errors = append(res.Errors, geoErrors...)

	// Host-route filters that rely on Linux/Android host metadata have no
	// consumer in an Apple packet tunnel, but they never change which proxy
	// handles a flow, so normalizeRawNetworkExtensionSurfaces strips them
	// (tolerate + strip) and the config still starts. The plan surfaces them as
	// NOTICES so the containing app knows they were dropped, rather than failing
	// the config. route-address-set is different — it decides which traffic
	// enters the tunnel and must be materialized to prefixes app-side, so it
	// stays a hard plan error (routeSetErrors).
	if tun, ok := root["tun"].(map[string]any); ok {
		res.Errors = append(res.Errors, routeSetErrors(root, tun)...)
	}
	res.Notices = append(res.Notices, strippedHostRouteKnobNotices(root, raw)...)
	res.Notices = append(res.Notices, strippedDNSSchemeNotices(root)...)
	// Detection only: detectUnroutableDNSFragments is pure by its own contract
	// ("Detection only, NEVER mutation"), and the other helpers on this path
	// were swept for writes when the body moved onto the shared handle -- the
	// handle's views must stay pristine for projections served after this call.
	// (An older comment here claimed the raw was deliberately mutated; that
	// stopped being true when fragment stripping became fail-closed detection.)
	res.Notices = append(res.Notices, strippedDNSFragmentNotices(raw)...)
	for _, loc := range outboundEgressOverrideLocations(raw) {
		res.Notices = append(res.Notices, loc+": outbound egress override has no iOS equivalent and is stripped (Apple owns physical egress)")
	}
	res.Errors = append(res.Errors, hardRejectErrors(root, raw)...)

	b, err := json.Marshal(res)
	if err != nil {
		return nil, err
	}
	if err := validateConfigurationJSONResult(string(b)); err != nil {
		return nil, err
	}
	return WrapString(string(b)), nil
}

func planGeodata(raw *config.RawConfig) ([]planGeo, []planError) {
	required := requiredGeodata(raw)
	plans := make([]planGeo, 0, 3)
	errors := make([]planError, 0, 3)
	appendPlan := func(kind, field, url, format, path string) {
		if strings.TrimSpace(url) == "" {
			errors = append(errors, planError{
				Field:  field,
				Reason: "required geodata URL is empty; the containing App must materialize this resource before activation",
			})
			return
		}
		normalizedURL, err := normalizeResourceURL(url, "geodata")
		if err != nil {
			errors = append(errors, planError{Field: field, Reason: err.Error()})
			return
		}
		plans = append(plans, planGeo{
			Kind:         kind,
			URL:          normalizedURL,
			Format:       format,
			Path:         path,
			MaximumBytes: maximumGeodataResourceBytes,
		})
	}
	if required.geoIP {
		if raw.GeodataMode {
			appendPlan("geoip", "geox-url.geoip", raw.GeoXUrl.GeoIp, "dat", "GeoIP.dat")
		} else {
			appendPlan("geoip", "geox-url.mmdb", raw.GeoXUrl.Mmdb, "mmdb", "geoip.metadb")
		}
	}
	if required.geoSite {
		appendPlan("geosite", "geox-url.geosite", raw.GeoXUrl.GeoSite, "dat", "GeoSite.dat")
	}
	if required.asn {
		appendPlan("asn", "geox-url.asn", raw.GeoXUrl.ASN, "mmdb", "ASN.mmdb")
	}
	return plans, errors
}

func httpProviders(root map[string]any, key, kind string) ([]planProvider, []planError, []string) {
	out := []planProvider{}
	errors := []planError{}
	notices := []string{}
	m, ok := root[key].(map[string]any)
	if !ok {
		return out, errors, notices
	}
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		raw := m[name]
		def, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		typeName, _ := def["type"].(string)
		if typeName == "file" {
			errors = append(errors, planError{
				Field:  key + "." + name + ".path",
				Reason: "external file providers are not part of this imported profile; use an HTTPS or inline provider",
			})
			continue
		}
		if typeName == "http" {
			providerURL, _ := def["url"].(string)
			format, _ := def["format"].(string)
			behavior, _ := def["behavior"].(string)
			proxy, _ := def["proxy"].(string)
			headers, headerErr := providerHeaders(def["header"])
			normalizedURL, urlErr := normalizeResourceURL(providerURL, "provider")
			if urlErr != nil {
				errors = append(errors, planError{
					Field:  key + "." + name + ".url",
					Reason: urlErr.Error(),
				})
			}
			if proxy != "" {
				// Fetch-egress selection only affects HOW the payload is
				// downloaded, never which proxy serves user traffic. The iOS App
				// resource downloader cannot dial through a named clash proxy, so
				// the field is stripped (the App fetches directly; on failure the
				// cached copy stays authoritative) and surfaced as a notice —
				// tolerate + strip, the config still starts.
				notices = append(notices, key+"."+name+".proxy: provider fetch proxy '"+proxy+"' is stripped on iOS (the App downloads directly; a failed refresh falls back to the cached copy)")
				proxy = ""
			}
			maximumBytes, limitErr := effectiveProviderMaximumBytes(def["size-limit"])
			if limitErr != nil {
				errors = append(errors, planError{
					Field:  key + "." + name + ".size-limit",
					Reason: limitErr.Error(),
				})
			}
			updateIntervalSeconds, intervalErr := providerUpdateIntervalSeconds(def["interval"])
			if intervalErr != nil {
				errors = append(errors, planError{
					Field:  key + "." + name + ".interval",
					Reason: intervalErr.Error(),
				})
			}
			if headerErr != nil {
				errors = append(errors, planError{
					Field:  key + "." + name + ".header",
					Reason: headerErr.Error(),
				})
			}
			if urlErr != nil {
				continue
			}
			out = append(out, planProvider{
				Name: name, Kind: kind, ResourceKey: providerResourceKey(kind, name), Type: "http", URL: normalizedURL,
				Behavior: behavior, Format: format, Path: providerFileName(kind, name, ext(format, def)),
				Headers: headers, Proxy: proxy, MaximumBytes: maximumBytes,
				UpdateIntervalSeconds: updateIntervalSeconds,
			})
		}
	}
	return out, errors, notices
}

// normalizeResourceURL accepts what upstream accepts and the App can fetch.
//
// HTTPS is what a subscription should use and what nearly all of them do. It is
// not what all of them can: a Sub-Store on a home server, a rule set published
// by a router, an internal mirror — these answer on http and have no
// certificate to present. Refusing them here did not make those readers safer,
// it made the app unusable for them, and upstream has always accepted both. The
// App applies the same rule and still refuses an https URL that redirects into
// plaintext, which is the case where a reader's choice would be spent without
// them knowing.
func normalizeResourceURL(raw, resource string) (string, error) {
	normalized := strings.TrimSpace(raw)
	parsed, err := url.Parse(normalized)
	if err != nil || parsed.Scheme == "" || parsed.Hostname() == "" {
		return "", fmt.Errorf("%s URL must be an absolute http:// or https:// URL with a host", resource)
	}
	if !strings.EqualFold(parsed.Scheme, "https") && !strings.EqualFold(parsed.Scheme, "http") {
		return "", fmt.Errorf("%s URL must use http:// or https://, not %q", resource, parsed.Scheme)
	}
	// Userinfo is how a private rule server is authenticated, and the core
	// treats it as a feature: component/http/http.go:58 turns it into Basic
	// auth. Refusing it here told readers to "store credentials in
	// Keychain-backed headers" — a mechanism abolished in favour of
	// keeping a reader's configuration byte for byte — so the message named a
	// remedy that no longer exists and the rejection outlived its own reason.
	//
	// A fragment is never transmitted: Go builds the request line from
	// RequestURI(), which excludes it. Upstream ignores one silently, and a
	// refusal over something with no effect on the wire is a refusal over
	// nothing.
	return normalized, nil
}

func effectiveProviderMaximumBytes(raw any) (int64, error) {
	if raw == nil {
		return int64(maximumProviderResourceBytes), nil
	}
	var limit int64
	switch value := raw.(type) {
	case int:
		limit = int64(value)
	case int64:
		limit = value
	case uint64:
		if value > math.MaxInt64 {
			return int64(maximumProviderResourceBytes), fmt.Errorf("provider size-limit is out of range")
		}
		limit = int64(value)
	case string:
		parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		if err != nil {
			return int64(maximumProviderResourceBytes), fmt.Errorf("provider size-limit must be a non-negative byte count")
		}
		limit = parsed
	default:
		return int64(maximumProviderResourceBytes), fmt.Errorf("provider size-limit must be a non-negative byte count")
	}
	if limit < 0 {
		return int64(maximumProviderResourceBytes), fmt.Errorf("provider size-limit must not be negative")
	}
	if limit == 0 || limit > int64(maximumProviderResourceBytes) {
		return int64(maximumProviderResourceBytes), nil
	}
	return limit, nil
}

const (
	maximumProviderHeaderFields = 64
	maximumProviderHeaderValues = 16
	maximumProviderHeaderBytes  = 8 * 1024
)

var forbiddenProviderHeaders = map[string]struct{}{
	"connection":          {},
	"content-length":      {},
	"host":                {},
	"keep-alive":          {},
	"proxy-authenticate":  {},
	"proxy-authorization": {},
	"proxy-connection":    {},
	"te":                  {},
	"trailer":             {},
	"transfer-encoding":   {},
	"upgrade":             {},
}

func providerHeaders(raw any) (map[string][]string, error) {
	result := map[string][]string{}
	if raw == nil {
		return result, nil
	}
	mapping, ok := raw.(map[string]any)
	if !ok {
		return result, fmt.Errorf("provider header must be a mapping of field names to string values")
	}
	if len(mapping) > maximumProviderHeaderFields {
		return result, fmt.Errorf("provider header has too many fields")
	}
	names := make([]string, 0, len(mapping))
	for name := range mapping {
		names = append(names, name)
	}
	sort.Strings(names)
	seen := make(map[string]struct{}, len(names))
	totalBytes := 0
	for _, name := range names {
		lowerName := strings.ToLower(name)
		if !validProviderHeaderName(name) {
			return map[string][]string{}, fmt.Errorf("provider header contains an invalid field name")
		}
		if _, forbidden := forbiddenProviderHeaders[lowerName]; forbidden {
			return map[string][]string{}, fmt.Errorf("provider header contains a field controlled by the HTTP transport")
		}
		if _, duplicate := seen[lowerName]; duplicate {
			return map[string][]string{}, fmt.Errorf("provider header contains duplicate case-insensitive field names")
		}
		seen[lowerName] = struct{}{}

		value := mapping[name]
		var values []string
		switch typed := value.(type) {
		case string:
			values = []string{typed}
		case []any:
			if len(typed) == 0 || len(typed) > maximumProviderHeaderValues {
				return map[string][]string{}, fmt.Errorf("provider header has an invalid value count")
			}
			for _, item := range typed {
				text, ok := item.(string)
				if !ok {
					return map[string][]string{}, fmt.Errorf("provider header values must be strings")
				}
				values = append(values, text)
			}
		case []string:
			values = append(values, typed...)
		default:
			return map[string][]string{}, fmt.Errorf("provider header values must be strings or string lists")
		}
		if len(values) == 0 || len(values) > maximumProviderHeaderValues {
			return map[string][]string{}, fmt.Errorf("provider header has an invalid value count")
		}
		for _, value := range values {
			if len(value) > maximumProviderHeaderBytes || !validProviderHeaderValue(value) {
				return map[string][]string{}, fmt.Errorf("provider header contains an invalid field value")
			}
			totalBytes += len(value) + 2 // value plus conservative separator/line overhead
		}
		totalBytes += len(name) + 2 // field name plus colon/space overhead
		if totalBytes > maximumProviderHeaderBytes {
			return map[string][]string{}, fmt.Errorf("provider header exceeds the total byte limit")
		}
		result[name] = values
	}
	return result, nil
}

func validProviderHeaderName(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range []byte(value) {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') {
			continue
		}
		switch character {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		}
		return false
	}
	return true
}

func validProviderHeaderValue(value string) bool {
	for _, character := range []byte(value) {
		if character == '\t' || character >= 0x20 && character != 0x7f {
			continue
		}
		return false
	}
	return true
}

func providerResourceKey(kind, name string) string {
	return kind + ":" + name
}

func providerFileName(kind, name, extension string) string {
	digest := sha256.Sum256([]byte(providerResourceKey(kind, name)))
	return fmt.Sprintf("provider-%x.%s", digest[:16], extension)
}

func ext(format string, def map[string]any) string {
	switch format {
	case "mrs":
		return "mrs"
	case "text":
		return "txt"
	default:
		return "yaml"
	}
}

func routeSetErrors(root, tun map[string]any) []planError {
	out := []planError{}
	ipcidrProviders := ipcidrRuleProviders(root)
	for _, field := range []string{"route-address-set", "route-exclude-address-set"} {
		list, ok := tun[field].([]any)
		if !ok {
			continue
		}
		for _, item := range list {
			name, _ := item.(string)
			if !ipcidrProviders[name] {
				out = append(out, planError{
					Field:  "tun." + field,
					Reason: "rule-provider '" + name + "' not defined as an ipcidr set; cannot expand to routes",
				})
			}
		}
	}
	return out
}

func ipcidrRuleProviders(root map[string]any) map[string]bool {
	out := map[string]bool{}
	m, ok := root["rule-providers"].(map[string]any)
	if !ok {
		return out
	}
	for name, raw := range m {
		if def, ok := raw.(map[string]any); ok {
			if b, _ := def["behavior"].(string); b == "ipcidr" {
				out[name] = true
			}
		}
	}
	return out
}

// strippedHostRouteKnobNotices mirrors normalizeRawNetworkExtensionSurfaces and
// validateRawNetworkExtensionIntent: the host-route knobs iOS cannot execute are
// stripped, not rejected, so the plan reports them as notices and the config
// still starts ("every upstream config must start; unsupported settings are tolerated and stripped"). Covered here:
// every tun UID/package/MAC/port/interface filter and auto-redirect/iproute2
// mark, top-level interface-name/routing-mark, find-process-mode, and
// PROCESS/UID/IN-USER rules. Per-proxy egress overrides, DNS scheme/fragment
// nameservers and route-address-set remain hardReject/route errors for now.
func strippedHostRouteKnobNotices(root map[string]any, raw *config.RawConfig) []string {
	notices := []string{}
	if tun, ok := root["tun"].(map[string]any); ok {
		for _, k := range unsupportedTunIntentKeys {
			if v, present := tun[k]; present && !isZeroish(v) {
				notices = append(notices, "tun."+k+" has no NetworkExtension consumer and is stripped on iOS; the config still starts")
			}
		}
	}
	for _, field := range outboundEgressOverrideFields(root) {
		notices = append(notices, field+": global egress override has no iOS equivalent and is stripped (Apple owns physical egress)")
	}
	if s, ok := root["find-process-mode"].(string); ok && s != "" && s != "off" {
		notices = append(notices, "find-process-mode is forced off on iOS: the Network Extension exposes no process metadata")
	}
	for _, summary := range summarizeMetadataRuleOccurrences(raw, appleProcessMetadataCapability{}) {
		notices = append(notices, summary+": "+metadataRuleKeptExplanation)
	}
	return notices
}

func hardRejectErrors(root map[string]any, raw *config.RawConfig) []planError {
	out := []planError{}
	if field, reason := firstUnsafeOutboundRuntimeOption(raw); field != "" {
		out = append(out, planError{Field: field, Reason: reason})
	}
	if field := firstOutboundEmbeddedDNSFragment(raw); field != "" {
		out = append(out, planError{
			Field:  field,
			Reason: "L3 outbound nested DNS is pinned to that outbound; a bare fragment would be silently ignored and must be removed",
		})
	}
	if dns, ok := root["dns"].(map[string]any); ok {
		// The query-resolver lists AND nameserver policies are stripped on iOS
		// (tolerate + strip) and reported as notices. system/dhcp in a
		// non-strippable field stays a hard error; default-nameserver (the
		// bootstrap) is handled specially below — stripped when a usable pure-IP
		// resolver remains, else a hard error.
		strippable := map[string]bool{
			"nameserver": true, "fallback": true,
			"proxy-server-nameserver": true, "direct-nameserver": true,
			"nameserver-policy": true, "proxy-server-nameserver-policy": true,
		}
		fields := make([]string, 0, len(dns))
		for field := range dns {
			fields = append(fields, field)
		}
		sort.Strings(fields)
		for _, field := range fields {
			if strippable[field] {
				continue
			}
			if field == "default-nameserver" {
				// Bootstrap: system/dhcp entries are stripped like the query
				// slots and a bootstrap left empty is refilled with mihomo's
				// own defaults, so the only error left is a survivor mihomo
				// itself refuses — hostless junk that fails its pure-IP check.
				if _, _, rejected := defaultNameserverStrip(dns[field]); rejected {
					out = append(out, planError{
						Field:  "dns.default-nameserver",
						Reason: "bootstrap keeps a resolver mihomo rejects (\"default nameserver should be pure IP\"); add an explicit IP nameserver",
					})
				}
				continue
			}
			walkStrings(dns[field], func(v string) {
				if isNEIncompatibleNameserver(v) {
					out = append(out, planError{
						Field:  "dns." + field,
						Reason: "system/dhcp resolver '" + v + "' has no iOS equivalent here and cannot be stripped; use an explicit core nameserver",
					})
				}
			})
		}
	}
	return out
}

// defaultNameserverStrip reports how the bootstrap default-nameserver list is
// handled, mirroring filterBootstrap: strip=true when NE-incompatible entries
// are removed while a usable pure-IP bootstrap remains (a notice); kept=true
// when NE-incompatible entries are KEPT verbatim because stripping would leave
// no usable bootstrap and mihomo still accepts the list (a different notice --
// the entries are not stripped, and inside a packet tunnel a system bootstrap
// resolves back through NEDNSSettings); empty=true when what reaches mihomo is
// a bootstrap mihomo itself refuses (an error).
//
// The verdict is computed in two stages that must match the runtime exactly:
// first simulate the strip (filterBootstrap removes NE-incompatible entries
// only while a usable pure-IP sibling survives; otherwise the ORIGINAL list is
// kept verbatim -- the `if !usable` return in config_pipeline.go), then ask
// whether mihomo accepts what survives. The first version of this function
// asked about every entry instead of every survivor, so a dhcp:// entry that
// the runtime strips away still failed the plan.
//
// The mihomo question is answered by mihomoRejectsBootstrap below, which calls
// mihomo's own parser rather than imitating it. This function's second version
// imitated it and got three shapes wrong in one review (case-folding a
// case-sensitive comparison, missing the dhcp://system alias, missing that an
// unknown scheme fails the parse). TestPlanAndRuntimeAgreeOnBootstrapShapes
// drives both sides over the same inputs, so any residual divergence goes red.
func defaultNameserverStrip(v any) (strip, repaired, rejected bool) {
	entries := []string{}
	walkStrings(v, func(s string) { entries = append(entries, s) })
	if len(entries) == 0 {
		// Absent field: mihomo's prefilled defaults apply and there is nothing
		// to say. An EXPLICIT empty list overwrites those defaults, and mihomo
		// refuses it ("default nameserver should have at least one
		// nameserver", config/config.go:1453-1454) -- but the repair refills
		// it before mihomo ever sees it, so it is a notice now, not an error.
		// Absence and an explicit empty list are told apart by the field being
		// present while yielding no strings.
		return false, v != nil, false
	}
	// What reaches mihomo, in the runtime's own order: filterBootstrap may keep
	// the original list verbatim, but repairApplePacketTunnelDNS then removes
	// every NE-incompatible entry regardless, so the survivors are the same
	// either way -- and an empty result is refilled with mihomo's defaults.
	survivors := make([]string, 0, len(entries))
	var hasBad bool
	for _, s := range entries {
		if isNEIncompatibleNameserver(s) {
			hasBad = true
			continue
		}
		survivors = append(survivors, s)
	}
	switch {
	case len(survivors) == 0:
		// Every entry was system/dhcp. The repair substitutes mihomo's own
		// explicit bootstrap, which is a change worth reporting but not a
		// reason to refuse the configuration.
		return false, true, false
	case mihomoRejectsBootstrap(survivors):
		// Something survived that mihomo itself refuses -- a hostname where
		// the pure-IP check wants an address ("tls://dns.google", bare
		// "dhcp"). Not system/dhcp-schemed, so the repair keeps it and the
		// bootstrap is never refilled. This is the one bootstrap shape that is
		// still a hard error, and it is upstream's verdict, not ours. (Hostless
		// junk like "udp://:53" is NOT this shape: mihomo's check cannot find a
		// host in it and lets it load -- the hole mihomoRejectsBootstrap
		// reproduces on purpose.)
		return false, false, true
	default:
		return hasBad, false, false
	}
}

// mihomoRejectsBootstrap reports whether mihomo refuses this exact
// default-nameserver list. It does not imitate mihomo's parser -- it CALLS it:
// dns.ParseNameServer is the exported hook config/config.go:1297-1301 wires to
// the real parseNameServer, so scheme handling, the case-sensitive bare
// "system" (config.go:1308), the "dhcp://system" old-notation alias
// (config.go:1252-1255) and the unsupported-scheme failure (config.go:1269-1270)
// are all mihomo's own answers. Only two things are reproduced by hand, each a
// verbatim copy of a numbered upstream line: the non-empty requirement
// (config.go:1453-1454) and the pure-IP loop over the PARSED servers
// (config.go:1459-1473), including its known hole -- a hostless Addr like ":53"
// makes url.Parse error and the rejection branch never runs. Reproducing the
// hole is the point: this predicate predicts mihomo's verdict, it does not
// improve on it.
func mihomoRejectsBootstrap(servers []string) bool {
	if len(servers) == 0 {
		return true
	}
	parsed, err := dns.ParseNameServer(servers)
	if err != nil {
		return true
	}
	for _, ns := range parsed {
		if ns.Net == "system" {
			continue
		}
		host, _, err := net.SplitHostPort(ns.Addr)
		if err != nil || net.ParseIP(host) == nil {
			u, err := url.Parse(ns.Addr)
			if err == nil && net.ParseIP(u.Host) == nil {
				if ip, _, err := net.SplitHostPort(u.Host); err != nil || net.ParseIP(ip) == nil {
					return true
				}
			}
		}
	}
	return false
}

// strippedDNSSchemeNotices mirrors stripNEIncompatibleNameservers: system/dhcp
// entries in the DNS resolver lists are stripped on iOS so the config still
// starts, so the plan reports them as notices rather than failing.
// default-nameserver splits three ways, exactly like the runtime: stripped when
// something the tunnel can bootstrap from remains (a strip notice); REPAIRED
// with mihomo's own explicit defaults when nothing does (a different notice --
// saying "stripped" there would be false, and saying nothing was reviewed as
// 's silent-no-op shape); and a survivor mihomo itself refuses is a hard
// error instead (the plan loop).
func strippedDNSSchemeNotices(root map[string]any) []string {
	dns, ok := root["dns"].(map[string]any)
	if !ok {
		return nil
	}
	notices := []string{}
	for _, field := range []string{
		"nameserver", "fallback", "proxy-server-nameserver", "direct-nameserver",
		"nameserver-policy", "proxy-server-nameserver-policy",
	} {
		walkStrings(dns[field], func(v string) {
			if isNEIncompatibleNameserver(v) {
				notices = append(notices, "dns."+field+" '"+v+"' (system/dhcp) is stripped on iOS; resolution stays inside the core")
			}
		})
	}
	strip, repaired, _ := defaultNameserverStrip(dns["default-nameserver"])
	switch {
	case strip:
		walkStrings(dns["default-nameserver"], func(v string) {
			if isNEIncompatibleNameserver(v) {
				notices = append(notices, "dns.default-nameserver '"+v+"' (system/dhcp) is stripped on iOS; resolution stays inside the core")
			}
		})
	case repaired:
		notices = append(notices, "dns.default-nameserver has no resolver a packet tunnel can bootstrap from, so it receives mihomo's own explicit defaults; set an IP bootstrap (e.g. 223.5.5.5) to choose your own")
	}
	return notices
}

// strippedDNSFragmentNotices reports each fragment iOS cannot statically route
// as a notice, never an error: the fragment is kept and that resolver fails
// closed at runtime unless the name materializes (never silently rerouted).
func strippedDNSFragmentNotices(raw *config.RawConfig) []string {
	notices := []string{}
	for _, entry := range detectUnroutableDNSFragments(raw) {
		notices = append(notices, "dns."+entry+": fragment names a physical interface/unknown proxy; kept — fails closed at runtime unless the name materializes")
	}
	return notices
}

// helpers
func isZeroish(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case bool:
		return !t
	case string:
		return t == ""
	case []any:
		return len(t) == 0
	case int:
		return t == 0
	case float64:
		return t == 0
	}
	return false
}

func walkStrings(v any, fn func(string)) {
	switch t := v.(type) {
	case string:
		fn(t)
	case []any:
		for _, e := range t {
			walkStrings(e, fn)
		}
	case map[string]any:
		keys := make([]string, 0, len(t))
		for key := range t {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			walkStrings(t[key], fn)
		}
	}
}
