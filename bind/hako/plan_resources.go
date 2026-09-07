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

	"github.com/dlclark/regexp2"
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
	// Notices is the technical sentence per notice, as it always was.
	Notices []string `json:"notices"`
	// StructuredNotices is the same list with a kind, a field and a value a client can key its
	// own wording on instead of parsing the sentence. Parallel to Notices, index for index.
	StructuredNotices []planNotice `json:"structuredNotices"`
	Errors            []planError  `json:"errors"`
}

// planNotice is one notice with the bits a client needs to say it in its own words: Kind is
// a fixed vocabulary (the planNotice* constants), Field the YAML path or location it is
// about, Value the offending value where there is one, Count how many when it summarises,
// Text the technical sentence that also appears in Notices.
type planNotice struct {
	Kind  string `json:"kind"`
	Field string `json:"field,omitempty"`
	Value string `json:"value,omitempty"`
	Count int    `json:"count,omitempty"`
	// RuleKind names the rule kind a rules notice is about, as data (metadata-rules-inert).
	RuleKind string `json:"ruleKind,omitempty"`
	Text     string `json:"text"`
}

// The notice vocabulary. A client keys its presentation on these; adding one is an API
// change for the client lanes and a line in HAKO-SDK-REFERENCE.
const (
	// Renamed 2026-09-05 from provider-fetch-proxy-stripped: the field is no longer
	// stripped, it is handed to the core ('s deferred-fetch path already existed for
	// "the app has no local copy"; a named fetch proxy is now routed onto the same path
	// rather than treated as a reason to strip it). Keeping the old string with new text
	// would have a client render "we ignored your setting" for a field that is now
	// honoured -- a rename is the honest choice, not renaming would be the lie.
	planNoticeProviderFetchProxyHonoured = "provider-fetch-proxy-honoured"
	// A provider naming ITSELF as its own fetch proxy is checkable at plan time from the
	// document alone -- unlike "does the named proxy exist", which depends on what has
	// loaded by the time this provider is fetched. Informational only: the core will
	// reach the exact same "proxy %s not found" upstream would, this only says so before
	// the fetch is attempted rather than after.
	planNoticeProviderFetchProxySelfReferential = "provider-fetch-proxy-self-referential"
	planNoticeTunKnobStripped                   = "tun-knob-stripped"
	planNoticeEgressOverrideStripped            = "egress-override-stripped"
	planNoticeProxyEgressOverrideStripped       = "proxy-egress-override-stripped"
	planNoticeFindProcessModeForcedOff          = "find-process-mode-forced-off"
	planNoticeRouteSetInert                     = "route-set-inert"
	planNoticeMetadataRulesInert                = "metadata-rules-inert"
	planNoticeDNSSystemResolverStripped         = "dns-system-resolver-stripped"
	planNoticeDNSSystemResolverSubstituted      = "dns-system-resolver-substituted"
	planNoticeDNSBootstrapReplaced              = "dns-bootstrap-replaced"
	planNoticeDNSFragmentUnroutable             = "dns-fragment-unroutable"
	// The kernel starts on every one of these. Each names the upstream line that
	// tolerates the same input, so a reader can check the claim rather than trust it.
	planNoticeProviderFileInert             = "provider-file-inert"
	planNoticeProviderURLUnusable           = "provider-url-unusable"
	planNoticeProviderOptionDefaulted       = "provider-option-defaulted"
	planNoticeProviderHeaderDropped         = "provider-header-dropped"
	planNoticeOutboundDNSFragmentInert      = "outbound-dns-fragment-inert"
	planNoticeOutboundOptionUnrepresentable = "outbound-option-unrepresentable"
	planNoticeProviderCoreFetch             = "provider-core-fetch"
)

// note records one notice in both forms.
func (res *planResources) note(notices ...planNotice) {
	for _, n := range notices {
		res.Notices = append(res.Notices, n.Text)
		res.StructuredNotices = append(res.StructuredNotices, n)
	}
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
//
// It keeps that meaning -- the iOS packet tunnel -- and a client on another platform calls
// PlanResourcesForProfile: the notices depend on the profile (which rule kinds resolve,
// whether find-process-mode is forced, which DNS shapes a packet tunnel strips), and a plan
// computed for the wrong one states facts that are false there; a Mac was told
// "find-process-mode is forced off on iOS".
func PlanResourcesForIOS(mergedYAML string) (*StringBox, error) {
	bridgedValue0, bridgedErr := PlanResourcesForProfile(mergedYAML, RuntimeProfileIOSPacketTunnel)
	return bridgedValue0, bridgeSafeError(bridgedErr)
}

// PlanResourcesForProfile plans for the named runtime profile (the RuntimeProfile* constants).
func PlanResourcesForProfile(mergedYAML string, targetProfile string) (*StringBox, error) {
	profile, err := normalizeRuntimeProfile(targetProfile)
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	doc, err := NewConfigDocument(mergedYAML)
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	defer doc.Close()
	bridgedValue0, bridgedErr := doc.planResourcesJSON(runtimePolicyFor(profile, true))
	return bridgedValue0, bridgeSafeError(bridgedErr)
}

// PlanResourcesJSON is the existing plan logic reading the handle's views.
// The projection is deliberately NOT part of this result: the plan result has
// a 16 MiB ceiling (validateConfigurationJSONResult below), and a projection
// pushing a legal plan past it would turn "slower" into "activation fails";
// ask ProjectionJSON on the same handle instead.
//
// This one plans for the iOS packet tunnel; PlanResourcesJSONForProfile takes the profile.
func (d *ConfigDocument) PlanResourcesJSON() (*StringBox, error) {
	bridgedValue0, bridgedErr := d.PlanResourcesJSONForProfile(RuntimeProfileIOSPacketTunnel)
	return bridgedValue0, bridgeSafeError(bridgedErr)
}

// PlanResourcesJSONForProfile plans for the named runtime profile on an open document.
func (d *ConfigDocument) PlanResourcesJSONForProfile(targetProfile string) (*StringBox, error) {
	profile, err := normalizeRuntimeProfile(targetProfile)
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	bridgedValue0, bridgedErr := d.planResourcesJSON(runtimePolicyFor(profile, true))
	return bridgedValue0, bridgeSafeError(bridgedErr)
}

func (d *ConfigDocument) planResourcesJSON(policy appleRuntimePolicy) (*StringBox, error) {
	views, err := d.snapshot()
	if err != nil {
		return nil, err
	}
	root := views.root
	raw := views.raw
	res := planResources{
		SchemaVersion:     resourcePlanSchemaVersion,
		Providers:         []planProvider{},
		Geodata:           []planGeo{},
		Notices:           []string{},
		StructuredNotices: []planNotice{},
		Errors:            []planError{},
	}

	// providers
	proxyProviders, proxyErrors, proxyNotices := httpProviders(root, "proxy-providers", "proxy")
	ruleProviders, ruleErrors, ruleNotices := httpProviders(root, "rule-providers", "rule")
	res.note(proxyNotices...)
	res.note(ruleNotices...)
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
	// goes inert and is reported (routeSetNotices).
	if tun, ok := root["tun"].(map[string]any); ok {
		res.note(routeSetNotices(root, tun)...)
	}
	res.note(strippedHostRouteKnobNotices(root, raw, policy)...)
	res.note(strippedDNSSchemeNotices(root, policy)...)
	// Detection only: detectUnroutableDNSFragments is pure by its own contract
	// ("Detection only, NEVER mutation"), and the other helpers on this path
	// were swept for writes when the body moved onto the shared handle -- the
	// handle's views must stay pristine for projections served after this call.
	// (An older comment here claimed the raw was deliberately mutated; that
	// stopped being true when fragment stripping became fail-closed detection.)
	res.note(strippedDNSFragmentNotices(raw, policy)...)
	if policy.networkExtension {
		for _, loc := range outboundEgressOverrideLocations(raw) {
			res.note(planNotice{Kind: planNoticeProxyEgressOverrideStripped, Field: loc,
				Text: loc + ": outbound egress override has no Network Extension equivalent and is stripped (the system owns physical egress)"})
		}
	}
	tierErrors, tierNotices := hardRejectErrors(root, raw)
	res.Errors = append(res.Errors, tierErrors...)
	res.note(tierNotices...)

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
			// refusal-id: PlanResources.geodataUrlEmpty
			errors = append(errors, planError{
				Field:  field,
				Reason: "required geodata URL is empty; the containing App must materialize this resource before activation",
			})
			return
		}
		normalizedURL, err := normalizeResourceURL(url, "geodata")
		if err != nil {
			// refusal-id: PlanResources.geodataUrlMalformed
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

func httpProviders(root map[string]any, key, kind string) ([]planProvider, []planError, []planNotice) {
	out := []planProvider{}
	errors := []planError{}
	notices := []planNotice{}
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
			// The kernel starts on this: it builds a FileVehicle without reading the
			// file (adapter/provider/parser.go:80, rules/provider/parse.go:45), the
			// read fails later (component/resource/vehicle.go:66) and
			// hub/executor/executor.go:400 logs it and keeps going -- the provider
			// rides empty and the tunnel runs. Nothing here is downloadable, so it
			// stays out of the plan, but it must not cost the whole configuration.
			path, _ := def["path"].(string)
			// refusal-id: PlanResources.fileProvider (aligned to a notice; kept registered so the evidence survives)
			notices = append(notices, planNotice{Kind: planNoticeProviderFileInert, Field: key + "." + name + ".path", Value: path,
				Text: key + "." + name + ": a file provider reads a path this app does not carry; the provider loads empty and everything else still starts"})
			continue
		}
		if typeName == "http" {
			providerURL, _ := def["url"].(string)
			format, _ := def["format"].(string)
			behavior, _ := def["behavior"].(string)
			proxy, _ := def["proxy"].(string)
			headers, headerDrops := providerHeaders(def["header"])
			normalizedURL, urlErr := normalizeResourceURL(providerURL, "provider")
			if urlErr != nil {
				// adapter/provider/parser.go:94 hands the url to NewHTTPVehicle
				// unchecked; the download fails into executor.go:400 and the
				// provider rides empty. rewriteProviders asks this same question
				// with this same predicate before demanding materialization, so
				// the definition survives finalize untouched and the kernel gets
				// to fail it the way upstream does.
				// refusal-id: PlanResources.providerUrlMalformed (aligned to a notice)
				notices = append(notices, planNotice{Kind: planNoticeProviderURLUnusable, Field: key + "." + name + ".url", Value: providerURL,
					Text: key + "." + name + ": " + urlErr.Error() + "; the provider is not downloaded and everything else still starts"})
			}
			if proxy != "" {
				// Upstream's own vehicle dials through the named proxy
				// (component/resource/vehicle.go:139, mihomoHttp.WithSpecialProxy);
				// this used to be the one field this layer could not honour, because
				// the app fetches before a core exists to route through. It no
				// longer is: already gave every remote provider the app has no
				// local copy of a path where the CORE fetches it once running, in the
				// background. A named fetch proxy is routed onto that same path now —
				// the app never attempts this one itself, at any budget — so the field
				// reaches the core and the core dials through the proxy exactly as
				// upstream would. The app-side materializer decides not to fetch it;
				// nothing here has to ask it to.
				// refusal-id: PlanResources.providerFetchProxy
				notices = append(notices, planNotice{Kind: planNoticeProviderFetchProxyHonoured, Field: key + "." + name + ".proxy", Value: proxy,
					Text: key + "." + name + ".proxy: provider fetch proxy '" + proxy + "' is honoured; the core fetches this provider through it once the tunnel is running, and the app does not pre-download it"})
				if proxy == name {
					// The core resolves a fetch proxy at dial time by looking the name up
					// in the live outbound table (tunnel.go resolveMetadata:
					// proxies[metadata.SpecialProxy]) -- a provider's own key in
					// proxy-providers is never an entry in that table, with or without this
					// provider having loaded, so this can never resolve. Told before the
					// fetch is attempted rather than only after; not a divergence -- the
					// consequence and the wording are the core's own, quoted exactly.
					// refusal-id: PlanResources.providerFetchProxySelfReferential
					notices = append(notices, planNotice{Kind: planNoticeProviderFetchProxySelfReferential, Field: key + "." + name + ".proxy", Value: proxy,
						Text: key + "." + name + ".proxy: names this same provider ('" + name + "') as its own fetch proxy; a provider is not itself a proxy, so the core will report \"proxy " + proxy + " not found\" and this provider never fetches"})
				}
			}
			maximumBytes, limitErr := effectiveProviderMaximumBytes(def["size-limit"])
			if limitErr != nil {
				// component/resource/vehicle.go:157 reads `if h.sizeLimit > 0`, so
				// zero and negative both mean "no limit" upstream and the schema
				// field takes them (adapter/provider/parser.go:38). This layer needs
				// a representable number for the app's downloader, so it falls back
				// to the ceiling instead of refusing the configuration.
				// refusal-id: PlanResources.providerSizeLimit (aligned to a fallback)
				notices = append(notices, planNotice{Kind: planNoticeProviderOptionDefaulted, Field: key + "." + name + ".size-limit", Value: fmt.Sprintf("%v", def["size-limit"]),
					Text: key + "." + name + ": " + limitErr.Error() + "; the download ceiling falls back to the default and the provider still loads"})
			}
			updateIntervalSeconds, intervalErr := providerUpdateIntervalSeconds(def["interval"])
			if intervalErr != nil {
				// Upstream's schema is a plain `Interval int` (parser.go:33,
				// rules/provider/parse.go:21) and nothing validates its sign. Zero
				// is upstream's own "do not refresh on a timer".
				updateIntervalSeconds = 0
				// refusal-id: PlanResources.providerInterval (aligned to a fallback)
				notices = append(notices, planNotice{Kind: planNoticeProviderOptionDefaulted, Field: key + "." + name + ".interval", Value: fmt.Sprintf("%v", def["interval"]),
					Text: key + "." + name + ": " + intervalErr.Error() + "; the provider is not refreshed on a timer and still loads"})
			}
			for _, drop := range headerDrops {
				// refusal-id: PlanResources.providerHeader (aligned to a per-field degrade)
				notices = append(notices, planNotice{Kind: planNoticeProviderHeaderDropped, Field: key + "." + name + ".header." + drop.Name, Value: drop.Name,
					Text: key + "." + name + ": header field " + drop.Name + " is dropped (" + drop.Reason + "); the remaining fields are sent and the provider still loads"})
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
	if fetchable := len(out); fetchable > 0 {
		// Remote providers used to be refused at activation unless the app had
		// downloaded every one of them. They are accepted now: what the app
		// manages to download is staged as before, and what it cannot reach starts
		// empty inside the core and is fetched there in the background with backoff
		// .
		// refusal-id: ConfigPipeline.remoteProviderNotPreDownloaded (aligned to a notice)
		notices = append(notices, planNotice{Kind: planNoticeProviderCoreFetch, Field: key, Value: fmt.Sprintf("%d", fetchable),
			Text: fmt.Sprintf("%s: %d remote provider(s); any this app has no copy of at activation starts empty and is downloaded by the core in the background", key, fetchable)})
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

// The three numeric caps that stood here -- 64 fields, 16 values per field,
// 8 KiB -- are gone (2026-08-27). Upstream has none: component/resource/vehicle.go:125-139
// hands the header map straight to mihomoHttp.HttpRequest with no count or size
// limit anywhere. No Apple API forbids a large header either, so the burden was
// on this tree to justify them and nothing did; the registry recorded
// platformForced as null the whole time. A user whose subscription needs a long
// token or many fields lost them silently, which is the shape the 2026-08-27
// rule exists to remove. Found by Codex.
//
// The forbidden list below is NOT a cap and stays. Those fields are owned by
// whoever performs the request, and this product's downloader is not Go's
// http.Transport -- the App fetches the resource before the core exists.
// Passing Content-Length or Transfer-Encoding to a different HTTP client is not
// the same inert act it is upstream. That is a reason, not a measurement: no
// end-to-end test against a real server has been run, and the registry says so.

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

// providerHeaderDrop names one header field the plan removed, and why. Upstream
// caps nothing here -- component/resource/vehicle.go:125-139 hands the map
// straight to the request, with no field count, value count, size limit or
// forbidden list -- so a field this layer cannot represent is dropped on its
// own and every other field still travels.
type providerHeaderDrop struct {
	Name   string
	Reason string
}

func providerHeaders(raw any) (map[string][]string, []providerHeaderDrop) {
	result := map[string][]string{}
	drops := []providerHeaderDrop{}
	if raw == nil {
		return result, drops
	}
	mapping, ok := raw.(map[string]any)
	if !ok {
		return result, append(drops, providerHeaderDrop{Name: "header", Reason: "header must be a mapping of field names to string values"})
	}
	names := make([]string, 0, len(mapping))
	for name := range mapping {
		names = append(names, name)
	}
	sort.Strings(names)
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		lowerName := strings.ToLower(name)
		if !validProviderHeaderName(name) {
			drops = append(drops, providerHeaderDrop{Name: name, Reason: "field name is not a valid HTTP field name"})
			continue
		}
		if _, forbidden := forbiddenProviderHeaders[lowerName]; forbidden {
			drops = append(drops, providerHeaderDrop{Name: name, Reason: "field is controlled by the HTTP transport"})
			continue
		}
		if _, duplicate := seen[lowerName]; duplicate {
			drops = append(drops, providerHeaderDrop{Name: name, Reason: "field repeats an earlier field with different casing"})
			continue
		}
		seen[lowerName] = struct{}{}

		value := mapping[name]
		var values []string
		badValue := ""
		switch typed := value.(type) {
		case string:
			values = []string{typed}
		case []any:
			for _, item := range typed {
				text, ok := item.(string)
				if !ok {
					badValue = "field values must be strings"
					break
				}
				values = append(values, text)
			}
		case []string:
			values = append(values, typed...)
		default:
			badValue = "field values must be strings or string lists"
		}
		if badValue != "" {
			drops = append(drops, providerHeaderDrop{Name: name, Reason: badValue})
			continue
		}
		if len(values) == 0 {
			drops = append(drops, providerHeaderDrop{Name: name, Reason: "field carries no value"})
			continue
		}
		// Representability still matters -- a value with a newline in it is not
		// a header value in any client -- but length no longer does.
		invalid := false
		for _, value := range values {
			if !validProviderHeaderValue(value) {
				invalid = true
				break
			}
		}
		if invalid {
			drops = append(drops, providerHeaderDrop{Name: name, Reason: "field value is not representable in an HTTP header"})
			continue
		}
		result[name] = values
	}
	return result, drops
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

// routeSetNotices reports route sets that contribute no routes. It used to be
// routeSetErrors and refused the whole configuration; upstream refuses neither
// shape it judged (listener/sing_tun/server.go:565-593 falls to `default:
// return`, and mihomo accepts both when driven), so the set goes inert here too
// and expandRouteSet skips it on the activation path. Changing only this half
// is what went wrong twice before -- see the note on
// TestEveryToleratedInputSurvivesActivation.
func routeSetNotices(root, tun map[string]any) []planNotice {
	notices := []planNotice{}
	ipcidrProviders := ipcidrRuleProviders(root)
	for _, field := range []string{"route-address-set", "route-exclude-address-set"} {
		list, ok := tun[field].([]any)
		if !ok {
			continue
		}
		for _, item := range list {
			name, _ := item.(string)
			if !ipcidrProviders[name] {
				// refusal-id: PlanResources.routeAddressSet (aligned to a notice)
				notices = append(notices, planNotice{
					Kind:  planNoticeRouteSetInert,
					Field: "tun." + field,
					Text: "tun." + field + ": rule-provider '" + name + "' is not an ipcidr set, so it contributes no " +
						"routes; the tunnel still starts, as it does upstream",
				})
			}
		}
	}
	return notices
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
func strippedHostRouteKnobNotices(root map[string]any, raw *config.RawConfig, policy appleRuntimePolicy) []planNotice {
	if !policy.networkExtension {
		return nil
	}
	notices := []planNotice{}
	if tun, ok := root["tun"].(map[string]any); ok {
		for _, k := range unsupportedTunIntentKeys {
			if v, present := tun[k]; present && !isZeroish(v) {
				notices = append(notices, planNotice{Kind: planNoticeTunKnobStripped, Field: "tun." + k,
					Text: "tun." + k + " has no Network Extension consumer and is stripped; the config still starts"})
			}
		}
	}
	for _, field := range outboundEgressOverrideFields(root) {
		notices = append(notices, planNotice{Kind: planNoticeEgressOverrideStripped, Field: field,
			Text: field + ": global egress override has no Network Extension equivalent and is stripped (the system owns physical egress)"})
	}
	// Forced only where the registry says it is forced: the same predicate the deviation
	// report uses, so the plan and the report cannot disagree about a profile.
	if s, ok := root["find-process-mode"].(string); ok && s != "" && s != "off" {
		if registration := deviationRuleByField("find-process-mode"); registration != nil &&
			(registration.applies == nil || registration.applies(policy)) {
			notices = append(notices, planNotice{Kind: planNoticeFindProcessModeForcedOff, Field: "find-process-mode", Value: s,
				Text: "find-process-mode is forced off: this packet tunnel exposes no process metadata"})
		}
	}
	for _, occurrence := range summarizeMetadataRuleOccurrenceKinds(raw, policy.processMetadata()) {
		notices = append(notices, planNotice{Kind: planNoticeMetadataRulesInert, Field: "rules", Value: occurrence.summary, RuleKind: occurrence.kind, Count: occurrence.count,
			Text: occurrence.summary + ": " + metadataRuleKeptExplanation})
	}
	return notices
}

// dnsResolverFields names the dns fields that hold query resolvers, in the
// order repairApplePacketTunnelDNS strips them (config_pipeline.go:844-853).
// Together with default-nameserver -- the bootstrap, filtered separately
// because mihomo's own pure-IP check applies there -- these are every
// resolver-bearing field upstream's RawDNS declares. The plan layer needs the
// list to know which fields it must NOT judge: a system/dhcp entry in any of
// them is stripped with a notice at activation, so refusing it here would
// refuse a configuration that runs.
//
// TestEveryDNSResolverFieldIsClassified drives this against RawDNS by
// reflection, so an upstream release that adds a resolver slot goes red here
// instead of silently handing an NE-incompatible resolver to the core.
var dnsResolverFields = []string{
	"nameserver",
	"fallback",
	"proxy-server-nameserver",
	"direct-nameserver",
	"nameserver-policy",
	"proxy-server-nameserver-policy",
}

func hardRejectErrors(root map[string]any, raw *config.RawConfig) ([]planError, []planNotice) {
	out := []planError{}
	notices := []planNotice{}
	// The transport-option value checks are gone from both layers: the
	// plan no longer reports them and the activation path no longer refuses
	// them, because upstream judges none of these values. Keeping the plan half
	// alone would have been the worst of both -- a notice about something that
	// still stopped the tunnel.
	//
	// What remains is one notice, and it is not a judgement about a range: a
	// value this build cannot represent at all is reported so the reader knows
	// the transport will read something other than what they wrote. Upstream
	// reads it as given too; it just says nothing. The node loads either way.
	// A proxy-group filter that will not compile, predicted here for the same
	// reason. It was refused only on the activation path
	// (validateRawProxyGroupRegexForIOS) until 2026-08-28, so the plan told the
	// reader their configuration was fine and the tunnel failed at Start --
	// while upstream, given the same input, PANICS in regexp2's Must-compile.
	// The parity sweep found it: mihomo refuses the document, the plan did not.
	for index, group := range raw.ProxyGroup {
		for _, field := range []string{"filter", "exclude-filter"} {
			value, ok := group[field].(string)
			if !ok || value == "" {
				continue
			}
			bad := false
			for _, expression := range strings.Split(value, "`") {
				if _, err := regexp2.Compile(expression, regexp2.None); err != nil {
					bad = true
					break
				}
			}
			if bad {
				// The expression is user-controlled and must not be echoed; the
				// indexed path is enough for an editor to find it.
				// refusal-id: ConfigPipeline.proxyGroupFilterRegex
				out = append(out, planError{
					Field:  fmt.Sprintf("proxy-groups[%d].%s", index, field),
					Reason: "is not a valid regular expression",
				})
			}
		}
	}

	// Upstream refuses these, so predicting the refusal here is not being
	// stricter -- it is telling the user now instead of at Start. Every reason
	// string is upstream's own error text, produced by upstream's own parser
	// (see upstreamRefusedOutboundOption).
	for _, issue := range upstreamRefusedOutboundOptions(raw) {
		// refusal-id: PlanResources.outboundOptionUpstreamRefuses
		out = append(out, planError{Field: issue.Field, Reason: issue.Reason})
	}
	for _, issue := range unrepresentableOutboundOptions(raw) {
		// refusal-id: PlanResources.outboundRuntimeOption (aligned to a notice)
		notices = append(notices, planNotice{Kind: planNoticeOutboundOptionUnrepresentable, Field: issue.Field,
			Text: issue.Field + ": " + issue.Reason + "; the node still loads and the transport reads what it can"})
	}
	if field := firstOutboundEmbeddedDNSFragment(raw); field != "" {
		// adapter/outbound/wireguard.go:496-503 parses the nested servers and
		// then overwrites ProxyAdapter unconditionally, so the fragment is
		// dropped and the outbound is built anyway. Upstream drops it in
		// silence; this says so.
		// refusal-id: PlanResources.outboundEmbeddedDnsFragment (aligned to a notice)
		notices = append(notices, planNotice{Kind: planNoticeOutboundDNSFragmentInert, Field: field,
			Text: field + ": nested DNS is pinned to that outbound, so the '#' fragment selects nothing; the outbound still starts"})
	}
	if dns, ok := root["dns"].(map[string]any); ok {
		// Only the bootstrap is left to judge. Every OTHER dns field that holds
		// resolvers -- the six in dnsResolverFields -- tolerates system/dhcp and
		// strips it with a notice, and the seven names in dnsResolverFields plus
		// default-nameserver are ALL of the resolver-bearing fields upstream's
		// RawDNS declares. TestEveryDNSResolverFieldIsClassified pins that, so a
		// new upstream slot cannot arrive unnoticed.
		//
		// There used to be a catch-all here: every string in every OTHER dns
		// field was run through isNEIncompatibleNameserver and a hit refused the
		// whole configuration. It could not fire on a resolver -- those are all
		// handled above -- so every input it COULD reach was a false positive,
		// and three of them are pinned in
		// TestNonResolverDNSFieldsAreNotJudgedAsResolvers: a fake-ip-filter
		// entry, a fallback-filter domain and dns.listen, each refused with a
		// sentence about a "system/dhcp resolver" that the field never held.
		// The registry recorded the premise as unverified for exactly this
		// reason ("why can it strip from six and must refuse on a seventh") --
		// the answer is that there is no seventh.
		//
		// refusal-id: PlanResources.systemDhcpResolver (removed, nothing replaced it)
		if raw, present := dns["default-nameserver"]; present {
			// Bootstrap: system/dhcp entries are stripped like the query slots
			// and a bootstrap left empty is refilled with mihomo's own defaults,
			// so the only error left is a survivor mihomo itself refuses --
			// hostless junk that fails its pure-IP check.
			if _, _, rejected := defaultNameserverStrip(raw); rejected {
				// refusal-id: PlanResources.bootstrapNameserver
				out = append(out, planError{
					Field:  "dns.default-nameserver",
					Reason: "bootstrap keeps a resolver mihomo rejects (\"default nameserver should be pure IP\"); add an explicit IP nameserver",
				})
			}
		}
	}
	return out, notices
}

// defaultNameserverStrip reports how the bootstrap default-nameserver list is
// handled, mirroring filterBootstrap: strip=true when NE-incompatible entries
// are removed while a usable pure-IP bootstrap remains (a notice); kept=true
// when NE-incompatible entries are KEPT verbatim because stripping would leave
// no usable bootstrap and mihomo still accepts the list (a different notice --
// the entries are not stripped, and inside a packet tunnel a system bootstrap
// resolves only to the tunnel's own DNS address, which mihomo blacklists);
// empty=true when what reaches mihomo is
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
func strippedDNSSchemeNotices(root map[string]any, policy appleRuntimePolicy) []planNotice {
	if !policy.networkExtension {
		return nil
	}
	dns, ok := root["dns"].(map[string]any)
	if !ok {
		return nil
	}
	notices := []planNotice{}
	for _, field := range []string{
		"nameserver", "fallback", "proxy-server-nameserver", "direct-nameserver",
		"nameserver-policy", "proxy-server-nameserver-policy",
	} {
		walkStrings(dns[field], func(v string) {
			if isNEIncompatibleNameserver(v) {
				notices = append(notices, planNotice{Kind: planNoticeDNSSystemResolverStripped, Field: "dns." + field, Value: v,
					Text: "dns." + field + " '" + v + "' (system/dhcp) is stripped inside a packet tunnel; resolution stays inside the core"})
			}
		})
	}
	strip, repaired, _ := defaultNameserverStrip(dns["default-nameserver"])
	switch {
	case strip:
		walkStrings(dns["default-nameserver"], func(v string) {
			if isNEIncompatibleNameserver(v) {
				notices = append(notices, planNotice{Kind: planNoticeDNSSystemResolverStripped, Field: "dns.default-nameserver", Value: v,
					Text: "dns.default-nameserver '" + v + "' (system/dhcp) is stripped inside a packet tunnel; resolution stays inside the core"})
			}
		})
	case repaired:
		notices = append(notices, planNotice{Kind: planNoticeDNSBootstrapReplaced, Field: "dns.default-nameserver",
			Text: "dns.default-nameserver has no resolver a packet tunnel can bootstrap from, so it receives the core's own explicit defaults; set an IP bootstrap (e.g. 223.5.5.5) to choose your own"})
	}
	return notices
}

// strippedDNSFragmentNotices reports each fragment iOS cannot statically route
// as a notice, never an error: the fragment is kept and that resolver fails
// closed at runtime unless the name materializes (never silently rerouted).
func strippedDNSFragmentNotices(raw *config.RawConfig, policy appleRuntimePolicy) []planNotice {
	if !policy.networkExtension {
		return nil
	}
	notices := []planNotice{}
	for _, entry := range detectUnroutableDNSFragments(raw) {
		notices = append(notices, planNotice{Kind: planNoticeDNSFragmentUnroutable, Field: "dns." + entry,
			Text: "dns." + entry + ": fragment names a physical interface/unknown proxy; kept — fails closed at runtime unless the name materializes"})
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
