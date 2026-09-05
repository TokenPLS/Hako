package hako

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"

	P "github.com/TokenPLS/Hako/constant/provider"
	"github.com/TokenPLS/Hako/log"
	ruleprovider "github.com/TokenPLS/Hako/rules/provider"
	"gopkg.in/yaml.v3"
)

const maximumExpandedRoutePrefixes = 65_536

type resourceMap struct {
	// ProviderPaths are keyed by schema-v2 "proxy:<name>" / "rule:<name>".
	// A bare name remains accepted only when it is unambiguous across the two
	// provider namespaces.
	ProviderPaths map[string]string `json:"providerPaths"`
	// ProviderReadPaths point at unpublished candidate files that Finalize may
	// inspect while expanding route-address-set. They are never serialized into
	// the resulting YAML. Older clients may omit this field.
	ProviderReadPaths map[string]string `json:"providerReadPaths"`
}

// FinalizeForIOS rewrites materialized http providers to type:file and expands
// route-address-set references into literal route-address CIDR lists read from
// the local provider files. Unsupported route intent is deliberately preserved
// so the subsequent iOS preflight rejects it instead of silently changing it.
func FinalizeForIOS(mergedYAML string, resourceMapJSON string) (*StringBox, error) {
	if err := validateConfigurationInput(mergedYAML); err != nil {
		return nil, bridgeSafeError(err)
	}
	if err := validateConfigurationJSONInput(resourceMapJSON); err != nil {
		return nil, bridgeSafeError(err)
	}
	var rm resourceMap
	if resourceMapJSON != "" {
		if err := json.Unmarshal([]byte(resourceMapJSON), &rm); err != nil {
			return nil, bridgeSafeError(err)
		}
	}
	var root map[string]any
	if err := yaml.Unmarshal([]byte(mergedYAML), &root); err != nil {
		return nil, bridgeSafeError(err)
	}
	// Upstream matches definition keys case-insensitively; every reader below
	// spells them lowercase. Canonicalize before any of them looks, or a
	// `Type: http` provider walks past the http→file rewrite and reaches the
	// published revision still remote.
	canonicalizeProviderDefinitionKeysInDocument(root)
	routeProviders := routeProviderSpecs(root)
	platformRouteProviders := map[string]bool{}
	if tun, ok := root["tun"].(map[string]any); ok {
		platformRouteProviders = routeSetProviderNames(tun)
	}
	annotateRuleProviderSideUpdateSafety(root, platformRouteProviders)
	collisions := providerNamespaceCollisions(root)
	if err := rewriteProviders(root, "proxy-providers", "proxy", rm.ProviderPaths, collisions); err != nil {
		return nil, bridgeSafeError(err)
	}
	if err := rewriteProviders(root, "rule-providers", "rule", rm.ProviderPaths, collisions); err != nil {
		return nil, bridgeSafeError(err)
	}
	readPaths := rm.ProviderReadPaths
	if len(readPaths) == 0 {
		readPaths = rm.ProviderPaths
	}
	if tun, ok := root["tun"].(map[string]any); ok {
		if err := expandRouteSet(tun, "route-address-set", "route-address", readPaths, routeProviders, collisions); err != nil {
			return nil, bridgeSafeError(err)
		}
		if err := expandRouteSet(tun, "route-exclude-address-set", "route-exclude-address", readPaths, routeProviders, collisions); err != nil {
			return nil, bridgeSafeError(err)
		}
	}
	out, err := yaml.Marshal(root)
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	// This runs on every activation, with or without an override, so without this line every
	// profile reaches the core with its mappings alphabetised -- including the one the DNS
	// resolver walks in order. See restoreSourceKeyOrder.
	finalized := restoreSourceKeyOrder(mergedYAML, string(out))
	if err := validateConfigurationResult(finalized); err != nil {
		return nil, bridgeSafeError(err)
	}
	return WrapString(finalized), nil
}

func routeSetProviderNames(tun map[string]any) map[string]bool {
	result := make(map[string]bool)
	for _, field := range []string{"route-address-set", "route-exclude-address-set"} {
		values, _ := tun[field].([]any)
		for _, value := range values {
			if name, ok := value.(string); ok && name != "" {
				result[name] = true
			}
		}
	}
	return result
}

// The marker is consumed and removed by parseConfigForIOSInternal before
// upstream parsing. Absence is deliberately fail-closed for old revisions.
func annotateRuleProviderSideUpdateSafety(root map[string]any, platformRouteProviders map[string]bool) {
	providers, _ := root["rule-providers"].(map[string]any)
	for name, raw := range providers {
		definition, _ := raw.(map[string]any)
		typeName, _ := definition["type"].(string)
		if typeName != "file" && typeName != "http" {
			continue
		}
		definition[providerSideUpdateSafeField] = !platformRouteProviders[name]
	}
}

type routeProviderSpec struct {
	format   string
	behavior string
	inline   []string
	isInline bool
}

func routeProviderSpecs(root map[string]any) map[string]routeProviderSpec {
	result := map[string]routeProviderSpec{}
	providers, ok := root["rule-providers"].(map[string]any)
	if !ok {
		return result
	}
	for name, raw := range providers {
		definition, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		format, _ := definition["format"].(string)
		if format == "" {
			format = "yaml"
		}
		behavior, _ := definition["behavior"].(string)
		spec := routeProviderSpec{
			format:   strings.ToLower(format),
			behavior: strings.ToLower(behavior),
		}
		if typeName, _ := definition["type"].(string); strings.EqualFold(typeName, "inline") {
			spec.isInline = true
			if payload, ok := definition["payload"].([]any); ok {
				for _, item := range payload {
					if value, ok := item.(string); ok {
						spec.inline = append(spec.inline, value)
					}
				}
			}
		}
		result[name] = spec
	}
	return result
}

func providerNamespaceCollisions(root map[string]any) map[string]bool {
	proxyNames := httpProviderNameSet(root, "proxy-providers")
	ruleNames := httpProviderNameSet(root, "rule-providers")
	collisions := map[string]bool{}
	for name := range proxyNames {
		if ruleNames[name] {
			collisions[name] = true
		}
	}
	return collisions
}

func httpProviderNameSet(root map[string]any, key string) map[string]bool {
	result := map[string]bool{}
	providers, _ := root[key].(map[string]any)
	for name, raw := range providers {
		definition, _ := raw.(map[string]any)
		if typeName, _ := definition["type"].(string); strings.EqualFold(typeName, "http") {
			result[name] = true
		}
	}
	return result
}

func providerPath(paths map[string]string, kind, name string, collisions map[string]bool) (string, bool, error) {
	if path, ok := paths[providerResourceKey(kind, name)]; ok {
		if strings.TrimSpace(path) == "" {
			return "", false, fmt.Errorf("provider resource path %q is empty", providerResourceKey(kind, name))
		}
		return path, true, nil
	}
	if collisions[name] {
		if _, legacy := paths[name]; legacy {
			return "", false, fmt.Errorf("provider %q exists in proxy and rule namespaces; use schema-v2 resource keys", name)
		}
		return "", false, nil
	}
	path, ok := paths[name]
	if ok && strings.TrimSpace(path) == "" {
		return "", false, fmt.Errorf("provider resource path %q is empty", name)
	}
	return path, ok, nil
}

func rewriteProviders(root map[string]any, key, kind string, paths map[string]string, collisions map[string]bool) error {
	m, ok := root[key].(map[string]any)
	if !ok {
		return nil
	}
	for name, raw := range m {
		def, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if t, _ := def["type"].(string); !strings.EqualFold(t, "http") {
			continue
		}
		// A provider whose url this build cannot use was never put in the
		// download plan, so demanding that it be materialized would refuse the
		// configuration for a provider nobody was ever asked to fetch -- and
		// the message would be about our plumbing ("was not materialized")
		// rather than about the url the user typed. Both layers ask the same
		// question with the same predicate; the definition is then left alone
		// and reaches the kernel, which fails its download and rides empty
		// (hub/executor/executor.go:400), exactly as upstream does.
		// No `rawURL != ""` guard: an absent url is exactly a url this build
		// cannot fetch, and skipping the question for it sent an http provider
		// with no url down the "was not materialized" path -- a message about
		// our plumbing, for a provider the app was never asked to fetch.
		// Upstream declares url as omitempty, never checks it, and accepts the
		// document. Same predicate as validate.go's unfetchableProviderNames
		// and config_pipeline.go's raw check; three layers, one question.
		if rawURL, _ := def["url"].(string); true {
			if _, err := normalizeResourceURL(rawURL, "provider"); err != nil {
				continue
			}
		}
		path, found, err := providerPath(paths, kind, name, collisions)
		if err != nil {
			return err
		}
		if !found {
			// The app has no copy of this one (offline at activation, or a host it
			// could not reach). The definition stays a remote provider with every
			// field it was written with; the core starts it empty and downloads it
			// in the background (DeferRemoteInitialFetch), storing it under the
			// path the profile names or upstream's default
			// <home>/<proxies|rules>/<hash(url)>.
			continue
		}
		def["type"] = "file"
		def["path"] = path
		for _, remoteOnlyField := range []string{
			"url", "interval", "size-limit", "proxy", "header", "age-secret-key",
		} {
			delete(def, remoteOnlyField)
		}
	}
	return nil
}

func expandRouteSet(tun map[string]any, setKey, destKey string, paths map[string]string, providers map[string]routeProviderSpec, collisions map[string]bool) error {
	list, ok := tun[setKey].([]any)
	if !ok {
		return nil
	}
	var cidrs []any
	var skipped []string
	seen := map[string]struct{}{}
	for _, item := range list {
		name, _ := item.(string)
		// Both of these used to refuse the whole configuration, and upstream
		// refuses neither. listener/sing_tun/server.go:565-593 switches on the
		// provider's behavior and falls to `default: return`, so a set that is
		// not ipcidr contributes no routes and the tunnel starts; an undefined
		// name is equally inert. Driving mihomo over both confirms it accepts
		// each one, which is what settled this rather than reading the switch.
		//
		// So they are skipped here too. The set contributes nothing, exactly as
		// upstream, instead of costing the user every other line of their
		// configuration. Twice before this was changed in the plan layer alone
		// and reverted, because THIS function refused a second time further
		// down and the tunnel still would not start -- that is the whole reason
		// TestEveryToleratedInputSurvivesActivation now drives
		// parseConfigForIOSRuntime instead of stopping at Finalize.
		//
		// Registered as PlanResources.routeAddressSet, whose upstream verdict
		// this corrects: it read "rejects" while its own evidence said upstream
		// "would tolerate", and its platformForced named app-side expansion --
		// this product's architecture, not a NetworkExtension limit. Found by
		// Codex 2026-08-27.
		spec, defined := providers[name]
		if !defined {
			skipped = append(skipped, name+" (no such provider)")
			continue
		}
		if spec.behavior != "ipcidr" {
			skipped = append(skipped, name+" (behavior "+spec.behavior+", not ipcidr)")
			continue
		}
		var entries []string
		var err error
		if spec.isInline {
			entries, err = validateRouteCIDRs(spec.inline)
		} else {
			path, found, pathErr := providerPath(paths, "rule", name, collisions)
			if pathErr != nil {
				return pathErr
			}
			if !found {
				return fmt.Errorf("%s provider %q was not materialized", setKey, name)
			}
			entries, err = readCIDRs(path, spec.format)
		}
		if err != nil {
			return fmt.Errorf("read %s provider %q: %w", setKey, name, err)
		}
		for _, c := range entries {
			if _, exists := seen[c]; exists {
				continue
			}
			seen[c] = struct{}{}
			cidrs = append(cidrs, c)
		}
		if len(cidrs) > maximumExpandedRoutePrefixes {
			return fmt.Errorf("%s expands to more than %d prefixes", setKey, maximumExpandedRoutePrefixes)
		}
	}
	if len(skipped) > 0 {
		log.Warnln("[Apple] tun.%s: %s contributed no routes and were skipped; the tunnel still starts, as it does upstream",
			setKey, strings.Join(skipped, ", "))
	}
	delete(tun, setKey)
	if len(cidrs) > 0 {
		if existing, ok := tun[destKey].([]any); ok {
			if len(existing)+len(cidrs) > maximumExpandedRoutePrefixes {
				return fmt.Errorf("%s and %s exceed %d prefixes", destKey, setKey, maximumExpandedRoutePrefixes)
			}
			tun[destKey] = append(existing, cidrs...)
		} else {
			tun[destKey] = cidrs
		}
	}
	return nil
}

// readCIDRs reads the exact ipcidr provider format declared in the profile.
func readCIDRs(path, format string) ([]string, error) {
	data, err := readBoundedRegularFile(path, int64(maximumProviderResourceBytes), "route-set provider")
	if err != nil {
		return nil, err
	}
	var entries []string
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "yaml":
		var doc struct {
			Payload []string `yaml:"payload"`
		}
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("parse yaml: %w", err)
		}
		entries = doc.Payload
	case "text":
		entries, err = scanCIDRText(data)
	case "mrs":
		if err := validateMRSForIOS(data, P.IPCIDR); err != nil {
			return nil, fmt.Errorf("validate mrs: %w", err)
		}
		var decoded boundedBuffer
		decoded.maximum = int64(maximumProviderResourceBytes)
		if err := ruleprovider.ConvertToMrs(data, P.IPCIDR, P.MrsRule, &decoded); err != nil {
			return nil, fmt.Errorf("decode mrs: %w", err)
		}
		entries, err = scanCIDRText(decoded.Bytes())
	default:
		return nil, fmt.Errorf("unsupported ipcidr provider format %q", format)
	}
	if err != nil {
		return nil, err
	}
	return validateRouteCIDRs(entries)
}

func scanCIDRText(data []byte) ([]string, error) {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("provider contains no CIDR entries")
	}
	return out, nil
}

func validateRouteCIDRs(entries []string) ([]string, error) {
	if len(entries) == 0 {
		return nil, fmt.Errorf("provider contains no CIDR entries")
	}
	result := make([]string, 0, len(entries))
	seen := make(map[netip.Prefix]struct{}, len(entries))
	for index, entry := range entries {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(entry))
		if err != nil {
			return nil, fmt.Errorf("CIDR %d %q is invalid: %w", index, entry, err)
		}
		prefix = prefix.Masked()
		if _, exists := seen[prefix]; exists {
			continue
		}
		seen[prefix] = struct{}{}
		result = append(result, prefix.String())
		if len(result) > maximumExpandedRoutePrefixes {
			return nil, fmt.Errorf("provider exceeds %d route prefixes", maximumExpandedRoutePrefixes)
		}
	}
	return result, nil
}

type boundedBuffer struct {
	bytes.Buffer
	maximum int64
}

func (buffer *boundedBuffer) Write(data []byte) (int, error) {
	if int64(buffer.Len())+int64(len(data)) > buffer.maximum {
		return 0, fmt.Errorf("decoded provider exceeds %d bytes", buffer.maximum)
	}
	return buffer.Buffer.Write(data)
}
