package hako

import (
	"fmt"
	"sort"
	"strings"

	"github.com/TokenPLS/Hako/common/structure"
)

const (
	projectionPackageCatalog   = "catalog"
	projectionPackageResources = "resources"
	projectionPackageRuleFacts = "ruleFacts"
	projectionPackageScalars   = "scalars"
)

// Bumped whenever a package's shape changes in a way a stored projection could
// not survive; the client keys stored projections by revision AND this.
const projectionSchemaVersion = 1

// Document kinds a caller may claim. The kernel cannot verify the claim, but
// embedding it makes misuse auditable: a source-census page that reads a
// "merged" artifact can refuse on sight. Two real incidents of exactly that
// confusion are on record.
const (
	projectionKindSource = "source"
	projectionKindMerged = "merged"
)

type projectionNode struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type projectionGroup struct {
	Name string `json:"name"`
	Type string `json:"type"`
	// Declared membership only -- never the effective set.
	Proxies    []string `json:"proxies"`
	Use        []string `json:"use"`
	IncludeAll bool     `json:"includeAll"`
	Filter     string   `json:"filter"`
}

type projectionCatalog struct {
	Proxies []projectionNode  `json:"proxies"`
	Groups  []projectionGroup `json:"groups"`
}

type projectionProvider struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Behavior string `json:"behavior"` // rule providers only; empty otherwise
	Path     string `json:"path"`
}

type projectionResources struct {
	ProxyProviders []projectionProvider `json:"proxyProviders"`
	RuleProviders  []projectionProvider `json:"ruleProviders"`
}

type projectionRuleFacts struct {
	RuleCount       int      `json:"ruleCount"`
	LastMatchTarget string   `json:"lastMatchTarget"` // "" when the file has no MATCH
	SubRuleNames    []string `json:"subRuleNames"`
}

// Scalars: PRESENCE from the generic root, VALUE from the typed RawConfig.
// Presence must not come from RawConfig -- it starts from DefaultRawConfig
// (config.go:507), so a key the reader never wrote would look declared. Value
// must not come from the root's dynamic type -- the runtime applies YAML-1.1
// and weak conversions (`enable: yes` is true, `global-ua: 123` is "123"),
// and requiring an exact Go type here reported those declared settings as
// absent. Absent stays absent; declared means what the runtime will do.
type projectionScalars struct {
	Mode      *string `json:"mode"`
	GlobalUA  *string `json:"globalUA"`
	DNSEnable *bool   `json:"dnsEnable"`
}

type configProjection struct {
	SchemaVersion int                  `json:"schemaVersion"`
	DocumentKind  string               `json:"documentKind"`
	Catalog       *projectionCatalog   `json:"catalog,omitempty"`
	Resources     *projectionResources `json:"resources,omitempty"`
	RuleFacts     *projectionRuleFacts `json:"ruleFacts,omitempty"`
	Scalars       *projectionScalars   `json:"scalars,omitempty"`
}

// The projection reads each mapping through mihomo's OWN weak decoder, with
// the same tag names the runtime parsers use (adapter/parser.go "proxy",
// adapter/outboundgroup/parser.go "group", adapter/provider/parser.go and
// rules/provider/parse.go "provider"). A first draft read exact Go types off
// the generic maps instead, and Codex's review showed how that lies:
// `include-all: 1` is true to the runtime (structure.go weak int->bool) but
// was projected as false, and a numeric member in `use` is a string to the
// runtime but was silently dropped. Reimplementing the conversion here would
// be a second decoder that drifts; borrowing the real one cannot drift.
//
// Every field is omitempty: a declaration the runtime would refuse (a group
// with no name) is still a declaration; refusing it is the runtime's job, not
// the projection's. Decode errors leave the partially-filled declaration --
// the runtime's own error remains the authoritative rejection.
type projectionProxyDecl struct {
	Name string `proxy:"name,omitempty"`
	Type string `proxy:"type,omitempty"`
}

type projectionGroupDecl struct {
	Name       string   `group:"name,omitempty"`
	Type       string   `group:"type,omitempty"`
	Proxies    []string `group:"proxies,omitempty"`
	Use        []string `group:"use,omitempty"`
	IncludeAll bool     `group:"include-all,omitempty"`
	Filter     string   `group:"filter,omitempty"`
}

type projectionProviderDecl struct {
	Type     string `provider:"type,omitempty"`
	Behavior string `provider:"behavior,omitempty"`
	Path     string `provider:"path,omitempty"`
}

// buildConfigProjection is the ONLY producer of a projection. Both the handle
// method and the one-shot export route through it; two producers that can
// disagree is the failure this design is most likely to have.
//
// It performs no I/O by construction: a provider's nodes are downloaded while
// the tunnel runs and are not in this document, so the projection can only
// ever report that a provider was declared.
func buildConfigProjection(doc *ConfigDocument, kind string, packages []string) (configProjection, error) {
	views, err := doc.snapshot()
	if err != nil {
		return configProjection{}, err
	}
	if kind != projectionKindSource && kind != projectionKindMerged {
		return configProjection{}, fmt.Errorf("hako: unknown projection document kind %q", kind)
	}
	out := configProjection{SchemaVersion: projectionSchemaVersion, DocumentKind: kind}
	wanted := make(map[string]bool, len(packages))
	for _, name := range packages {
		wanted[name] = true
	}
	// Per-call decoders: structure.Decoder itself is a thin option holder, but
	// per-call construction removes any shared-state question under concurrent
	// ProjectionJSON calls on one handle.
	proxyDecoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true})
	groupDecoder := structure.NewDecoder(structure.Option{TagName: "group", WeaklyTypedInput: true})
	providerDecoder := structure.NewDecoder(structure.Option{TagName: "provider", WeaklyTypedInput: true})
	if wanted[projectionPackageCatalog] {
		catalog := &projectionCatalog{
			Proxies: make([]projectionNode, 0, len(views.raw.Proxy)),
			Groups:  make([]projectionGroup, 0, len(views.raw.ProxyGroup)),
		}
		for _, proxy := range views.raw.Proxy {
			var decl projectionProxyDecl
			_ = proxyDecoder.Decode(proxy, &decl)
			catalog.Proxies = append(catalog.Proxies, projectionNode{
				Name: decl.Name, Type: decl.Type,
			})
		}
		for _, group := range views.raw.ProxyGroup {
			var decl projectionGroupDecl
			_ = groupDecoder.Decode(group, &decl)
			catalog.Groups = append(catalog.Groups, projectionGroup{
				Name:       decl.Name,
				Type:       decl.Type,
				Proxies:    decl.Proxies,
				Use:        decl.Use,
				IncludeAll: decl.IncludeAll,
				Filter:     decl.Filter,
			})
		}
		out.Catalog = catalog
	}
	if wanted[projectionPackageResources] {
		resources := &projectionResources{
			ProxyProviders: make([]projectionProvider, 0, len(views.raw.ProxyProvider)),
			RuleProviders:  make([]projectionProvider, 0, len(views.raw.RuleProvider)),
		}
		for name, definition := range views.raw.ProxyProvider {
			var decl projectionProviderDecl
			_ = providerDecoder.Decode(definition, &decl)
			resources.ProxyProviders = append(resources.ProxyProviders, projectionProvider{
				Name: name, Type: decl.Type, Path: decl.Path,
			})
		}
		for name, definition := range views.raw.RuleProvider {
			var decl projectionProviderDecl
			_ = providerDecoder.Decode(definition, &decl)
			resources.RuleProviders = append(resources.RuleProviders, projectionProvider{
				Name: name, Type: decl.Type, Behavior: decl.Behavior, Path: decl.Path,
			})
		}
		// Go randomizes map iteration; unsorted output would defeat any cache
		// keyed by content hash, and the symptom ("cache never hits") would sit
		// far from this cause.
		sort.Slice(resources.ProxyProviders, func(i, j int) bool {
			return resources.ProxyProviders[i].Name < resources.ProxyProviders[j].Name
		})
		sort.Slice(resources.RuleProviders, func(i, j int) bool {
			return resources.RuleProviders[i].Name < resources.RuleProviders[j].Name
		})
		out.Resources = resources
	}
	if wanted[projectionPackageRuleFacts] {
		facts := &projectionRuleFacts{
			RuleCount:    len(views.raw.Rule),
			SubRuleNames: make([]string, 0, len(views.raw.SubRules)),
		}
		for _, rule := range views.raw.Rule {
			parts := strings.Split(rule, ",")
			if len(parts) >= 2 && strings.EqualFold(strings.TrimSpace(parts[0]), "MATCH") {
				facts.LastMatchTarget = strings.TrimSpace(parts[1])
			}
		}
		for name := range views.raw.SubRules {
			facts.SubRuleNames = append(facts.SubRuleNames, name)
		}
		sort.Strings(facts.SubRuleNames)
		out.RuleFacts = facts
	}
	if wanted[projectionPackageScalars] {
		// Presence from the generic root (RawConfig fills defaults for absent
		// keys, config.go:507); VALUE from the typed RawConfig, which applied
		// the same YAML-1.1 and weak conversions the runtime lives by. The
		// first draft required the root value's exact dynamic type, so
		// `dns: {enable: yes}` (string in root, true to the runtime) and
		// `global-ua: 123` ("123" to the runtime) were reported as absent --
		// declared settings the UI would then not see.
		scalars := &projectionScalars{}
		if _, present := views.root["mode"]; present {
			mode := views.raw.Mode.String()
			scalars.Mode = &mode
		}
		if _, present := views.root["global-ua"]; present {
			globalUA := views.raw.GlobalUA
			scalars.GlobalUA = &globalUA
		}
		if dns, ok := views.root["dns"].(map[string]any); ok {
			if _, present := dns["enable"]; present {
				enable := views.raw.DNS.Enable
				scalars.DNSEnable = &enable
			}
		}
		out.Scalars = scalars
	}
	return out, nil
}
