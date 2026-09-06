package main

import (
	"os"
	"path/filepath"
	"testing"
)

// configFixture is a miniature RawConfig schema exercising each shape the
// collector must handle: scalar leaf, external-typed leaf, nested struct,
// doubly-nested struct, pointer-to-generic leaf, map/slice leaves, an untagged
// field and a yaml:"-" field (both excluded). It also carries the fields the
// enforcement fixtures below write/read (external-controller, tun.route-address-set).
const configFixture = `package config
type RawConfig struct {
	Port               int                                 ` + "`yaml:\"port\"`" + `
	Mode               T.TunnelMode                        ` + "`yaml:\"mode\"`" + `
	Interface          string                              ` + "`yaml:\"interface-name\"`" + `
	GeoAutoUpdate      bool                                ` + "`yaml:\"geo-auto-update\"`" + `
	GeodataLoader      string                              ` + "`yaml:\"geodata-loader\"`" + `
	ExternalController string                              ` + "`yaml:\"external-controller\"`" + `
	Listeners          []map[string]any                    ` + "`yaml:\"listeners\"`" + `
	Proxies            []map[string]any                    ` + "`yaml:\"proxies\"`" + `
	DNS                RawDNS                              ` + "`yaml:\"dns\"`" + `
	Tun                RawTun                              ` + "`yaml:\"tun\"`" + `
	Rule               []string                            ` + "`yaml:\"rules\"`" + `
	Secret             string                              ` + "`yaml:\"-\"`" + `
	Untagged           string
}
type RawDNS struct {
	Listen string                              ` + "`yaml:\"listen\"`" + `
	Filter RawFilter                           ` + "`yaml:\"fallback-filter\"`" + `
	Policy *orderedmap.OrderedMap[string, any] ` + "`yaml:\"nameserver-policy\"`" + `
}
type RawFilter struct {
	GeoIP bool ` + "`yaml:\"geoip\"`" + `
}
type RawTun struct {
	RouteAddressSet []string ` + "`yaml:\"route-address-set\"`" + `
}
`

const overrideFixture = `package hako
func overrideForIOS(cfg *config.Config) {
	cfg.General.GeoAutoUpdate = false
	cfg.General.Interface = ""
	cfg.General.GeodataLoader = "memconservative"
	cfg.DNS.Listen = ""
	cfg.Listeners = nil
	*cfg.Controller = config.Controller{}
	local := 5
	_ = local
}
`

const pipelineFixture = `package hako
func normalizeRawNetworkExtensionSurfaces(raw *config.RawConfig) {
	raw.Port = 0
	raw.ExternalController = ""
	raw.GeodataLoader = "memconservative"
	raw.Rule = filterRules(raw.Rule)
}
func repairMacOSPacketTunnelDNS(raw *config.RawConfig) {
	raw.Port = 5353
}
`

// validateFixture proves reject extraction is scoped to the reject function: the
// read in somethingElse must NOT surface as a reject.
const validateFixture = `package hako
func validateRawNetworkExtensionIntentForApple(raw *config.RawConfig, policy appleRuntimePolicy) error {
	if len(raw.Tun.RouteAddressSet) > 0 {
		return errReject
	}
	return nil
}
func somethingElse(raw *config.RawConfig) {
	_ = raw.DNS.Listen
}
`

func newFixture(t *testing.T) (*generator, string) {
	t.Helper()
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cfgDir := filepath.Join(dir, "config")
	if err := os.Mkdir(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfgDir, "config.go"), []byte(configFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	gen, err := newGenerator(cfgDir)
	if err != nil {
		t.Fatalf("newGenerator: %v", err)
	}
	write("override.go", overrideFixture)
	write("config_pipeline.go", pipelineFixture)
	write("validate.go", validateFixture)
	return gen, dir
}

func TestCollectFlattensDottedPathsAndSkipsNonSurface(t *testing.T) {
	gen, _ := newFixture(t)
	fields, err := gen.collect(entryStruct, "", map[string]bool{})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	got := map[string]string{}
	for _, f := range fields {
		got[f.Path] = f.GoType
	}
	want := map[string]string{
		"port":                      "int",
		"mode":                      "T.TunnelMode",
		"interface-name":            "string",
		"geo-auto-update":           "bool",
		"geodata-loader":            "string",
		"external-controller":       "string",
		"listeners":                 "[]map[string]any",
		"proxies":                   "[]map[string]any",
		"dns.listen":                "string",
		"dns.fallback-filter.geoip": "bool",
		"dns.nameserver-policy":     "*orderedmap.OrderedMap[string, any]",
		"tun.route-address-set":     "[]string",
		"rules":                     "[]string",
	}
	for path, typ := range want {
		if got[path] != typ {
			t.Errorf("field %q: goType = %q, want %q", path, got[path], typ)
		}
	}
	if len(got) != len(want) {
		t.Errorf("field count = %d, want %d; got paths: %v", len(got), len(want), keys(got))
	}
	if _, leaked := got["dns"]; leaked {
		t.Error("nested struct 'dns' emitted as a leaf; must recurse only")
	}
}

func TestAssignEvidenceOverrideAndPipeline(t *testing.T) {
	gen, dir := newFixture(t)
	// override.go: processed *config.Config, wrappers flattened.
	ov, err := gen.assignEvidence(filepath.Join(dir, "override.go"), "cfg", true, nil)
	if err != nil {
		t.Fatalf("assignEvidence override: %v", err)
	}
	assertEvidence(t, "override", ov, map[string]struct {
		path, kind string
		resolved   bool
	}{
		"General.GeoAutoUpdate": {"geo-auto-update", "cleared", true}, // wrapper flattened
		"General.Interface":     {"interface-name", "cleared", true},
		"General.GeodataLoader": {"geodata-loader", "forced", true}, // non-zero literal
		"DNS.Listen":            {"dns.listen", "cleared", true},    // nested sub-struct
		"Listeners":             {"listeners", "cleared", true},
		"Controller":            {"", "cleared", false}, // not a RawConfig member
	})

	// config_pipeline.go: *config.RawConfig directly, no wrapper flattening.
	cp, err := gen.assignEvidence(filepath.Join(dir, "config_pipeline.go"), "raw", false, nil, "repairMacOSPacketTunnelDNS")
	if err != nil {
		t.Fatalf("assignEvidence pipeline: %v", err)
	}
	assertEvidence(t, "pipeline", cp, map[string]struct {
		path, kind string
		resolved   bool
	}{
		"Port":               {"port", "cleared", true},
		"ExternalController": {"external-controller", "cleared", true},
		"GeodataLoader":      {"geodata-loader", "forced", true},
		"Rule":               {"rules", "normalized", true}, // filter(raw.Rule): kept, entries stripped
	})
}

func TestRejectEvidenceScopedToFunction(t *testing.T) {
	gen, dir := newFixture(t)
	ev, err := gen.rejectEvidence(filepath.Join(dir, "validate.go"), "validateRawNetworkExtensionIntentForApple")
	if err != nil {
		t.Fatalf("rejectEvidence: %v", err)
	}
	paths := map[string]bool{}
	for _, e := range ev {
		if e.Kind != "reject" {
			t.Errorf("evidence kind = %q, want reject", e.Kind)
		}
		paths[e.Path] = true
	}
	if !paths["tun.route-address-set"] {
		t.Error("reject on tun.route-address-set not extracted")
	}
	if paths["dns.listen"] {
		t.Error("dns.listen read in a DIFFERENT function leaked as a reject; scoping is broken")
	}
	if paths["tun"] {
		t.Error("non-leaf 'tun' emitted as reject; only leaf fields should be")
	}
}

func TestEnforcementUsesAppleProfileRejectFunction(t *testing.T) {
	gen, dir := newFixture(t)
	ev, err := gen.enforcement(dir)
	if err != nil {
		t.Fatalf("enforcement: %v", err)
	}
	for _, e := range ev {
		if e.Kind == "reject" && e.Path == "tun.route-address-set" {
			return
		}
	}
	t.Fatal("enforcement omitted the Apple profile route-set reject")
}

func TestAssignEvidenceExcludesPlatformSpecificFunctions(t *testing.T) {
	gen, dir := newFixture(t)
	ev, err := gen.assignEvidence(
		filepath.Join(dir, "config_pipeline.go"),
		"raw",
		false,
		nil,
		"repairMacOSPacketTunnelDNS",
	)
	if err != nil {
		t.Fatalf("assignEvidence: %v", err)
	}
	for _, item := range ev {
		if item.Path == "port" && item.Kind == "forced" {
			t.Fatalf("macOS-only forced port leaked into iOS evidence: %+v", item)
		}
	}
}

func assertEvidence(t *testing.T, label string, ev []evidence, want map[string]struct {
	path, kind string
	resolved   bool
}) {
	t.Helper()
	got := map[string]evidence{}
	for _, e := range ev {
		got[e.Selector] = e
	}
	for sel, w := range want {
		e, ok := got[sel]
		if !ok {
			t.Errorf("%s: missing evidence for %q", label, sel)
			continue
		}
		if e.Path != w.path || e.Kind != w.kind || e.Resolved != w.resolved {
			t.Errorf("%s %q: got {path:%q kind:%q resolved:%v}, want {path:%q kind:%q resolved:%v}",
				label, sel, e.Path, e.Kind, e.Resolved, w.path, w.kind, w.resolved)
		}
	}
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
