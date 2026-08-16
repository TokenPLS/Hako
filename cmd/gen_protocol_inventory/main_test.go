package main

import "testing"

const outboundDir = "../../adapter/outbound"

func testGenerator(t *testing.T) *generator {
	t.Helper()
	gen, err := newGenerator(outboundDir)
	if err != nil {
		t.Fatalf("newGenerator: %v", err)
	}
	return gen
}

func collectType(t *testing.T, gen *generator, proxyType string) []inventoryField {
	t.Helper()
	structName, ok := proxyTypeStructs[proxyType]
	if !ok {
		t.Fatalf("unknown proxy type %q", proxyType)
	}
	fields, err := gen.collect(structName, map[string]bool{})
	if err != nil {
		t.Fatalf("collect %s: %v", proxyType, err)
	}
	return fields
}

func fieldByKey(fields []inventoryField, key string) *inventoryField {
	for i := range fields {
		if fields[i].Key == key {
			return &fields[i]
		}
	}
	return nil
}

func hasGoName(fields []inventoryField, goName string) bool {
	for _, f := range fields {
		if f.GoName == goName {
			return true
		}
	}
	return false
}

func TestInventoryMapsEveryParserType(t *testing.T) {
	gen := testGenerator(t)
	if len(proxyTypeStructs) != 26 {
		t.Fatalf("expected 26 proxy types, got %d", len(proxyTypeStructs))
	}
	if got := proxyTypeStructs["shadowquic"]; got != "ShadowQuicOption" {
		t.Fatalf("shadowquic maps to %q, want ShadowQuicOption", got)
	}
	for proxyType, structName := range proxyTypeStructs {
		if _, ok := gen.structs[structName]; !ok {
			t.Errorf("type %q maps to %q which is not defined in the outbound package", proxyType, structName)
		}
	}
}

func TestInventoryFlattensBasicOptionAndRendersSourceTypes(t *testing.T) {
	gen := testGenerator(t)
	http := collectType(t, gen, "http")
	// BasicOption is flattened into the top level, ahead of the type's own keys.
	for _, want := range []string{"tfo", "mptcp", "interface-name", "routing-mark", "ip-version", "dialer-proxy", "server", "port"} {
		if fieldByKey(http, want) == nil {
			t.Errorf("http inventory missing flattened key %q", want)
		}
	}
	// goType is the source literal, which reflection could not reproduce.
	if f := fieldByKey(http, "ip-version"); f == nil || f.GoType != "C.DNSPrefer" {
		t.Errorf("ip-version goType = %q, want C.DNSPrefer", goTypeOrEmpty(f))
	}
	if f := fieldByKey(http, "server"); f == nil || !f.Required {
		t.Errorf("server should be required (no omitempty): %+v", f)
	}
	if f := fieldByKey(http, "sni"); f == nil || f.Required {
		t.Errorf("sni should be optional (omitempty): %+v", f)
	}
	// Internal proxy:"-" fields must never leak into the editor catalog.
	for _, internal := range []string{"DialerForAPI", "TunnelForAPI", "ProviderName"} {
		if hasGoName(http, internal) {
			t.Errorf("http leaked internal proxy:\"-\" field %q", internal)
		}
	}
}

func TestInventoryNestsStructsAndKeepsMapLeaf(t *testing.T) {
	gen := testGenerator(t)
	wg := collectType(t, gen, "wireguard")
	peers := fieldByKey(wg, "peers")
	if peers == nil || len(peers.Nested) == 0 {
		t.Fatalf("wireguard peers must be nested, got %+v", peers)
	}
	if fieldByKey(peers.Nested, "public-key") == nil {
		t.Errorf("wireguard peers nested fields missing public-key")
	}
	// plugin-opts is map[string]any: a leaf, never expanded.
	ss := collectType(t, gen, "ss")
	pluginOpts := fieldByKey(ss, "plugin-opts")
	if pluginOpts == nil || pluginOpts.GoType != "map[string]any" || len(pluginOpts.Nested) != 0 {
		t.Errorf("ss plugin-opts should be a map[string]any leaf, got %+v", pluginOpts)
	}
}

func TestInventoryExcludesSingMux(t *testing.T) {
	gen := testGenerator(t)
	for proxyType := range proxyTypeStructs {
		for _, f := range collectType(t, gen, proxyType) {
			if f.Key == "smux" || f.GoType == "SingMuxOption" {
				t.Errorf("type %q leaked an excluded SMUX field: %+v", proxyType, f)
			}
		}
	}
}

func goTypeOrEmpty(f *inventoryField) string {
	if f == nil {
		return ""
	}
	return f.GoType
}
