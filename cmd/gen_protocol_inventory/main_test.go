package main

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

const repoRoot = "../.."

func testSurface(t *testing.T, name string) (*generator, map[string]string) {
	t.Helper()
	s := surfaces[name]
	gen, err := newGenerator(filepath.Join(repoRoot, s.optionDir), s.tagName)
	if err != nil {
		t.Fatalf("newGenerator(%s): %v", name, err)
	}
	roots, err := parserRoots(filepath.Join(repoRoot, s.parserFile), s.parserFunc, s.optionPkg, gen.constructors)
	if err != nil {
		t.Fatalf("parserRoots(%s): %v", name, err)
	}
	return gen, roots
}

func collectType(t *testing.T, gen *generator, roots map[string]string, typeName string) []inventoryField {
	t.Helper()
	structName, ok := roots[typeName]
	if !ok {
		t.Fatalf("unknown type %q", typeName)
	}
	fields, err := gen.collect(structName, map[string]bool{})
	if err != nil {
		t.Fatalf("collect %s: %v", typeName, err)
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

// The roots come from the parser switch, so a type upstream adds appears here the
// commit it lands. The 26 types the hand map used to carry are the floor (a walk
// that silently lost one would still "work"); zerotier is the 27th, the one the
// hand map missed for a whole upstream sync.
func TestProxyRootsAreReadFromTheParserSwitch(t *testing.T) {
	gen, roots := testSurface(t, "proxies")
	previouslyHandKept := []string{
		"ss", "ssr", "socks5", "http", "vmess", "vless", "snell", "trojan", "hysteria", "hysteria2",
		"wireguard", "tuic", "gost-relay", "direct", "dns", "reject", "rematch", "ssh", "mieru", "anytls",
		"sudoku", "masque", "trusttunnel", "openvpn", "tailscale", "shadowquic",
	}
	for _, typeName := range previouslyHandKept {
		if _, ok := roots[typeName]; !ok {
			t.Errorf("type %q vanished from the derived roots", typeName)
		}
	}
	if got := roots["zerotier"]; got != "ZeroTierOption" {
		t.Fatalf("zerotier maps to %q, want ZeroTierOption (v1.19.30's new outbound)", got)
	}
	if got := roots["shadowquic"]; got != "ShadowQuicOption" {
		t.Fatalf("shadowquic maps to %q, want ShadowQuicOption", got)
	}
	if len(roots) != 27 {
		t.Fatalf("expected 27 proxy types at v1.19.30, derived %d: %v", len(roots), sortedKeys(roots))
	}
	for typeName, structName := range roots {
		if _, ok := gen.structs[structName]; !ok {
			t.Errorf("type %q maps to %q which is not defined in the outbound package", typeName, structName)
		}
	}
}

// The listener surface uses the same walk over ParseListener; hysteria2-realm is
// the one case that obtains its option through a constructor rather than a literal.
func TestListenerRootsAreReadFromTheParserSwitch(t *testing.T) {
	gen, roots := testSurface(t, "listeners")
	for _, typeName := range []string{"socks", "http", "mixed", "tun", "tuic", "hysteria2", "shadowquic", "anytls"} {
		if _, ok := roots[typeName]; !ok {
			t.Errorf("listener type %q missing from the derived roots", typeName)
		}
	}
	if got := roots["hysteria2-realm"]; got != "Hysteria2RealmServerOption" {
		t.Fatalf("hysteria2-realm maps to %q, want Hysteria2RealmServerOption via the constructor shape", got)
	}
	if len(roots) != 20 {
		t.Fatalf("expected 20 listener types at v1.19.30, derived %d: %v", len(roots), sortedKeys(roots))
	}
	for typeName, structName := range roots {
		if _, ok := gen.structs[structName]; !ok {
			t.Errorf("listener type %q maps to %q which is not defined in listener/inbound", typeName, structName)
		}
	}
	realm := collectType(t, gen, roots, "hysteria2-realm")
	if len(realm) == 0 || fieldByKey(realm, "listen") == nil {
		t.Fatalf("hysteria2-realm inventory should flatten BaseOption (listen), got %d fields", len(realm))
	}
}

// A case the walk cannot pair with an option struct must be an error, never a
// silently dropped type -- that silence is the failure this generator replaces.
func TestParserRootsFailClosedOnAnUnrecognisedCaseShape(t *testing.T) {
	dir := t.TempDir()
	src := `package p

func ParseThing(mapping map[string]any) (any, error) {
	kind, _ := mapping["type"].(string)
	var out any
	switch kind {
	case "known":
		o := &opt.KnownOption{}
		out = o
	case "mystery":
		out = buildSomewhereElse(mapping)
	default:
		return nil, nil
	}
	return out, nil
}
`
	path := filepath.Join(dir, "parse.go")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := parserRoots(path, "ParseThing", "opt", map[string]string{})
	if err == nil || !strings.Contains(err.Error(), `case "mystery"`) {
		t.Fatalf("a case with no option struct must fail by name, got %v", err)
	}
	// The same file with the constructor shape resolves once the constructor is known.
	src = strings.Replace(src, "out = buildSomewhereElse(mapping)", "o := opt.DefaultMysteryOption()\n\t\tout = o", 1)
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	roots, err := parserRoots(path, "ParseThing", "opt", map[string]string{"DefaultMysteryOption": "MysteryOption"})
	if err != nil {
		t.Fatal(err)
	}
	if roots["known"] != "KnownOption" || roots["mystery"] != "MysteryOption" {
		t.Fatalf("roots = %v", roots)
	}
}

func TestInventoryFlattensBasicOptionAndRendersSourceTypes(t *testing.T) {
	gen, roots := testSurface(t, "proxies")
	http := collectType(t, gen, roots, "http")
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
	gen, roots := testSurface(t, "proxies")
	wg := collectType(t, gen, roots, "wireguard")
	peers := fieldByKey(wg, "peers")
	if peers == nil || len(peers.Nested) == 0 {
		t.Fatalf("wireguard peers must be nested, got %+v", peers)
	}
	if fieldByKey(peers.Nested, "public-key") == nil {
		t.Errorf("wireguard peers nested fields missing public-key")
	}
	// plugin-opts is map[string]any: a leaf, never expanded.
	ss := collectType(t, gen, roots, "ss")
	pluginOpts := fieldByKey(ss, "plugin-opts")
	if pluginOpts == nil || pluginOpts.GoType != "map[string]any" || len(pluginOpts.Nested) != 0 {
		t.Errorf("ss plugin-opts should be a map[string]any leaf, got %+v", pluginOpts)
	}
	// v1.19.30's nested additions recurse: ip-stack is a struct on four outbounds and
	// zerotier's orbit is a slice of structs.
	for _, typeName := range []string{"wireguard", "masque", "openvpn", "zerotier"} {
		if f := fieldByKey(collectType(t, gen, roots, typeName), "ip-stack"); f == nil || fieldByKey(f.Nested, "mode") == nil {
			t.Errorf("%s ip-stack must nest IPStackOption (mode, congestion-controller), got %+v", typeName, f)
		}
	}
	if f := fieldByKey(collectType(t, gen, roots, "zerotier"), "orbit"); f == nil || fieldByKey(f.Nested, "seed") == nil {
		t.Errorf("zerotier orbit must nest ZeroTierOrbitOption (seed, world), got %+v", f)
	}
}

func TestInventoryExcludesSingMux(t *testing.T) {
	gen, roots := testSurface(t, "proxies")
	for typeName := range roots {
		for _, f := range collectType(t, gen, roots, typeName) {
			if f.Key == "smux" || f.GoType == "SingMuxOption" {
				t.Errorf("type %q leaked an excluded SMUX field: %+v", typeName, f)
			}
		}
	}
}

// zerotier is declared twice under build tags (zerotier.go / zerotier_stub.go); the
// walk takes the first by file name. That choice must not matter: upstream keeps
// the stub field-for-field identical, and this pins it so a divergence is seen
// here rather than as a mysterious inventory flip.
func TestZeroTierStubMirrorsTheRealOptionFieldForField(t *testing.T) {
	fset := token.NewFileSet()
	fieldsOf := func(file string) []string {
		parsed, err := parser.ParseFile(fset, filepath.Join(repoRoot, "adapter/outbound", file), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		var keys []string
		for _, decl := range parsed.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, spec := range gd.Specs {
				ts := spec.(*ast.TypeSpec)
				st, ok := ts.Type.(*ast.StructType)
				if !ok || !strings.HasPrefix(ts.Name.Name, "ZeroTier") {
					continue
				}
				for _, f := range st.Fields.List {
					if key, req, ok := tagKey(f.Tag, "proxy"); ok {
						keys = append(keys, ts.Name.Name+"."+key+"/"+boolWord(req))
					}
				}
			}
		}
		sort.Strings(keys)
		return keys
	}
	real, stub := fieldsOf("zerotier.go"), fieldsOf("zerotier_stub.go")
	if len(real) == 0 {
		t.Fatal("no ZeroTier* proxy-tagged fields found in zerotier.go")
	}
	if !reflect.DeepEqual(real, stub) {
		t.Fatalf("zerotier.go and zerotier_stub.go declare different proxy fields:\n real %v\n stub %v", real, stub)
	}
}

// Two runs of the whole document must be byte-identical: the gate diffs it.
func TestAllSurfacesRenderDeterministically(t *testing.T) {
	render := func() []byte {
		all := map[string]map[string][]inventoryField{}
		for _, name := range []string{"proxies", "listeners"} {
			inventory, err := inventoryFor(repoRoot, surfaces[name])
			if err != nil {
				t.Fatal(err)
			}
			all[name] = inventory
		}
		encoded, err := json.MarshalIndent(all, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	first, second := render(), render()
	if !bytes.Equal(first, second) {
		t.Fatal("two renders of the field inventory differ")
	}
	var doc map[string]map[string][]inventoryField
	if err := json.Unmarshal(first, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc["proxies"]) != 27 || len(doc["listeners"]) != 20 {
		t.Fatalf("all-surface document has %d proxies / %d listeners", len(doc["proxies"]), len(doc["listeners"]))
	}
}

func boolWord(b bool) string {
	if b {
		return "required"
	}
	return "optional"
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func goTypeOrEmpty(f *inventoryField) string {
	if f == nil {
		return ""
	}
	return f.GoType
}
