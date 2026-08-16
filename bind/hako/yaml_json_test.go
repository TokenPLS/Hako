package hako

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/TokenPLS/Hako/common/orderedmap"
	"github.com/TokenPLS/Hako/config"
)

func TestYamlToJSONResolvesAliasesAndPreservesLargeIntegers(t *testing.T) {
	box, err := YamlToJSON(`
defaults: &defaults
  interval: 9007199254740993
profile:
  <<: *defaults
  enabled: true
`)
	if err != nil {
		t.Fatalf("YamlToJSON: %v", err)
	}
	root := decodeJSONNumbers(t, box.Value)
	profile := root["profile"].(map[string]any)
	if got := profile["interval"].(json.Number).String(); got != "9007199254740993" {
		t.Fatalf("large integer = %q", got)
	}
	if enabled, ok := profile["enabled"].(bool); !ok || !enabled {
		t.Fatalf("merged profile = %#v", profile)
	}
}

func TestJSONToYamlRoundTripsCompleteConfigTree(t *testing.T) {
	rawJSON := `{
  "mode": "rule",
  "large": 9007199254740993,
  "fraction": 1.25e-7,
  "nullable": null,
  "proxies": [{"name": "node", "ports": [80, 443], "enabled": true}]
}`
	box, err := JSONToYaml(rawJSON)
	if err != nil {
		t.Fatalf("JSONToYaml: %v", err)
	}
	converted, err := YamlToJSON(box.Value)
	if err != nil {
		t.Fatalf("YamlToJSON(round trip): %v", err)
	}
	want := decodeJSONNumbers(t, rawJSON)
	got := decodeJSONNumbers(t, converted.Value)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip mismatch\n got: %#v\nwant: %#v\nyaml:\n%s", got, want, box.Value)
	}
}

func TestYamlToJSONRejectsNonObjectRoot(t *testing.T) {
	// A multi-document config is no longer rejected here: first-document-wins is
	// covered by TestYamlToJSONTakesFirstDocumentLikeUpstream.
	for name, input := range map[string]string{
		"sequence": "- one\n- two\n",
		"scalar":   "hello\n",
		"empty":    "",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := YamlToJSON(input); err == nil {
				t.Fatal("expected conversion error")
			}
		})
	}
}

func TestYamlToJSONTakesFirstDocumentLikeUpstream(t *testing.T) {
	// Upstream yaml.v3 Unmarshal decodes only the first document and ignores the
	// rest, and every upstream-aligned Core entry (FormatConfig, CheckConfig,
	// Start, PlatformConfigIntentJSON) accepts a multi-document config by taking
	// document one. YamlToJSON must not reject it at activation.
	for name, input := range map[string]string{
		"valid second document":       "mode: rule\n---\nmode: global\n",
		"malformed trailing document": "mode: rule\n---\n[unterminated\n",
	} {
		t.Run(name, func(t *testing.T) {
			box, err := YamlToJSON(input)
			if err != nil {
				t.Fatalf("multi-document YAML must convert (first document wins): %v", err)
			}
			if box.Value != `{"mode":"rule"}` {
				t.Fatalf("expected the first document only, got %s", box.Value)
			}
		})
	}
}

func TestJSONToYamlRejectsNonObjectInvalidAndTrailingInput(t *testing.T) {
	for name, input := range map[string]string{
		"sequence": `["one", "two"]`,
		"scalar":   `true`,
		"null":     `null`,
		"invalid":  `{"mode":`,
		"trailing": `{"mode":"rule"} {"mode":"direct"}`,
		"empty":    ``,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := JSONToYaml(input); err == nil {
				t.Fatal("expected conversion error")
			}
		})
	}
}

func TestYAMLJSONBridgeOutputIsDeterministic(t *testing.T) {
	const yamlInput = "zebra: 1\nalpha:\n  second: false\n  first: null\n"
	firstJSON, err := YamlToJSON(yamlInput)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := YamlToJSON(yamlInput)
	if err != nil {
		t.Fatal(err)
	}
	if firstJSON.Value != secondJSON.Value {
		t.Fatalf("JSON output changed: %q != %q", firstJSON.Value, secondJSON.Value)
	}

	firstYAML, err := JSONToYaml(firstJSON.Value)
	if err != nil {
		t.Fatal(err)
	}
	secondYAML, err := JSONToYaml(firstJSON.Value)
	if err != nil {
		t.Fatal(err)
	}
	if firstYAML.Value != secondYAML.Value {
		t.Fatalf("YAML output changed: %q != %q", firstYAML.Value, secondYAML.Value)
	}
	// Source order is preserved, not alphabetized: "zebra" precedes "alpha" and
	// the nested "second" precedes "first" exactly as written.
	if !strings.HasPrefix(firstYAML.Value, "zebra:") {
		t.Fatalf("YAML did not preserve source key order: %q", firstYAML.Value)
	}
	if strings.Index(firstYAML.Value, "second:") > strings.Index(firstYAML.Value, "first:") {
		t.Fatalf("YAML did not preserve nested key order: %q", firstYAML.Value)
	}
}

func TestYAMLJSONBridgeRoundTripsOfficialConfigCatalog(t *testing.T) {
	payload, err := os.ReadFile("../../docs/config.yaml")
	if err != nil {
		t.Fatalf("read official config catalog: %v", err)
	}
	initial, err := YamlToJSON(string(payload))
	if err != nil {
		t.Fatalf("official YAML to JSON: %v", err)
	}
	converted, err := JSONToYaml(initial.Value)
	if err != nil {
		t.Fatalf("official JSON to YAML: %v", err)
	}
	roundTrip, err := YamlToJSON(converted.Value)
	if err != nil {
		t.Fatalf("round-trip official YAML to JSON: %v", err)
	}
	if got, want := decodeJSONNumbers(t, roundTrip.Value), decodeJSONNumbers(t, initial.Value); !reflect.DeepEqual(got, want) {
		t.Fatal("official config catalog changed JSON semantics during YAML round trip")
	}
}

func TestYAMLJSONBridgePreservesNameserverPolicyOrder(t *testing.T) {
	// nameserver-policy (and proxy-server-nameserver-policy) are first-match and
	// order-sensitive in the kernel: config.go builds them into an
	// orderedmap.OrderedMap and dns/resolver.go matchPolicy walks them in order,
	// returning the first hit; makePolicy also groups consecutive plain-domain
	// entries into one DomainTrie, so reordering changes both first-match and
	// trie grouping. The client override bridge (YamlToJSON then JSONToYaml) must
	// preserve source order. These orders are deliberately NOT alphabetical
	// ("+.example.com" sorts before "geosite:cn"), so an alphabetizing bridge
	// fails this test.
	const source = `dns:
  enable: true
  nameserver-policy:
    "geosite:cn": 223.5.5.5
    "+.example.com": 1.1.1.1
    "geosite:google": 8.8.8.8
  proxy-server-nameserver-policy:
    "geosite:telegram": 8.8.8.8
    "geosite:cn": 223.5.5.5
`
	want := []string{"geosite:cn", "+.example.com", "geosite:google"}
	wantProxy := []string{"geosite:telegram", "geosite:cn"}

	asJSON, err := YamlToJSON(source)
	if err != nil {
		t.Fatalf("YamlToJSON: %v", err)
	}
	// The JSON intermediate the client override script consumes must already be
	// ordered — historically the first order-destruction point (map+Marshal).
	if got := nameserverPolicyKeysFromJSON(t, asJSON.Value); !reflect.DeepEqual(got, want) {
		t.Fatalf("JSON nameserver-policy order = %v, want %v", got, want)
	}

	backToYAML, err := JSONToYaml(asJSON.Value)
	if err != nil {
		t.Fatalf("JSONToYaml: %v", err)
	}
	raw, err := config.UnmarshalRawConfig([]byte(backToYAML.Value))
	if err != nil {
		t.Fatalf("UnmarshalRawConfig after client bridge: %v", err)
	}
	if got := orderedMapKeys(raw.DNS.NameServerPolicy); !reflect.DeepEqual(got, want) {
		t.Fatalf("kernel NameServerPolicy order = %v, want %v (yaml:\n%s)", got, want, backToYAML.Value)
	}
	if got := orderedMapKeys(raw.DNS.ProxyServerNameserverPolicy); !reflect.DeepEqual(got, wantProxy) {
		t.Fatalf("kernel ProxyServerNameserverPolicy order = %v, want %v", got, wantProxy)
	}
}

func TestYamlToJSONRejectsUnsafeAndAmbiguousInput(t *testing.T) {
	cases := map[string]string{
		"self-referential anchor": "a: &a\n  b: *a\n",
		"billion laughs": "a: &a [\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\"]\n" +
			"b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\n" +
			"c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]\n" +
			"d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]\n" +
			"e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]\n" +
			"f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]\n" +
			"g: [*f,*f,*f,*f,*f,*f,*f,*f,*f]\n",
		"duplicate top-level key": "mode: rule\nmode: direct\n",
		// An alias key and a scalar key that resolve to the same string are not
		// duplicates to yaml.v3's node-level check, so the pre-flight accepts
		// them; the resolved-key collision must still be rejected.
		"alias-resolved duplicate key": "seed: &k mode\n*k: first\nmode: second\n",
		"merge alias to sequence":      "base: &b [1, 2]\nm:\n  <<: *b\n  y: 1\n",
		"merge nested sequence":        "base: &b {x: 1}\nm:\n  <<: [[*b]]\n  y: 1\n",
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := YamlToJSON(input); err == nil {
				t.Fatalf("expected rejection for %q", name)
			}
		})
	}
}

func TestYamlToJSONTreatsQuotedMergeKeyAsLiteral(t *testing.T) {
	// A quoted "<<" is a !!str key, not a merge directive; it must survive.
	box, err := YamlToJSON("m:\n  \"<<\": literal\n  y: 2\n")
	if err != nil {
		t.Fatalf("YamlToJSON: %v", err)
	}
	root := decodeJSONNumbers(t, box.Value)
	m, ok := root["m"].(map[string]any)
	if !ok || m["<<"] != "literal" {
		t.Fatalf("quoted merge key not preserved: %#v", root["m"])
	}
}

func TestYamlToJSONResolvesValidSequenceMerge(t *testing.T) {
	// A flat sequence of mappings is a valid merge; earlier sources win.
	box, err := YamlToJSON("one: &one {a: 1}\ntwo: &two {b: 2, a: 9}\nm:\n  <<: [*one, *two]\n  c: 3\n")
	if err != nil {
		t.Fatalf("YamlToJSON: %v", err)
	}
	m := decodeJSONNumbers(t, box.Value)["m"].(map[string]any)
	if m["a"].(json.Number).String() != "1" || m["b"].(json.Number).String() != "2" ||
		m["c"].(json.Number).String() != "3" {
		t.Fatalf("sequence merge resolved wrong: %#v", m)
	}
}

func TestJSONToYamlRejectsDuplicateObjectKeys(t *testing.T) {
	if _, err := JSONToYaml(`{"mode":"rule","mode":"direct"}`); err == nil {
		t.Fatal("expected duplicate JSON object key rejection")
	}
}

func orderedMapKeys(policy *orderedmap.OrderedMap[string, any]) []string {
	if policy == nil {
		return nil
	}
	keys := make([]string, 0, policy.Len())
	for pair := policy.Oldest(); pair != nil; pair = pair.Next() {
		keys = append(keys, pair.Key)
	}
	return keys
}

func nameserverPolicyKeysFromJSON(t *testing.T, value string) []string {
	t.Helper()
	var probe struct {
		DNS struct {
			NameserverPolicy *orderedmap.OrderedMap[string, any] `json:"nameserver-policy"`
		} `json:"dns"`
	}
	if err := json.Unmarshal([]byte(value), &probe); err != nil {
		t.Fatalf("decode JSON probe: %v", err)
	}
	return orderedMapKeys(probe.DNS.NameserverPolicy)
}

func decodeJSONNumbers(t *testing.T, value string) map[string]any {
	t.Helper()
	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.UseNumber()
	var root map[string]any
	if err := decoder.Decode(&root); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	return root
}

// The full projection stays (design §4-6). Script paths, whole-document
// rewrites, backup redaction and migration diffs genuinely need everything --
// including keys this kernel does not know. If YamlToJSON ever starts
// dropping content, the projection work has quietly amputated its neighbors.
func TestYamlToJSONStillCarriesEverything(t *testing.T) {
	box, err := YamlToJSON(`
some-unknown-top-level-key: {kept: true}
dns: {enable: true, nameserver: ["1.1.1.1"]}
rules:
  - MATCH,DIRECT
sub-rules:
  extra: ["MATCH,REJECT"]
proxies:
  - {name: A, type: socks5, server: e.test, port: 1080}
`)
	if err != nil {
		t.Fatalf("conversion failed: %v", err)
	}
	var root map[string]any
	if err := json.Unmarshal([]byte(box.Value), &root); err != nil {
		t.Fatalf("result does not decode: %v", err)
	}
	// Deep values, not key presence: a hollowed-out `dns: {}` would keep the
	// key while losing the content.
	unknown, _ := root["some-unknown-top-level-key"].(map[string]any)
	if kept, _ := unknown["kept"].(bool); !kept {
		t.Fatalf("unknown key's nested content lost: %+v", root["some-unknown-top-level-key"])
	}
	dns, _ := root["dns"].(map[string]any)
	if servers, _ := dns["nameserver"].([]any); len(servers) != 1 || servers[0] != "1.1.1.1" {
		t.Fatalf("dns content lost: %+v", dns)
	}
	if rules, _ := root["rules"].([]any); len(rules) != 1 || rules[0] != "MATCH,DIRECT" {
		t.Fatalf("rules content lost: %+v", root["rules"])
	}
	sub, _ := root["sub-rules"].(map[string]any)
	if extra, _ := sub["extra"].([]any); len(extra) != 1 || extra[0] != "MATCH,REJECT" {
		t.Fatalf("sub-rules content lost: %+v", sub)
	}
}
