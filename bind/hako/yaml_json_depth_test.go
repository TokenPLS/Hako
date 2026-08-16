package hako

import (
	"strings"
	"testing"
)

// JSONToYaml walks a JSON document with two mutually recursive functions, so
// the recursion depth IS the document's nesting depth and the only bound was
// the 16 MiB input limit -- about sixteen million levels of `[`. A Go stack
// overflow is a fatal throw: recover cannot catch it, the whole process dies,
// and inside a Network Extension that is the tunnel dropping with no error to
// report. The YAML direction is not affected (yaml.v3's scanner stops at
// 10000 levels), which is exactly why this side needs its own bound.
//
// Threat model: whoever supplies the configuration JSON -- a subscription, a
// pasted profile, an imported backup.

// The root must be an object (JSONToYaml enforces that), so the nesting rides
// inside one -- which is also how a real attack would arrive.
func nestedJSONArray(depth int) string {
	return `{"rules":` + strings.Repeat("[", depth) + strings.Repeat("]", depth) + "}"
}

func TestJSONToYamlRefusesRunawayNesting(t *testing.T) {
	// Deep enough to overflow the stack if nothing bounds it, small enough to
	// build instantly. The real attack uses the full 16 MiB.
	_, err := JSONToYaml(nestedJSONArray(200_000))
	if err == nil {
		t.Fatal("a document nested 200000 levels deep was accepted; the stack, not the input limit, is what stops it today")
	}
	if !strings.Contains(err.Error(), "nested") {
		t.Fatalf("the refusal does not say what was wrong: %v", err)
	}
}

func TestJSONToYamlRefusesRunawayObjectNesting(t *testing.T) {
	var builder strings.Builder
	const depth = 200_000
	for i := 0; i < depth; i++ {
		builder.WriteString(`{"a":`)
	}
	builder.WriteString("1")
	builder.WriteString(strings.Repeat("}", depth))

	if _, err := JSONToYaml(builder.String()); err == nil {
		t.Fatal("an object nested 200000 levels deep was accepted")
	}
}

// The bound must sit far above anything a real configuration reaches: a mihomo
// profile nests a handful of levels, and rejecting a legitimate document would
// be a worse bug than the one being fixed.
func TestJSONToYamlAcceptsOrdinaryNesting(t *testing.T) {
	if _, err := JSONToYaml(nestedJSONArray(64)); err != nil {
		t.Fatalf("64 levels is ordinary and must be accepted: %v", err)
	}
	realistic := `{"proxies":[{"name":"a","type":"ss","server":"1.2.3.4","port":443,` +
		`"cipher":"aes-128-gcm","password":"x","plugin-opts":{"mode":"websocket","headers":{"Host":"e.com"}}}],` +
		`"rules":["MATCH,DIRECT"]}`
	if _, err := JSONToYaml(realistic); err != nil {
		t.Fatalf("a realistic profile must convert: %v", err)
	}
}
