package hako

import (
	"reflect"
	"strings"
	"testing"

	"github.com/TokenPLS/Hako/config"
	"gopkg.in/yaml.v3"
)

// The classification gate next door is a statement ABOUT the code; this one
// drives the code. It exists because the classification gate has a blind spot
// the iOS lane named during review: it cannot catch a resolver slot
// added upstream and then classified as not-a-resolver by hand. Nothing can
// catch that automatically -- the classification IS the judgement -- but this
// gate makes standing behind it a commitment in both directions rather than a
// silence:
//
//	a field classified "resolver" must come out of FinalizeForIOS with every
//	system/dhcp entry gone, and a field classified "not-a-resolver" must come
//	out with its entries VERBATIM, "system" included.
//
// So mislabeling a real resolver slot is no longer a quiet omission. It is an
// assertion, printed right here, that a system resolver in that field is meant
// to reach the core untouched.
//
// The inputs are built by reflection off config.RawDNS, so a new []string or
// policy-map field is exercised the day it appears upstream rather than the day
// somebody remembers to add it.

func dnsFieldsByKind(t *testing.T, kind string) []reflect.StructField {
	t.Helper()
	typ := reflect.TypeOf(config.RawDNS{})
	out := []reflect.StructField{}
	for i := range typ.NumField() {
		field := typ.Field(i)
		tag := strings.Split(field.Tag.Get("yaml"), ",")[0]
		if tag == "" || tag == "-" {
			continue
		}
		if dnsFieldClassification[tag] != kind {
			continue
		}
		// Only the shapes that can hold a list of resolvers: a []string slot
		// and a policy map. Scalars cannot carry one.
		isList := field.Type.Kind() == reflect.Slice && field.Type.Elem().Kind() == reflect.String
		isPolicy := strings.Contains(field.Type.String(), "OrderedMap")
		if isList || isPolicy {
			out = append(out, field)
		}
	}
	if len(out) == 0 {
		t.Fatalf("reflected no %q fields able to hold resolvers; the derivation is wrong, not the behaviour", kind)
	}
	return out
}

// normalizedDNSField runs one dns document through the strip the way the core
// meets it and hands back the value of one field afterwards.
//
// The first version of this helper drove FinalizeForIOS and read the yaml it
// emits. All seven resolver fields came back still carrying "system", which
// looks exactly like the strip being broken and is not: FinalizeForIOS produces
// the DOCUMENT handed to the core, and the strip runs afterwards, inside
// normalizeRawConfigForApple (config_pipeline.go:310), on the parsed RawConfig.
// The probe was reading the wrong artifact. Drive the function that strips.
func normalizedDNSField(t *testing.T, dns map[string]any, fieldName string) any {
	t.Helper()
	document, err := yaml.Marshal(map[string]any{"dns": dns})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	raw, err := config.UnmarshalRawConfig(document)
	if err != nil {
		t.Fatalf("the document does not even parse upstream, so it tests nothing: %v\n%s", err, document)
	}
	normalizeRawConfigForApple(raw, nePolicy())
	value := reflect.ValueOf(raw.DNS).FieldByName(fieldName)
	if !value.IsValid() {
		t.Fatalf("RawDNS has no field %q; the reflection is wrong, not the behaviour", fieldName)
	}
	return value.Interface()
}

// neIncompatibleIn collects the system/dhcp entries anywhere inside a value.
//
// The value comes back off RawDNS by reflection, so it is a real []string or a
// real *orderedmap.OrderedMap -- and walkStrings only descends an `any` tree of
// []any / map[string]any. Handing it a []string walks nothing and reports
// nothing, which is a clean sweep that swept nothing: the first version of this
// helper did exactly that and every subtest passed vacuously. Round-tripping
// through yaml turns whatever it is into the shape walkStrings understands.
func neIncompatibleIn(t *testing.T, v any) []string {
	t.Helper()
	encoded, err := yaml.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var tree any
	if err := yaml.Unmarshal(encoded, &tree); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	hits := []string{}
	walkStrings(tree, func(s string) {
		if isNEIncompatibleNameserver(s) {
			hits = append(hits, s)
		}
	})
	return hits
}

func TestEveryResolverFieldActuallyStripsSystemAndDhcp(t *testing.T) {
	for _, field := range append(dnsFieldsByKind(t, "resolver"), dnsFieldsByKind(t, "bootstrap")...) {
		key := strings.Split(field.Tag.Get("yaml"), ",")[0]
		t.Run(key, func(t *testing.T) {
			var value any = []string{"system", "dhcp://en0", "223.5.5.5"}
			if strings.Contains(field.Type.String(), "OrderedMap") {
				value = map[string]any{"+.example.com": []string{"system", "dhcp://en0", "223.5.5.5"}}
			}
			// enable + a clean nameserver so the document is one the core runs;
			// the field under test is then overwritten with the poisoned value.
			dns := map[string]any{"enable": true, "nameserver": []string{"223.5.5.5"}}
			dns[key] = value
			if hits := neIncompatibleIn(t, normalizedDNSField(t, dns, field.Name)); len(hits) != 0 {
				t.Errorf("dns.%s is classified as holding resolvers but reached the core still carrying %v -- "+
					"add it to repairApplePacketTunnelDNS, or its classification is wrong", key, hits)
			}
		})
	}
}

func TestFieldsClassifiedNotAResolverReachTheCoreVerbatim(t *testing.T) {
	for _, field := range dnsFieldsByKind(t, "not-a-resolver") {
		key := strings.Split(field.Tag.Get("yaml"), ",")[0]
		t.Run(key, func(t *testing.T) {
			dns := map[string]any{
				"enable":        true,
				"nameserver":    []string{"223.5.5.5"},
				"enhanced-mode": "fake-ip",
			}
			dns[key] = []string{"system", "+.lan"}
			got := normalizedDNSField(t, dns, field.Name)
			hits := neIncompatibleIn(t, got)
			if len(hits) == 0 {
				t.Errorf("dns.%s is classified as NOT holding resolvers, which asserts a 'system' entry there is "+
					"an ordinary value and must reach the core untouched -- it did not (%v). Either the strip now "+
					"reaches this field, or the classification is wrong and dns.%s really is a resolver slot.",
					key, got, key)
			}
		})
	}
}
