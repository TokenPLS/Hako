package hako

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/TokenPLS/Hako/config"
)

// Nothing this core changes about a configuration may go unregistered.
//
// CONFIG-DEVIATION-REGISTRY.json is what the client lanes gate against: a field in the
// registry must not also be a control the reader can set, because that is a control the core
// then ignores. The registry is generated from deviationRules, so it cannot drift from the
// route that serves the same var -- but deviationRules is a table of sentences maintained
// beside the code that does the overriding, not by it. A field that finalizeConfigForApple
// changes and nobody added a rule for is absent from the registry, and a client gate reading
// the registry goes green on it. That is the false green this test closes, and it is the one
// shape a golden over deviationRules can never catch: both halves would agree, and both would
// be missing the same row.
//
// So the question is asked of the code instead. Seed every reachable field of a parsed
// configuration with a marker, run the real finalize path once per runtime profile, and diff
// the struct by reflection. Every field that moved has to be a field the registry already
// names as forced or stripped for that profile.
//
// Twice, with opposite seeds. A force that writes false is invisible against a zero value and
// a force that writes "" is invisible against an empty string, so one pass seeds everything
// high and the other seeds everything low, and the union is what the core is capable of
// touching. Measuring one side only is the mistake of using a positive control as a
// discriminator: it lights up and it cannot tell the two cases apart.

// Go paths whose struct carries no json tag, mapped to the field name the registry uses.
// Checked in both directions below -- an entry naming a field that no longer exists fails,
// and so does an observed change that is neither tagged nor listed here. It is a map rather
// than a derivation because kebab-casing QUICGoDisableGSO or ExternalControllerTLS means
// guessing at the spelling, and a guessed key that happens to match nothing reads exactly
// like a field nobody registered.
var deviationFieldAliases = map[string]string{
	"Controller.ExternalController":            "external-controller",
	"Controller.ExternalControllerTLS":         "external-controller-tls",
	"Controller.ExternalControllerUnix":        "external-controller-unix",
	"Controller.ExternalControllerPipe":        "external-controller-pipe",
	"Controller.ExternalControllerRoutingMark": "external-controller-routing-mark",
	"Controller.ExternalUI":                    "external-ui",
	"Controller.ExternalUIURL":                 "external-ui-url",
	"Controller.ExternalUIName":                "external-ui-name",
	"Controller.ExternalDohServer":             "external-doh-server",
	"Controller.Secret":                        "secret",
	"Experimental.QUICGoDisableGSO":            "experimental.quic-go-disable-gso",
	"Experimental.QUICGoDisableECN":            "experimental.quic-go-disable-ecn",
	"Experimental.IP4PEnable":                  "experimental.dialer-ip4p-convert",
	"Profile.StoreSelected":                    "profile.store-selected",
	"Profile.StoreFakeIP":                      "profile.store-fake-ip",
	"DNS.ListenRoutingMark":                    "dns.listen-routing-mark",
	"NTP.WriteToSystem":                        "ntp.write-to-system",
}

// The top-level members finalizeConfigForApple can reach. Rules name tun fields without a
// "general." prefix because that is how a reader writes them.
var deviationProbeRoots = []struct {
	goName string
	prefix string
}{
	{"General", ""},
	{"Controller", ""},
	{"Experimental", ""},
	{"Profile", ""},
	{"DNS", "dns"},
	{"NTP", ""},
}

type observedChange struct {
	goPath string
	before string
	after  string
}

// seedValue returns a marker for a field, distinguishable from any value the core would write
// by accident. high=false produces the opposite marker so a write in either direction shows.
func seedValue(t reflect.Type, high bool, path string) (reflect.Value, bool) {
	switch t.Kind() {
	case reflect.Bool:
		return reflect.ValueOf(high).Convert(t), true
	case reflect.String:
		if high {
			return reflect.ValueOf("hako-probe-" + path).Convert(t), true
		}
		return reflect.ValueOf("").Convert(t), true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if high {
			return reflect.ValueOf(int64(424242)).Convert(t), true
		}
		return reflect.ValueOf(int64(0)).Convert(t), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if high {
			return reflect.ValueOf(uint64(424242)).Convert(t), true
		}
		return reflect.ValueOf(uint64(0)).Convert(t), true
	default:
		return reflect.Value{}, false
	}
}

// seedStruct fills every settable scalar it can reach, allocating pointers on the way so a
// nil branch does not hide a field from the probe.
func seedStruct(v reflect.Value, high bool, path string, depth int) {
	if depth > 6 {
		return
	}
	switch v.Kind() {
	case reflect.Ptr:
		if v.IsNil() {
			if !v.CanSet() {
				return
			}
			v.Set(reflect.New(v.Type().Elem()))
		}
		seedStruct(v.Elem(), high, path, depth+1)
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			field := v.Type().Field(i)
			if field.PkgPath != "" { // unexported
				continue
			}
			child := path
			if !field.Anonymous {
				if child == "" {
					child = field.Name
				} else {
					child += "." + field.Name
				}
			}
			target := v.Field(i)
			if seeded, ok := seedValue(target.Type(), high, child); ok && target.CanSet() {
				target.Set(seeded)
				continue
			}
			seedStruct(target, high, child, depth+1)
		}
	}
}

// diffStruct walks two seeded-then-run copies and reports every scalar that moved.
func diffStruct(before, after reflect.Value, path string, depth int, out *[]observedChange) {
	if depth > 6 || !before.IsValid() || !after.IsValid() {
		return
	}
	switch before.Kind() {
	case reflect.Ptr:
		if before.IsNil() != after.IsNil() {
			*out = append(*out, observedChange{path, fmt.Sprint(before.IsNil()), fmt.Sprint(after.IsNil())})
			return
		}
		if before.IsNil() {
			return
		}
		diffStruct(before.Elem(), after.Elem(), path, depth+1, out)
	case reflect.Struct:
		for i := 0; i < before.NumField(); i++ {
			field := before.Type().Field(i)
			if field.PkgPath != "" {
				continue
			}
			child := path
			if !field.Anonymous {
				if child == "" {
					child = field.Name
				} else {
					child += "." + field.Name
				}
			}
			diffStruct(before.Field(i), after.Field(i), child, depth+1, out)
		}
	case reflect.Bool, reflect.String,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if !before.Equal(after) {
			*out = append(*out, observedChange{path, fmt.Sprint(before), fmt.Sprint(after)})
		}
	}
}

// registryFieldFor maps a Go path onto the field name a rule would use, preferring the json
// tag the struct already carries.
func registryFieldFor(root string, prefix string, goPath string, rootType reflect.Type) (string, bool) {
	if alias, ok := deviationFieldAliases[root+"."+goPath]; ok {
		return alias, true
	}
	segments := strings.Split(goPath, ".")
	current := rootType
	parts := []string{}
	for _, segment := range segments {
		for current.Kind() == reflect.Ptr {
			current = current.Elem()
		}
		if current.Kind() != reflect.Struct {
			return "", false
		}
		field, ok := fieldByNameFlattening(current, segment)
		if !ok {
			return "", false
		}
		tag := strings.Split(field.Tag.Get("json"), ",")[0]
		if tag == "" || tag == "-" {
			return "", false
		}
		parts = append(parts, tag)
		current = field.Type
	}
	joined := strings.Join(parts, ".")
	if prefix != "" {
		joined = prefix + "." + joined
	}
	return joined, true
}

func fieldByNameFlattening(t reflect.Type, name string) (reflect.StructField, bool) {
	if field, ok := t.FieldByName(name); ok && len(field.Index) > 0 {
		return field, true
	}
	return reflect.StructField{}, false
}

func rulesByField() map[string][]deviationRule {
	byField := map[string][]deviationRule{}
	for _, rule := range deviationRules {
		byField[rule.field] = append(byField[rule.field], rule)
	}
	return byField
}

func TestEveryFieldTheCoreChangesIsRegistered(t *testing.T) {
	// allow-lan reads a process-wide atomic that another test may have moved.
	restore := allowLanPermitted.Load()
	t.Cleanup(func() { allowLanPermitted.Store(restore) })

	byField := rulesByField()

	// Both directions of the alias map, so a rename on either side fails here instead of
	// silently turning a registered field into an unaccounted change.
	configType := reflect.TypeOf(config.Config{})
	for goPath, field := range deviationFieldAliases {
		root := strings.SplitN(goPath, ".", 2)
		structField, ok := configType.FieldByName(root[0])
		if !ok {
			t.Errorf("alias %q names top-level %q, which config.Config does not have",
				goPath, root[0])
			continue
		}
		inner := structField.Type
		for inner.Kind() == reflect.Ptr {
			inner = inner.Elem()
		}
		if _, ok := inner.FieldByName(strings.Split(root[1], ".")[0]); !ok {
			t.Errorf("alias %q names a field %s no longer has", goPath, root[0])
		}
		if _, ok := byField[field]; !ok {
			t.Logf("alias %q maps to %q, which no rule currently names "+
				"(fine while the core does not change it; it is here so that if it starts "+
				"changing, the failure names the right key)", goPath, field)
		}
	}

	for _, seat := range registryProfiles {
		for _, high := range []bool{true, false} {
			seat, high := seat, high
			name := fmt.Sprintf("%s/seed=%v", seat.name, high)
			t.Run(name, func(t *testing.T) {
				policy := runtimePolicyFor(seat.profile, seat.underNetworkExtension)

				build := func() *config.Config {
					cfg := &config.Config{}
					seedStruct(reflect.ValueOf(cfg), high, "", 0)
					return cfg
				}
				before, after := build(), build()

				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("finalizeConfigForApple panicked on a fully seeded "+
								"configuration (%v) -- the probe cannot answer the question "+
								"it was asked, so this is not a pass", r)
						}
					}()
					finalizeConfigForApple(after, policy)
				}()

				var changes []observedChange
				beforeValue, afterValue := reflect.ValueOf(before).Elem(), reflect.ValueOf(after).Elem()
				for _, root := range deviationProbeRoots {
					b := beforeValue.FieldByName(root.goName)
					a := afterValue.FieldByName(root.goName)
					if !b.IsValid() || !a.IsValid() {
						t.Fatalf("config.Config no longer has %s; the probe's roots are stale "+
							"and it would silently stop looking there", root.goName)
					}
					var rootChanges []observedChange
					diffStruct(b, a, "", 0, &rootChanges)
					rootType := b.Type()
					for rootType.Kind() == reflect.Ptr {
						rootType = rootType.Elem()
					}
					for _, change := range rootChanges {
						change.goPath = root.goName + "." + change.goPath
						changes = append(changes, change)
					}
					_ = rootType
				}

				var unaccounted []string
				for _, change := range changes {
					root := strings.SplitN(change.goPath, ".", 2)
					var prefix string
					var rootType reflect.Type
					for _, candidate := range deviationProbeRoots {
						if candidate.goName == root[0] {
							prefix = candidate.prefix
							field, _ := configType.FieldByName(candidate.goName)
							rootType = field.Type
							for rootType.Kind() == reflect.Ptr {
								rootType = rootType.Elem()
							}
						}
					}
					field, ok := registryFieldFor(root[0], prefix, root[1], rootType)
					if !ok {
						unaccounted = append(unaccounted, fmt.Sprintf(
							"%s (%s -> %s): no json tag and no alias, so it cannot be matched "+
								"to a registry field at all",
							change.goPath, change.before, change.after))
						continue
					}
					matches := byField[field]
					if len(matches) == 0 {
						unaccounted = append(unaccounted, fmt.Sprintf(
							"%s = %q (%s -> %s): the core changes it and no rule names it",
							change.goPath, field, change.before, change.after))
						continue
					}
					// unavailable counts, and the first version of this test was wrong to
					// skip it. It excluded unavailable on the theory that "upstream cannot do
					// this here" describes a fact rather than an action, so a field carrying
					// it should not also be moving. Three of them do move -- redir-port,
					// tproxy-port and dns.listen-routing-mark are zeroed as defence in depth
					// over a raw layer that already dropped them -- and the distinction does
					// not change the answer to the question the registry is gated on. That
					// question is "may the reader set this and have it honoured", and
					// unavailable answers no as flatly as stripped does. Treating the clear as
					// unregistered would have pushed three correct entries toward being
					// recategorised to make a test pass.
					fires := false
					for _, rule := range matches {
						if rule.applies == nil || rule.applies(policy) {
							fires = true
						}
					}
					if !fires {
						unaccounted = append(unaccounted, fmt.Sprintf(
							"%s = %q (%s -> %s): registered, but not as forced/stripped for "+
								"this profile, so the registry says this profile leaves it alone",
							change.goPath, field, change.before, change.after))
					}
				}

				sort.Strings(unaccounted)
				if len(unaccounted) > 0 {
					t.Fatalf("%d field(s) this core changes are not registered for %s:\n  %s\n\n"+
						"Either add a deviationRule (and regenerate "+
						"CONFIG-DEVIATION-REGISTRY.json) or stop changing the field. A client "+
						"gate reading the registry treats an unregistered field as one the "+
						"reader may safely set.",
						len(unaccounted), seat.name, strings.Join(unaccounted, "\n  "))
				}
				t.Logf("%d change(s), all registered", len(changes))
			})
		}
	}
}

// The probe has to be able to see a change before "no unregistered changes" means anything.
func TestTheDeviationProbeSeesAChange(t *testing.T) {
	cfg := &config.Config{}
	seedStruct(reflect.ValueOf(cfg), true, "", 0)
	if cfg.General == nil || cfg.Experimental == nil || cfg.Profile == nil {
		t.Fatal("seeding left a top-level member nil, so the probe would look at nothing there")
	}
	if !cfg.General.GeoAutoUpdate {
		t.Fatal("seeding did not set General.GeoAutoUpdate, so the force that clears it " +
			"would be invisible -- this is the positive control for the whole probe")
	}

	after := &config.Config{}
	seedStruct(reflect.ValueOf(after), true, "", 0)
	finalizeConfigForApple(after, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true))

	var changes []observedChange
	diffStruct(reflect.ValueOf(cfg.General), reflect.ValueOf(after.General), "", 0, &changes)
	if len(changes) == 0 {
		t.Fatal("the probe observed no change at all on an iOS packet tunnel, which is wrong: " +
			"geo-auto-update alone is forced off there. A probe that sees nothing reports " +
			"the same thing as a core that changes nothing.")
	}
	found := false
	for _, change := range changes {
		if change.goPath == "GeoAutoUpdate" {
			found = true
		}
	}
	if !found {
		t.Fatalf("geo-auto-update was not among the observed changes (%v) -- the diff walks "+
			"the struct but does not reach the field the force is known to touch", changes)
	}
}
