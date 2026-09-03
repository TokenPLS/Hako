package hako

import (
	"reflect"
	"testing"

	"github.com/TokenPLS/Hako/config"
)

// The converse of TestEveryFieldTheCoreChangesIsRegistered.
//
// That test proves every field the core changes is registered. It says nothing about the
// other direction -- that every registration is a change -- and the other direction is where
// geodata-loader slipped through: registered for all four profiles, forced only where
// memoryConservativeGeodata is set, so on a macOS profile the registry claimed a change that
// finalize never made. A client reading the registry on a Mac showed "forced: memconservative"
// over a loader that was exactly what the reader wrote. The iOS lane asked how a self-proving
// registry let that past; the answer is that it proved one direction.
//
// So: seed every field, run the real finalize once per profile, and for every forced rule with
// a forcedValue require that the field MOVED on each profile the rule claims and DID NOT move
// on each profile it does not claim. appliesTo is then derived from the code's behaviour in
// both directions, not from a hand-written applies alone.

func TestEveryRegisteredForcedRuleActuallyFiresOnEachProfileItClaims(t *testing.T) {
	restore := allowLanPermitted.Load()
	t.Cleanup(func() { allowLanPermitted.Store(restore) })

	// changed[profile] = set of registry field names finalize moved, seeding high so a force to
	// false/""/0/off is visible. (Seeding only high misses a force TO the high value; the
	// registry's forced values that are "true" -- dns.enable, tun.enable, store-fake-ip,
	// disable-icmp-forwarding -- are covered by the low seed below.)
	changedOn := func(high bool) map[string]map[string]bool {
		out := map[string]map[string]bool{}
		for _, seat := range registryProfiles {
			policy := runtimePolicyFor(seat.profile, seat.underNetworkExtension)
			before, after := &config.Config{}, &config.Config{}
			seedStruct(reflect.ValueOf(before), high, "", 0)
			seedStruct(reflect.ValueOf(after), high, "", 0)
			finalizeConfigForApple(after, policy)
			moved := map[string]bool{}
			b, a := reflect.ValueOf(before).Elem(), reflect.ValueOf(after).Elem()
			for _, root := range deviationProbeRoots {
				var changes []observedChange
				diffStruct(b.FieldByName(root.goName), a.FieldByName(root.goName), "", 0, &changes)
				rootType := b.FieldByName(root.goName).Type()
				for rootType.Kind() == reflect.Ptr {
					rootType = rootType.Elem()
				}
				for _, c := range changes {
					if field, ok := registryFieldFor(root.goName, root.prefix, c.goPath, rootType); ok {
						moved[field] = true
					}
				}
			}
			out[seat.name] = moved
		}
		return out
	}
	movedHigh, movedLow := changedOn(true), changedOn(false)
	moved := func(profile, field string) bool { return movedHigh[profile][field] || movedLow[profile][field] }

	claims := map[string]map[string]bool{} // field -> profiles the registry claims
	for _, rule := range deviationRules {
		if rule.category != deviationForced || rule.forcedValue == "" {
			continue
		}
		claims[rule.field] = map[string]bool{}
		for _, seat := range registryProfiles {
			policy := runtimePolicyFor(seat.profile, seat.underNetworkExtension)
			if rule.applies == nil || rule.applies(policy) {
				claims[rule.field][seat.name] = true
			}
		}
	}
	if len(claims) == 0 {
		t.Fatal("no forced rule carries a forcedValue; the converse has nothing to check")
	}

	// Fields the seeder cannot reach (no json tag and no alias) are skipped with a log line, so
	// a silent skip cannot masquerade as a pass.
	for field, profiles := range claims {
		reachable := false
		for _, seat := range registryProfiles {
			if movedHigh[seat.name][field] || movedLow[seat.name][field] {
				reachable = true
			}
		}
		if !reachable {
			t.Logf("%s: finalize never moved it on any profile under either seed -- either the "+
				"force is unreachable from this probe (tun.dns-hijack is a list, tun.mtu is "+
				"runtime) or the registration is wrong everywhere; listed, not passed", field)
			continue
		}
		for _, seat := range registryProfiles {
			claimed, did := profiles[seat.name], moved(seat.name, field)
			if claimed && !did {
				t.Errorf("%s: registry claims %s but finalize did not change it there -- appliesTo is a lie on that profile", field, seat.name)
			}
			if !claimed && did {
				t.Errorf("%s: finalize changes it on %s but the registry does not claim that profile", field, seat.name)
			}
		}
	}
}

// Two forces fire on the RAW configuration, before parsing: dns.enable inside
// normalizeRawConfigForApple (the packet-tunnel DNS repair) and profile.store-fake-ip in
// applyStoreFakeIPDefault, which parseConfigForIOSInternal runs right after it for every
// profile -- neither is in finalizeConfigForApple.
// The parsed-config probe above cannot see them ("never moved ... listed, not passed"), which
// is a blind spot of its own, so they get the same converse check on the path they actually
// run on: seed the raw field with the non-forced value, run the raw normaliser per profile,
// and require the field to move exactly on the profiles the registry claims.
func TestRawPathForcesFireExactlyWhereTheRegistryClaims(t *testing.T) {
	cases := []struct {
		field string
		seed  func(raw *config.RawConfig)
		moved func(raw *config.RawConfig) bool
	}{
		{"dns.enable",
			func(r *config.RawConfig) { r.DNS.Enable = false },
			func(r *config.RawConfig) bool { return r.DNS.Enable }},
		{"profile.store-fake-ip",
			func(r *config.RawConfig) { r.Profile.StoreFakeIP = false; r.Profile.StoreFakeIPSet = false },
			func(r *config.RawConfig) bool { return r.Profile.StoreFakeIP }},
	}
	for _, c := range cases {
		var rule *deviationRule
		for i := range deviationRules {
			if deviationRules[i].field == c.field {
				rule = &deviationRules[i]
			}
		}
		if rule == nil {
			t.Fatalf("%s: no rule", c.field)
		}
		for _, seat := range registryProfiles {
			policy := runtimePolicyFor(seat.profile, seat.underNetworkExtension)
			claimed := rule.applies == nil || rule.applies(policy)
			raw := config.DefaultRawConfig()
			c.seed(raw)
			// The same two calls, in the same order, that parseConfigForIOSInternal makes.
			normalizeRawConfigForApple(raw, policy)
			applyStoreFakeIPDefault(raw)
			did := c.moved(raw)
			if claimed && !did {
				t.Errorf("%s: registry claims %s but the raw normaliser did not change it there", c.field, seat.name)
			}
			if !claimed && did {
				t.Errorf("%s: the raw normaliser changes it on %s but the registry does not claim that profile", c.field, seat.name)
			}
		}
	}
}
