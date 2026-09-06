package provider

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/TokenPLS/Hako/component/cidr"
	"github.com/TokenPLS/Hako/component/geodata/compiled"
	C "github.com/TokenPLS/Hako/constant"
	P "github.com/TokenPLS/Hako/constant/provider"
)

// Compiled country codes claim to be rule sets of behavior ipcidr in the same binary
// layout, and that claim is only worth making if THIS reader accepts them.
//
// The round-trip test in component/geodata/compiled reads the artifact with the writer's
// own reader, so it proves the two agree with each other and nothing else. The layout
// lives in two files -- mrs_converter.go writes it for rule sets, ipcidr.go writes it for
// compiled countries -- and a field added to one and not the other surfaces as an
// unreadable cache on a reader's device rather than as a failing test.
//
// The geosite half of this has had such a test since the artifacts existed. The GeoIP half
// shipped without one, which is the same defect class this repository keeps finding: a
// fixture that agrees with the code instead of with what the other side actually reads.
func TestCompiledGeoIPArtifactIsReadableAsARuleSet(t *testing.T) {
	set := cidr.NewIpCidrSet()
	for _, prefix := range []string{"1.1.1.0/24", "8.8.8.0/24", "2001:db8::/32"} {
		if err := set.AddIpCidr(netip.MustParsePrefix(prefix)); err != nil {
			t.Fatal(err)
		}
	}
	if err := set.Merge(); err != nil {
		t.Fatal(err)
	}

	var artifact bytes.Buffer
	if err := compiled.WriteIPCIDR(&artifact, set, 3); err != nil {
		t.Fatal(err)
	}

	strategy, err := rulesMrsParse(artifact.Bytes(), newStrategy(P.IPCIDR, nil))
	if err != nil {
		t.Fatalf("the rule set reader refused a compiled country: %v", err)
	}
	if strategy.Count() != 3 {
		t.Fatalf("count = %d, want 3", strategy.Count())
	}
	matches := func(address string) bool {
		return strategy.Match(&C.Metadata{DstIP: netip.MustParseAddr(address)}, C.RuleMatchHelper{})
	}
	for _, hit := range []string{"1.1.1.1", "8.8.8.8", "2001:db8::1"} {
		if !matches(hit) {
			t.Fatalf("the rule set does not match %s", hit)
		}
	}
	if matches("9.9.9.9") {
		t.Fatal("the rule set matches an address it was not given")
	}
}
