package hako

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/TokenPLS/Hako/config"
)

const substitutionPlanYAML = `
tun:
  enable: true
dns:
  enable: true
  fake-ip-range: 172.19.0.1/16
  nameserver: ['system', '223.5.5.5']
  fallback: ['dhcp://en0']
  default-nameserver: ['system']
  nameserver-policy:
    '+.corp.example': ['system']
`

func noticeFieldsOfKind(r planResult, kind string) []string {
	fields := []string{}
	for _, n := range r.StructuredNotices {
		if n.Kind == kind {
			fields = append(fields, n.Field)
		}
	}
	sort.Strings(fields)
	return fields
}

func TestPlanReportsSubstitutionNotStripWhenTheAppSuppliesResolvers(t *testing.T) {
	supplySystemResolvers(t, "1.1.1.1", "9.9.9.9")
	r := planOf(t, substitutionPlanYAML)
	mustNotRefuse(t, r, "a configuration whose system resolvers are substituted")
	want := []string{"dns.default-nameserver", "dns.fallback", "dns.nameserver", "dns.nameserver-policy"}
	if got := noticeFieldsOfKind(r, planNoticeDNSSystemResolverSubstituted); !reflect.DeepEqual(got, want) {
		t.Fatalf("substituted notices on %v, want %v\n%+v", got, want, r.StructuredNotices)
	}
	for _, kind := range []string{planNoticeDNSSystemResolverStripped, planNoticeDNSBootstrapReplaced} {
		if got := noticeFieldsOfKind(r, kind); len(got) != 0 {
			t.Fatalf("a %s notice on %v would tell the user the opposite of what the runtime does", kind, got)
		}
	}
	for _, n := range r.StructuredNotices {
		if n.Kind == planNoticeDNSSystemResolverSubstituted && !strings.Contains(n.Text, "1.1.1.1, 9.9.9.9") {
			t.Errorf("the notice must name the resolvers that take the entry's place: %q", n.Text)
		}
	}
}

func TestPlanKeepsTheStripNoticesWhenNothingUsableIsSupplied(t *testing.T) {
	supplySystemResolvers(t, "172.19.0.2")
	r := planOf(t, substitutionPlanYAML)
	mustNotRefuse(t, r, "a configuration whose supplied resolvers are all the tunnel's own")
	if got := noticeFieldsOfKind(r, planNoticeDNSSystemResolverSubstituted); len(got) != 0 {
		t.Fatalf("nothing usable was supplied, yet the plan promised a substitution on %v", got)
	}
	if got, want := noticeFieldsOfKind(r, planNoticeDNSSystemResolverStripped), []string{"dns.fallback", "dns.nameserver", "dns.nameserver-policy"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("stripped notices on %v, want %v", got, want)
	}
	if got, want := noticeFieldsOfKind(r, planNoticeDNSBootstrapReplaced), []string{"dns.default-nameserver"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("bootstrap-replaced notices on %v, want %v", got, want)
	}
}

// The plan predicts the runtime: the fields the plan says are substituted are exactly
// the fields the pipeline rewrites, over the same inputs, including the tunnel-range drop.
func TestPlanAndRuntimeAgreeOnWhichFieldsAreSubstituted(t *testing.T) {
	for _, supplied := range [][]string{
		{"1.1.1.1", "9.9.9.9"},
		{"172.19.0.2", "1.1.1.1"},
		{"172.19.0.2"},
		{},
	} {
		supplySystemResolvers(t, supplied...)
		planFields := noticeFieldsOfKind(planOf(t, substitutionPlanYAML), planNoticeDNSSystemResolverSubstituted)

		raw := rawConfigOf(t, substitutionPlanYAML)
		runtimeFields := []string{}
		seen := map[string]bool{}
		changes := substituteSystemResolvers(raw, usableSubstitutesFor(raw, systemDNSServerSubstitutes()))
		for _, change := range changes {
			if !seen[change.field] {
				seen[change.field] = true
				runtimeFields = append(runtimeFields, "dns."+change.field)
			}
		}
		sort.Strings(runtimeFields)
		if !reflect.DeepEqual(planFields, runtimeFields) {
			t.Errorf("supplied %v: plan substitutes %v, runtime substitutes %v", supplied, planFields, runtimeFields)
		}
	}
}

func rawConfigOf(t *testing.T, document string) *config.RawConfig {
	t.Helper()
	raw, err := config.UnmarshalRawConfig([]byte(document))
	if err != nil {
		t.Fatalf("the document does not parse upstream: %v", err)
	}
	return raw
}
