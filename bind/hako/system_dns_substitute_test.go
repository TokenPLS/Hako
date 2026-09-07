package hako

import (
	"net/netip"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/TokenPLS/Hako/config"
	"github.com/TokenPLS/Hako/dns"

	"gopkg.in/yaml.v3"
)

// supplySystemResolvers stands in for SetupOptions.SystemDNSServerLines for one test.
func supplySystemResolvers(t *testing.T, lines ...string) {
	t.Helper()
	previous := systemDNSSubstitutes.Load()
	parsed := append([]string(nil), lines...)
	systemDNSSubstitutes.Store(&parsed)
	t.Cleanup(func() { systemDNSSubstitutes.Store(previous) })
}

// normalizedRawFor runs a whole document through the Apple packet-tunnel normalization.
func normalizedRawFor(t *testing.T, doc map[string]any) *config.RawConfig {
	t.Helper()
	document, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	raw, err := config.UnmarshalRawConfig(document)
	if err != nil {
		t.Fatalf("the document does not even parse upstream, so it tests nothing: %v\n%s", err, document)
	}
	normalizeRawConfigForApple(raw, nePolicy())
	return raw
}

// stringsIn collects every string inside a value, in order (see neIncompatibleIn for
// why the yaml round trip is needed).
func stringsIn(t *testing.T, v any) []string {
	t.Helper()
	encoded, err := yaml.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var tree any
	if err := yaml.Unmarshal(encoded, &tree); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	out := []string{}
	walkStrings(tree, func(s string) { out = append(out, s) })
	return out
}

func TestParseSystemDNSServerLines(t *testing.T) {
	cases := []struct {
		in   string
		want []string
		err  string
	}{
		{in: "", want: nil},
		{in: "\n  \n", want: nil},
		{in: "1.1.1.1\n\n 9.9.9.9 \n", want: []string{"1.1.1.1", "9.9.9.9"}},
		{in: "1.1.1.1:5353", want: []string{"1.1.1.1:5353"}},
		{in: "[2001:db8::1]:53", want: []string{"[2001:db8::1]:53"}},
		{in: "2001:db8::1", want: []string{"2001:db8::1"}},
		{in: "1.1.1.1\ndns.google", err: "line 2: \"dns.google\" is neither an IP address nor ip:port"},
		{in: "1.1.1.1:0", err: "line 1: \"1.1.1.1:0\" names port 0"},
		{in: "fe80::1%en0", err: "line 1: \"fe80::1%en0\" carries an interface zone"},
	}
	for _, c := range cases {
		got, err := parseSystemDNSServerLines(c.in)
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("%q: err = %v, want one containing %q", c.in, err, c.err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: unexpected error %v", c.in, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%q: parsed %v, want %v", c.in, got, c.want)
		}
	}
}

func TestSetupStoresSystemDNSServerLinesAndRejectsWhatIsNotAnAddress(t *testing.T) {
	base := t.TempDir()
	options := func(lines string) *SetupOptions {
		return &SetupOptions{
			BasePath:             base,
			WorkingPath:          filepath.Join(base, "working"),
			TempPath:             filepath.Join(base, "temp"),
			SystemDNSServerLines: lines,
		}
	}
	previous := systemDNSSubstitutes.Load()
	t.Cleanup(func() { systemDNSSubstitutes.Store(previous) })

	if err := Setup(options("119.29.29.29\n[2402:4e00::]:53\n")); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if got, want := systemDNSServerSubstitutes(), []string{"119.29.29.29", "[2402:4e00::]:53"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("substitutes after Setup = %v, want %v", got, want)
	}
	err := Setup(options("119.29.29.29\ndns.google\n"))
	if err == nil {
		t.Fatal("Setup accepted a hostname in SystemDNSServerLines")
	}
	for _, want := range []string{"SetupOptions.SystemDNSServerLines", "line 2", "dns.google"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err.Error(), want)
		}
	}
	if got, want := systemDNSServerSubstitutes(), []string{"119.29.29.29", "[2402:4e00::]:53"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("a refused Setup must leave the previous list in place, got %v", got)
	}
	if err := Setup(options("")); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if got := systemDNSServerSubstitutes(); len(got) != 0 {
		t.Fatalf("an empty SystemDNSServerLines means no substitution, got %v", got)
	}
}

// Every field the strip reaches, the substitution reaches: the same classification
// drives both (dns_resolver_field_classification_test.go), so a resolver slot added
// upstream goes red here as well as there.
func TestSuppliedSystemResolversReplaceSystemAndDhcpInEveryResolverField(t *testing.T) {
	supplySystemResolvers(t, "1.1.1.1", "9.9.9.9")
	for _, field := range append(dnsFieldsByKind(t, "resolver"), dnsFieldsByKind(t, "bootstrap")...) {
		key := strings.Split(field.Tag.Get("yaml"), ",")[0]
		t.Run(key, func(t *testing.T) {
			var value any = []string{"system", "dhcp://en0", "223.5.5.5"}
			if strings.Contains(field.Type.String(), "OrderedMap") {
				value = map[string]any{"+.example.com": []string{"system", "dhcp://en0", "223.5.5.5"}}
			}
			dns := map[string]any{"enable": true, "nameserver": []string{"223.5.5.5"}}
			dns[key] = value
			got := stringsIn(t, normalizedDNSField(t, dns, field.Name))
			// One expansion per list, at the first system/dhcp entry; the second
			// system-class entry names the same resolvers and is not expanded twice.
			want := []string{"1.1.1.1", "9.9.9.9", "223.5.5.5"}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("dns.%s reached the core as %v, want %v", key, got, want)
			}
		})
	}
}

func TestAPolicyWhoseResolversWereAllSystemNowNamesTheSystemResolvers(t *testing.T) {
	doc := func() map[string]any {
		return map[string]any{"dns": map[string]any{
			"enable":            true,
			"nameserver":        []string{"223.5.5.5"},
			"nameserver-policy": map[string]any{"+.corp.example": []string{"system"}},
		}}
	}
	policyValue := func(raw *config.RawConfig) []string {
		pair := raw.DNS.NameServerPolicy.GetPair("+.corp.example")
		if pair == nil {
			t.Fatal("the policy entry vanished; deleting it would leak the domain to the public resolver")
		}
		return dnsServerStrings(pair.Value)
	}
	// Without supplied resolvers the entry fails closed, as it has since the strip.
	if got, want := policyValue(normalizedRawFor(t, doc())), []string{"rcode://name_error"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("without supplied resolvers the emptied policy = %v, want %v", got, want)
	}
	supplySystemResolvers(t, "10.0.0.53", "10.0.0.54")
	if got, want := policyValue(normalizedRawFor(t, doc())), []string{"10.0.0.53", "10.0.0.54"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("with supplied resolvers the policy = %v, want %v", got, want)
	}
}

func TestSuppliedResolversInsideTheTunnelsOwnRangesAreDropped(t *testing.T) {
	// A list read AFTER the tunnel's DNS settings applied names the tunnel itself
	// (198.18.0.2, or whatever fake-ip-range implies). Substituting that would
	// reproduce #21 in a new shape, so the configuration's own ranges filter it.
	prefixes := []netip.Prefix{netip.MustParsePrefix("172.19.0.0/16"), netip.MustParsePrefix("28.0.0.1/8")}
	usable, dropped := usableSystemResolverSubstitutes(
		[]string{"198.18.0.2", "172.19.0.2", "fdfe:dcba:9876::2", "28.0.0.53:53", "1.1.1.1", "[2001:db8::1]:5353"},
		prefixes,
	)
	if want := []string{"1.1.1.1", "[2001:db8::1]:5353"}; !reflect.DeepEqual(usable, want) {
		t.Fatalf("usable = %v, want %v", usable, want)
	}
	if want := []string{"198.18.0.2", "172.19.0.2", "fdfe:dcba:9876::2", "28.0.0.53:53"}; !reflect.DeepEqual(dropped, want) {
		t.Fatalf("dropped = %v, want %v", dropped, want)
	}

	supplySystemResolvers(t, "172.19.0.2", "1.1.1.1")
	raw := normalizedRawFor(t, map[string]any{
		"tun": map[string]any{"enable": true},
		"dns": map[string]any{"enable": true, "fake-ip-range": "172.19.0.1/16", "nameserver": []string{"system"}},
	})
	if got, want := raw.DNS.NameServer, []string{"1.1.1.1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("nameserver = %v, want %v (the tunnel's own address dropped, the physical one kept)", got, want)
	}
}

func TestWhenEverySuppliedResolverIsTheTunnelsOwnTheStripStands(t *testing.T) {
	supplySystemResolvers(t, "172.19.0.2")
	raw := normalizedRawFor(t, map[string]any{
		"tun": map[string]any{"enable": true},
		"dns": map[string]any{
			"enable":            true,
			"fake-ip-range":     "172.19.0.1/16",
			"nameserver":        []string{"system", "223.5.5.5"},
			"nameserver-policy": map[string]any{"+.corp.example": []string{"system"}},
		},
	})
	if got, want := raw.DNS.NameServer, []string{"223.5.5.5"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("nameserver = %v, want %v (nothing usable was supplied, so system is stripped as before)", got, want)
	}
	pair := raw.DNS.NameServerPolicy.GetPair("+.corp.example")
	if pair == nil || !reflect.DeepEqual(dnsServerStrings(pair.Value), []string{"rcode://name_error"}) {
		t.Fatalf("the emptied policy must still fail closed, got %+v", pair)
	}
}

func TestMihomoParsesEverySubstituteShape(t *testing.T) {
	// The shapes parseSystemDNSServerLines emits are handed to mihomo verbatim, so
	// mihomo's own parser (config.go parsePureDNSServer) is the judge of them.
	parsed, err := dns.ParseNameServer([]string{"1.1.1.1", "2001:db8::1", "1.1.1.1:5353", "[2001:db8::1]:5353"})
	if err != nil {
		t.Fatalf("mihomo refused a substitute shape: %v", err)
	}
	got := []string{}
	for _, ns := range parsed {
		got = append(got, ns.Addr)
	}
	want := []string{"1.1.1.1:53", "[2001:db8::1]:53", "1.1.1.1:5353", "[2001:db8::1]:5353"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mihomo parsed %v, want %v", got, want)
	}
}
