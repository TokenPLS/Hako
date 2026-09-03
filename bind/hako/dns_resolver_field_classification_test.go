package hako

import (
	"reflect"
	"strings"
	"testing"

	"github.com/TokenPLS/Hako/config"
)

// . The plan layer used to run every string in every dns field it did not
// recognise through isNEIncompatibleNameserver, and a hit refused the whole
// configuration with "system/dhcp resolver '…' has no iOS equivalent here and
// cannot be stripped". The registry carried the premise as unverified with the
// question "why can this tree strip them from six fields and must refuse on a
// seventh?"
//
// The answer is that there is no seventh. Upstream's RawDNS declares exactly
// seven resolver-bearing fields; six are in dnsResolverFields and are stripped
// with a notice, the seventh is default-nameserver and is filtered as the
// bootstrap. So the catch-all could never reach a resolver, and every input it
// COULD reach was something else wearing a resolver's clothes.
//
// These two tests hold the finding in place from both sides: the classification
// stays complete as upstream moves, and the fields that are not resolvers stay
// unjudged.

// dnsFieldClassification records what every yaml key in upstream's RawDNS is.
// A field added upstream is unclassified until someone says which it is, and
// this test is where they are asked.
var dnsFieldClassification = map[string]string{
	// Resolver-bearing. Stripped with a notice at activation.
	"nameserver":                     "resolver",
	"fallback":                       "resolver",
	"proxy-server-nameserver":        "resolver",
	"direct-nameserver":              "resolver",
	"nameserver-policy":              "resolver",
	"proxy-server-nameserver-policy": "resolver",
	// The bootstrap. Filtered by filterBootstrap, judged by
	// defaultNameserverStrip against mihomo's own pure-IP check.
	"default-nameserver": "bootstrap",
	// Everything else holds no resolver. Listed so the sweep is a sweep: a
	// name that vanishes upstream goes red too, rather than rotting here.
	"enable":                          "not-a-resolver",
	"prefer-h3":                       "not-a-resolver",
	"ipv6":                            "not-a-resolver",
	"ipv6-timeout":                    "not-a-resolver",
	"use-hosts":                       "not-a-resolver",
	"use-system-hosts":                "not-a-resolver",
	"respect-rules":                   "not-a-resolver",
	"fallback-filter":                 "not-a-resolver",
	"fallback-lazy-query":             "not-a-resolver",
	"listen":                          "not-a-resolver",
	"listen-routing-mark":             "not-a-resolver",
	"enhanced-mode":                   "not-a-resolver",
	"fake-ip-range":                   "not-a-resolver",
	"fake-ip-range6":                  "not-a-resolver",
	"fake-ip-filter":                  "not-a-resolver",
	"fake-ip-filter-mode":             "not-a-resolver",
	"fake-ip-ttl":                     "not-a-resolver",
	"cache-algorithm":                 "not-a-resolver",
	"cache-max-size":                  "not-a-resolver",
	"direct-nameserver-follow-policy": "not-a-resolver",
}

func rawDNSYAMLKeys(t *testing.T) []string {
	t.Helper()
	typ := reflect.TypeOf(config.RawDNS{})
	keys := make([]string, 0, typ.NumField())
	for i := range typ.NumField() {
		tag := typ.Field(i).Tag.Get("yaml")
		if tag == "" || tag == "-" {
			continue
		}
		keys = append(keys, strings.Split(tag, ",")[0])
	}
	if len(keys) == 0 {
		t.Fatal("reflected no yaml keys off config.RawDNS; the derivation is wrong, not the classification")
	}
	return keys
}

func TestEveryDNSResolverFieldIsClassified(t *testing.T) {
	upstream := rawDNSYAMLKeys(t)
	seen := map[string]bool{}
	for _, key := range upstream {
		seen[key] = true
		kind, ok := dnsFieldClassification[key]
		if !ok {
			t.Errorf("upstream's dns.%s is not classified. If it holds resolvers, add it to "+
				"dnsResolverFields AND to repairApplePacketTunnelDNS so system/dhcp is stripped "+
				"there too; if it does not, record it here as not-a-resolver.", key)
			continue
		}
		if kind == "resolver" && !contains(dnsResolverFields, key) {
			t.Errorf("dns.%s is classified as a resolver field but is missing from dnsResolverFields", key)
		}
	}
	for key := range dnsFieldClassification {
		if !seen[key] {
			t.Errorf("dns.%s is classified here but upstream's RawDNS no longer declares it; drop the entry", key)
		}
	}
	// The claim the deleted catch-all rested on, stated as an assertion: the
	// resolver-bearing fields are exactly dnsResolverFields + the bootstrap.
	for _, key := range dnsResolverFields {
		if dnsFieldClassification[key] != "resolver" {
			t.Errorf("dnsResolverFields lists dns.%s, which is classified %q", key, dnsFieldClassification[key])
		}
	}
	if dnsFieldClassification["default-nameserver"] != "bootstrap" {
		t.Error("default-nameserver must stay classified as the bootstrap; defaultNameserverStrip is the only judge it has")
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// The three shapes the catch-all actually reached, each a legal upstream
// configuration refused with a sentence about a resolver the field never held.
func TestNonResolverDNSFieldsAreNotJudgedAsResolvers(t *testing.T) {
	for _, tc := range []struct{ name, what, yaml string }{
		{
			name: "fake-ip-filter entry named system",
			what: "a fake-ip-filter domain entry",
			yaml: `
dns:
  enable: true
  enhanced-mode: fake-ip
  nameserver: ['223.5.5.5']
  fake-ip-filter: ['system', '+.lan']
`,
		},
		{
			name: "fallback-filter domain starting with system:",
			what: "a fallback-filter domain",
			yaml: `
dns:
  enable: true
  nameserver: ['223.5.5.5']
  fallback: ['8.8.8.8']
  fallback-filter:
    geoip: true
    domain: ['system:8080']
`,
		},
		{
			name: "dns.listen literally system",
			what: "the dns listen address",
			yaml: `
dns:
  enable: true
  nameserver: ['223.5.5.5']
  listen: 'system'
`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mustNotRefuse(t, planOf(t, tc.yaml), tc.what)
		})
	}
}

// The strip itself is unchanged: a system/dhcp entry in a real resolver field
// is still tolerated, stripped and reported. Without this, deleting the
// catch-all could be mistaken for deleting the handling.
func TestSystemResolverInARealFieldIsStillANotice(t *testing.T) {
	r := planOf(t, `
dns:
  enable: true
  nameserver: ['system', '223.5.5.5']
  fallback: ['dhcp://en0']
`)
	mustNotRefuse(t, r, "a system nameserver")
}
