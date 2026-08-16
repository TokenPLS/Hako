package hako

import (
	"reflect"
	"testing"

	MDNS "github.com/TokenPLS/Hako/dns"
)

func TestClassifyDNSTransportsIsProtocolOnlyAndDistinguishesStrictH3(t *testing.T) {
	servers := []MDNS.NameServer{
		{Net: "", Addr: "192.0.2.1:53"},
		{Net: "tcp", Addr: "192.0.2.2:53"},
		{Net: "tls", Addr: "resolver.example:853"},
		{Net: "https", Addr: "https://resolver.example/dns-query"},
		{Net: "https", Addr: "https://preferred.example/dns-query", PreferH3: true},
		{Net: "https", Addr: "https://strict.example/dns-query", Params: map[string]string{"h3": "true"}},
		{Net: "quic", Addr: "resolver.example:853"},
		{Net: "system"},
		{Net: "udp", Addr: "duplicate.example:53"},
	}
	want := []string{"doh", "doh-h3-preferred", "doh3", "doq", "dot", "system", "tcp", "udp"}
	if got := classifyDNSTransports(servers); !reflect.DeepEqual(got, want) {
		t.Fatalf("classifyDNSTransports() = %v, want %v", got, want)
	}
}
