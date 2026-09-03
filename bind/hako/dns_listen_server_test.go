package hako

import "testing"

const dnsListenDocument = `
dns:
  enable: true
  listen: 0.0.0.0:1053
  listen-routing-mark: 666
  nameserver:
    - 223.5.5.5
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`

// dns.listen names a DNS server this core is being asked to run. It outlived the rest of the
// listener surface by one batch on a reason that was never about the platform: a subscription
// copied from a desktop tutorial can say 0.0.0.0:53, and because the exposure is written into
// the address rather than into a separate switch, there was no boolean to put behind the
// allow-lan permission. The note on record proposed sending it through that gate anyway, which
// would have meant rewriting the address to 127.0.0.1 -- inventing a value the user never
// wrote, and the same downgrade shape that was already rejected twice. So it opens.
//
// The mechanism was checked before the strip came out, because the controller family had
// already taught the other failure -- a field marked "kept" that nothing dispatched.
// hub/executor/executor.go:362 calls dns.ReCreateServer(c.Listen, lc, s) from updateDNS, which
// ApplyConfig runs on every start and reload, and dns/server.go:84-110 binds UDP and TCP at
// that address. Honouring this field starts a server; it is not a value carried for tidiness.
//
// What happens when the OS refuses the bind is upstream's answer, not ours: dns/server.go:87
// logs "Start DNS server(UDP) error" from inside the goroutine and the tunnel starts anyway.
// A privileged port on a non-root host is the obvious case, and desktop mihomo has always
// behaved this way there. Inheriting the failure mode is the point of inheriting the field.
func TestDNSListenSurvivesBothNormalizationLayers(t *testing.T) {
	mihomo, ours := parseBoth(t, dnsListenDocument)

	if mihomo.DNS.Listen != "0.0.0.0:1053" {
		t.Fatalf("fixture is wrong, not the code: mihomo parsed dns.listen as %q", mihomo.DNS.Listen)
	}

	// Both layers, in one test on purpose. The raw layer and overrideForNetworkExtension each
	// cleared this field, and the batch that opened the local proxy ports removed only the raw
	// one -- the ports stayed shut on a device while the parse output looked correct here.
	// parseBoth covers normalizeRawConfigForIOS; finalizeConfigForIOS covers the override.
	if ours.DNS.Listen != mihomo.DNS.Listen {
		t.Fatalf("dns.listen after the raw layer: mihomo %q, ours %q", mihomo.DNS.Listen, ours.DNS.Listen)
	}
	finalizeConfigForIOS(ours, true)
	if ours.DNS.Listen != mihomo.DNS.Listen {
		t.Errorf("dns.listen after finalize: mihomo %q, ours %q -- updateDNS reads this field, "+
			"so clearing it here means the configured server never starts", mihomo.DNS.Listen, ours.DNS.Listen)
	}
}

// The mark that travels with it does not open, and the difference is the whole point of the
// ruling: SO_MARK is a Linux socket option, iPhoneOS's sys/socket.h does not define it, and no
// value written here can reach a kernel that has nowhere to put it. Platform walls stay;
// judgements about what the user meant do not.
//
// Both layers are asserted separately, and that is not redundancy. The first version checked
// only the finished config, and a mutation removing the raw-layer line left it GREEN -- the
// override layer alone still produced a zero, so the test could not tell "defence in depth" from
// "one layer left". It only turned red when both lines went, which means it was pinning the
// outcome while reading like it pinned the code. Two assertions, two mutations, two reds.
func TestDNSListenRoutingMarkStaysStrippedBecauseDarwinHasNoSOMARK(t *testing.T) {
	_, ours := parseBoth(t, dnsListenDocument)

	if ours.DNS.ListenRoutingMark != 0 {
		t.Errorf("dns.listen-routing-mark = %d survived the raw layer", ours.DNS.ListenRoutingMark)
	}
	finalizeConfigForIOS(ours, true)
	if ours.DNS.ListenRoutingMark != 0 {
		t.Errorf("dns.listen-routing-mark = %d survived; Darwin has no SO_MARK, so carrying it "+
			"would promise a routing decision nothing can execute", ours.DNS.ListenRoutingMark)
	}
}

// The override layer's copy is the one a raw-layer assertion cannot see, and it is the layer
// that was left behind the last two times a field was opened. Parsing a config that never named
// the mark, then injecting it between the layers, is the only way to make that line the sole
// thing under test.
func TestTheOverrideLayerClearsTheMarkOnItsOwn(t *testing.T) {
	const noMark = `
dns:
  enable: true
  listen: 0.0.0.0:1053
  nameserver:
    - 223.5.5.5
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	_, ours := parseBoth(t, noMark)
	ours.DNS.ListenRoutingMark = 666

	finalizeConfigForIOS(ours, true)

	if ours.DNS.ListenRoutingMark != 0 {
		t.Error("overrideForNetworkExtension stopped clearing dns.listen-routing-mark; the raw " +
			"layer covers the configured path, but this is the defence that survives a raw-layer edit")
	}
}
