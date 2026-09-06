package hako

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func inspectProxyPayloadReport(t *testing.T, payload, context string) proxyImportReport {
	t.Helper()
	box, err := InspectProxyPayloadForIOS([]byte(payload), context)
	if err != nil {
		t.Fatalf("InspectProxyPayloadForIOS(%s) returned an error instead of a report: %v", context, err)
	}
	var report proxyImportReport
	if err := json.Unmarshal([]byte(box.Value), &report); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	return report
}

// An unmapped query key is refused whether or not it carries a value. An empty
// value is still a key this build does not map, and the ledger is the sentence
// the client copy repeats: every key it does not know is refused.
// A key this build does not map is named, and the node still arrives -- with or
// without a value on it.
//
// This asserted the opposite until 2026-08-28. The whitelist was treated as the
// judgement rather than as a lookup, so any spelling an exporter invents cost
// the node; the reader lost two links from their own subscription to it within
// an hour. Upstream reads the keys it knows and ignores the rest.
//
// The empty-value row is here because it was here before: `?key=` and `?key=1`
// took different paths through the ledger once, and a rule about unknown keys
// that only holds when they carry a value is not a rule about unknown keys.
func TestAnUnmappedQueryKeyIsNamedAndTheNodeStillArrives(t *testing.T) {
	for name, link := range map[string]string{
		"with value":  "trojan://secret@example.invalid:443?peer=sni.example.invalid&hakoUnmappedField=1#node",
		"empty value": "trojan://secret@example.invalid:443?peer=sni.example.invalid&hakoUnmappedField=#node",
	} {
		t.Run(name, func(t *testing.T) {
			report := inspectProxyPayloadReport(t, link, "nodeBundle")
			if len(report.Proxies) != 1 {
				t.Fatalf("an unmapped key cost the node: %+v", report)
			}
			if len(report.Skipped) != 0 {
				t.Fatalf("the record was skipped over one unmapped key: %+v", report.Skipped)
			}
			if len(report.NotHonoured) != 1 ||
				!strings.Contains(report.NotHonoured[0].Message, "hakoUnmappedField") {
				t.Fatalf("the unmapped key was dropped without saying so: %+v", report.NotHonoured)
			}
		})
	}
}

// The ledger check still refuses an unmapped key when it is asked to.
//
// Nothing calls it that way any more -- both entry points pass tolerate=true --
// but the parameter is the seam the change was made at, and a test that the
// strict branch still works is what makes it safe to keep. Deleting it would
// leave the branch unexercised and looking dead.
func TestValidateProxyShareLinkQueryFieldsIsFailClosedWhenAsked(t *testing.T) {
	capability := proxyImportCapability{Scheme: "trojan", CanonicalType: "trojan", Status: proxyImportSupported}
	if _, err := validateProxyShareLinkQueryFields("trojan://secret@example.invalid:443?peer=sni.example.invalid", capability, false); err != nil {
		t.Fatalf("a mapped key was refused: %v", err)
	}
	for _, link := range []string{
		"trojan://secret@example.invalid:443?hakoUnmappedField=1",
		"trojan://secret@example.invalid:443?hakoUnmappedField=",
	} {
		if _, err := validateProxyShareLinkQueryFields(link, capability, false); err == nil {
			t.Fatalf("an unmapped key passed the ledger: %s", link)
		}
	}
}

// singleNode reports what happened. The importer already knows which record
// failed and why; collapsing that into one sentence at the exit throws away the
// only part the reader can act on.
func TestSingleNodeFailureCarriesTheReason(t *testing.T) {
	for name, testCase := range map[string]struct{ payload, wantCode string }{
		"unknown scheme": {"hakonotascheme://x@example.invalid:443#n", "unknownScheme"},

		"recognized but unsupported scheme": {"juicity://x@example.invalid:443#n", proxyImportCoreUnsupported},
	} {
		t.Run(name, func(t *testing.T) {
			report := inspectProxyPayloadReport(t, testCase.payload, "singleNode")
			issues := report.Skipped
			if len(issues) != 1 {
				t.Fatalf("want exactly one issue, got %d: %+v", len(issues), report)
			}
			if issues[0].Code != testCase.wantCode {
				t.Fatalf("code %q, want %q", issues[0].Code, testCase.wantCode)
			}
			if len(report.Proxies) != 0 {
				t.Fatalf("a failed single-node import still produced proxies: %v", report.Proxies)
			}
		})
	}
}

func TestProxyPayloadSizeRefusalsNameWhatIsWrong(t *testing.T) {
	if _, err := InspectProxyPayloadForIOS(nil, "singleNode"); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("the empty-payload refusal does not say it is empty: %v", err)
	}
	oversized := make([]byte, maximumProviderResourceBytes+1)
	_, err := InspectProxyPayloadForIOS(oversized, "singleNode")
	if err == nil {
		t.Fatal("an oversized payload was accepted")
	}
	for _, want := range []string{fmt.Sprint(maximumProviderResourceBytes), fmt.Sprint(len(oversized))} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the oversize refusal %q carries neither the limit nor the size (%s)", err.Error(), want)
		}
	}
}

// mieru has two schemes upstream (pkg/appctl/client.go: "URL must begin with
// mieru:// or mierus://"). Only the simple one is constructible here, so the
// standard one is recognized and refused by name, not reported as gibberish.
func TestMieruStandardURLIsRecognizedNotUnknown(t *testing.T) {
	report := inspectProxyPayloadReport(t, "mieru://x@198.51.100.30:443#M", "nodeBundle")
	// One outcome, distinguished by its code rather than by which array it
	// landed in. `mieru://` is a scheme this importer knows and cannot build,
	// which is not the same as a scheme it has never heard of, and the reason
	// the person is shown differs accordingly -- but both mean the link did not
	// become a node, and the report says that once.
	if len(report.Skipped) != 1 {
		t.Fatalf("mieru:// is not reported as skipped: %+v", report)
	}
	if report.Skipped[0].Code != proxyImportCoreUnsupported {
		t.Fatalf("code %q, want %q -- mieru:// is recognized, not unknown",
			report.Skipped[0].Code, proxyImportCoreUnsupported)
	}
}

// The repeat suffix is upstream's own: common/convert/converter.go uniqueName
// formats a repeat as "%s-%02d". Renaming differently would leave hand-written
// proxy-group members pointing at a name this importer never emits.
func TestDuplicateNamesFollowUpstreamUniqueNameFormat(t *testing.T) {
	payload := strings.Join([]string{
		"trojan://a@example.invalid:443#Site",
		"trojan://b@example.invalid:443#Site",
		"trojan://c@example.invalid:443#Site",
	}, "\n")
	report := inspectProxyPayloadReport(t, payload, "nodeBundle")
	want := []string{"Site", "Site-01", "Site-02"}
	if len(report.Proxies) != len(want) {
		t.Fatalf("want %d proxies, got %d: %+v", len(want), len(report.Proxies), report)
	}
	for index, wanted := range want {
		if name, _ := report.Proxies[index]["name"].(string); name != wanted {
			t.Fatalf("proxy %d is named %q, want %q", index, name, wanted)
		}
	}
}

// The registry owns the routing decision too. A client that re-derives "which
// scheme is a node" keeps a second scheme set, which is exactly what the
// capability export exists to remove.
func TestCapabilityDocumentCarriesThePasteRole(t *testing.T) {
	var document proxyImportCapabilitiesDocument
	if err := json.Unmarshal([]byte(ProxyImportCapabilitiesForIOS().Value), &document); err != nil {
		t.Fatalf("decode capability document: %v", err)
	}
	roles := make(map[string]string, len(document.Schemes))
	for _, capability := range document.Schemes {
		if capability.PasteRole == "" {
			t.Fatalf("scheme %q carries no paste role", capability.Scheme)
		}
		roles[capability.Scheme] = capability.PasteRole
	}
	for scheme, want := range map[string]string{
		"sub":     proxyImportPasteWrapper,
		"http":    proxyImportPasteSubscription,
		"https":   proxyImportPasteSubscription,
		"trojan":  proxyImportPasteNode,
		"juicity": proxyImportPasteNode,
		"mierus":  proxyImportPasteNode,
	} {
		if roles[scheme] != want {
			t.Fatalf("scheme %q has paste role %q, want %q", scheme, roles[scheme], want)
		}
	}
}

// A reader looking at twenty pasted lines cannot count records. Share-link
// records carry the line and byte offset they were read from; container
// formats keep the array index, which is what locates an entry there.
func TestShareLinkIssuesAreLocatableInTheOriginalText(t *testing.T) {
	payload := strings.Join([]string{
		"trojan://a@example.invalid:443#First",
		"hakonotascheme://b@example.invalid:443#Second",
		"trojan://c@example.invalid:443#Third",
	}, "\n")
	report := inspectProxyPayloadReport(t, payload, "nodeBundle")
	if len(report.Skipped) != 1 {
		t.Fatalf("want one rejected record, got %d: %+v", len(report.Skipped), report.Skipped)
	}
	issue := report.Skipped[0]
	if issue.Line != 2 {
		t.Fatalf("rejected record reports line %d, want 2", issue.Line)
	}
	if want := strings.Index(payload, "hakonotascheme"); issue.Offset != want {
		t.Fatalf("rejected record reports offset %d, want %d", issue.Offset, want)
	}
}

// Hysteria 2 accepts a hopping list in the authority ("443,5000-6000") and the
// ecosystem also sends it as a query field -- Shadowrocket spells it mport,
// mihomo spells it ports. All three reach the kernel's own `ports`, which stays
// the validator for the exact grammar. The deleted Swift parser handled the
// authority form on purpose; dropping it made links that used to
// import report a malformed URI.
func TestHysteria2PortHoppingSurvivesEverySpelling(t *testing.T) {
	for name, testCase := range map[string]struct{ link, wantPorts string }{
		"authority list":  {"hysteria2://pw@example.invalid:443,5000-6000#N", "443,5000-6000"},
		"authority range": {"hysteria2://pw@example.invalid:40000-50000#N", "40000-50000"},
		"query mport":     {"hysteria2://pw@example.invalid:443?mport=40000-50000#N", "40000-50000"},
		"query ports":     {"hysteria2://pw@example.invalid:443?ports=40000-50000#N", "40000-50000"},
	} {
		t.Run(name, func(t *testing.T) {
			report := inspectProxyPayloadReport(t, testCase.link, "singleNode")
			if len(report.Proxies) != 1 {
				t.Fatalf("want one proxy, got %d: %+v", len(report.Proxies), report)
			}
			if ports, _ := report.Proxies[0]["ports"].(string); ports != testCase.wantPorts {
				t.Fatalf("ports = %q, want %q", ports, testCase.wantPorts)
			}
		})
	}

	// A single port is untouched: no ports key, and the port itself survives.
	report := inspectProxyPayloadReport(t, "hysteria2://pw@example.invalid:443#N", "singleNode")
	if len(report.Proxies) != 1 {
		t.Fatalf("the single-port control stopped working: %+v", report)
	}
	if _, present := report.Proxies[0]["ports"]; present {
		t.Fatalf("a single-port link grew a ports key: %+v", report.Proxies[0])
	}
}

// The importer and the core it feeds must answer the same thing. This case is
// upstream's own (TestConvertsV2Ray_hysteria2PortHopping in common/convert),
// input and expectations copied rather than invented -- a hand-made fixture is
// how a false red gets manufactured, which happened twice in this batch.
func TestHysteria2PortHoppingMatchesUpstreamFieldForField(t *testing.T) {
	report := inspectProxyPayloadReport(t,
		"hysteria2://letmein@example.invalid:443,5000-6000/?sni=example.invalid#hop", "singleNode")
	if len(report.Proxies) != 1 {
		t.Fatalf("want one proxy, got %d: %+v", len(report.Proxies), report)
	}
	proxy := report.Proxies[0]
	for key, want := range map[string]string{
		"server": "example.invalid",
		"port":   "443",
		"ports":  "443,5000-6000",
	} {
		if got := anyString(proxy[key]); got != want {
			t.Fatalf("%s = %q, want %q (upstream converter_test asserts this)", key, got, want)
		}
	}
}
