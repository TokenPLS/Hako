package hako

import (
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"testing"
)

// proxyImportExporterFieldOracle says where each query key the exporter emits has
// to land in the proxy this importer builds. It is the difference between "the
// link was accepted" and "the link was understood": a websocket node imports
// perfectly well as tcp, and nothing about the record count says otherwise.
//
// A dotted path walks nested option objects. Two keys have a value that depends
// on the transport and carry both destinations.
var proxyImportExporterFieldOracle = map[string][]string{
	"path":          {"ws-opts.path", "grpc-opts.grpc-service-name"},
	"obfsParam":     {"ws-opts.headers.Host"},
	"obfs":          {"network"},
	"alpn":          {"alpn"},
	"fingerprint":   {"client-fingerprint"},
	"pbk":           {"reality-opts.public-key"},
	"sid":           {"reality-opts.short-id"},
	"peer":          {"servername", "sni"},
	"alterId":       {"alterId"},
	"allowInsecure": {"skip-cert-verify"},
	"xtls":          {"flow"},
	"tls":           {"tls"},
	"tfo":           {"tfo"},
	"udp":           {"udp"},
}

type exporterDialectCorpus struct {
	Source map[string]string `json:"source"`
	Pairs  []struct {
		Input    string `json:"input"`
		Exported string `json:"exported"`
	} `json:"pairs"`
}

func lookupProxyPath(proxy map[string]any, path string) (any, bool) {
	current := any(proxy)
	for _, segment := range strings.Split(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = object[segment]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

// TestEveryShadowrocketExportImportsWithItsFieldsIntact is the acceptance oracle
// for "compatible with Shadowrocket": every URI in the corpus is what the exporter
// itself replied when handed the paired input, so the assertion is not that our
// dialect table is complete but that nothing the exporter actually emits is lost.
func TestEveryShadowrocketExportImportsWithItsFieldsIntact(t *testing.T) {
	raw, err := os.ReadFile("testdata/shadowrocket-2.2.90-3378-dialect-matrix.json")
	if err != nil {
		t.Fatalf("read the exporter corpus: %v", err)
	}
	var corpus exporterDialectCorpus
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatalf("corpus: %v", err)
	}
	if len(corpus.Pairs) == 0 {
		t.Fatal("the corpus is empty, so this test would pass without importing anything")
	}
	graded := 0
	for _, pair := range corpus.Pairs {
		parsed, err := url.Parse(pair.Exported)
		if err != nil {
			t.Errorf("corpus entry is not a URI: %s", pair.Exported)
			continue
		}
		box, err := InspectProxyPayloadForIOS([]byte(pair.Exported), "singleNode")
		if err != nil {
			t.Errorf("refused an export of %s: %v", pair.Input, err)
			continue
		}
		var report proxyImportReport
		if err := json.Unmarshal([]byte(box.Value), &report); err != nil {
			t.Fatalf("report: %v", err)
		}
		if len(report.Proxies) != 1 {
			t.Errorf("refused an export of %s: %+v %+v",
				pair.Input, report.Skipped, report.Skipped)
			continue
		}
		proxy := report.Proxies[0]
		for key, values := range parsed.Query() {
			destinations, oracled := proxyImportExporterFieldOracle[key]
			if !oracled || len(values) == 0 || values[0] == "" {
				continue
			}
			landed := false
			for _, destination := range destinations {
				if _, ok := lookupProxyPath(proxy, destination); ok {
					landed = true
					break
				}
			}
			graded++
			if !landed {
				encoded, _ := json.Marshal(proxy)
				t.Errorf("%s=%s went nowhere (wanted one of %v)\n  export: %s\n  proxy:  %s",
					key, values[0], destinations, pair.Exported, encoded)
			}
		}
	}
	// A run that grades nothing passes without comparing anything.
	if graded < len(corpus.Pairs) {
		t.Fatalf("graded only %d field(s) across %d export(s) -- the oracle no longer matches the corpus",
			graded, len(corpus.Pairs))
	}
	t.Logf("graded %d field placement(s) across %d exporter replies", graded, len(corpus.Pairs))
}
