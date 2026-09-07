package hako

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/TokenPLS/Hako/common/utils"
	"github.com/TokenPLS/Hako/component/resource"
	P "github.com/TokenPLS/Hako/constant/provider"
	ruleprovider "github.com/TokenPLS/Hako/rules/provider"
	"github.com/TokenPLS/Hako/tunnel"
)

func TestRuleProviderCatalogReportsLoadedBytesWithoutReadingTheCache(t *testing.T) {
	ruleprovider.SetTunnel(tunnel.Tunnel)
	path := filepath.Join(t.TempDir(), "rules.yaml")
	payload := []byte("payload:\n  - 203.0.113.0/24\n  - 192.0.2.0/24\n")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	live := ruleprovider.NewRuleSetProvider("live", P.IPCIDR, P.YamlRule, 0, resource.NewFileVehicle(path), nil, nil, nil)
	t.Cleanup(func() {
		if c, ok := live.(io.Closer); ok {
			_ = c.Close()
		}
	})
	if err := live.Initial(); err != nil {
		t.Fatal(err)
	}
	// A partial or missing on-disk cache must not become the reported loaded identity.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	empty := ruleprovider.NewRuleSetProvider("pending", P.IPCIDR, P.YamlRule, 0, resource.NewFileVehicle(path), nil, nil, nil)
	t.Cleanup(func() {
		if c, ok := empty.(io.Closer); ok {
			_ = c.Close()
		}
	})
	inline := ruleprovider.NewInlineProvider("inline", P.IPCIDR, []string{"198.51.100.0/24"}, nil)
	catalog := ruleProvidersCatalog(map[string]P.RuleProvider{"live": live, "pending": empty, "inline": inline})
	rows := catalog["providers"].(map[string]any)
	row, ok := rows["live"].(map[string]any)
	if !ok {
		t.Fatal("live provider missing")
	}
	if row["loaded"] != true || row["contentHash"] != utils.MakeHash(payload).String() || row["algorithm"] != "md5" {
		t.Fatalf("loaded cache identity = %#v", row)
	}
	if row["ruleCount"] != float64(2) {
		t.Fatalf("rule count = %#v", row["ruleCount"])
	}
	if rows["pending"].(map[string]any)["loaded"] != false {
		t.Fatal("uninitialized provider reported loaded")
	}
	inlineRow := rows["inline"].(map[string]any)
	if inlineRow["loaded"] != true {
		t.Fatal("inline provider not loaded")
	}
	if _, exists := inlineRow["contentHash"]; exists {
		t.Fatal("inline provider claimed a cache file hash")
	}
}

func TestRuleProviderCatalogSnapshotsConcurrentUpdates(t *testing.T) {
	ruleprovider.SetTunnel(tunnel.Tunnel)
	path := filepath.Join(t.TempDir(), "rules.yaml")
	provider := ruleprovider.NewRuleSetProvider("rules", P.IPCIDR, P.YamlRule, 0, resource.NewFileVehicle(path), nil, nil, nil)
	t.Cleanup(func() { _ = provider.(io.Closer).Close() })
	updater := provider.(interface{ SideUpdate([]byte) error })
	one := []byte("payload:\n  - 192.0.2.0/24\n")
	two := []byte("payload:\n  - 192.0.2.0/24\n  - 198.51.100.0/24\n")
	if err := updater.SideUpdate(one); err != nil {
		t.Fatal(err)
	}
	counts := map[string]float64{utils.MakeHash(one).String(): 1, utils.MakeHash(two).String(): 2}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			if _, err := json.Marshal(provider); err != nil {
				t.Error(err)
			}
			rows := ruleProvidersCatalog(map[string]P.RuleProvider{"rules": provider})["providers"].(map[string]any)
			row := rows["rules"].(map[string]any)
			if row["ruleCount"] != counts[row["contentHash"].(string)] {
				t.Error("metadata and hash crossed cache generations")
			}
		}
	}()
	for i := 0; i < 50; i++ {
		payload := one
		if i%2 == 0 {
			payload = two
		}
		if err := updater.SideUpdate(payload); err != nil {
			t.Error(err)
		}
	}
	wg.Wait()
}

func TestInlineProviderOffersPayloadFreeMetadata(t *testing.T) {
	provider := ruleprovider.NewInlineProvider("inline", P.IPCIDR, []string{"198.51.100.0/24"}, nil)
	reader, ok := provider.(interface{ LoadedMetadataJSON() ([]byte, error) })
	if !ok {
		t.Fatal("inline status must not serialize the full rules payload")
	}
	data, err := reader.LoadedMetadataJSON()
	if err != nil {
		t.Fatal(err)
	}
	var row map[string]any
	if err := json.Unmarshal(data, &row); err != nil {
		t.Fatal(err)
	}
	if _, ok := row["payload"]; ok {
		t.Fatal("metadata contains inline payload")
	}
	if row["loaded"] != true || row["ruleCount"] != float64(1) {
		t.Fatalf("inline metadata = %#v", row)
	}
}
