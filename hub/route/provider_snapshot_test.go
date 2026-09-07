package route

import (
	"os"
	"os/exec"
	"sync"
	"testing"

	"github.com/metacubex/http/httptest"
	P "github.com/TokenPLS/Hako/constant/provider"
	ruleprovider "github.com/TokenPLS/Hako/rules/provider"
	"github.com/TokenPLS/Hako/tunnel"
)

func TestRuleProviderQueriesDuringReplacement(t *testing.T) {
	// Configuration belongs to the whole Core process. Keep this replacement
	// stress test isolated from other route tests' configuration and listeners.
	if os.Getenv("HAKO_RULE_PROVIDER_SNAPSHOT_CHILD") != "1" {
		command := exec.Command(os.Args[0], "-test.run=^TestRuleProviderQueriesDuringReplacement$", "-test.count=1")
		command.Env = append(os.Environ(), "HAKO_RULE_PROVIDER_SNAPSHOT_CHILD=1")
		if out, err := command.CombinedOutput(); err != nil {
			t.Fatalf("provider query stress: %v\n%s", err, out)
		}
		return
	}
	provider := ruleprovider.NewInlineProvider("rules", P.IPCIDR, []string{"192.0.2.0/24"}, nil)
	tunnel.UpdateRules(nil, nil, map[string]P.RuleProvider{"rules": provider})
	router := ruleProviderRouter()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			tunnel.UpdateRules(nil, nil, map[string]P.RuleProvider{"rules": provider})
		}
	}()
	for i := 0; i < 100; i++ {
		for _, methodPath := range [][2]string{{"GET", "/"}, {"PUT", "/rules/"}} {
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(methodPath[0], methodPath[1], nil))
			if response.Code != 200 && response.Code != 204 {
				t.Errorf("unexpected provider response: %d", response.Code)
			}
		}
	}
	wg.Wait()
}
