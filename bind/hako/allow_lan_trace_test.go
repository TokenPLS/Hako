package hako

import (
	"strings"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/log"
)

// The gate's failure direction is silent exposure, so "no evidence either way" is the worst
// state it can leave behind. Measured before writing this: of the four combinations, three left
// the kernel with no record at all --
//
//	allow-lan unwritten, permission denied   -> nothing
//	allow-lan unwritten, permission granted  -> nothing
//	allow-lan written,   permission denied   -> one deviation (the SAFE case)
//	allow-lan written,   permission granted  -> nothing (no longer a deviation)
//
// The one case that spoke was the safe one. The dangerous state -- permission granted -- was
// the one with no kernel trace, and a configuration that opens no ports leaves none at all
// because the listen address cannot be read back either.
//
// The consuming lane logs what the APP told the extension. This records what the KERNEL holds
// when it actually applies the gate. Those two disagreeing is the exact bug class this batch
// has been chasing all day, and only the second one can reveal it.
func TestEveryParseRecordsWhichWayTheGateWent(t *testing.T) {
	for _, permitted := range []bool{true, false} {
		SetAllowLanPermitted(permitted)
		t.Cleanup(func() { SetAllowLanPermitted(false) })

		subscription := log.Subscribe()
		done := make(chan string, 1)
		go func() {
			deadline := time.After(3 * time.Second)
			for {
				select {
				case event, open := <-subscription:
					if !open {
						done <- ""
						return
					}
					if strings.Contains(event.Payload, "allow-lan permitted") {
						done <- event.Payload
						return
					}
				case <-deadline:
					done <- ""
					return
				}
			}
		}()

		// A configuration that opens no ports: the case where nothing else leaves a trace.
		if _, err := parseConfigForIOS("proxies: []\nproxy-groups: []\nrules:\n  - MATCH,DIRECT\n", true); err != nil {
			log.UnSubscribe(subscription)
			t.Fatalf("parse: %v", err)
		}
		line := <-done
		log.UnSubscribe(subscription)

		if line == "" {
			t.Errorf("permitted=%v: no line records which way the gate went. A configuration "+
				"with no listeners leaves no address to read back, so this is the only record "+
				"that the dangerous state was or was not armed", permitted)
			continue
		}
		want := "permitted=false"
		if permitted {
			want = "permitted=true"
		}
		if !strings.Contains(line, want) {
			t.Errorf("permitted=%v: line says %q, want it to contain %q", permitted, line, want)
		}
	}
}
