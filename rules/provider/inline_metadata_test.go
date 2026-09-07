package provider

import (
	"encoding/json"
	P "github.com/TokenPLS/Hako/constant/provider"
	"sync"
	"testing"
)

func TestInlineMetadataConcurrentUpdate(t *testing.T) {
	p := NewInlineProvider("inline", P.IPCIDR, []string{"192.0.2.0/24"}, nil)
	metadata := p.(interface{ LoadedMetadataJSON() ([]byte, error) })
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			if err := p.Update(); err != nil {
				t.Error(err)
			}
		}
	}()
	for i := 0; i < 1000; i++ {
		if _, err := metadata.LoadedMetadataJSON(); err != nil {
			t.Error(err)
		}
		if _, err := json.Marshal(p); err != nil {
			t.Error(err)
		}
	}
	wg.Wait()
}
