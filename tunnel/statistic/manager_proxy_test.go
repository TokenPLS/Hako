package statistic

import (
	"sync"
	"testing"
)

func TestManagerSeparatesOnlyExactDirectTraffic(t *testing.T) {
	m := &Manager{}

	m.PushUploaded("DIRECT", 10)
	m.PushDownloaded("DIRECT", 20)
	m.PushUploaded("Proxy", 30)
	m.PushDownloaded("Proxy", 40)
	m.PushUploaded("direct", 50)
	m.PushDownloaded("DIRECT-chain", 60)
	m.PushUploaded("", 70)

	if up, down := m.TotalTraffic(false); up != 160 || down != 120 {
		t.Fatalf("all traffic = %d/%d, want 160/120", up, down)
	}
	if up, down := m.TotalTraffic(true); up != 150 || down != 100 {
		t.Fatalf("proxy traffic = %d/%d, want 150/100", up, down)
	}
}

func TestManagerProxyRatesAndReset(t *testing.T) {
	m := &Manager{}
	m.uploadBlip.Store(7)
	m.downloadBlip.Store(8)
	m.proxyUploadBlip.Store(3)
	m.proxyDownloadBlip.Store(4)
	m.PushUploaded("Proxy", 11)
	m.PushDownloaded("Proxy", 12)

	if up, down := m.NowTraffic(false); up != 7 || down != 8 {
		t.Fatalf("all rate = %d/%d, want 7/8", up, down)
	}
	if up, down := m.NowTraffic(true); up != 3 || down != 4 {
		t.Fatalf("proxy rate = %d/%d, want 3/4", up, down)
	}

	m.ResetStatistic()
	if up, down := m.NowTraffic(true); up != 0 || down != 0 {
		t.Fatalf("reset proxy rate = %d/%d, want 0/0", up, down)
	}
	if up, down := m.TotalTraffic(true); up != 0 || down != 0 {
		t.Fatalf("reset proxy total = %d/%d, want 0/0", up, down)
	}
}

func TestManagerConcurrentDualCounters(t *testing.T) {
	const (
		workers    = 16
		iterations = 1_000
	)
	m := &Manager{}
	var group sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		finalOutbound := "Proxy"
		if worker%2 == 0 {
			finalOutbound = "DIRECT"
		}
		group.Add(1)
		go func() {
			defer group.Done()
			for iteration := 0; iteration < iterations; iteration++ {
				m.PushUploaded(finalOutbound, 1)
				m.PushDownloaded(finalOutbound, 2)
			}
		}()
	}
	group.Wait()

	if up, down := m.TotalTraffic(false); up != workers*iterations || down != workers*iterations*2 {
		t.Fatalf("all concurrent traffic = %d/%d", up, down)
	}
	if up, down := m.TotalTraffic(true); up != workers*iterations/2 || down != workers*iterations {
		t.Fatalf("proxy concurrent traffic = %d/%d", up, down)
	}
}
