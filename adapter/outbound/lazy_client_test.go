package outbound


import (
	"runtime"
	"sync"
	"testing"
	"time"
)

func hysteria2Option() Hysteria2Option {
	return Hysteria2Option{
		Name: "h", Server: "203.0.113.10", Port: 443, Password: "x",
		Ports: "40000-50000", Up: "50 Mbps", Down: "100 Mbps",
	}
}

func anyTLSOption() AnyTLSOption {
	return AnyTLSOption{
		Name: "a", Server: "203.0.113.11", Port: 443, Password: "x",
	}
}

func TestLazyAdaptersKeepLoadTimeErrors(t *testing.T) {
	cases := []struct {
		name string
		run  func() error
		want string
	}{
		{"hysteria2 obfs without password", func() error {
			o := hysteria2Option()
			o.Obfs = "salamander"
			_, err := NewHysteria2(o)
			return err
		}, "missing obfs password"},
		{"hysteria2 unknown obfs", func() error {
			o := hysteria2Option()
			o.Obfs = "nope"
			o.ObfsPassword = "p"
			_, err := NewHysteria2(o)
			return err
		}, "unknown obfs type"},
		{"hysteria2 bad ports range", func() error {
			o := hysteria2Option()
			o.Ports = "not-a-range"
			_, err := NewHysteria2(o)
			return err
		}, "invalid range"},
		{"hysteria2 no port at all", func() error {
			o := hysteria2Option()
			o.Port = 0
			o.Ports = ""
			_, err := NewHysteria2(o)
			return err
		}, "invalid port"},
		{"anytls exclusive security modes", func() error {
			o := anyTLSOption()
			o.ShadowTLSOpts.Password = "p"
			o.ShadowTLSOpts.Version = 2
			o.RestlsOpts.Password = "p"
			o.RestlsOpts.VersionHint = "tls13"
			_, err := NewAnyTLS(o)
			return err
		}, "security modes are mutually exclusive"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run()
			if err == nil {
				t.Fatal("the load-time rejection vanished; preflight depends on it")
			}
			if tc.want != "" && !containsString(err.Error(), tc.want) {
				t.Fatalf("error = %q, want it to contain %q", err.Error(), tc.want)
			}
		})
	}
}

func containsString(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexString(s, sub) >= 0)
}

func indexString(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestAnyTLSConstructionSpawnsNoGoroutine(t *testing.T) {
	const nodes = 50
	runtime.GC()
	before := runtime.NumGoroutine()
	hold := make([]*AnyTLS, 0, nodes)
	for i := 0; i < nodes; i++ {
		p, err := NewAnyTLS(anyTLSOption())
		if err != nil {
			t.Fatal(err)
		}
		hold = append(hold, p)
	}
	time.Sleep(50 * time.Millisecond)
	after := runtime.NumGoroutine()
	if grew := after - before; grew >= nodes/2 {
		t.Fatalf("constructing %d idle anytls nodes grew goroutines by %d; "+
			"the idle-cleanup routine must wait for the first dial", nodes, grew)
	}
	_ = hold
}

func TestHysteria2ConstructionDefersTheHeavyState(t *testing.T) {
	const nodes = 100
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	hold := make([]*Hysteria2, 0, nodes)
	for i := 0; i < nodes; i++ {
		p, err := NewHysteria2(hysteria2Option())
		if err != nil {
			t.Fatal(err)
		}
		hold = append(hold, p)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	perNode := (int64(after.HeapAlloc) - int64(before.HeapAlloc)) / nodes
	// 10001 ports × 2B ≈ 20KB per node in the array alone today, plus the
	// client. Deferred, a node should keep only its option and base.
	if perNode > 8*1024 {
		t.Fatalf("each idle hysteria2 node retains %d bytes at load; the ports "+
			"array and the client must wait for the first dial", perNode)
	}
	_ = hold
}

func TestLazyClientBuildsOnceUnderConcurrency(t *testing.T) {
	p, err := NewHysteria2(hysteria2Option())
	if err != nil {
		t.Fatal(err)
	}
	const callers = 50
	clients := make(chan interface{}, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := p.lazyClient()
			if err != nil {
				t.Error(err)
				return
			}
			clients <- c
		}()
	}
	wg.Wait()
	close(clients)
	var first interface{}
	for c := range clients {
		if first == nil {
			first = c
		} else if c != first {
			t.Fatal("two callers saw two different clients; the Once is not once")
		}
	}

	a, err := NewAnyTLS(anyTLSOption())
	if err != nil {
		t.Fatal(err)
	}
	var wg2 sync.WaitGroup
	anyClients := make(chan interface{}, callers)
	for i := 0; i < callers; i++ {
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			anyClients <- a.lazyClient()
		}()
	}
	wg2.Wait()
	close(anyClients)
	first = nil
	for c := range anyClients {
		if first == nil {
			first = c
		} else if c != first {
			t.Fatal("two callers saw two different anytls clients")
		}
	}
	_ = a.Close()
}
