package hako

import (
	"errors"
	"net/netip"
	"reflect"
	"testing"
)

func stubRoutes(t *testing.T, primary int, primaryErr error, routes map[string]int, routeErr map[string]error) {
	t.Helper()
	previousResolver, previousPrimary := resolverRouteInterface, primaryRouteInterface
	resolverRouteInterface = func(addr netip.Addr) (int, error) {
		if err, ok := routeErr[addr.String()]; ok {
			return 0, err
		}
		if index, ok := routes[addr.String()]; ok {
			return index, nil
		}
		return 0, errNoRoute
	}
	primaryRouteInterface = func() (int, error) { return primary, primaryErr }
	t.Cleanup(func() { resolverRouteInterface, primaryRouteInterface = previousResolver, previousPrimary })
}

// The reader's Mac, 2026-09-06: resolv.conf listed Tailscale's MagicDNS pair, routed
// through utun9 only, while the default route was en0. A tunnel bound to en0 cannot reach
// them, so they must not become the substitutes for `system`.
func TestResolversRoutedOffThePrimaryInterfaceAreDropped(t *testing.T) {
	const en0, utun9, lo0 = 11, 24, 1
	stubRoutes(t, en0, nil,
		map[string]int{"192.168.1.1": en0, "2001:4860:4860::8888": en0, "100.100.100.100": utun9, "fd7a:115c:a1e0::53": utun9, "127.0.0.1": lo0},
		nil)
	got := reachableFromThePhysicalPath([]string{"100.100.100.100", "fd7a:115c:a1e0::53", "192.168.1.1", "2001:4860:4860::8888", "127.0.0.1", "10.9.9.9"})
	want := []string{"192.168.1.1", "2001:4860:4860::8888", "127.0.0.1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("kept %v, want %v (MagicDNS through utun9 and the unrouted 10.9.9.9 go; loopback stays)", got, want)
	}
}

func TestAnUnansweredRouteQuestionDropsNothing(t *testing.T) {
	// The platform cannot ask (non-darwin, or a sandbox that refuses the routing socket):
	// the filter must not be stricter than what it knows.
	stubRoutes(t, 0, errRouteLookupUnsupported, nil, map[string]error{"100.100.100.100": errRouteLookupUnsupported})
	in := []string{"100.100.100.100", "192.168.1.1"}
	if got := reachableFromThePhysicalPath(in); !reflect.DeepEqual(got, []string{"100.100.100.100"}) && !reflect.DeepEqual(got, in) {
		t.Fatalf("kept %v; an unanswered lookup must keep the address", got)
	}
	// Primary unknown but per-address lookups answered: still keep everything, because
	// "not the primary" cannot be judged.
	stubRoutes(t, 0, errors.New("no default route"), map[string]int{"100.100.100.100": 24, "192.168.1.1": 11}, nil)
	if got := reachableFromThePhysicalPath(in); !reflect.DeepEqual(got, in) {
		t.Fatalf("kept %v, want %v when the primary interface is unknown", got, in)
	}
}

func TestSystemResolverLinesAppliesTheRouteFilter(t *testing.T) {
	stubPlatformResolvers(t, nil, nil)
	stubRoutes(t, 11, nil, map[string]int{"119.29.29.29": 11, "100.100.100.100": 24}, nil)
	withResolvConf(t, "nameserver 100.100.100.100\nnameserver 119.29.29.29\n")
	if got, want := SystemResolverLines(), "119.29.29.29"; got != want {
		t.Fatalf("SystemResolverLines = %q, want %q", got, want)
	}
}

func TestResolverPortsStillUsePhysicalRouteFilter(t *testing.T) {
	const physical, tunnel = 11, 24
	tests := []struct {
		name, server, address string
		route                 int
		routeErr              error
		keep                  bool
	}{
		{"v4 physical", "192.0.2.1:5353", "192.0.2.1", physical, nil, true},
		{"v6 physical", "[2001:db8::1]:5353", "2001:db8::1", physical, nil, true},
		{"v4 tunnel", "192.0.2.2:5353", "192.0.2.2", tunnel, nil, false},
		{"v6 tunnel", "[2001:db8::2]:5353", "2001:db8::2", tunnel, nil, false},
		{"v4 no route", "192.0.2.3:5353", "192.0.2.3", 0, errNoRoute, false},
		{"v6 no route", "[2001:db8::3]:5353", "2001:db8::3", 0, errNoRoute, false},
		{"v4 loopback", "127.0.0.1:5353", "127.0.0.1", 0, errNoRoute, true},
		{"v6 loopback", "[::1]:5353", "::1", 0, errNoRoute, true},
		{"unknown route", "192.0.2.4:5353", "192.0.2.4", 0, errRouteLookupUnsupported, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var failures map[string]error
			if tt.routeErr != nil {
				failures = map[string]error{tt.address: tt.routeErr}
			}
			stubRoutes(t, physical, nil, map[string]int{tt.address: tt.route}, failures)
			got := reachableFromThePhysicalPath([]string{tt.server})
			if tt.keep {
				if !reflect.DeepEqual(got, []string{tt.server}) {
					t.Fatalf("kept %v, want original resolver %q including its port", got, tt.server)
				}
			} else if len(got) != 0 {
				t.Fatalf("kept %v; unreachable resolver with a port must be dropped", got)
			}
		})
	}
}
