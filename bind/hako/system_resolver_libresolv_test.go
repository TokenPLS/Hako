package hako

import (
	"errors"
	"reflect"
	"testing"
)

func stubPlatformResolvers(t *testing.T, lines []string, err error) {
	t.Helper()
	previous := platformResolvers
	platformResolvers = func() ([]string, error) { return lines, err }
	t.Cleanup(func() { platformResolvers = previous })
}

// iOS has no /etc/resolv.conf (ENOENT from the App and the extension alike, iPhone 17 Pro
// Max, 2026-09-06): the platform resolver library is the source there, and the file is only
// a fallback for where the library has nothing.
func TestTheResolverLibraryIsTheSourceAndTheFileTheFallback(t *testing.T) {
	stubRoutes(t, 11, nil, map[string]int{"10.0.0.53": 11, "fe80::1": 11, "198.18.0.2": 11, "192.0.2.53": 11, "119.29.29.29": 11}, nil)
	withResolvConf(t, "nameserver 119.29.29.29\n")

	stubPlatformResolvers(t, []string{"10.0.0.53", "fe80::1", "198.18.0.2", "192.0.2.53:5353"}, nil)
	if got, want := SystemResolverLines(), "10.0.0.53\n192.0.2.53:5353"; got != want {
		t.Fatalf("library lines = %q, want %q (link-local and the tunnel's own range filtered like the file's, a non-53 port kept)", got, want)
	}
	stubPlatformResolvers(t, nil, errors.New("res_ninit failed"))
	if got, want := SystemResolverLines(), "119.29.29.29"; got != want {
		t.Fatalf("with the library failing, the file must answer: %q, want %q", got, want)
	}
	stubPlatformResolvers(t, []string{"fe80::1"}, nil)
	if got, want := SystemResolverLines(), "119.29.29.29"; got != want {
		t.Fatalf("a library list that filters to nothing must fall back to the file: %q, want %q", got, want)
	}
	stubPlatformResolvers(t, nil, nil)
	resolvConfPath = "/nonexistent/resolv.conf"
	if got := SystemResolverLines(); got != "" {
		t.Fatalf("nothing anywhere must read as no resolvers, got %q", got)
	}
}

func TestLibraryLinesKeepTheOSOrder(t *testing.T) {
	stubRoutes(t, 11, nil, map[string]int{"9.9.9.9": 11, "1.1.1.1": 11}, nil)
	stubPlatformResolvers(t, []string{"9.9.9.9", "1.1.1.1"}, nil)
	if got, want := systemResolverAddresses(), []string{"9.9.9.9", "1.1.1.1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
}
