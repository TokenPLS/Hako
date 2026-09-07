package hako

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Issue #21: a `system` nameserver inside a packet tunnel answers NXDOMAIN because the
// only file the resolver may read lists the tunnel's own address. The App now reads the
// physical resolvers BEFORE the tunnel's DNS settings apply and hands them to Setup; it
// reads them through the core so that no client target needs libresolv or a modulemap,
// and so the file is the one mihomo's own system nameserver reads (dns/system_posix.go).

func TestReadResolvConfKeepsUsableNameserversInFileOrder(t *testing.T) {
	const text = `#
# macOS Notice
#
domain example.lan
search example.lan corp.example
nameserver 192.168.1.1
nameserver 2001:4860:4860::8888
nameserver fe80::1%en0
nameserver 198.18.0.2
nameserver fdfe:dcba:9876::2
nameserver ::
nameserver 224.0.0.251
nameserver not-an-address
nameserver
nameserver 1.1.1.1 trailing words
options ndots:1
`
	got := readResolvConf(strings.NewReader(text))
	want := []string{"192.168.1.1", "2001:4860:4860::8888", "1.1.1.1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("readResolvConf = %v, want %v (link-local, the tunnel's own ranges, unspecified and multicast go; everything else stays in file order)", got, want)
	}
}

func TestSystemResolverLinesReadsTheFileMihomoReadsAndIsEmptyWithoutIt(t *testing.T) {
	stubPlatformResolvers(t, nil, nil) // the library has nothing: the file answers
	stubRoutes(t, 11, nil, map[string]int{"119.29.29.29": 11, "223.5.5.5": 11}, nil)
	withResolvConf(t, "nameserver 119.29.29.29\nnameserver 223.5.5.5\n")
	if got, want := SystemResolverLines(), "119.29.29.29\n223.5.5.5"; got != want {
		t.Fatalf("SystemResolverLines = %q, want %q", got, want)
	}
	resolvConfPath = filepath.Join(t.TempDir(), "missing")
	if got := SystemResolverLines(); got != "" {
		t.Fatalf("a missing file must read as no resolvers, got %q", got)
	}
}

func TestSystemResolverLinesReadsUpstreamsFile(t *testing.T) {
	// dns/system_posix.go:13 -- the same file, so the export sees exactly what a
	// `system` nameserver would have seen, not a second opinion.
	if resolvConfPath != "/etc/resolv.conf" {
		t.Fatalf("resolvConfPath = %q, want /etc/resolv.conf", resolvConfPath)
	}
}

// withResolvConf points the export at a fixture file for one test.
func withResolvConf(t *testing.T, text string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := resolvConfPath
	resolvConfPath = path
	t.Cleanup(func() { resolvConfPath = previous })
}
