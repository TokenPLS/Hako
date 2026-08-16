package compiled

import (
	"bytes"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/TokenPLS/Hako/component/cidr"
)

func sampleCidrSet(t *testing.T, prefixes ...string) (*cidr.IpCidrSet, int) {
	t.Helper()
	set := cidr.NewIpCidrSet()
	for _, prefix := range prefixes {
		if err := set.AddIpCidr(netip.MustParsePrefix(prefix)); err != nil {
			t.Fatal(err)
		}
	}
	if err := set.Merge(); err != nil {
		t.Fatal(err)
	}
	return set, len(prefixes)
}

func TestCompiledCidrSetRoundTrips(t *testing.T) {
	set, count := sampleCidrSet(t, "1.1.1.0/24", "8.8.8.0/24", "2001:db8::/32")
	var buffer bytes.Buffer
	if err := WriteIPCIDR(&buffer, set, count); err != nil {
		t.Fatal(err)
	}
	restored, restoredCount, err := ReadIPCIDR(bytes.NewReader(buffer.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if restoredCount != count {
		t.Fatalf("count = %d, want %d", restoredCount, count)
	}
	for _, hit := range []string{"1.1.1.1", "8.8.8.8", "2001:db8::1"} {
		if !restored.IsContain(netip.MustParseAddr(hit)) {
			t.Fatalf("restored set does not contain %s", hit)
		}
	}
	for _, miss := range []string{"9.9.9.9", "2001:dead::1"} {
		if restored.IsContain(netip.MustParseAddr(miss)) {
			t.Fatalf("restored set wrongly contains %s", miss)
		}
	}
}

// A compiled country and a compiled category can carry the SAME name -- cn is both a
// country code in GeoIP.dat and a category in GeoSite.dat -- so they cannot share a
// directory. If they did, whichever was written second would answer for both, and a
// tunnel would match IPs against domains.
func TestCompiledGeoIPDoesNotCollideWithGeoSite(t *testing.T) {
	if IPCIDRDirectoryName == DirectoryName {
		t.Fatal("geoip and geosite artifacts share a directory; cn would overwrite cn")
	}

	root := t.TempDir()
	geoipDir := filepath.Join(root, IPCIDRDirectoryName)
	geositeDir := filepath.Join(root, DirectoryName)

	set, count := sampleCidrSet(t, "1.1.1.0/24")
	if err := StoreIPCIDR(geoipDir, "cn", set, count); err != nil {
		t.Fatal(err)
	}
	domains, domainCount := sampleSet(t, "+.example.com")
	if err := Store(geositeDir, "cn", domains, domainCount, nil); err != nil {
		t.Fatal(err)
	}

	// Each still answers with its own contents.
	restored, _, err := LoadIPCIDR(geoipDir, "cn")
	if err != nil {
		t.Fatal(err)
	}
	if !restored.IsContain(netip.MustParseAddr("1.1.1.1")) {
		t.Fatal("the geoip artifact for cn no longer holds its own addresses")
	}
	restoredDomains, _, _, err := Load(geositeDir, "cn")
	if err != nil {
		t.Fatal(err)
	}
	if !restoredDomains.Has("example.com") {
		t.Fatal("the geosite artifact for cn no longer holds its own domains")
	}
}

// Reading a geosite artifact as geoip must fail loudly rather than produce an empty or
// nonsense matcher: the behavior byte is in the format precisely so this is detectable.
func TestCompiledCidrSetRefusesADomainArtifact(t *testing.T) {
	domains, count := sampleSet(t, "+.example.com")
	var buffer bytes.Buffer
	if err := Write(&buffer, domains, count, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadIPCIDR(bytes.NewReader(buffer.Bytes())); err == nil {
		t.Fatal("read a domain artifact as an ip set")
	}
}

func TestLoadIPCIDRReportsAnAbsentArtifact(t *testing.T) {
	if _, _, err := LoadIPCIDR(t.TempDir(), "zz"); !errors.Is(err, ErrNotCompiled) {
		t.Fatalf("absent artifact reported as %v, want ErrNotCompiled", err)
	}
}

// The country code reaches this from a configuration, so it is untrusted.
func TestIPCIDRPathRefusesUnsafeCountryNames(t *testing.T) {
	for _, name := range []string{"", "../evil", `cn\evil`, "cn/../../evil", "c n"} {
		if _, err := IPCIDRPath("/tmp", name); err == nil {
			t.Fatalf("accepted unsafe country name %q", name)
		}
	}
	if _, err := IPCIDRPath("/tmp", "cn"); err != nil {
		t.Fatalf("rejected a legitimate country code: %v", err)
	}
}

// A half-written artifact must never be visible: the tunnel would read it as corrupt and
// have no way to tell that from a real one.
func TestStoreIPCIDRIsAtomic(t *testing.T) {
	directory := t.TempDir()
	set, count := sampleCidrSet(t, "1.1.1.0/24")
	if err := StoreIPCIDR(directory, "cn", set, count); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() != "cn.mrs" {
			t.Fatalf("left a temporary artifact behind: %s", entry.Name())
		}
	}
}
