package hako

import (
	"net/netip"
	"testing"
)

func TestStringIterator(t *testing.T) {
	it := newStringIterator([]string{"a", "b", "c"})
	if it.Len() != 3 {
		t.Fatalf("Len = %d, want 3", it.Len())
	}
	var got []string
	for it.HasNext() {
		got = append(got, it.Next())
	}
	if len(got) != 3 || got[0] != "a" || got[2] != "c" {
		t.Fatalf("iterated %v", got)
	}
	if it.HasNext() {
		t.Fatal("HasNext after exhaustion")
	}
	if it.Next() != "" {
		t.Fatal("exhausted Next should return zero value")
	}
}

func TestRoutePrefixIterator(t *testing.T) {
	it := mapRoutePrefix([]netip.Prefix{
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("::/0"),
	})
	first := it.Next()
	if first.String() != "198.18.0.0/15" {
		t.Fatalf("String() = %q", first.String())
	}
	if first.Address() != "198.18.0.0" || first.Prefix() != 15 {
		t.Fatalf("Address/Prefix = %q/%d", first.Address(), first.Prefix())
	}
	if first.Mask() != "255.254.0.0" {
		t.Fatalf("Mask() = %q, want 255.254.0.0", first.Mask())
	}
	if it.Len() != 1 || !it.HasNext() {
		t.Fatalf("Len after one Next = %d", it.Len())
	}
	if it.Next().String() != "::/0" {
		t.Fatal("second prefix mismatch")
	}
	if it.Next() != nil {
		t.Fatal("exhausted Next should return nil")
	}
}

func TestNetworkInterfaceIterator(t *testing.T) {
	it := newNetworkInterfaceIterator([]*NetworkInterface{
		{Index: 4, Name: "en0", Addresses: newStringIterator([]string{"10.0.0.2/24"})},
	})
	ni := it.Next()
	if ni.Name != "en0" || ni.Addresses.Next() != "10.0.0.2/24" {
		t.Fatal("interface fields lost in transit")
	}
}

func TestStringBox(t *testing.T) {
	if WrapString("x").Value != "x" {
		t.Fatal("WrapString")
	}
}
