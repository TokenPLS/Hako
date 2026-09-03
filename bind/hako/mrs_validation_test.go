package hako

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/TokenPLS/Hako/component/cidr"

	"github.com/TokenPLS/Hako/component/trie"
	P "github.com/TokenPLS/Hako/constant/provider"
)

// A domain rule set built the way meta-rules-dat builds every geosite file:
// suffix rules. mihomo's own writer stores `+.example.com` as two entries in
// the trie ("example.com" and the wildcard form), so the leaf count is twice
// the header's rule count — and upstream accepts that without comparing the
// two. The official geosite cn.mrs is exactly this shape (111,873 rules /
// 223,746 leaves), and a leaves-vs-rules invariant rejected every one of them.
func TestSuffixDomainMRSIsAcceptedLikeUpstream(t *testing.T) {
	domains := []string{"+.example.com", "+.example.org", "+.example.net"}
	trieBuilder := trie.New[struct{}]()
	for _, domain := range domains {
		if err := trieBuilder.Insert(domain, struct{}{}); err != nil {
			t.Fatal(err)
		}
	}
	set := trieBuilder.NewDomainSet()
	if set == nil {
		t.Fatal("nil domain set")
	}
	leaves := 0
	set.Foreach(func(string) bool { leaves++; return true })
	if leaves <= len(domains) {
		t.Fatalf("fixture does not reproduce the shape: %d leaves for %d rules",
			leaves, len(domains))
	}

	var body bytes.Buffer
	if err := set.WriteBin(&body); err != nil {
		t.Fatal(err)
	}
	decoded := buildDecodedMRSTestPayload(
		t, P.Domain, int64(len(domains)),
		func(buffer *bytes.Buffer) {
			// extra length (reserved by the format), then the domain-set body
			if err := binary.Write(buffer, binary.BigEndian, int64(0)); err != nil {
				t.Fatal(err)
			}
			buffer.Write(body.Bytes())
		},
	)
	payload := compressMRSTestPayload(t, decoded)

	if err := validateMRSForIOS(payload, P.Domain); err != nil {
		t.Fatalf("validator rejected a rule set mihomo itself writes: %v", err)
	}
}

// The IP-CIDR half of the same story: mihomo's header count is display-only
// there too (ipcidrStrategy.FromMrs assigns it to i.count and never compares
// it with the set), so a file whose range count exceeds its rule count is
// something upstream reads without complaint — and a rule that has to be
// expressed as several ranges produces exactly that shape.
func TestIPCIDRMRSCountIsNotComparedWithItsRanges(t *testing.T) {
	set := cidr.NewIpCidrSet()
	for _, prefix := range []string{"1.0.0.0/8", "9.9.9.9/32", "203.0.113.0/24"} {
		if err := set.AddIpCidrForString(prefix); err != nil {
			t.Fatal(err)
		}
	}
	if err := set.Merge(); err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	if err := set.WriteBin(&body); err != nil {
		t.Fatal(err)
	}
	// Header says one rule; the set carries three ranges.
	decoded := buildDecodedMRSTestPayload(t, P.IPCIDR, 1, func(buffer *bytes.Buffer) {
		if err := binary.Write(buffer, binary.BigEndian, int64(0)); err != nil {
			t.Fatal(err)
		}
		buffer.Write(body.Bytes())
	})
	payload := compressMRSTestPayload(t, decoded)

	if err := validateMRSForIOS(payload, P.IPCIDR); err != nil {
		t.Fatalf("validator rejected an IP-CIDR set mihomo itself writes: %v", err)
	}
}

// Bytes after the body are bytes upstream never reads. `rulesMrsParse`
// (rules/provider/mrs_reader.go:15-71) hands its zstd stream to
// `FromMrs(reader, count)`, which reads exactly the structures it needs --
// `trie.ReadDomainSetBin` for domains, `cidr.ReadIpCidrSet` for IP-CIDR -- and
// returns. Whatever follows stays unread in the stream, so a trailing-data
// rejection is a rule about a region upstream has no opinion on.
//
// It is also the region the format reserves for growth: the header carries an
// explicit "extra (reserved for future using)" length field, and MRSv1 gaining a
// trailing section is the documented way this format extends. A reader that
// refuses unknown trailing bytes is a reader that breaks on the next revision
// while upstream keeps working.
func TestTrailingBytesAreIgnoredLikeUpstream(t *testing.T) {
	trieBuilder := trie.New[struct{}]()
	if err := trieBuilder.Insert("example.com", struct{}{}); err != nil {
		t.Fatal(err)
	}
	set := trieBuilder.NewDomainSet()
	if set == nil {
		t.Fatal("nil domain set")
	}
	var body bytes.Buffer
	if err := set.WriteBin(&body); err != nil {
		t.Fatal(err)
	}
	decoded := buildDecodedMRSTestPayload(t, P.Domain, 1, func(buffer *bytes.Buffer) {
		if err := binary.Write(buffer, binary.BigEndian, int64(0)); err != nil {
			t.Fatal(err)
		}
		buffer.Write(body.Bytes())
		// A future section upstream would skip, and this reader refused.
		buffer.Write([]byte{'M', 'R', 'S', 2, 0, 0, 0, 0})
	})

	if err := validateMRSForIOS(compressMRSTestPayload(t, decoded), P.Domain); err != nil {
		t.Fatalf("rejected trailing bytes upstream never reads: %v", err)
	}
}

// The header count is display-only upstream, so its value is not a reason to
// refuse a file. `rulesMrsParse` (rules/provider/mrs_reader.go:43-48) reads it
// with `binary.Read` and passes it straight to `FromMrs(reader, int(count))`,
// where `domainStrategy.FromMrs` and `ipcidrStrategy.FromMrs` each assign it to
// their `count` field and never look at it again -- it surfaces through Count()
// for the API's rule tally and nothing else. There is no validation of it
// anywhere on that path: not a lower bound, not an upper bound.
//
// Honest about the exposure: mihomo's own converter cannot emit count 0, because
// `ConvertToMrs` (rules/provider/mrs_converter.go:21-23) refuses a strategy whose
// Count() is zero with "empty rule". So this is not a rejection anyone has hit
// with a kernel-written file. It is a rule about other people's writers and about
// the next version of this format, held to the same standard as the rest: we do
// not refuse what upstream reads.
func TestMRSHeaderCountIsNotValidated(t *testing.T) {
	trieBuilder := trie.New[struct{}]()
	if err := trieBuilder.Insert("example.com", struct{}{}); err != nil {
		t.Fatal(err)
	}
	set := trieBuilder.NewDomainSet()
	if set == nil {
		t.Fatal("nil domain set")
	}
	var body bytes.Buffer
	if err := set.WriteBin(&body); err != nil {
		t.Fatal(err)
	}
	for _, count := range []int64{0, 1 << 30} {
		decoded := buildDecodedMRSTestPayload(t, P.Domain, count, func(buffer *bytes.Buffer) {
			if err := binary.Write(buffer, binary.BigEndian, int64(0)); err != nil {
				t.Fatal(err)
			}
			buffer.Write(body.Bytes())
		})
		if err := validateMRSForIOS(compressMRSTestPayload(t, decoded), P.Domain); err != nil {
			t.Errorf("header count %d rejected, but upstream only stores it: %v", count, err)
		}
	}
}

// The depth cap counted characters, not labels, and so quietly banned long
// domain names from rule sets.
//
// mihomo's domain set is a succinct character trie over the reversed name, so
// one tree level is one character. `maximumMRSDomainDepth = 253` was clearly
// written with the DNS length limit in mind, but applied to tree levels it
// becomes "no rule in this file may contain a name longer than 253 characters"
// -- and one such entry rejects the entire file, every other rule in it
// included.
//
// The kernel writes these without complaint: `Insert` accepts the name,
// `NewDomainSet` builds the trie, `WriteBin` serialises it, and upstream's
// reader has no depth notion at all -- `ReadDomainSetBin`
// (component/trie/domain_set_bin.go:53-115) reads three arrays, calls
// `ds.init()` and returns.
//
// The rest of the topology walk stays. It is what stops a malformed bitmap from
// reaching `getBit` (component/trie/domain_set.go:187-189), which indexes a
// slice with no bounds check inside `Has`'s unbounded `for ; ; bmIdx++` loop --
// a panic that takes the tunnel down. That walk terminates on its own: the node
// loop is bounded by len(labels)+1 and bitPosition by the bitmap length, so the
// depth counter was never what made it finite.
func TestLongDomainNamesAreNotADepthViolation(t *testing.T) {
	// 255 characters: four maximum-length labels. Longer names than this appear
	// in aggregated block lists, and a single one poisoned the whole rule set.
	label := strings.Repeat("a", 63)
	domain := strings.Join([]string{label, label, label, label}, ".")
	if len(domain) <= maximumMRSDomainDepthProbe {
		t.Fatalf("fixture is not long enough: %d characters", len(domain))
	}

	trieBuilder := trie.New[struct{}]()
	if err := trieBuilder.Insert(domain, struct{}{}); err != nil {
		t.Fatalf("the kernel's own writer accepts this name; fixture invalid: %v", err)
	}
	set := trieBuilder.NewDomainSet()
	if set == nil {
		t.Fatal("nil domain set")
	}
	var body bytes.Buffer
	if err := set.WriteBin(&body); err != nil {
		t.Fatal(err)
	}
	decoded := buildDecodedMRSTestPayload(t, P.Domain, 1, func(buffer *bytes.Buffer) {
		if err := binary.Write(buffer, binary.BigEndian, int64(0)); err != nil {
			t.Fatal(err)
		}
		buffer.Write(body.Bytes())
	})

	if err := validateMRSForIOS(compressMRSTestPayload(t, decoded), P.Domain); err != nil {
		t.Fatalf("rejected a %d-character name the kernel itself writes: %v",
			len(domain), err)
	}
}

// Kept separate from the production constant so removing it does not break the
// fixture's own sanity check.
const maximumMRSDomainDepthProbe = 253

// The structural walk is the only thing between a hostile .mrs and a panic
// inside the packet tunnel, and until now nothing tested it: deleting any one of
// its guards left the whole suite green, so a refactor of the bitPosition /
// levelRemaining bookkeeping -- exactly the kind of edit that removed the depth
// cap -- could disable it silently.
//
// The panic is real, not rhetorical. `trie.ReadDomainSetBin` validates only that
// each length is >= 1 (component/trie/domain_set_bin.go), so it accepts a body
// with two labels and a one-word all-zero label bitmap; `DomainSet.Has` then
// walks off the end of ss.labels and dies with "index out of range [2] with
// length 2" (domain_set.go:150-160 via getBit at :187-189). Reproduced directly
// against upstream before writing this.
//
// Each case below names the guard it must trip. Asserting the message rather
// than merely `err != nil` is the point: a fixture that stops earlier than
// intended still fails an err-only test for the wrong reason, which is how the
// existing "oversized domain bitmap" case drifted into dying in the length
// cursor without anyone noticing.
func TestMalformedDomainTreeIsRejectedByEachGuard(t *testing.T) {
	// A well-formed body from the kernel's own writer, to mutate.
	trieBuilder := trie.New[struct{}]()
	for _, domain := range []string{"example.com", "example.org", "sub.example.net"} {
		if err := trieBuilder.Insert(domain, struct{}{}); err != nil {
			t.Fatal(err)
		}
	}
	set := trieBuilder.NewDomainSet()
	if set == nil {
		t.Fatal("nil domain set")
	}
	var healthy bytes.Buffer
	if err := set.WriteBin(&healthy); err != nil {
		t.Fatal(err)
	}
	base := healthy.Bytes()

	// Layout: version(1) leavesLen(8) leaves(8n) bitmapLen(8) bitmap(8m) labelsLen(8) labels
	leafWords := int(binary.BigEndian.Uint64(base[1:9]))
	bitmapLenAt := 1 + 8 + leafWords*8
	bitmapWords := int(binary.BigEndian.Uint64(base[bitmapLenAt : bitmapLenAt+8]))
	bitmapAt := bitmapLenAt + 8

	fill := func(value byte) []byte {
		out := append([]byte(nil), base...)
		for i := bitmapAt; i < bitmapAt+bitmapWords*8; i++ {
			out[i] = value
		}
		return out
	}

	cases := []struct {
		name string
		body []byte
		want string
	}{
		{"all-zero bitmap has no node delimiter", fill(0x00), "too many children"},
		{"all-one bitmap gives every node no children", fill(0xFF), "disconnected"},
		{"version is not 1", func() []byte {
			out := append([]byte(nil), base...)
			out[0] = 2
			return out
		}(), "version is invalid"},
		{"bitmap shorter than the labels require", func() []byte {
			out := append([]byte(nil), base...)
			binary.BigEndian.PutUint64(out[bitmapLenAt:bitmapLenAt+8], 1)
			return append(out[:bitmapAt+8], out[bitmapAt+bitmapWords*8:]...)
		}(), "bitmap is too short"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			decoded := buildDecodedMRSTestPayload(t, P.Domain, 3, func(buffer *bytes.Buffer) {
				if err := binary.Write(buffer, binary.BigEndian, int64(0)); err != nil {
					t.Fatal(err)
				}
				buffer.Write(testCase.body)
			})
			var panicked any
			var err error
			func() {
				defer func() { panicked = recover() }()
				err = validateMRSForIOS(compressMRSTestPayload(t, decoded), P.Domain)
			}()
			if panicked != nil {
				t.Fatalf("validator panicked instead of rejecting: %v", panicked)
			}
			if err == nil {
				t.Fatal("malformed domain tree accepted; upstream's Has would index out of range")
			}
			if !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("error = %q, want it to mention %q -- the fixture is tripping a "+
					"different guard than the one it is written for", err, testCase.want)
			}
		})
	}

	// The healthy body must still pass, so a guard that rejects everything cannot
	// masquerade as coverage.
	decoded := buildDecodedMRSTestPayload(t, P.Domain, 3, func(buffer *bytes.Buffer) {
		if err := binary.Write(buffer, binary.BigEndian, int64(0)); err != nil {
			t.Fatal(err)
		}
		buffer.Write(base)
	})
	if err := validateMRSForIOS(compressMRSTestPayload(t, decoded), P.Domain); err != nil {
		t.Fatalf("the unmutated control body was rejected: %v", err)
	}
}

// The header count reaches Swift, so the contract has to be pinned at the
// exported boundary, not at the internal validator that throws the value away.
//
// The fixture distinguishes the two things it could be doing. A suffix rule set
// carries twice the header's count in trie leaves, so a reader that COUNTS the
// trie returns 6 while one that REPORTS the header returns 3 -- upstream reports,
// and so do we. A fixture whose header equals its true size, which is what the
// round-trip test uses, cannot tell those apart.
//
// The negative values are here because removing the count bound made them
// reachable, and the docstring now says so. Anyone re-adding a plausible
// `if count < 0 { count = 0 }` changes a documented contract, and this is where
// that shows up.
func TestProviderEntryCountForIOSReportsTheHeaderVerbatim(t *testing.T) {
	trieBuilder := trie.New[struct{}]()
	suffixes := []string{"+.example.com", "+.example.org", "+.example.net"}
	for _, domain := range suffixes {
		if err := trieBuilder.Insert(domain, struct{}{}); err != nil {
			t.Fatal(err)
		}
	}
	set := trieBuilder.NewDomainSet()
	if set == nil {
		t.Fatal("nil domain set")
	}
	leaves := 0
	set.Foreach(func(string) bool { leaves++; return true })
	if leaves == len(suffixes) {
		t.Fatalf("fixture cannot distinguish header from trie: both are %d", leaves)
	}
	var body bytes.Buffer
	if err := set.WriteBin(&body); err != nil {
		t.Fatal(err)
	}
	build := func(header int64) []byte {
		decoded := buildDecodedMRSTestPayload(t, P.Domain, header, func(buffer *bytes.Buffer) {
			if err := binary.Write(buffer, binary.BigEndian, int64(0)); err != nil {
				t.Fatal(err)
			}
			buffer.Write(body.Bytes())
		})
		return compressMRSTestPayload(t, decoded)
	}

	got, err := ProviderEntryCountForIOS("rule", "domain", "mrs", build(int64(len(suffixes))))
	if err != nil {
		t.Fatalf("ProviderEntryCountForIOS: %v", err)
	}
	if got != len(suffixes) {
		t.Fatalf("count = %d, want the header's %d (the trie holds %d leaves)",
			got, len(suffixes), leaves)
	}

	for _, header := range []int64{-1, 0} {
		got, err := ProviderEntryCountForIOS("rule", "domain", "mrs", build(header))
		if err != nil {
			t.Errorf("header %d: %v", header, err)
			continue
		}
		if got != int(header) {
			t.Errorf("header %d reported as %d; the documented contract is verbatim",
				header, got)
		}
	}
}
