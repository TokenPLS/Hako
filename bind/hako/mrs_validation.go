package hako

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"

	"github.com/klauspost/compress/zstd"
	P "github.com/TokenPLS/Hako/constant/provider"
	ruleprovider "github.com/TokenPLS/Hako/rules/provider"
)

type mrsCursor struct {
	data   []byte
	offset int
}

func (c *mrsCursor) remaining() int {
	return len(c.data) - c.offset
}

func (c *mrsCursor) take(size int, label string) ([]byte, error) {
	if size < 0 || size > c.remaining() {
		return nil, fmt.Errorf("MRS %s exceeds the decoded payload", label)
	}
	value := c.data[c.offset : c.offset+size]
	c.offset += size
	return value, nil
}

func (c *mrsCursor) byte(label string) (byte, error) {
	value, err := c.take(1, label)
	if err != nil {
		return 0, err
	}
	return value[0], nil
}

func (c *mrsCursor) int64(label string) (int64, error) {
	value, err := c.take(8, label)
	if err != nil {
		return 0, err
	}
	return int64(binary.BigEndian.Uint64(value)), nil
}

func (c *mrsCursor) sized(length int64, unit int, label string, allowEmpty bool) ([]byte, error) {
	if length < 0 || (!allowEmpty && length == 0) {
		return nil, fmt.Errorf("MRS %s length is invalid", label)
	}
	if unit <= 0 || length > int64(c.remaining())/int64(unit) {
		return nil, fmt.Errorf("MRS %s length exceeds the decoded payload", label)
	}
	return c.take(int(length)*unit, label)
}

func validateMRSForIOS(payload []byte, expectedBehavior P.RuleBehavior) error {
	_, err := inspectMRSForIOS(payload, expectedBehavior)
	return err
}

func inspectMRSForIOS(payload []byte, expectedBehavior P.RuleBehavior) (int, error) {
	decoder, err := zstd.NewReader(
		bytes.NewReader(payload),
		zstd.WithDecoderMaxMemory(uint64(maximumProviderResourceBytes)),
	)
	if err != nil {
		return 0, fmt.Errorf("open MRS zstd payload: %w", err)
	}
	defer decoder.Close()
	decoded, err := io.ReadAll(io.LimitReader(decoder, int64(maximumProviderResourceBytes)+1))
	if err != nil {
		return 0, fmt.Errorf("decode MRS payload: %w", err)
	}
	if len(decoded) == 0 || len(decoded) > maximumProviderResourceBytes {
		return 0, fmt.Errorf("decoded MRS payload exceeds the %d-byte iOS provider limit", maximumProviderResourceBytes)
	}

	cursor := &mrsCursor{data: decoded}
	magic, err := cursor.take(len(ruleprovider.MrsMagicBytes), "magic")
	if err != nil {
		return 0, err
	}
	if !bytes.Equal(magic, ruleprovider.MrsMagicBytes[:]) {
		return 0, fmt.Errorf("MRS magic is invalid")
	}
	behavior, err := cursor.byte("behavior")
	if err != nil {
		return 0, err
	}
	if behavior != expectedBehavior.Byte() {
		return 0, fmt.Errorf("MRS behavior does not match the provider")
	}
	count, err := cursor.int64("rule count")
	if err != nil {
		return 0, err
	}
	// The header count is not validated here. `rulesMrsParse` reads it and passes
	// it to FromMrs (rules/provider/mrs_reader.go:43-67), where both strategies
	// store it and expose it only through Count(); nothing on the READ path
	// branches on it, and the upper bound this replaces was dimensionally wrong
	// anyway -- a rule count compared against a byte limit.
	//
	// Not "upstream never treats it as data", which an earlier version of this
	// comment claimed and which is false: ConvertToMrs refuses Count() == 0
	// (rules/provider/mrs_converter.go:21-23), and config_finalize.go runs
	// validateMRSForIOS and ConvertToMrs back to back when expanding a
	// route-address-set. A header count of 0 therefore still fails there, one
	// line later, as "decode mrs: empty rule". Same outcome, different message --
	// worth knowing before someone assumes this field can never stop a load.
	//
	// Consequence to keep in view: inspectMRSForIOS returns this number verbatim,
	// so ProviderEntryCountForIOS can hand the App a negative or absurd tally from
	// a corrupt file. No caller sizes anything on it (traced to the status string
	// in ProvidersView), which is why that is acceptable rather than merely
	// unnoticed.
	extraLength, err := cursor.int64("extra length")
	if err != nil {
		return 0, err
	}
	if _, err := cursor.sized(extraLength, 1, "extra", true); err != nil {
		return 0, err
	}

	switch expectedBehavior {
	case P.Domain:
		if err := validateDomainMRSBody(cursor); err != nil {
			return 0, err
		}
	case P.IPCIDR:
		if err := validateIPCIDRMRSBody(cursor); err != nil {
			return 0, err
		}
	default:
		return 0, fmt.Errorf("MRS format is unsupported for provider behavior %s", expectedBehavior.String())
	}
	// No trailing-data rejection. Upstream reads MRS from a stream
	// (rules/provider/mrs_reader.go:67 hands the zstd reader to FromMrs, which
	// consumes exactly the domain-set or IP-CIDR-set structures and returns) and
	// nothing on that path ever looks at what follows. The bytes are physically
	// reachable -- the reader wraps a bytes.Reader -- so the accurate statement is
	// that upstream never reads them, not that it cannot.
	//
	// An earlier version of this comment also argued the format "reserves room to
	// grow" there, citing the header's "extra (reserved for future using)" field.
	// That field is read BEFORE the body (mrs_reader.go:50-65), so if anything it
	// is evidence the format grows in the header rather than after the body. The
	// deletion does not need that argument and no longer makes it: refusing bytes
	// no reader reads is a rule with no counterpart upstream, and the 16 MiB
	// decoded cap above is what actually bounds the payload.
	return int(count), nil
}

func validateDomainMRSBody(cursor *mrsCursor) error {
	version, err := cursor.byte("domain-set version")
	if err != nil {
		return err
	}
	if version != 1 {
		return fmt.Errorf("MRS domain-set version is invalid")
	}
	leavesLength, err := cursor.int64("domain leaves length")
	if err != nil {
		return err
	}
	leaves, err := cursor.sized(leavesLength, 8, "domain leaves", false)
	if err != nil {
		return err
	}
	bitmapLength, err := cursor.int64("domain label bitmap length")
	if err != nil {
		return err
	}
	bitmap, err := cursor.sized(bitmapLength, 8, "domain label bitmap", false)
	if err != nil {
		return err
	}
	labelsLength, err := cursor.int64("domain labels length")
	if err != nil {
		return err
	}
	labels, err := cursor.sized(labelsLength, 1, "domain labels", false)
	if err != nil {
		return err
	}

	nodes := len(labels) + 1
	if len(leaves)/8*64 < nodes {
		return fmt.Errorf("MRS domain leaves bitmap is too short")
	}
	logicalBitmapBits := 2*len(labels) + 1
	if len(bitmap)/8*64 < logicalBitmapBits {
		return fmt.Errorf("MRS domain label bitmap is too short")
	}

	bitPosition := 0
	childrenSeen := 0
	levelRemaining := 1
	nextLevel := 0
	for node := 0; node < nodes; node++ {
		for bitPosition < logicalBitmapBits && !mrsBit(bitmap, bitPosition) {
			childrenSeen++
			nextLevel++
			bitPosition++
			if childrenSeen > len(labels) {
				return fmt.Errorf("MRS domain tree has too many children")
			}
		}
		if bitPosition >= logicalBitmapBits {
			return fmt.Errorf("MRS domain tree lacks a node delimiter")
		}
		bitPosition++
		levelRemaining--
		if levelRemaining == 0 && node+1 < nodes {
			// No depth cap. This trie is a succinct character trie over the
			// reversed name, so one level is one character -- a 253-level bound
			// was really "no rule here may name a domain longer than 253
			// characters", and one such entry rejected the whole file. mihomo
			// writes those names without complaint and its reader has no depth
			// notion at all (ReadDomainSetBin reads three arrays and calls
			// init()). The walk stays finite without it: node is bounded by
			// len(labels)+1 and bitPosition by the bitmap length.
			if nextLevel == 0 {
				return fmt.Errorf("MRS domain tree is disconnected")
			}
			levelRemaining = nextLevel
			nextLevel = 0
		}
	}
	if childrenSeen != len(labels) || bitPosition != logicalBitmapBits || levelRemaining != 0 || nextLevel != 0 {
		return fmt.Errorf("MRS domain tree topology is inconsistent")
	}
	// No leaves-vs-rules comparison. mihomo stores a suffix rule as two trie
	// entries, so `+.` rule sets — every geosite file meta-rules-dat ships —
	// carry twice the header's rule count in leaves (cn.mrs: 111,873 rules,
	// 223,746 leaves). Upstream keeps the header count for display only and
	// never checks it against the trie, so a comparison here rejects files
	// the kernel itself writes. The structural checks above are what this
	// validator is for: they bound the parse before the tunnel touches it.
	return nil
}

func validateIPCIDRMRSBody(cursor *mrsCursor) error {
	version, err := cursor.byte("IP-CIDR-set version")
	if err != nil {
		return err
	}
	if version != 1 {
		return fmt.Errorf("MRS IP-CIDR-set version is invalid")
	}
	rangeCount, err := cursor.int64("IP-CIDR range count")
	if err != nil {
		return err
	}
	ranges, err := cursor.sized(rangeCount, 32, "IP-CIDR ranges", false)
	if err != nil {
		return err
	}
	// Same reasoning as the domain half: the header count is display-only
	// upstream (ipcidrStrategy.FromMrs assigns it to i.count and never looks
	// at it again), and one rule can need several ranges, so a comparison
	// here rejects files the kernel writes.
	for offset := 0; offset < len(ranges); offset += 32 {
		var fromBytes, toBytes [16]byte
		copy(fromBytes[:], ranges[offset:offset+16])
		copy(toBytes[:], ranges[offset+16:offset+32])
		from := netip.AddrFrom16(fromBytes).Unmap()
		to := netip.AddrFrom16(toBytes).Unmap()
		if from.BitLen() != to.BitLen() || from.Compare(to) > 0 {
			return fmt.Errorf("MRS IP-CIDR range is invalid")
		}
	}
	return nil
}

func mrsBit(serializedWords []byte, index int) bool {
	wordOffset := index / 64 * 8
	word := binary.BigEndian.Uint64(serializedWords[wordOffset : wordOffset+8])
	return word&(uint64(1)<<uint(index&63)) != 0
}
