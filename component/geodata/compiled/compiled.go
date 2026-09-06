// Package compiled stores a domain set the way it will be used, instead of the
// way it was written.
//
// A geosite category on disk is source material: every domain is a separate
// record that has to be decoded into its own heap object before the succinct
// set that actually answers queries can be built. Measured on the shipped
// GeoSite.dat, the scaffolding for one category is an order of magnitude larger
// than the result — geosite:cn peaks at 72.7 MiB to produce 0.9 MiB. A packet
// tunnel has 50 MiB for everything, so that category cannot be loaded there at
// all, however the configuration is written.
//
// The compiled form is the result, written out: reading it back is 2 ms and
// 1.2 MiB. This is not a new idea or a new format — it is what a rule set in
// MRS form already is, and this package writes that same layout so the two are
// interchangeable and a compiled category can be read by anything that reads a
// rule set.
package compiled

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/TokenPLS/Hako/component/trie"
	P "github.com/TokenPLS/Hako/constant/provider"
)

// MagicBytes and the field order below are the rule-set binary layout, not a
// convention of this package. A test asserts our writer against the rule-set
// reader so the two cannot drift apart silently.
var MagicBytes = [4]byte{'M', 'R', 'S', 1}

// DirectoryName is where compiled categories live under the working directory.
const DirectoryName = "compiled-geosite"

// ErrNotCompiled says the artifact is absent, which is a fact about this
// installation rather than a defect: the caller decides whether to build it
// (with a budget to spare) or to carry on without it.
var ErrNotCompiled = errors.New("category has not been compiled")

// Path is where the compiled artifact for a category belongs.
//
// The category name reaches this function from a configuration, so it is
// treated as untrusted: "../../evil" and "cn/../../evil" both name a file
// outside the directory unless the separators are refused rather than cleaned.
func Path(directory, category string) (string, error) {
	name := strings.ToLower(strings.TrimSpace(category))
	if name == "" {
		return "", errors.New("empty category")
	}
	if strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
		return "", fmt.Errorf("unsafe category name %q", category)
	}
	// The attribute form (cn@ads, printed cn@a,b when there are several)
	// selects a subset of one category and is compiled under its own name, so
	// '@' and ',' stay. '!' stays because it can be part of a category's
	// literal name (geolocation-!cn); a *leading* '!' is negation, applied to
	// the matcher after loading, and the canonical key strips it before any
	// path is formed.
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.', r == '@', r == ',', r == '!':
		default:
			return "", fmt.Errorf("unsafe category name %q", category)
		}
	}
	return filepath.Join(directory, name+".mrs"), nil
}

// Write compiles a domain set to the rule-set binary layout.
//
// Callers hold the source material while this runs, so this must be called
// where there is memory to hold it — the containing App, not the tunnel.
func Write(w io.Writer, set *trie.DomainSet, count int, residual []Residual) (err error) {
	if set == nil {
		return errors.New("nil domain set")
	}
	encoder, err := zstd.NewWriter(w)
	if err != nil {
		return err
	}
	defer func() {
		closeErr := encoder.Close()
		if err == nil {
			err = closeErr
		}
	}()
	if _, err = encoder.Write(MagicBytes[:]); err != nil {
		return err
	}
	if _, err = encoder.Write([]byte{P.Domain.Byte()}); err != nil {
		return err
	}
	if err = binary.Write(encoder, binary.BigEndian, int64(count)); err != nil {
		return err
	}
	// The format reserves an "extra" block and its reader skips whatever length
	// it declares, so entries a domain set cannot hold ride here without making
	// the artifact unreadable to anything else that reads rule sets.
	extra := encodeResidual(residual)
	if err = binary.Write(encoder, binary.BigEndian, int64(len(extra))); err != nil {
		return err
	}
	if len(extra) > 0 {
		if _, err = encoder.Write(extra); err != nil {
			return err
		}
	}
	return set.WriteBin(encoder)
}

// Read restores a compiled domain set. It allocates the set and nothing else:
// there is no decode step and no intermediate representation, which is the
// whole point of the artifact.
func Read(r io.Reader) (*trie.DomainSet, int, []Residual, error) {
	decoder, err := zstd.NewReader(r)
	if err != nil {
		return nil, 0, nil, err
	}
	defer decoder.Close()

	var magic [4]byte
	if _, err := io.ReadFull(decoder, magic[:]); err != nil {
		return nil, 0, nil, err
	}
	if magic != MagicBytes {
		return nil, 0, nil, errors.New("not a compiled rule set")
	}
	var behavior [1]byte
	if _, err := io.ReadFull(decoder, behavior[:]); err != nil {
		return nil, 0, nil, err
	}
	if behavior[0] != P.Domain.Byte() {
		return nil, 0, nil, fmt.Errorf("compiled rule set holds %d, want a domain set", behavior[0])
	}
	var count int64
	if err := binary.Read(decoder, binary.BigEndian, &count); err != nil {
		return nil, 0, nil, err
	}
	var extraLength int64
	if err := binary.Read(decoder, binary.BigEndian, &extraLength); err != nil {
		return nil, 0, nil, err
	}
	if extraLength < 0 || extraLength > maximumResidualBytes {
		return nil, 0, nil, errors.New("extra block length is invalid")
	}
	var residual []Residual
	if extraLength > 0 {
		extra := make([]byte, extraLength)
		if _, err := io.ReadFull(decoder, extra); err != nil {
			return nil, 0, nil, err
		}
		residual, err = decodeResidual(extra)
		if err != nil {
			return nil, 0, nil, err
		}
	}
	set, err := trie.ReadDomainSetBin(decoder)
	if err != nil {
		return nil, 0, nil, err
	}
	return set, int(count), residual, nil
}

// Load reads the compiled artifact for one category, or reports that there
// isn't one.
func Load(directory, category string) (*trie.DomainSet, int, []Residual, error) {
	path, err := Path(directory, category)
	if err != nil {
		return nil, 0, nil, err
	}
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, nil, ErrNotCompiled
		}
		return nil, 0, nil, err
	}
	return Read(bytes.NewReader(content))
}

// Store writes the compiled artifact for one category, creating the directory.
//
// It writes to a temporary file and renames, so a tunnel reading the directory
// never sees a half-written artifact — which would be indistinguishable from a
// corrupt one and would take the tunnel down for a cache.
func Store(
	directory, category string, set *trie.DomainSet, count int, residual []Residual,
) error {
	path, err := Path(directory, category)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".compiling-*")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	if err := Write(temporary, set, count, residual); err != nil {
		temporary.Close()
		return err
	}
	// Rename is atomic for the name, not the bytes: on power loss the rename
	// can survive while data blocks that were never synced do not, which is a
	// truncated artifact wearing a fresh mtime. Sync first so the bytes are as
	// durable as the name that claims them.
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporary.Name(), path)
}

// Residual is a category entry the domain set cannot hold, carried verbatim.
type Residual struct {
	// Type is the source domain type, encoded as its protobuf value so the
	// artifact does not depend on this package's own naming.
	Type  int32
	Value string
}

// A ceiling on the extra block, so a corrupt artifact cannot ask this process
// to allocate an arbitrary amount before anything has validated it.
const maximumResidualBytes = 1 << 20

func encodeResidual(residual []Residual) []byte {
	if len(residual) == 0 {
		return nil
	}
	var out bytes.Buffer
	for _, entry := range residual {
		// Tab-separated: a domain type is a small integer and neither a
		// keyword nor a regex may contain a tab or a newline in the source
		// format, so the two are unambiguous separators.
		if strings.ContainsAny(entry.Value, "\t\n") {
			continue
		}
		fmt.Fprintf(&out, "%d\t%s\n", entry.Type, entry.Value)
	}
	return out.Bytes()
}

func decodeResidual(extra []byte) ([]Residual, error) {
	var residual []Residual
	for _, line := range strings.Split(string(extra), "\n") {
		if line == "" {
			continue
		}
		separator := strings.IndexByte(line, '\t')
		if separator <= 0 {
			return nil, fmt.Errorf("malformed extra entry %q", line)
		}
		kind, err := strconv.ParseInt(line[:separator], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("malformed extra entry %q: %w", line, err)
		}
		residual = append(residual, Residual{Type: int32(kind), Value: line[separator+1:]})
	}
	return residual, nil
}

// EntryCount reports how many entries a compiled artifact holds, reading the
// whole artifact to say so.
//
// An artifact is "current" only if it is both newer than its source and reads
// back whole. Trusting the timestamp alone made a batch of empty artifacts —
// written by a compile step that had taken an empty matcher from a poisoned
// cache — permanently authoritative. Trusting the header alone repeated that
// shape one layer down: a file truncated after its count field answered the
// probe, was reused forever, and the tunnel's full read then failed into a
// category that matches nothing under compiled-only. Reading it whole costs
// what the tunnel's ordinary load costs, and this runs where compiling runs —
// the App — so the saving the header-only probe bought was never worth what
// it silently accepted.
func EntryCount(directory, category string) (int, error) {
	path, err := Path(directory, category)
	if err != nil {
		return 0, err
	}
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, ErrNotCompiled
		}
		return 0, err
	}
	defer file.Close()
	_, count, _, err := Read(file)
	if err != nil {
		return 0, err
	}
	return count, nil
}
