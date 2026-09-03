package compiled

// GeoIP source material has the same shape of problem geosite does, one size larger.
//
// A country code in GeoIP.dat is a list of protobuf CIDR records, each decoded into its own
// heap object before the set that answers queries exists. Measured on the shipped file,
// geoip:us peaks at 130 MiB to produce a set that weighs 3.15 MiB, and loading every country
// code the file contains peaks at 164 MiB to arrive at 27.9 MiB of matchers. The end state
// was always inside a packet tunnel's 50 MiB; only the path there was not.
//
// So the same answer: write the result, read the result. The layout is the rule-set binary
// form again, with the behavior byte saying IPCIDR instead of Domain, so a compiled country
// is interchangeable with an MRS rule set of behavior ipcidr and nothing new was invented.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/klauspost/compress/zstd"
	"github.com/TokenPLS/Hako/component/cidr"
	P "github.com/TokenPLS/Hako/constant/provider"
)

// IPCIDRDirectoryName is where compiled country codes live under the working directory.
//
// It is deliberately NOT DirectoryName. Country codes and geosite categories share a
// namespace of short lowercase names -- cn is both -- so one directory would let whichever
// was written second answer for both, and a tunnel would match addresses against domains.
const IPCIDRDirectoryName = "compiled-geoip"

// IPCIDRPath is where the compiled artifact for one country code belongs.
//
// The country code reaches this from a configuration, so it is untrusted for the same
// reasons Path documents. The permitted set is narrower than a category's: country codes
// carry no attribute or negation syntax, so letters, digits, '-' and '_' are all a
// legitimate one can contain.
func IPCIDRPath(directory, country string) (string, error) {
	name := strings.ToLower(strings.TrimSpace(country))
	if name == "" {
		return "", errors.New("empty country code")
	}
	if strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
		return "", fmt.Errorf("unsafe country code %q", country)
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '-', r == '_':
		default:
			return "", fmt.Errorf("unsafe country code %q", country)
		}
	}
	return filepath.Join(directory, name+".mrs"), nil
}

// WriteIPCIDR compiles an address set to the rule-set binary layout.
//
// Callers hold the decoded source while this runs, so like Write it must be called where
// there is memory to hold it -- the containing App, not the tunnel.
func WriteIPCIDR(w io.Writer, set *cidr.IpCidrSet, count int) (err error) {
	if set == nil {
		return errors.New("nil ip set")
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
	if _, err = encoder.Write([]byte{P.IPCIDR.Byte()}); err != nil {
		return err
	}
	if err = binary.Write(encoder, binary.BigEndian, int64(count)); err != nil {
		return err
	}
	// An empty extra block, so the layout stays the one a rule-set reader expects and a
	// later version can carry something here without changing the framing.
	if err = binary.Write(encoder, binary.BigEndian, int64(0)); err != nil {
		return err
	}
	return set.WriteBin(encoder)
}

// One decoder for every artifact this process reads, instead of one per artifact.
//
// zstd.NewReader builds decoder state -- window buffers, and by default a worker per core
// -- and a runtime that reads every country code the shipped file holds would build 260 of
// them. Measured: reading 260 artifacts through a per-call reader peaked 21.9 MiB above
// reading the same 260 sets raw, and that entire difference was the framing rather than the
// data. DecodeAll on a shared decoder is the pattern the library documents for many small
// frames, and it is safe for concurrent use.
//
// Lowmem and a single worker because this exists for the process that has 50 MiB, and the
// artifacts are small enough that decode throughput was never the constraint.
var sharedDecoder = sync.OnceValues(func() (*zstd.Decoder, error) {
	return zstd.NewReader(nil,
		zstd.WithDecoderConcurrency(1),
		zstd.WithDecoderLowmem(true),
	)
})

// ReadIPCIDR restores a compiled address set, allocating the set and nothing else.
func ReadIPCIDR(r io.Reader) (*cidr.IpCidrSet, int, error) {
	framed, err := io.ReadAll(r)
	if err != nil {
		return nil, 0, err
	}
	shared, err := sharedDecoder()
	if err != nil {
		return nil, 0, err
	}
	plain, err := shared.DecodeAll(framed, nil)
	if err != nil {
		return nil, 0, err
	}
	decoder := bytes.NewReader(plain)

	var magic [4]byte
	if _, err := io.ReadFull(decoder, magic[:]); err != nil {
		return nil, 0, err
	}
	if magic != MagicBytes {
		return nil, 0, errors.New("not a compiled rule set")
	}
	var behavior [1]byte
	if _, err := io.ReadFull(decoder, behavior[:]); err != nil {
		return nil, 0, err
	}
	// The behavior byte exists so a domain artifact read as an address set fails here
	// rather than producing a set that answers wrongly and silently.
	if behavior[0] != P.IPCIDR.Byte() {
		return nil, 0, fmt.Errorf("compiled rule set holds behavior %d, want an ip set", behavior[0])
	}
	var count int64
	if err := binary.Read(decoder, binary.BigEndian, &count); err != nil {
		return nil, 0, err
	}
	var extraLength int64
	if err := binary.Read(decoder, binary.BigEndian, &extraLength); err != nil {
		return nil, 0, err
	}
	if extraLength < 0 || extraLength > maximumResidualBytes {
		return nil, 0, errors.New("extra block length is invalid")
	}
	if extraLength > 0 {
		if _, err := io.CopyN(io.Discard, decoder, extraLength); err != nil {
			return nil, 0, err
		}
	}
	set, err := cidr.ReadIpCidrSet(decoder)
	if err != nil {
		return nil, 0, err
	}
	return set, int(count), nil
}

// LoadIPCIDR reads the compiled artifact for one country code, or reports that there
// isn't one.
func LoadIPCIDR(directory, country string) (*cidr.IpCidrSet, int, error) {
	path, err := IPCIDRPath(directory, country)
	if err != nil {
		return nil, 0, err
	}
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, ErrNotCompiled
		}
		return nil, 0, err
	}
	return ReadIPCIDR(bytes.NewReader(content))
}

// StoreIPCIDR writes the compiled artifact for one country code, creating the directory.
//
// Written to a temporary file and renamed for the reason Store documents: a tunnel reading
// the directory must never see a half-written artifact, which is indistinguishable from a
// corrupt one and would take the tunnel down for a cache.
func StoreIPCIDR(directory, country string, set *cidr.IpCidrSet, count int) error {
	path, err := IPCIDRPath(directory, country)
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
	if err := WriteIPCIDR(temporary, set, count); err != nil {
		temporary.Close()
		return err
	}
	// Sync before rename for the reason Store documents: rename is atomic for the name,
	// not for blocks that were never written.
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporary.Name(), path)
}

// EntryCountIPCIDR reports how many source records the artifact for one country was built
// from.
//
// It DOES build the set and throw it away -- the count sits behind the frame, so reaching
// it means decompressing, and cidr.ReadIpCidrSet consumes the rest of the stream. An
// earlier comment here claimed otherwise, which would have misled anyone calling this from
// the tunnel: it is affordable in the App's freshness loop (once per named country, on a
// set that is 3 MiB at worst) and it is not a cheap peek.
//
// Used to tell a cached answer from an artifact holding nothing: an empty artifact is a
// country that will silently match nothing, and a timestamp-only freshness check would make
// that permanent.
func EntryCountIPCIDR(directory, country string) (int, error) {
	path, err := IPCIDRPath(directory, country)
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
	_, count, err := ReadIPCIDR(file)
	if err != nil {
		return 0, err
	}
	return count, nil
}
