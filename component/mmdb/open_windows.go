//go:build windows

package mmdb

import (
	"io"
	"os"

	"github.com/oschwald/maxminddb-golang"
)

// openDatabaseFile reads a database into memory instead of mapping it.
//
// Windows will not replace a file another handle has open, and this
// transaction's whole point is to keep the CURRENT reader alive while the new
// file is renamed into its place -- so a mapped reader would make every
// replacement after the first one fail, and the geo data would stay whatever
// it was until the process restarted. Upstream avoids the same collision by
// closing the live reader before overwriting, which is the unsafe half this
// transaction exists to remove.
//
// Reading the bytes costs the heap what the file weighs, and a replacement
// holds two of them for as long as a lookup keeps the old reader -- so the
// size is checked against the open handle before the read, not against the
// path before someone else could swap it. The real databases here are 9-12
// MiB. The memory-constrained platform is the iOS packet tunnel, which is not
// this one.
func openDatabaseFile(path string) (*maxminddb.Reader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if err := checkDatabaseSize(path, info.Size()); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, info.Size()))
	if err != nil {
		return nil, err
	}
	return maxminddb.FromBytes(data)
}
