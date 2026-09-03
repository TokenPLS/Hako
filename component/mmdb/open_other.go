//go:build !windows

package mmdb

import "github.com/oschwald/maxminddb-golang"

// openDatabaseFile maps the database. A rename over a mapped file is fine
// here: the old reader keeps the inode it opened and its lookups keep
// answering until the last reference goes (see open_windows.go for the
// platform where that is not true).
//
// The size is checked first even though mapping does not read the file: the
// ceiling is what makes "a database" a bounded thing on every platform, and a
// file that is refused here is refused there.
func openDatabaseFile(path string) (*maxminddb.Reader, error) {
	if err := statDatabaseSize(path); err != nil {
		return nil, err
	}
	return maxminddb.Open(path)
}
