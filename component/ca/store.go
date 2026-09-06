package ca

import (
	"crypto/x509"
	_ "embed"
	"fmt"
	"strings"
)

// Certificate store selection, ported from sing-box rather than designed here.
//
// Upstream shape (option/certificate.go, common/certificate/store.go newBasePool):
//
//	system   the platform trust store, the DEFAULT
//	mozilla  the embedded Mozilla root list
//	chrome   the embedded Chrome root list
//	none     no roots at all; only certificates the configuration supplies
//
// Why this exists at all is the Apple cost model. On darwin crypto/x509 delegates verification
// to the OS whenever the pool it is handed carries the systemPool mark -- verify.go branches on
// that mark ALONE, so the round trip to trustd is paid on every verification and appending roots
// to a system pool does not avoid it. Only a pool built by x509.NewCertPool() is verified
// in-process, which is exactly what mozilla, chrome and none produce.
//
// It is deliberately NOT automatic. An earlier attempt in this tree activated an embedded bundle
// merely because one was present, and needed three guards to contain its own consequences;
// upstream never silently replaces the platform trust store. The reason is the same one those
// guards were about: selecting mozilla or chrome DROPS every root the platform trusts that the
// bundle does not carry, including MDM-installed enterprise roots and anything a developer added
// locally. That is a decision only an operator can make, so it is an explicit selection with
// system as the default and no behaviour change unless it is set.
//
// The bundles are the files sing-box ships, copied verbatim, so their provenance is answerable:
// they are upstream's, not a snapshot of some build machine's /etc/ssl. mihomo's own CI populates
// ca-certificates.crt from the build host instead, which is not reproducible and would mark
// every Apple build dirty in this tree's build provenance.
type Store string

const (
	// StoreDefault is the empty value: no selection made, behave exactly as before.
	StoreDefault Store = ""
	StoreSystem  Store = "system"
	StoreMozilla Store = "mozilla"
	StoreChrome  Store = "chrome"
	StoreNone    Store = "none"
)

//go:embed mozilla.pem
var mozillaRoots []byte

//go:embed chrome.pem
var chromeRoots []byte

// selectedStore is process-wide because globalCertPool is: mihomo keeps one pool for the whole
// process and hands it to every TLS client, so a per-configuration selection would promise
// something the mechanism cannot deliver.
var selectedStore = StoreDefault

// ParseStore validates a store name, failing closed on anything unrecognised.
//
// Fail-closed matters more here than in most option parsing: silently falling back to the
// platform store when an operator asked for "mozzila" would leave them believing verification
// had moved in-process when every handshake still reaches trustd.
func ParseStore(value string) (Store, error) {
	switch Store(strings.ToLower(strings.TrimSpace(value))) {
	case StoreDefault:
		return StoreDefault, nil
	case StoreSystem:
		return StoreSystem, nil
	case StoreMozilla:
		return StoreMozilla, nil
	case StoreChrome:
		return StoreChrome, nil
	case StoreNone:
		return StoreNone, nil
	default:
		return StoreDefault, fmt.Errorf(
			"unknown certificate store %q; expected %q, %q, %q or %q",
			value, StoreSystem, StoreMozilla, StoreChrome, StoreNone)
	}
}

// SetStore selects the trust source and rebuilds the pool.
//
// Rebuilding immediately is the point: the pool is built lazily on first use, so a selection
// made after some TLS client had already taken it would apply to nothing. Callers must set this
// before starting anything that dials.
func SetStore(store Store) {
	mutex.Lock()
	selectedStore = store
	mutex.Unlock()
	ResetCertificate()
}

// SelectedStore reports the current selection, for diagnostics that need to say which trust
// source a verification failure was measured against.
func SelectedStore() Store {
	mutex.RLock()
	defer mutex.RUnlock()
	return selectedStore
}

// storeRoots returns the embedded roots for a bundle-backed store, and whether the store is
// bundle-backed at all.
func storeRoots(store Store) ([]byte, bool) {
	switch store {
	case StoreMozilla:
		return mozillaRoots, true
	case StoreChrome:
		return chromeRoots, true
	default:
		return nil, false
	}
}

// basePool builds the starting pool for the selected store, mirroring upstream's newBasePool.
//
// Returns the pool and whether the embedded ca-certificates.crt should still be appended to it.
// That distinction is the reason this is not a one-liner: appending the build-time bundle on top
// of a deliberately chosen Mozilla or Chrome store would put roots back that the operator asked
// to exclude, and appending it to "none" would make the name a lie.
func basePool(store Store) (pool *x509.CertPool, appendEmbedded bool) {
	if roots, bundled := storeRoots(store); bundled {
		pool = x509.NewCertPool()
		pool.AppendCertsFromPEM(roots)
		return pool, false
	}
	if store == StoreNone {
		return x509.NewCertPool(), false
	}
	// system, or no selection at all: unchanged from before this file existed, including the
	// DisableSystemCa escape hatch that fix_windows.go and the environment variable drive.
	if DisableSystemCa {
		return x509.NewCertPool(), !DisableEmbedCa
	}
	systemPool, err := x509.SystemCertPool()
	if err != nil {
		systemPool = x509.NewCertPool()
	}
	return systemPool, !DisableEmbedCa
}
