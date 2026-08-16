package ca

import (
	"crypto/x509"
	"reflect"
	"runtime"
	"testing"
)

// On Apple platforms every TLS certificate verification is an XPC round trip to trustd, and
// what causes it is the SHAPE of the pool, not the number of handshakes.
//
// crypto/x509's Verify takes the platform-verifier branch when opts.Roots is nil OR when the
// pool it was handed is marked as the system pool (verify.go, the windows/darwin/ios branch).
// On darwin loadSystemRoots returns &CertPool{systemPool: true} holding ZERO certificates,
// because the roots live behind the verifier -- so initializeCertPool starting from
// x509.SystemCertPool() means every TLS client in the process gets an empty system-marked pool,
// and since it holds no certificates the platform answer is returned unconditionally with no
// in-process fallback at all. Clone preserves the flag and AppendCertsFromPEM does not clear
// it, so adding certificates does not change the branch taken.
//
// Adding certificates to that pool does NOT remove the round trip, and this is the trap: the
// branch is taken on the systemPool mark ALONE (verify.go: `if opts.Roots != nil &&
// opts.Roots.systemPool`). With extra roots present, systemVerify still runs FIRST and the Go
// verifier is reached only when the platform verifier fails -- `if err == nil ||
// opts.Roots.len() == 0 { return platformChains, err }`. So appending a Mozilla-style bundle to
// the default pool buys nothing on the cost side and quietly loosens trust: a chain Apple
// rejects can then succeed through the Go fallback. Escaping trustd requires a pool that is not
// system-marked at all, which is what DisableSystemCa produces and what sing-box's
// certificate.store = mozilla|chrome produces -- both opt-in.
//
// Session resumption does not avoid it either: metacubex/tls revalidates the cached chain
// before resuming and on darwin that revalidation is a full leaf.Verify.
//
// A mechanism that replaced this pool with an embedded bundle lived here briefly and was
// removed, because it was ours and not upstream's. sing-box's default certificate store on
// darwin lands in exactly the same place we do: newBasePool clones the pool it got from
// x509.SystemCertPool(), and its own systemCertificates() -- which WOULD build a fresh,
// unmarked pool from the real platform anchors -- is implemented for Android only
// (system_android.go via JNI; system_other.go returns nil). Its two answers to the cost are
// both opt-in: certificate.store = mozilla|chrome, which does produce an unmarked pool, and
// tls.engine = apple, which hands the whole handshake to Network.framework and is unreleased.
//
// So this file no longer tests a mechanism. It pins the platform fact the whole analysis rests
// on, which is worth keeping on its own: if a future Go release changes darwin's pool shape,
// the conclusion changes, and that should surface here rather than in the field.

func TestSystemPoolIsWhatCostsTheXPCRoundTrip(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "ios" {
		t.Skipf("the empty-system-pool shape is Apple-specific; %s loads real roots", runtime.GOOS)
	}
	systemPool, err := x509.SystemCertPool()
	if err != nil {
		t.Fatalf("SystemCertPool: %v", err)
	}
	if got := len(systemPool.Subjects()); got != 0 {
		t.Fatalf("darwin's system pool carries %d certificates; this analysis assumes it carries "+
			"none because the roots live behind the platform verifier", got)
	}
	if !isSystemPool(systemPool) {
		t.Fatal("darwin's system pool is not marked as a system pool; if that is true then Verify " +
			"no longer routes to the platform verifier and this problem is gone")
	}
}

// TestTheSystemMarkSurvivesCloneAndAppend: both are the operations a caller would reach for to
// "add a CA", and neither takes the pool off the platform verifier. Upstream relies on this too
// -- sing-box's newBasePool clones the system pool for its default store.
func TestTheSystemMarkSurvivesCloneAndAppend(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "ios" {
		t.Skipf("Apple-specific; %s does not mark a system pool", runtime.GOOS)
	}
	systemPool, err := x509.SystemCertPool()
	if err != nil {
		t.Fatalf("SystemCertPool: %v", err)
	}

	clone := systemPool.Clone()
	if !isSystemPool(clone) {
		t.Fatal("Clone dropped the system mark; sing-box's default store clones the system pool " +
			"and would behave differently from what this analysis assumes")
	}

	certificate, _, _, err := NewRandomTLSKeyPair(KeyPairTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	if !clone.AppendCertsFromPEM([]byte(certificate)) {
		t.Fatal("AppendCertsFromPEM rejected a freshly generated certificate")
	}
	if !isSystemPool(clone) {
		t.Fatal("AppendCertsFromPEM cleared the system mark; adding a CA would then silently " +
			"change which verifier every TLS client in the process uses")
	}
}

// isSystemPool reads the unexported flag crypto/x509's Verify branches on. Reflection is the
// only way to observe it, and observing it is the point: it is the difference between an
// in-process verification and an XPC round trip, and nothing in the public API exposes it.
func isSystemPool(pool *x509.CertPool) bool {
	value := reflect.ValueOf(pool)
	if value.Kind() == reflect.Ptr {
		value = value.Elem()
	}
	field := value.FieldByName("systemPool")
	if !field.IsValid() {
		return false
	}
	return field.Bool()
}
