//go:build darwin

package ca

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"testing"
)

// The value of taking the pool off the platform verifier, measured rather than asserted.
//
// Run against a real chain so the numbers mean something:
//
//	HAKO_CA_BENCH_HOST=apple.com go test ./component/ca/ -run XXX -bench VerifyChain -benchtime 200x
//
// Without the variable the benchmark skips: it needs a live TLS endpoint, and a benchmark that
// silently measures nothing is worse than one that refuses to run.
//
// Measured on darwin/arm64, 200 verifications per host, with the shipped store rather than a
// supplied bundle:
//
//	host              platform verifier   store mozilla
//	apple.com                   1.87 ms         0.71 ms
//	cloudflare.com              0.93 ms         0.74 ms
//	github.com                  0.96 ms         1.06 ms   <- slower
//
// READ THE LIMITATION BEFORE QUOTING THESE. Verifying the SAME chain 200 times measures trustd's
// evaluation cache, not trustd's cost: the first verification pays the cross-process round trip
// and the rest are served warm. That is why the platform verifier looks competitive on two of
// three hosts and why the numbers vary by nearly 2x across hosts that should be similar.
//
// The workload that motivated any of this is the opposite case. A health check sweeps dozens of
// DISTINCT proxy endpoints, so nothing is warm, and an idle iPhone logged 17,568 verifications in
// 6.7 hours -- about 0.8 per second. This benchmark does not represent that, and a cold-cache
// benchmark would need a fresh chain per iteration.
//
// So the honest conclusion: the per-verification latency saving from an in-process pool is real
// but workload-dependent and sometimes negative. It is NOT the argument for the store option --
// the argument is avoiding a cross-process round trip per verification at all, and the fix for
// the storm itself was stopping the health checks while the device sleeps (the pause manager),
// not making each verification cheaper.

func BenchmarkVerifyChainPlatformVerifier(b *testing.B) {
	leaf, intermediates, host := liveChain(b)
	pool, err := x509.SystemCertPool() // system-marked: routes to SecTrustEvaluateWithError
	if err != nil {
		b.Fatal(err)
	}
	benchmarkVerify(b, leaf, intermediates, pool, host)
}

// BenchmarkVerifyChainStoreMozilla measures what a user actually gets by selecting
// certificate store "mozilla": the shipped bundle, not an arbitrary PEM handed in by an
// environment variable. That distinction matters -- the earlier version of this benchmark could
// only be run against a file someone supplied, so it measured a configuration nobody ships.
func BenchmarkVerifyChainStoreMozilla(b *testing.B) {
	leaf, intermediates, host := liveChain(b)

	prior := SelectedStore()
	b.Cleanup(func() { SetStore(prior) })
	SetStore(StoreMozilla)

	pool := GetCertPool()
	if poolIsSystemMarked(pool) {
		b.Fatal("store mozilla left the pool system-marked, so this would measure the platform " +
			"verifier twice and report a saving that does not exist")
	}
	benchmarkVerify(b, leaf, intermediates, pool, host)
}

func benchmarkVerify(b *testing.B, leaf *x509.Certificate, intermediates *x509.CertPool, roots *x509.CertPool, host string) {
	b.Helper()
	options := x509.VerifyOptions{DNSName: host, Intermediates: intermediates, Roots: roots}
	if _, err := leaf.Verify(options); err != nil {
		b.Fatalf("the chain must verify before it can be timed: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := leaf.Verify(options); err != nil {
			b.Fatal(err)
		}
	}
}

func liveChain(b *testing.B) (*x509.Certificate, *x509.CertPool, string) {
	b.Helper()
	host := os.Getenv("HAKO_CA_BENCH_HOST")
	if host == "" {
		b.Skip("set HAKO_CA_BENCH_HOST to a hostname whose real chain should be measured")
	}
	conn, err := tls.Dial("tcp", host+":443", &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		b.Skipf("cannot reach %s: %v", host, err)
	}
	defer conn.Close()
	state := conn.ConnectionState()
	intermediates := x509.NewCertPool()
	for _, certificate := range state.PeerCertificates[1:] {
		intermediates.AddCert(certificate)
	}
	return state.PeerCertificates[0], intermediates, host
}
