package hako

import (
	"crypto/x509"
	"reflect"
	"testing"

	"github.com/TokenPLS/Hako/component/ca"
)

// SetupOptions.CertificateStore, ported from sing-box's certificate.store.
//
// The property worth testing at this layer is not that the field exists but that Setup applies it
// BEFORE anything can dial. mihomo builds its certificate pool lazily and hands that one instance
// to every TLS client, so a selection applied a moment too late applies to nothing at all while
// still reporting success.
//
// The pool-shape contract itself is covered in component/ca; these tests cover the wiring and the
// failure modes an operator can actually hit.

func poolTakesThePlatformVerifier(pool *x509.CertPool) bool {
	// crypto/x509's verify.go branches on this mark alone, so it is the whole question: marked
	// means the OS verifies (an XPC round trip to trustd on Apple), unmarked means Go does.
	value := reflect.ValueOf(pool)
	if value.Kind() == reflect.Ptr {
		value = value.Elem()
	}
	field := value.FieldByName("systemPool")
	return field.IsValid() && field.Bool()
}

func restoreCertificateStore(t *testing.T) {
	t.Helper()
	prior := ca.SelectedStore()
	t.Cleanup(func() { ca.SetStore(prior) })
}

func TestSetupAppliesTheCertificateStore(t *testing.T) {
	cases := []struct {
		name             string
		value            string
		wantStore        ca.Store
		platformVerifier bool
		why              string
	}{
		{
			name:             "absent",
			value:            "",
			wantStore:        ca.StoreDefault,
			platformVerifier: true,
			why:              "the option is unset in every shipping configuration today; absent must change nothing",
		},
		{
			name:             "system",
			value:            "system",
			wantStore:        ca.StoreSystem,
			platformVerifier: true,
			why:              "upstream's default keeps the platform verifier and with it MDM and user-installed roots",
		},
		{
			name:             "mozilla",
			value:            "mozilla",
			wantStore:        ca.StoreMozilla,
			platformVerifier: false,
			why:              "leaving the platform verifier is the entire reason to select a bundle",
		},
		{
			name:             "chrome",
			value:            "chrome",
			wantStore:        ca.StoreChrome,
			platformVerifier: false,
			why:              "same contract, different root list",
		},
		{
			name:             "none",
			value:            "none",
			wantStore:        ca.StoreNone,
			platformVerifier: false,
			why:              "only what the configuration supplies; a marked empty pool would silently be the platform store",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			restoreCertificateStore(t)
			restoreRuntimeProfileForTest(t)

			options := testOptions(t)
			options.CertificateStore = testCase.value
			if err := Setup(options); err != nil {
				t.Fatalf("Setup with CertificateStore=%q: %v", testCase.value, err)
			}

			if got := ca.SelectedStore(); got != testCase.wantStore {
				t.Fatalf("selected store = %q, want %q", got, testCase.wantStore)
			}
			if got := poolTakesThePlatformVerifier(ca.GetCertPool()); got != testCase.platformVerifier {
				t.Fatalf("pool takes the platform verifier = %v, want %v — %s",
					got, testCase.platformVerifier, testCase.why)
			}
		})
	}
}

// TestSetupRejectsAnUnknownCertificateStore: silently keeping the platform store on a typo would
// leave an operator believing verification had moved in-process while every handshake still
// reached trustd. The failure has to be at Setup, where it is visible, not at the first dial.
func TestSetupRejectsAnUnknownCertificateStore(t *testing.T) {
	restoreCertificateStore(t)
	restoreRuntimeProfileForTest(t)
	before := ca.SelectedStore()

	options := testOptions(t)
	options.CertificateStore = "mozzila"
	err := Setup(options)
	if err == nil {
		t.Fatal("Setup accepted an unknown certificate store")
	}
	if got := ca.SelectedStore(); got != before {
		t.Fatalf("a rejected Setup still changed the store to %q; a failed option must leave the "+
			"process as it was", got)
	}
}

// TestCertificateStoreSurvivesSetupWithoutIt: Setup runs more than once in a process -- the
// containing App preflights, the extension starts, a reload re-enters. A later call that omits the
// option must not silently revert a selection the operator made, because the revert would be
// invisible and would restore the trustd cost this option exists to remove.
//
// This documents the CURRENT behaviour, which is that an omitted value is treated as "no
// selection" and does reset the store. That is worth pinning either way: if it is ever changed to
// sticky, this test is where the decision gets recorded.
func TestCertificateStoreSurvivesSetupWithoutIt(t *testing.T) {
	restoreCertificateStore(t)
	restoreRuntimeProfileForTest(t)

	options := testOptions(t)
	options.CertificateStore = "mozilla"
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	if ca.SelectedStore() != ca.StoreMozilla {
		t.Fatalf("first Setup did not select mozilla")
	}

	plain := testOptions(t)
	if err := Setup(plain); err != nil {
		t.Fatal(err)
	}
	if got := ca.SelectedStore(); got != ca.StoreDefault {
		t.Fatalf("omitting the option left the store at %q; this test records that an omitted "+
			"value means no selection, so a caller that wants mozilla must pass it every time", got)
	}
	if !poolTakesThePlatformVerifier(ca.GetCertPool()) {
		t.Fatal("the pool did not return to the platform verifier after the selection was dropped")
	}
}
