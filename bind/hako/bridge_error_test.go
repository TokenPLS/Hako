package hako

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestInspectProviderErrorCrossesBridgeAsValidUTF8(t *testing.T) {
	payload := []byte("proxies:\n  - name: ok\n    type: !!binary \"/t8=\"\n    server: a.com\n    port: 1\n")
	_, err := InspectProviderForIOS("proxy", "", "yaml", payload)
	if err == nil {
		t.Fatal("payload with a binary type field must be rejected; the positive control vanished")
	}
	message := err.Error()
	if !utf8.ValidString(message) {
		t.Fatalf("error message crossing the bridge is not valid UTF-8: %q", message)
	}
	if !strings.Contains(message, "unsupport proxy type") {
		t.Fatalf("sentence around the invalid bytes must survive verbatim, got: %q", message)
	}
}

func TestBridgeSafeError(t *testing.T) {
	t.Run("nil stays nil", func(t *testing.T) {
		if bridgeSafeError(nil) != nil {
			t.Fatal("nil error must stay nil")
		}
	})
	t.Run("valid message keeps the same error value", func(t *testing.T) {
		original := errors.New("hako: plain sentence")
		if got := bridgeSafeError(original); got != original {
			t.Fatalf("valid error must pass through unchanged, got %v", got)
		}
	})
	t.Run("wrapped chain with valid message keeps errors.Is", func(t *testing.T) {
		sentinel := errors.New("sentinel")
		wrapped := bridgeSafeError(errWrap(sentinel))
		if !errors.Is(wrapped, sentinel) {
			t.Fatal("valid chain must keep its identity")
		}
	})
	t.Run("valid multi-byte message passes byte-identical with zero replacement runes", func(t *testing.T) {
		message := "hako: select \"节点 🚀 café\" in \"組\": upstream said no\n\ttab and trailing space "
		original := errors.New(message)
		got := bridgeSafeError(original)
		if got != original {
			t.Fatal("valid error must keep the very same value")
		}
		if got.Error() != message {
			t.Fatalf("valid message must be byte-identical, got %q", got.Error())
		}
		if strings.Contains(got.Error(), "\uFFFD") {
			t.Fatal("a valid message must not gain replacement runes")
		}
	})
	t.Run("repaired error still unwraps to the original chain", func(t *testing.T) {
		sentinel := errors.New("sentinel")
		invalid := fmt.Errorf("prefix \xfe\xdf: %w", sentinel)
		repaired := bridgeSafeError(invalid)
		if repaired == invalid {
			t.Fatal("an invalid message must be repaired, not passed through")
		}
		if !errors.Is(repaired, sentinel) {
			t.Fatal("the repair must unwrap to the original error")
		}
	})
	t.Run("typed nil error answers loudly instead of crashing", func(t *testing.T) {
		var typed *wrappedForTest
		var err error = typed
		got := bridgeSafeError(err)
		if got == nil {
			t.Fatal("a typed-nil error must not become a success")
		}
		if !strings.Contains(got.Error(), "typed nil") {
			t.Fatalf("the answer must name the shape, got %q", got.Error())
		}
	})
	t.Run("invalid bytes become the replacement rune, rest verbatim", func(t *testing.T) {
		got := bridgeSafeError(errors.New("unsupport proxy type: \xfe\xdf tail")).Error()
		if !utf8.ValidString(got) {
			t.Fatalf("sanitized message still invalid: %q", got)
		}
		if !strings.HasPrefix(got, "unsupport proxy type: ") || !strings.HasSuffix(got, " tail") {
			t.Fatalf("sentence must survive verbatim around the replacement, got: %q", got)
		}
		if !strings.Contains(got, "�") {
			t.Fatalf("undecodable bytes must be visible as replacement runes, got: %q", got)
		}
	})
}

func errWrap(err error) error {
	return &wrappedForTest{err}
}

type wrappedForTest struct{ inner error }

func (w *wrappedForTest) Error() string { return "outer: " + w.inner.Error() }
func (w *wrappedForTest) Unwrap() error { return w.inner }
