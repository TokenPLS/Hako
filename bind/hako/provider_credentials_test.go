package hako

import (
	"encoding/json"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type extractedProviderCredentialBundle struct {
	SchemaVersion int `json:"schemaVersion"`
	RedactedYAML  string
	Credentials   []struct {
		ResourceKey string
		Kind        string
		Value       string
	}
}

func TestExtractProviderCredentialsForIOSRedactsAndNamespacesAgeKeys(t *testing.T) {
	input := `
proxy-providers:
  zebra:
    type: http
    url: https://example.com/zebra.yaml
    age-secret-key: AGE-SECRET-KEY-ZEBRA
    filter: keep-me
  alpha:
    type: http
    url: https://example.com/alpha.yaml
    age-secret-key: AGE-SECRET-KEY-ALPHA
`
	box, err := ExtractProviderCredentialsForIOS(input)
	if err != nil {
		t.Fatalf("extract provider credentials: %v", err)
	}
	var bundle extractedProviderCredentialBundle
	if err := json.Unmarshal([]byte(box.Value), &bundle); err != nil {
		t.Fatalf("decode credential bundle: %v", err)
	}
	if bundle.SchemaVersion != 1 || len(bundle.Credentials) != 2 {
		t.Fatalf("credential bundle = %+v", bundle)
	}
	if got := bundle.Credentials[0]; got.ResourceKey != "proxy:alpha" ||
		got.Kind != "age-secret-key" || got.Value != "AGE-SECRET-KEY-ALPHA" {
		t.Fatalf("first credential = %+v", got)
	}
	if got := bundle.Credentials[1]; got.ResourceKey != "proxy:zebra" ||
		got.Kind != "age-secret-key" || got.Value != "AGE-SECRET-KEY-ZEBRA" {
		t.Fatalf("second credential = %+v", got)
	}

	var redacted map[string]any
	if err := yaml.Unmarshal([]byte(bundle.RedactedYAML), &redacted); err != nil {
		t.Fatalf("parse redacted YAML: %v", err)
	}
	providers := redacted["proxy-providers"].(map[string]any)
	for _, name := range []string{"alpha", "zebra"} {
		definition := providers[name].(map[string]any)
		if _, exists := definition["age-secret-key"]; exists {
			t.Fatalf("%s age key remains in redacted YAML", name)
		}
	}
	if providers["zebra"].(map[string]any)["filter"] != "keep-me" {
		t.Fatalf("unrelated provider policy was lost: %+v", providers["zebra"])
	}
}

func TestExtractProviderCredentialsForIOSRejectsInvalidAgeKeyWithoutEcho(t *testing.T) {
	_, err := ExtractProviderCredentialsForIOS(`
proxy-providers:
  remote:
    type: http
    url: https://example.com/proxies.yaml
    age-secret-key: [DO-NOT-ECHO]
`)
	if err == nil {
		t.Fatal("expected invalid age-secret-key error")
	}
	if strings.Contains(err.Error(), "DO-NOT-ECHO") {
		t.Fatalf("credential leaked in error: %v", err)
	}
}

func TestExtractProviderCredentialsForIOSRejectsSharedSecretAliasWithoutEcho(t *testing.T) {
	_, err := ExtractProviderCredentialsForIOS(`
shared-value: &age-key AGE-SECRET-KEY-DO-NOT-ECHO
proxy-providers:
  remote:
    type: http
    url: https://example.com/proxies.yaml
    age-secret-key: *age-key
`)
	if err == nil {
		t.Fatal("expected shared age-secret-key rejection")
	}
	if strings.Contains(err.Error(), "DO-NOT-ECHO") {
		t.Fatalf("credential leaked in error: %v", err)
	}
}

func TestExtractProviderCredentialsAllowsSharedAgeIdentityAcrossProviders(t *testing.T) {
	// One age identity legitimately decrypting several providers is an upstream
	// pattern (main.go -age-secret-key). The same age-secret-key value on an http
	// provider (extracted to Keychain) and a non-http provider (kept in config)
	// must not be treated as a leak: the residual check ignores a value that lives
	// in a proxy-provider age-secret-key field, unlike the old whole-document
	// substring match.
	box, err := ExtractProviderCredentialsForIOS(`
proxy-providers:
  remote:
    type: http
    url: https://example.com/p.yaml
    age-secret-key: AGE-SECRET-KEY-1EXAMPLESHARED
  local:
    type: file
    path: ./local.yaml
    age-secret-key: AGE-SECRET-KEY-1EXAMPLESHARED
`)
	if err != nil {
		t.Fatalf("a shared age identity across providers must be allowed: %v", err)
	}
	var bundle extractedProviderCredentialBundle
	if err := json.Unmarshal([]byte(box.Value), &bundle); err != nil {
		t.Fatalf("decode credential bundle: %v", err)
	}
	if len(bundle.Credentials) != 1 || bundle.Credentials[0].ResourceKey != "proxy:remote" {
		t.Fatalf("only the http provider secret should be extracted: %+v", bundle.Credentials)
	}
}

func TestExtractProviderCredentialsRejectsMultilineAgeSecretLeakOutsideProvider(t *testing.T) {
	// age supports several newline-separated identities in one value. If such a
	// block scalar is anchored outside a provider field and aliased into an HTTP
	// provider, deleting the provider field leaves the top-level secret behind.
	// yaml.Marshal indents block-scalar continuation lines, so a serialized
	// substring match misses it; the structural check must still catch the leak.
	_, err := ExtractProviderCredentialsForIOS(`
_shared: &age-key |-
  AGE-SECRET-KEY-1FIRSTIDENTITYDONOTECHO
  AGE-SECRET-KEY-1SECONDIDENTITYDONOTECHO
proxy-providers:
  remote:
    type: http
    url: https://example.com/proxies.yaml
    age-secret-key: *age-key
`)
	if err == nil {
		t.Fatal("a multi-line age identity surviving outside a provider field must be rejected")
	}
	if strings.Contains(err.Error(), "DONOTECHO") {
		t.Fatalf("credential leaked in error: %v", err)
	}
}

func TestExtractProviderCredentialsRejectsAgeSecretEmbeddedInLargerScalar(t *testing.T) {
	// The extracted secret must be caught even when it is a SUBSTRING of another
	// scalar (not the whole value): the residual field still carries the private
	// identity into the active revision/backup. Both single-line and multi-line
	// containment must be rejected, and the error must not echo the secret.
	for name, input := range map[string]string{
		"single-line embedded": `
notes: "backup key is AGE-SECRET-KEY-1EMBEDDEDDONOTECHO here"
proxy-providers:
  remote:
    type: http
    url: https://example.com/proxies.yaml
    age-secret-key: AGE-SECRET-KEY-1EMBEDDEDDONOTECHO
`,
		"multi-line embedded": `
notes: |-
  first line
  key AGE-SECRET-KEY-1EMBEDDEDDONOTECHO trailing
proxy-providers:
  remote:
    type: http
    url: https://example.com/proxies.yaml
    age-secret-key: AGE-SECRET-KEY-1EMBEDDEDDONOTECHO
`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ExtractProviderCredentialsForIOS(input)
			if err == nil {
				t.Fatal("an age-secret embedded in another scalar must be rejected")
			}
			if strings.Contains(err.Error(), "DONOTECHO") {
				t.Fatalf("credential leaked in error: %v", err)
			}
		})
	}
}

func TestExtractProviderCredentialsRejectsSecretInMixedKeyMapping(t *testing.T) {
	// A mapping with a non-string key decodes to map[interface{}]interface{}, which
	// a string-only walker would skip entirely. The residual scan must still find a
	// secret hiding (and here embedded) inside such a mapping.
	_, err := ExtractProviderCredentialsForIOS(`
notes:
  1: keep AGE-SECRET-KEY-1MIXEDKEYDONOTECHO backup
proxy-providers:
  remote:
    type: http
    url: https://example.com/proxies.yaml
    age-secret-key: AGE-SECRET-KEY-1MIXEDKEYDONOTECHO
`)
	if err == nil {
		t.Fatal("a secret inside a non-string-keyed mapping must be rejected")
	}
	if strings.Contains(err.Error(), "DONOTECHO") {
		t.Fatalf("credential leaked in error: %v", err)
	}
}

func TestExtractProviderCredentialsHandlesMixedKeyProviderDefinition(t *testing.T) {
	// A provider definition with a non-string field key decodes as
	// map[interface{}]interface{}; extraction must still pull the age-secret-key
	// out rather than skip the definition and leave the secret in redactedYAML.
	box, err := ExtractProviderCredentialsForIOS(`
proxy-providers:
  remote:
    type: http
    url: https://example.com/p.yaml
    age-secret-key: AGE-SECRET-KEY-1MIXEDDEFDONOTECHO
    1: extra
`)
	if err != nil {
		t.Fatalf("mixed-key provider definition must extract cleanly: %v", err)
	}
	var bundle extractedProviderCredentialBundle
	if err := json.Unmarshal([]byte(box.Value), &bundle); err != nil {
		t.Fatal(err)
	}
	if len(bundle.Credentials) != 1 {
		t.Fatalf("expected the secret to be extracted, got %+v", bundle.Credentials)
	}
	if strings.Contains(bundle.RedactedYAML, "DONOTECHO") {
		t.Fatalf("secret leaked into redacted YAML: %s", bundle.RedactedYAML)
	}
}

func TestExtractProviderCredentialsAllowsReuseAcrossMixedKeyProvider(t *testing.T) {
	// The same age identity on an http provider (extracted) and a mixed-key file
	// provider (kept) must not be a false leak: the residual strip tolerates the
	// mixed-key definition before the walk.
	if _, err := ExtractProviderCredentialsForIOS(`
proxy-providers:
  remote:
    type: http
    url: https://example.com/p.yaml
    age-secret-key: AGE-SECRET-KEY-1REUSEDONOTECHO
  local:
    type: file
    path: ./local.yaml
    age-secret-key: AGE-SECRET-KEY-1REUSEDONOTECHO
    1: extra
`); err != nil {
		t.Fatalf("shared identity across a mixed-key provider must be allowed: %v", err)
	}
}

func TestExtractProviderCredentialsRejectsMixedKeyProviderNamespace(t *testing.T) {
	// If proxy-providers ITSELF has a non-string provider name, the whole namespace
	// decodes as map[interface{}]interface{}; a string-only assertion would skip
	// extraction and leave the secret in redactedYAML. Fail closed (upstream's typed
	// RawConfig rejects a non-string provider name anyway).
	_, err := ExtractProviderCredentialsForIOS(`
proxy-providers:
  remote:
    type: http
    url: https://example.com/p.yaml
    age-secret-key: AGE-SECRET-KEY-1NAMESPACEDONOTECHO
  1:
    type: http
    url: https://example.com/q.yaml
`)
	if err == nil {
		t.Fatal("a non-string-keyed proxy-providers namespace must be rejected (fail closed)")
	}
	if strings.Contains(err.Error(), "DONOTECHO") {
		t.Fatalf("credential leaked in error: %v", err)
	}
}

func TestExtractProviderCredentialsDropsSecretInTrailingDocument(t *testing.T) {
	// First-document-wins: a secret in a trailing YAML document is runtime-inert
	// (only document one is used), but must not survive verbatim in redactedYAML,
	// which is stored/backed up. Re-encoding document one drops it -- for both a
	// valid and a malformed secret-bearing trailing document.
	for name, input := range map[string]string{
		"valid trailing":     "mode: rule\n---\nproxy-providers:\n  p:\n    type: http\n    url: https://example.com/p.yaml\n    age-secret-key: AGE-SECRET-KEY-1TRAILINGDONOTECHO\n",
		"malformed trailing": "mode: rule\n---\nproxy-providers:\n  p:\n    age-secret-key: AGE-SECRET-KEY-1TRAILINGDONOTECHO\n    [unterminated\n",
	} {
		t.Run(name, func(t *testing.T) {
			box, err := ExtractProviderCredentialsForIOS(input)
			if err != nil {
				t.Fatalf("first-document-wins config must extract cleanly: %v", err)
			}
			var bundle extractedProviderCredentialBundle
			if err := json.Unmarshal([]byte(box.Value), &bundle); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(bundle.RedactedYAML, "DONOTECHO") {
				t.Fatalf("trailing-document secret survived in redacted YAML: %s", bundle.RedactedYAML)
			}
		})
	}
}

func TestExtractProviderCredentialsForIOSDoesNotRewriteUnrelatedConfig(t *testing.T) {
	input := `proxy-providers:
  inline:
    type: inline
    payload: []
mode: rule
`
	box, err := ExtractProviderCredentialsForIOS(input)
	if err != nil {
		t.Fatalf("extract provider credentials: %v", err)
	}
	var bundle extractedProviderCredentialBundle
	if err := json.Unmarshal([]byte(box.Value), &bundle); err != nil {
		t.Fatalf("decode credential bundle: %v", err)
	}
	if len(bundle.Credentials) != 0 || bundle.RedactedYAML != input {
		t.Fatalf("unrelated config changed: %+v", bundle)
	}
}
