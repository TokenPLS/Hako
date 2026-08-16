package hako

import (
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const providerCredentialBundleSchemaVersion = 1

type providerCredential struct {
	ResourceKey string `json:"resourceKey"`
	Kind        string `json:"kind"`
	Value       string `json:"value"`
}

type providerCredentialBundle struct {
	SchemaVersion int                  `json:"schemaVersion"`
	RedactedYAML  string               `json:"redactedYAML"`
	Credentials   []providerCredential `json:"credentials"`
}

// ExtractProviderCredentialsForIOS separates HTTP proxy-provider secrets from
// the configuration before the ordinary resource plan is produced. The
// containing App must never log the returned JSON: it stores each credential
// in a profile-scoped Keychain slot derived from resourceKey and uses
// RedactedYAML for every subsequent pipeline stage. This keeps the normal
// resource plan and immutable active revision free of age-secret-key values.
func ExtractProviderCredentialsForIOS(configContent string) (*StringBox, error) {
	if err := validateConfigurationInput(configContent); err != nil {
		return nil, err
	}
	decoder := yaml.NewDecoder(strings.NewReader(configContent))
	var root map[string]any
	if err := decoder.Decode(&root); err != nil {
		return nil, fmt.Errorf("hako: parse provider credentials: %w", err)
	}
	// First-document-wins, like the runtime (YamlToJSON): a secret in a trailing
	// document is runtime-inert but must not survive verbatim in redactedYAML, so
	// note trailing content and re-encode document one only when it is present.
	var trailing yaml.Node
	hasTrailingDocuments := decoder.Decode(&trailing) != io.EOF

	credentials := make([]providerCredential, 0)
	redacted := false
	providers, ok := root["proxy-providers"].(map[string]any)
	if !ok {
		// A proxy-providers namespace with a non-string provider name decodes as
		// map[interface{}]interface{}; the assertion fails and would silently skip
		// extraction, leaking an age-secret-key into the redacted config. Upstream's
		// typed RawConfig.ProxyProvider (map[string]map[string]any) rejects such a
		// name at UnmarshalRawConfig anyway, so fail closed here.
		if raw, present := root["proxy-providers"]; present && isDecodedMap(raw) {
			return nil, fmt.Errorf("hako: proxy-providers must use string provider names")
		}
	}
	names := make([]string, 0, len(providers))
	for name := range providers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		// A provider definition with a non-string field key decodes as
		// map[interface{}]interface{}, not map[string]any; use the reflect-based
		// helpers so such a definition cannot smuggle an un-redacted age-secret-key
		// past extraction.
		definition := providers[name]
		if !isDecodedMap(definition) {
			continue
		}
		typeValue, _ := mapValueByStringKey(definition, "type")
		if typeName, _ := typeValue.(string); typeName != "http" {
			continue
		}
		rawSecret, exists := mapValueByStringKey(definition, "age-secret-key")
		if !exists {
			continue
		}
		redacted = true
		deleteMapStringKey(definition, "age-secret-key")
		if rawSecret == nil {
			continue
		}
		secret, ok := rawSecret.(string)
		if !ok {
			return nil, fmt.Errorf("hako: an HTTP proxy-provider age-secret-key must be a string")
		}
		if secret == "" {
			continue
		}
		credentials = append(credentials, providerCredential{
			ResourceKey: providerResourceKey("proxy", name),
			Kind:        "age-secret-key",
			Value:       secret,
		})
	}

	redactedYAML := configContent
	if redacted || hasTrailingDocuments {
		// Re-encode document one only: this drops any trailing document (dropping a
		// secret hidden there) and removes the extracted keys. The leak check then
		// confirms no extracted value survives outside a provider field.
		encoded, err := yaml.Marshal(root)
		if err != nil {
			return nil, fmt.Errorf("hako: redact provider credentials: %w", err)
		}
		redactedYAML = string(encoded)
		if err := rejectAgeSecretLeakOutsideProviderFields(redactedYAML, credentials); err != nil {
			return nil, err
		}
	}
	bundle, err := json.Marshal(providerCredentialBundle{
		SchemaVersion: providerCredentialBundleSchemaVersion,
		RedactedYAML:  redactedYAML,
		Credentials:   credentials,
	})
	if err != nil {
		return nil, fmt.Errorf("hako: encode provider credentials: %w", err)
	}
	if err := validateConfigurationJSONResult(string(bundle)); err != nil {
		return nil, err
	}
	return WrapString(string(bundle)), nil
}

// rejectAgeSecretLeakOutsideProviderFields fails if an extracted age-secret-key
// value survives redaction anywhere OTHER than a proxy-provider's own
// age-secret-key field. It re-parses the redacted config, strips every
// proxy-provider age-secret-key (all types) so a value that legitimately lives on
// another provider -- upstream's one-key-decrypts-many pattern -- is not flagged,
// then checks whether any DECODED string value or key CONTAINS an extracted
// secret. It deliberately does not search re-serialised YAML: age allows a
// multi-line identity block, and yaml.Marshal indents block-scalar continuation
// lines, so a serialized-substring match would miss a multi-line secret anchored
// outside a provider field. Containment (not equality) also catches a secret
// embedded in a larger scalar. The error never echoes the secret value.
func rejectAgeSecretLeakOutsideProviderFields(redactedYAML string, credentials []providerCredential) error {
	var root map[string]any
	if err := yaml.Unmarshal([]byte(redactedYAML), &root); err != nil {
		return fmt.Errorf("hako: verify redacted provider credentials: %w", err)
	}
	if providers, ok := root["proxy-providers"].(map[string]any); ok {
		for _, raw := range providers {
			// deleteMapStringKey tolerates a mixed-key (map[interface{}]interface{})
			// provider definition, so a legitimate age identity reused on such a
			// provider is stripped here and not falsely reported as a leak.
			deleteMapStringKey(raw, "age-secret-key")
		}
	}
	secrets := make([]string, 0, len(credentials))
	for _, credential := range credentials {
		if credential.Value != "" {
			secrets = append(secrets, credential.Value)
		}
	}
	leaked := false
	walkYAMLStrings(root, func(value string) {
		for _, secret := range secrets {
			// Containment, not equality: a secret embedded in a larger scalar
			// (e.g. notes: "backup=AGE-SECRET-KEY-...") is still a leak into the
			// active revision/backup. Provider age-secret-key fields were removed
			// above, so a legitimate cross-provider reuse never reaches here.
			if strings.Contains(value, secret) {
				leaked = true
			}
		}
	})
	if leaked {
		return fmt.Errorf("hako: an age-secret-key value survives outside a proxy-provider age-secret-key field; inline it in the provider before import")
	}
	return nil
}

// walkYAMLStrings visits every decoded scalar string -- both map keys and values,
// at any depth -- reached from node. It reflects over the value so it traverses
// every map shape yaml.v3 can produce: a mapping with a non-string key decodes to
// map[interface{}]interface{}, not map[string]any, and a type-switch on the latter
// alone would skip the whole sub-tree (and any secret inside it). Comparing
// decoded strings (rather than re-serialised bytes) also stays insensitive to YAML
// block-scalar indentation and quoting.
func walkYAMLStrings(node any, visit func(string)) {
	value := reflect.ValueOf(node)
	switch value.Kind() {
	case reflect.String:
		visit(value.String())
	case reflect.Map:
		for _, key := range value.MapKeys() {
			walkYAMLStrings(key.Interface(), visit)
			walkYAMLStrings(value.MapIndex(key).Interface(), visit)
		}
	case reflect.Slice, reflect.Array:
		for index := 0; index < value.Len(); index++ {
			walkYAMLStrings(value.Index(index).Interface(), visit)
		}
	case reflect.Interface, reflect.Pointer:
		if !value.IsNil() {
			walkYAMLStrings(value.Elem().Interface(), visit)
		}
	}
}

// isDecodedMap reports whether m is a decoded YAML mapping of any key type
// (map[string]any or, with a non-string key, map[interface{}]interface{}).
func isDecodedMap(m any) bool {
	return reflect.ValueOf(m).Kind() == reflect.Map
}

// mapValueByStringKey reads a string key from a decoded YAML map regardless of
// whether it decoded as map[string]any or map[interface{}]interface{}. The second
// result reports whether the key exists.
func mapValueByStringKey(m any, key string) (any, bool) {
	v := reflect.ValueOf(m)
	if v.Kind() != reflect.Map {
		return nil, false
	}
	entry := v.MapIndex(reflect.ValueOf(key))
	if !entry.IsValid() {
		return nil, false
	}
	return entry.Interface(), true
}

// deleteMapStringKey removes a string key from a decoded YAML map of either
// map[string]any or map[interface{}]interface{} shape.
func deleteMapStringKey(m any, key string) {
	v := reflect.ValueOf(m)
	if v.Kind() == reflect.Map {
		v.SetMapIndex(reflect.ValueOf(key), reflect.Value{})
	}
}
