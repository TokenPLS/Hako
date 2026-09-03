package hako

import (
	"encoding/json"

	"gopkg.in/yaml.v3"
)

type overrideSpec struct {
	Patch        map[string]any `json:"patch"`
	AppendRules  []string       `json:"appendRules"`
	PrependRules bool           `json:"prependRules"`
}

// MergeOverrideForIOS deep-merges a user override onto a raw mihomo config.
// An empty overrideJSON returns rawYAML unchanged. Input and resulting YAML
// follow the Apple store's 4 MiB configuration boundary.
func MergeOverrideForIOS(rawYAML string, overrideJSON string) (*StringBox, error) {
	if err := validateConfigurationInput(rawYAML); err != nil {
		return nil, bridgeSafeError(err)
	}
	if err := validateConfigurationJSONInput(overrideJSON); err != nil {
		return nil, bridgeSafeError(err)
	}
	if overrideJSON == "" {
		return WrapString(rawYAML), nil
	}
	var spec overrideSpec
	if err := json.Unmarshal([]byte(overrideJSON), &spec); err != nil {
		return nil, bridgeSafeError(err)
	}
	var root map[string]any
	if err := yaml.Unmarshal([]byte(rawYAML), &root); err != nil {
		return nil, bridgeSafeError(err)
	}
	if root == nil {
		root = map[string]any{}
	}
	if spec.Patch != nil {
		deepMerge(root, spec.Patch)
	}
	if len(spec.AppendRules) > 0 {
		root["rules"] = mergeRules(root["rules"], spec.AppendRules, spec.PrependRules)
	}
	out, err := yaml.Marshal(root)
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	// The merge went through a Go map, so every mapping came back alphabetised. One of them
	// decides DNS routing -- see restoreSourceKeyOrder.
	// Two references: the reader's file first, then their override. A policy the override
	// introduced and the file never had takes its order from the override text, which is
	// ordered JSON -- without the second reference it would count as "added by the transform"
	// and come out alphabetised.
	//
	// The reference is the patch, not the envelope. overrideJSON is {"patch":{...}}, and a
	// document rooted at "patch" lines up with nothing in a document rooted at "dns", so the
	// first version of this handed the pass a reference that matched no key and the test
	// for exactly this case stayed red. The patch is re-extracted from the text rather than
	// re-marshalled from spec.Patch, because spec.Patch is a Go map and marshalling it would
	// alphabetise the very order this reference exists to supply.
	merged := restoreKeyOrderFrom(string(out), rawYAML, patchDocument(overrideJSON))
	if err := validateConfigurationResult(merged); err != nil {
		return nil, bridgeSafeError(err)
	}
	return WrapString(merged), nil
}

func deepMerge(dst map[string]any, src map[string]any) {
	for k, sv := range src {
		if sm, ok := sv.(map[string]any); ok {
			if dm, ok := dst[k].(map[string]any); ok {
				deepMerge(dm, sm)
				continue
			}
		}
		dst[k] = sv
	}
}

func mergeRules(existing any, add []string, prepend bool) []any {
	var base []any
	if list, ok := existing.([]any); ok {
		base = list
	}
	extra := make([]any, len(add))
	for i, r := range add {
		extra[i] = r
	}
	if prepend {
		return append(extra, base...)
	}
	return append(base, extra...)
}

// patchDocument returns the text of the "patch" member of an override envelope, in its
// original key order, or "" when there is none. It walks the JSON as a yaml.Node so the
// object order survives; decoding into a Go map and re-encoding would sort it.
func patchDocument(overrideJSON string) string {
	var envelope yaml.Node
	if err := yaml.Unmarshal([]byte(overrideJSON), &envelope); err != nil {
		return ""
	}
	if len(envelope.Content) == 0 || envelope.Content[0].Kind != yaml.MappingNode {
		return ""
	}
	root := envelope.Content[0]
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Kind == yaml.ScalarNode && root.Content[i].Value == "patch" {
			out, err := yaml.Marshal(root.Content[i+1])
			if err != nil {
				return ""
			}
			return string(out)
		}
	}
	return ""
}
