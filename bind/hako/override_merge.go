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
		return nil, err
	}
	if err := validateConfigurationJSONInput(overrideJSON); err != nil {
		return nil, err
	}
	if overrideJSON == "" {
		return WrapString(rawYAML), nil
	}
	var spec overrideSpec
	if err := json.Unmarshal([]byte(overrideJSON), &spec); err != nil {
		return nil, err
	}
	var root map[string]any
	if err := yaml.Unmarshal([]byte(rawYAML), &root); err != nil {
		return nil, err
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
		return nil, err
	}
	if err := validateConfigurationResult(string(out)); err != nil {
		return nil, err
	}
	return WrapString(string(out)), nil
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
