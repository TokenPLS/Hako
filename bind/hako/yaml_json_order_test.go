package hako

import (
	"strings"
	"testing"
)

// The YAML/JSON bridge keeps every mapping in the reader's order, both ways.
//
// This is the premise under the last client hop on every activation. ConfigTransforms'
// applyClientRuntimePolicy routes the whole configuration through YamlToJSON and back, and its
// own comment says it relies on "the Core YAML/JSON bridge preserves order end to end". If the
// bridge ever sorted -- a JSON encoder over a Go map would -- the nameserver-policy order the
// two transforms upstream of it now protect would be lost at the very end, and nothing after
// could put it back. Measured today as a throwaway probe; pinned here so it stays measured.
func TestTheBridgeKeepsMappingOrderBothWays(t *testing.T) {
	yaml := "dns:\n  nameserver-policy:\n    \"+.google.com\": 8.8.8.8\n    \"+.com\": 223.5.5.5\n"

	json, err := YamlToJSON(yaml)
	if err != nil {
		t.Fatalf("YamlToJSON: %v", err)
	}
	if strings.Index(json.Value, "+.com") < strings.Index(json.Value, "+.google.com") {
		t.Fatalf("YAML -> JSON alphabetised the policy: %s", json.Value)
	}

	back, err := JSONToYaml(json.Value)
	if err != nil {
		t.Fatalf("JSONToYaml: %v", err)
	}
	if strings.Index(back.Value, "+.com") < strings.Index(back.Value, "+.google.com") {
		t.Fatalf("JSON -> YAML alphabetised the policy:\n%s", back.Value)
	}
}
