package hako

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// YamlToJSON converts a complete YAML configuration object to JSON for an
// App-owned override script. YAML aliases and merge keys are resolved during
// conversion. Mapping key order is preserved end to end: several kernel
// sections are first-match and order-sensitive — most importantly
// dns.nameserver-policy and dns.proxy-server-nameserver-policy, which the
// kernel builds into an ordered map and evaluates in order (returning the
// first matching policy and grouping consecutive plain-domain entries into one
// trie), so reordering keys silently changes split-DNS routing. Comments,
// anchors, aliases and scalar style are not representable in JSON and are
// therefore not preserved by a round trip. The YAML input is capped at 4 MiB
// and the escaped JSON result at 16 MiB.
func YamlToJSON(rawYAML string) (*StringBox, error) {
	if err := validateConfigurationInput(rawYAML); err != nil {
		return nil, bridgeSafeError(err)
	}
	decoder := yaml.NewDecoder(strings.NewReader(rawYAML))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return nil, bridgeSafeError(fmt.Errorf("hako: decode YAML: %w", err))
	}
	// First-document-wins, matching upstream yaml.v3 Unmarshal -- and therefore
	// FormatConfig / CheckConfig / Start / PlatformConfigIntentJSON, which all
	// decode through it. Any trailing YAML documents are ignored, not rejected;
	// rejecting them would refuse a config the kernel itself accepts.
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nil, bridgeSafeError(fmt.Errorf("hako: YAML configuration root must be an object"))
	}

	// Pre-flight through yaml.v3's own decoder purely to reject inputs the
	// order-preserving walk below would mishandle: self-referential anchors
	// (which the manual alias-follow would recurse on forever), pathological
	// alias amplification (the "billion laughs" bomb), and duplicate keys.
	// Decode enforces yaml.v3's alias-ratio and duplicate-key limits and then
	// its result is discarded; the walk produces the ordered output. This is the
	// same decode the previous implementation performed, so it adds no new cost.
	var safety any
	if err := document.Content[0].Decode(&safety); err != nil {
		return nil, bridgeSafeError(fmt.Errorf("hako: reject unsafe YAML configuration: %w", err))
	}

	var payload bytes.Buffer
	if err := encodeYAMLNodeAsJSON(document.Content[0], &payload); err != nil {
		return nil, bridgeSafeError(err)
	}
	if err := validateConfigurationJSONResult(payload.String()); err != nil {
		return nil, bridgeSafeError(err)
	}
	return WrapString(payload.String()), nil
}

// encodeYAMLNodeAsJSON writes node to buf as JSON, preserving mapping key order
// and resolving aliases and merge keys. Scalars are decoded through yaml before
// marshaling so their type — and large-integer precision — matches a direct
// decode of the whole document.
func encodeYAMLNodeAsJSON(node *yaml.Node, buf *bytes.Buffer) error {
	switch node.Kind {
	case yaml.AliasNode:
		return encodeYAMLNodeAsJSON(node.Alias, buf)
	case yaml.MappingNode:
		pairs, err := resolvedMappingPairs(node)
		if err != nil {
			return err
		}
		buf.WriteByte('{')
		for index, pair := range pairs {
			if index > 0 {
				buf.WriteByte(',')
			}
			key, err := json.Marshal(pair.key)
			if err != nil {
				return err
			}
			buf.Write(key)
			buf.WriteByte(':')
			if err := encodeYAMLNodeAsJSON(pair.value, buf); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
		return nil
	case yaml.SequenceNode:
		buf.WriteByte('[')
		for index, item := range node.Content {
			if index > 0 {
				buf.WriteByte(',')
			}
			if err := encodeYAMLNodeAsJSON(item, buf); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
		return nil
	default:
		var value any
		if err := node.Decode(&value); err != nil {
			return fmt.Errorf("hako: decode YAML scalar: %w", err)
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			return fmt.Errorf("hako: encode YAML scalar as JSON: %w", err)
		}
		buf.Write(encoded)
		return nil
	}
}

type yamlMappingPair struct {
	key   string
	value *yaml.Node
}

// resolvedMappingPairs returns node's key/value pairs in source order with YAML
// merge keys (<<) expanded in place. Explicitly-defined keys win over merged
// ones, and earlier merge sources win over later; the first occurrence of a key
// keeps its position. This matches yaml.v3's decode-into-map merge semantics
// while preserving order, which decoding into a Go map would discard.
func resolvedMappingPairs(node *yaml.Node) ([]yamlMappingPair, error) {
	explicit := make(map[string]bool)
	for index := 0; index+1 < len(node.Content); index += 2 {
		key := node.Content[index]
		if isMergeKey(key) {
			continue
		}
		keyString, err := mappingKeyString(key)
		if err != nil {
			return nil, err
		}
		// yaml.v3's duplicate-key check compares raw key nodes, so an alias key
		// and a scalar key that resolve to the same string slip past the
		// pre-flight decode. Reject the resolved-key collision here rather than
		// silently keeping the first occurrence, which would diverge from the
		// map yaml.v3 produces.
		if explicit[keyString] {
			return nil, fmt.Errorf("hako: duplicate YAML mapping key %q", keyString)
		}
		explicit[keyString] = true
	}
	seen := make(map[string]bool)
	pairs := make([]yamlMappingPair, 0, len(node.Content)/2)
	appendPair := func(key string, value *yaml.Node) {
		if seen[key] {
			return
		}
		seen[key] = true
		pairs = append(pairs, yamlMappingPair{key: key, value: value})
	}
	for index := 0; index+1 < len(node.Content); index += 2 {
		key := node.Content[index]
		value := node.Content[index+1]
		if isMergeKey(key) {
			sources, err := mergeSources(value)
			if err != nil {
				return nil, err
			}
			for _, source := range sources {
				merged, err := resolvedMappingPairs(source)
				if err != nil {
					return nil, err
				}
				for _, pair := range merged {
					if explicit[pair.key] {
						continue
					}
					appendPair(pair.key, pair.value)
				}
			}
			continue
		}
		keyString, err := mappingKeyString(key)
		if err != nil {
			return nil, err
		}
		appendPair(keyString, value)
	}
	return pairs, nil
}

// mappingKeyString resolves a mapping key node to its JSON object key. An alias
// key is followed to its anchor; only a scalar key is representable as a JSON
// object key, so anything else is rejected rather than emitted as an empty or
// anchor-named key.
func mappingKeyString(key *yaml.Node) (string, error) {
	node := key
	if node.Kind == yaml.AliasNode {
		if node.Alias == nil {
			return "", fmt.Errorf("hako: YAML alias key has no anchor")
		}
		node = node.Alias
	}
	if node.Kind != yaml.ScalarNode {
		return "", fmt.Errorf("hako: YAML mapping key must be a scalar")
	}
	return node.Value, nil
}

// isMergeKey reports whether key is a YAML merge key (<<). It matches the
// resolved !!merge tag, not the literal value, so a quoted "<<" string key is
// treated as an ordinary key exactly as yaml.v3 does.
func isMergeKey(key *yaml.Node) bool {
	return key.Kind == yaml.ScalarNode && key.Tag == "!!merge"
}

// mergeSources resolves a << merge value into the mapping nodes it references.
// Matching yaml.v3, a merge value is a mapping, an alias to a mapping, or a flat
// sequence of those; an alias to a non-mapping, or a nested sequence, is
// rejected rather than silently flattened.
func mergeSources(value *yaml.Node) ([]*yaml.Node, error) {
	switch value.Kind {
	case yaml.AliasNode:
		if value.Alias == nil || value.Alias.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("hako: YAML merge key must reference a mapping")
		}
		return []*yaml.Node{value.Alias}, nil
	case yaml.MappingNode:
		return []*yaml.Node{value}, nil
	case yaml.SequenceNode:
		sources := make([]*yaml.Node, 0, len(value.Content))
		for _, item := range value.Content {
			resolved := item
			if resolved.Kind == yaml.AliasNode {
				resolved = resolved.Alias
			}
			if resolved == nil || resolved.Kind != yaml.MappingNode {
				return nil, fmt.Errorf("hako: YAML merge key must reference a mapping")
			}
			sources = append(sources, resolved)
		}
		return sources, nil
	default:
		return nil, fmt.Errorf("hako: YAML merge key must reference a mapping")
	}
}

// JSONToYaml converts an App-owned override script result back to a complete
// YAML configuration object. Object key order is preserved (see YamlToJSON for
// why the DNS policy sections require it). The caller must run the result
// through the normal plan/finalize/preflight pipeline before publishing or
// starting the core. The intermediate JSON is capped at 16 MiB and the YAML
// result at 4 MiB.
func JSONToYaml(rawJSON string) (*StringBox, error) {
	if err := validateConfigurationJSONInput(rawJSON); err != nil {
		return nil, bridgeSafeError(err)
	}
	decoder := json.NewDecoder(strings.NewReader(rawJSON))
	decoder.UseNumber()
	rootNode, err := decodeJSONValueAsYAMLNode(decoder, 0)
	if err != nil {
		return nil, bridgeSafeError(fmt.Errorf("hako: decode JSON: %w", err))
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return nil, bridgeSafeError(fmt.Errorf("hako: decode trailing JSON: %w", err))
		}
		return nil, bridgeSafeError(fmt.Errorf("hako: JSON configuration must contain exactly one value"))
	}
	if rootNode.Kind != yaml.MappingNode {
		return nil, bridgeSafeError(fmt.Errorf("hako: JSON configuration root must be an object"))
	}

	document := yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{rootNode}}
	var output bytes.Buffer
	encoder := yaml.NewEncoder(&output)
	encoder.SetIndent(2)
	if err := encoder.Encode(&document); err != nil {
		return nil, bridgeSafeError(fmt.Errorf("hako: encode JSON configuration as YAML: %w", err))
	}
	if err := encoder.Close(); err != nil {
		return nil, bridgeSafeError(fmt.Errorf("hako: finish YAML encoding: %w", err))
	}
	if err := validateConfigurationResult(output.String()); err != nil {
		return nil, bridgeSafeError(err)
	}
	return WrapString(output.String()), nil
}

// maximumJSONNestingDepth bounds the recursion below. The two functions recurse
// once per nesting level, so without a bound the only limit was the 16 MiB
// input size -- roughly sixteen million levels of `[`, and a Go stack overflow
// is a fatal throw that no recover can catch: the process dies, and inside a
// Network Extension that is the tunnel dropping with nothing to report.
//
// The YAML direction never had this problem (yaml.v3's scanner stops at 10000
// levels, scannerc.go), so this is that same bound restated for the JSON side.
// A mihomo profile nests a handful of levels; 10000 is far enough above
// anything real that refusing at it can only mean a document built to break
// something.
const maximumJSONNestingDepth = 10000

// decodeJSONValueAsYAMLNode reads exactly one JSON value from decoder and builds
// the equivalent yaml.Node. A json.Decoder yields object keys in document
// order, so object key order is preserved rather than sorted.
func decodeJSONValueAsYAMLNode(decoder *json.Decoder, depth int) (*yaml.Node, error) {
	if depth > maximumJSONNestingDepth {
		return nil, fmt.Errorf("hako: JSON is nested deeper than %d levels", maximumJSONNestingDepth)
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	return jsonTokenAsYAMLNode(token, decoder, depth)
}

func jsonTokenAsYAMLNode(token json.Token, decoder *json.Decoder, depth int) (*yaml.Node, error) {
	switch typed := token.(type) {
	case json.Delim:
		switch typed {
		case '{':
			node := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			// json.Decoder keeps every duplicate member; a plain decode into a
			// map would silently take the last. Reject duplicates outright so the
			// emitted YAML can never carry a duplicate key that downstream
			// yaml.v3 decoding would in turn reject.
			seen := make(map[string]bool)
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, fmt.Errorf("hako: JSON object key must be a string")
				}
				if seen[key] {
					return nil, fmt.Errorf("hako: duplicate JSON object key %q", key)
				}
				seen[key] = true
				value, err := decodeJSONValueAsYAMLNode(decoder, depth+1)
				if err != nil {
					return nil, err
				}
				node.Content = append(node.Content,
					&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
					value,
				)
			}
			if _, err := decoder.Token(); err != nil { // consume '}'
				return nil, err
			}
			return node, nil
		case '[':
			node := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
			for decoder.More() {
				item, err := decodeJSONValueAsYAMLNode(decoder, depth+1)
				if err != nil {
					return nil, err
				}
				node.Content = append(node.Content, item)
			}
			if _, err := decoder.Token(); err != nil { // consume ']'
				return nil, err
			}
			return node, nil
		default:
			return nil, fmt.Errorf("hako: unexpected JSON delimiter %q", typed)
		}
	case string:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: typed}, nil
	case json.Number:
		tag := "!!int"
		if strings.ContainsAny(typed.String(), ".eE") {
			tag = "!!float"
		}
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: typed.String()}, nil
	case bool:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: strconv.FormatBool(typed)}, nil
	case nil:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null", Value: "null"}, nil
	default:
		return nil, fmt.Errorf("hako: unsupported JSON value type %T", token)
	}
}
