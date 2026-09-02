package hako

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/TokenPLS/Hako/component/geodata"
	"github.com/TokenPLS/Hako/config"
)

// UpstreamScalarDefaultsJSON answers what this core does for a key when neither the profile
// nor an override says anything -- mihomo's own DefaultRawConfig(), read by reflection over
// the yaml tags.
//
// It is an export rather than a file the clients carry because all three platforms need the
// same answer and none of the offline routes worked: the deviation decoder is not compiled
// into the tvOS target, the generated JSON lives in the private adaptation docs (never shipped,
// and never open-sourced), and the Clash API is not there when the tunnel is down -- which is
// exactly when a settings page is open. The tvOS lane found the alternative already growing
// in the tree: HakoTVConfigFacts hard-codes `?? "rule"` for mode. That one is right today,
// and it is the shape that was wrong for sniffer.parse-pure-ip an hour earlier.
//
// Scalars and string lists, three levels deep; enums by name, not by integer. An empty list
// is [], because "the default is nothing" is an answer and an absent key is not.
//
// The committed is generated from this same
// function and reconciled against it by TestUpstreamScalarDefaults, so the file a gate reads
// and the bytes a client receives cannot disagree.
func UpstreamScalarDefaultsJSON() (*StringBox, error) {
	rendered, err := renderUpstreamDefaults()
	if err != nil {
		return nil, bridgeSafeError(fmt.Errorf("hako: render upstream defaults: %w", err))
	}
	return WrapString(rendered), nil
}

func collectScalarDefaults(value reflect.Value, prefix string, depth int, into map[string]any) {
	if depth > 3 {
		return
	}
	valueType := value.Type()
	for i := 0; i < valueType.NumField(); i++ {
		field := valueType.Field(i)
		if !field.IsExported() {
			continue
		}
		tag := strings.Split(field.Tag.Get("yaml"), ",")[0]
		if tag == "" || tag == "-" {
			continue
		}
		key := tag
		if prefix != "" {
			key = prefix + "." + tag
		}
		item := value.Field(i)
		// An enum rendered as its integer is a value no client can use: mode 1 means nothing
		// on a settings row, "rule" does. Every enum upstream uses here implements Stringer.
		if item.Kind() != reflect.Struct && item.CanInterface() {
			if stringer, ok := item.Interface().(fmt.Stringer); ok {
				into[key] = stringer.String()
				continue
			}
		}
		switch item.Kind() {
		case reflect.Bool:
			into[key] = item.Bool()
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			into[key] = item.Int()
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			into[key] = item.Uint()
		case reflect.String:
			into[key] = item.String()
		case reflect.Slice:
			// Lists of strings, or of anything that prints itself (netip.Prefix), render as
			// a JSON array of strings. The macOS lane's list rows need the same "what does
			// the core do when nobody speaks" answer the boolean rows do -- tun.inet6-address
			// defaults to one prefix, the other route lists to nothing -- and the alternative
			// was a second hand-copied table, which is the shape that just failed for
			// sniffer.parse-pure-ip. An empty default is recorded as an empty array, because
			// "the default is nothing" is an answer and absence from this file is not.
			elements := []string{}
			renderable := true
			for j := 0; j < item.Len(); j++ {
				element := item.Index(j)
				switch {
				case element.Kind() == reflect.String:
					elements = append(elements, element.String())
				case element.CanInterface():
					if stringer, ok := element.Interface().(fmt.Stringer); ok {
						elements = append(elements, stringer.String())
					} else {
						renderable = false
					}
				default:
					renderable = false
				}
				if !renderable {
					break
				}
			}
			if renderable && (item.Type().Elem().Kind() == reflect.String ||
				item.Type().Elem().Implements(reflect.TypeOf((*fmt.Stringer)(nil)).Elem())) {
				into[key] = elements
			}
		case reflect.Struct:
			collectScalarDefaults(item, key, depth+1, into)
		}
	}
}

func renderUpstreamDefaults() (string, error) {
	// DefaultRawConfig reads one package-level knob: geodata-mode comes from
	// geodata.GeodataMode(), which geodata_maximal_stack_test sets true and does not restore.
	// Alone this test saw false; after that one it saw true and reported the golden stale --
	// an order-dependent answer dressed as an upstream change. Pin the knob to a fresh
	// process's value for the read and put it back.
	previousGeodataMode := geodata.GeodataMode()
	geodata.SetGeodataMode(false)
	defer geodata.SetGeodataMode(previousGeodataMode)

	defaults := map[string]any{}
	raw := config.DefaultRawConfig()
	collectScalarDefaults(reflect.ValueOf(raw).Elem(), "", 1, defaults)

	keys := make([]string, 0, len(defaults))
	for key := range defaults {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	ordered := make([]map[string]any, 0, len(keys))
	for _, key := range keys {
		ordered = append(ordered, map[string]any{"key": key, "default": defaults[key]})
	}

	encoded, err := json.MarshalIndent(map[string]any{
		"schemaVersion": 1,
		"note": "mihomo's own DefaultRawConfig(), read by reflection over the yaml tags. What " +
			"the core does when neither the profile nor an override says anything. Scalars and " +
			"string lists, three levels deep; an empty list is recorded as []. Regenerate with HAKO_UPDATE_GOLDEN=1 go test ./bind/hako " +
			"-run TestUpstreamScalarDefaults",
		"defaults": ordered,
	}, "", "  ")
	if err != nil {
		return "", err
	}
	return string(encoded) + "\n", nil
}
