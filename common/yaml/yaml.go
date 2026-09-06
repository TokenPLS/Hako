// Package yaml provides a common entrance for YAML marshaling and unmarshalling.
package yaml

import (
	"gopkg.in/yaml.v3"
)

// Node is yaml.v3's document node, re-exported so a type in this repository
// can implement a custom unmarshaler without importing the library past this
// entrance.
type Node = yaml.Node

func Unmarshal(in []byte, out any) (err error) {
	return yaml.Unmarshal(in, out)
}

func Marshal(in any) (out []byte, err error) {
	return yaml.Marshal(in)
}
