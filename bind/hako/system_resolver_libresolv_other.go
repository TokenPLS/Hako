//go:build !(darwin && cgo)

package hako

func libresolvResolvers() ([]string, error) { return nil, errRouteLookupUnsupported }
