package hako

import "gopkg.in/yaml.v3"

// Put every mapping's keys back in the order the reader wrote them.
//
// The transforms on the activation path decode a configuration into map[string]any, change a
// few things, and marshal it again. A Go map has no order and yaml.v3 sorts what it is given,
// so the document that reaches the core has every mapping alphabetised -- and one of those
// mappings decides DNS routing.
//
// dns.nameserver-policy is an ordered map upstream (config.Config's RawDNS holds an
// orderedmap.OrderedMap) parsed into a []dns.Policy that the resolver walks in order,
// returning on the first match (dns/resolver.go). A reader who writes
//
//	nameserver-policy:
//	  "+.google.com": 8.8.8.8
//	  "+.com": 223.5.5.5
//
// is saying "Google's names go here, every other .com goes there". Sorted, "+.com" comes
// first, matches google.com too, and every name they routed deliberately goes to the fallback
// instead. No error, no log line, and the file on disk still reads the way they wrote it.
//
// Sequences were never affected -- rules, proxies and proxy-groups are YAML lists and a list
// keeps its order through a Go slice -- which is why this went unnoticed: the order-sensitive
// thing everyone thinks about is the rule list, and the rule list was fine.
//
// The repair is deliberately a pass over the output rather than a rewrite of the transforms
// into yaml.Node. The transforms are a few hundred lines of map access whose logic is not in
// question, and a pass that only reorders cannot change which keys exist or what they hold.
// It also covers whatever transform is added next, which a fix applied inside two functions
// would not.
//
// Keys the transform added are kept, and follow the ones the source had. Anything that cannot
// be parsed on either side returns the transformed document untouched: this exists to preserve
// an ordering, and failing to preserve it is not a reason to lose the document.
func restoreSourceKeyOrder(source, transformed string) string {
	return restoreKeyOrderFrom(transformed, source)
}

// restoreKeyOrderFrom is the general form: several reference documents, consulted in order.
// A key's position comes from the first reference that has it; a key no reference has
// follows, in the order the transform emitted it.
//
// Two references exist because the merge has two authors. The reader's file is one. Their
// override is the other -- and an override can introduce a whole nameserver-policy the file
// never had, written in the UI with "+.google.com" deliberately ahead of "+.com". Against the
// file alone that policy is "added by the transform", and the transform emits it through a Go
// map, which is to say alphabetised: the exact defect this pass exists to remove, reintroduced
// for every reader who wrote their policy in the app instead of in a file. The iOS lane caught
// it by reading the rule for added keys and asking what the merge's emit order actually was.
//
// The override arrives as JSON, which yaml.v3 parses directly with object key order intact, so
// it needs no conversion to serve as a reference. The pass ignores a reference that does not
// parse rather than failing; the file is always consulted first so a malformed override cannot
// displace the reader's own order.
func restoreKeyOrderFrom(transformed string, references ...string) string {
	var transformedRoot yaml.Node
	if err := yaml.Unmarshal([]byte(transformed), &transformedRoot); err != nil {
		return transformed
	}
	if len(transformedRoot.Content) == 0 {
		return transformed
	}

	roots := make([]*yaml.Node, 0, len(references))
	for _, reference := range references {
		var root yaml.Node
		if err := yaml.Unmarshal([]byte(reference), &root); err != nil {
			continue
		}
		if len(root.Content) == 0 {
			continue
		}
		roots = append(roots, root.Content[0])
	}
	if len(roots) == 0 {
		return transformed
	}

	reorderNodeFrom(roots, transformedRoot.Content[0], 0)

	out, err := yaml.Marshal(&transformedRoot)
	if err != nil {
		return transformed
	}
	return string(out)
}

const maxKeyOrderDepth = 64

// reorderNodeFrom walks the transformed document alongside every reference that has a node at
// the same place. Only mappings are touched; sequences are already in the reader's order and
// are descended into so a mapping nested in a list is not missed -- a rule-provider or a proxy
// can hold one.
//
// A reference whose node at this position is an alias, or of a different kind, simply drops
// out for this subtree: an alias has no children to line up with (following it would mean
// resolving the anchor, and a self-referential document would then not terminate), and a
// reference that says "sequence" where the document has a mapping has nothing to say about
// that mapping's key order.
func reorderNodeFrom(references []*yaml.Node, transformed *yaml.Node, depth int) {
	if depth > maxKeyOrderDepth || transformed == nil || transformed.Kind == yaml.AliasNode {
		return
	}
	usable := references[:0:0]
	for _, reference := range references {
		if reference == nil || reference.Kind == yaml.AliasNode || reference.Kind != transformed.Kind {
			continue
		}
		usable = append(usable, reference)
	}
	if len(usable) == 0 {
		return
	}

	switch transformed.Kind {
	case yaml.DocumentNode:
		if len(transformed.Content) == 0 {
			return
		}
		next := make([]*yaml.Node, 0, len(usable))
		for _, reference := range usable {
			if len(reference.Content) > 0 {
				next = append(next, reference.Content[0])
			}
		}
		reorderNodeFrom(next, transformed.Content[0], depth+1)
	case yaml.SequenceNode:
		// By position. A transform may add or drop an element, in which case the pairing after
		// that point is wrong -- but a wrong pairing only means a mapping keeps the order it
		// already had, never that a key moves somewhere the reader did not put it.
		for i := 0; i < len(transformed.Content); i++ {
			next := make([]*yaml.Node, 0, len(usable))
			for _, reference := range usable {
				if i < len(reference.Content) {
					next = append(next, reference.Content[i])
				}
			}
			if len(next) > 0 {
				reorderNodeFrom(next, transformed.Content[i], depth+1)
			}
		}
	case yaml.MappingNode:
		// Position from the first reference that has the key. Ranks from later references are
		// offset past every possible rank of earlier ones, so a later reference can never place
		// a key ahead of anything the first reference ordered.
		const perReference = 1 << 20
		sourceOrder := map[string]int{}
		for r, reference := range usable {
			for i := 0; i+1 < len(reference.Content); i += 2 {
				key := reference.Content[i]
				if key.Kind != yaml.ScalarNode {
					continue
				}
				if _, seen := sourceOrder[key.Value]; !seen {
					sourceOrder[key.Value] = r*perReference + i
				}
			}
		}

		type pair struct {
			key, value *yaml.Node
			rank       int
			position   int
		}
		// A key the transform added sorts after every key the source had, keeping the order
		// the transform emitted it in rather than inventing one.
		const addedByTransform = 1 << 30
		pairs := make([]pair, 0, len(transformed.Content)/2)
		for i := 0; i+1 < len(transformed.Content); i += 2 {
			key, value := transformed.Content[i], transformed.Content[i+1]
			rank := addedByTransform + i
			if key.Kind == yaml.ScalarNode {
				if at, ok := sourceOrder[key.Value]; ok {
					rank = at
				}
			}
			pairs = append(pairs, pair{key: key, value: value, rank: rank, position: i})
		}

		// Insertion sort: stable, and these are short.
		for i := 1; i < len(pairs); i++ {
			for j := i; j > 0 && pairs[j-1].rank > pairs[j].rank; j-- {
				pairs[j-1], pairs[j] = pairs[j], pairs[j-1]
			}
		}

		content := make([]*yaml.Node, 0, len(pairs)*2)
		for _, p := range pairs {
			content = append(content, p.key, p.value)
		}
		// An odd trailing node would be a malformed mapping; carry it rather than drop it.
		if len(transformed.Content)%2 == 1 {
			content = append(content, transformed.Content[len(transformed.Content)-1])
		}
		transformed.Content = content

		// Descend by key, not by position: the documents disagree on order until the line above
		// runs, and a transform may have removed a key entirely. Every reference that has the
		// key contributes its child, in the same precedence.
		childrenOf := func(reference *yaml.Node, key string) *yaml.Node {
			for i := 0; i+1 < len(reference.Content); i += 2 {
				if k := reference.Content[i]; k.Kind == yaml.ScalarNode && k.Value == key {
					return reference.Content[i+1]
				}
			}
			return nil
		}
		for i := 0; i+1 < len(transformed.Content); i += 2 {
			key := transformed.Content[i]
			if key.Kind != yaml.ScalarNode {
				continue
			}
			next := make([]*yaml.Node, 0, len(usable))
			for _, reference := range usable {
				if child := childrenOf(reference, key.Value); child != nil {
					next = append(next, child)
				}
			}
			if len(next) > 0 {
				reorderNodeFrom(next, transformed.Content[i+1], depth+1)
			}
		}
	}
}
