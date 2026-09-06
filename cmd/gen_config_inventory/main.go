// Command gen_config_inventory enumerates the upstream mihomo configuration
// schema (config.RawConfig) field-by-field straight from source with go/ast —
// not reflect, not by reading prose docs — and additionally extracts the fields
// that bind/hako/override.go forces or clears. The output feeds a per-field
// Hako iOS disposition catalog whose gate cross-checks the human keep/strip/
// apple judgment against what the enforcement code actually does.
//
//   - fields      : every yaml field reachable from RawConfig, dotted path.
//     Recurses into structs defined in the config package; maps,
//     slices of non-structs, and external types (netip.Prefix,
//     C.TUNStack, orderedmap.OrderedMap, …) are leaves.
//   - override    : each `cfg.<sel> = <value>` assignment in override.go, with
//     the selector resolved to a RawConfig yaml path where it maps
//     cleanly (General/Inbound are transparent wrappers RawConfig
//     flattens; Controller and the processed Inbound map to a
//     family, left unresolved for the disposition table to key on).
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

const entryStruct = "RawConfig"

// scope names the platform lane this inventory describes. Shared Apple source
// contains profile-specific helpers, so enforcement explicitly excludes the
// macOS-only functions from this iOS catalog.
const scope = "ios"

// wrapperStructs are processed-config structs whose fields RawConfig flattens to
// its top level (General, Inbound). override.go writes through them (cfg.General.X);
// RawConfig has no such level, so they are transparent when resolving a selector.
var wrapperStructs = map[string]bool{"General": true, "Inbound": true}

type field struct {
	Path   string `json:"path"`
	Key    string `json:"key"`
	GoType string `json:"goType"`
}

type evidence struct {
	Selector string `json:"selector"`
	Path     string `json:"path,omitempty"`
	Kind     string `json:"kind"` // cleared | forced | reject
	// Guarded: the assignment sits inside an if whose condition reads the field it writes,
	// so it decides on the user's value instead of overwriting it blind. Inventory consumers
	// accept "default" and "conditional" dispositions only for guarded assignments.
	Guarded  bool   `json:"guarded"`
	Value    string `json:"value,omitempty"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Resolved bool   `json:"resolved"`
}

type output struct {
	SchemaVersion int        `json:"schemaVersion"`
	Scope         string     `json:"scope"`
	Entry         string     `json:"entry"`
	Fields        []field    `json:"fields"`
	Enforcement   []evidence `json:"enforcement"`
}

// member is one struct field: its yaml key and, when the (deref/elem) type is a
// struct defined in the package, that struct's name for recursion/resolution.
type member struct {
	goName string
	key    string
	typ    ast.Expr
	nested string
}

type generator struct {
	fset    *token.FileSet
	structs map[string]*ast.StructType
	members map[string][]member // structName -> ordered members (exported, yaml-tagged)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gen_config_inventory:", err)
		os.Exit(1)
	}
}

func run() error {
	configDir := "config"
	bindDir := "bind/hako"
	if len(os.Args) > 1 {
		configDir = os.Args[1]
	}
	if len(os.Args) > 2 {
		bindDir = os.Args[2]
	}
	gen, err := newGenerator(configDir)
	if err != nil {
		return err
	}
	fields, err := gen.collect(entryStruct, "", map[string]bool{})
	if err != nil {
		return err
	}
	enf, err := gen.enforcement(bindDir)
	if err != nil {
		return err
	}
	out := output{SchemaVersion: 1, Scope: scope, Entry: entryStruct, Fields: fields, Enforcement: enf}
	enc, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	os.Stdout.Write(enc)
	os.Stdout.Write([]byte("\n"))
	return nil
}

// enforcement gathers, from the iOS adaptation layer, every config field the
// code clears/forces (override.go on *config.Config; config_pipeline.go on
// *config.RawConfig) and rejects (validate.go's NE-intent gate), sorted by
// file then line.
func (g *generator) enforcement(bindDir string) ([]evidence, error) {
	var all []evidence
	ov, err := g.assignEvidence(filepath.Join(bindDir, "override.go"), "cfg", true, nil, "clearTunForNonPacketTunnel")
	if err != nil {
		return nil, err
	}
	// The same file again, rooted at the `tun *LC.Tun` parameter overrideTunForIOS receives.
	// Without this pass every field that function forces -- stack, mtu, device, auto-route, gso,
	// recvmsgx and the rest -- looks unenforced, which is how eleven of them came to be recorded
	// as Apple's rather than as ours.
	ovTun, err := g.assignEvidence(filepath.Join(bindDir, "override.go"), "tun", true, []string{"Tun"}, "clearTunForNonPacketTunnel")
	if err != nil {
		return nil, err
	}
	cp, err := g.assignEvidence(
		filepath.Join(bindDir, "config_pipeline.go"),
		"raw",
		false,
		nil,
		"clearRawTunForNonPacketTunnel",
		"normalizeDHCPNameserversToSystem",
		"repairMacOSPacketTunnelDNS",
	)
	if err != nil {
		return nil, err
	}
	rj, err := g.rejectEvidence(filepath.Join(bindDir, "validate.go"), "validateRawNetworkExtensionIntentForApple")
	if err != nil {
		return nil, err
	}
	all = append(all, ov...)
	all = append(all, ovTun...)
	all = append(all, cp...)
	all = append(all, rj...)
	sort.Slice(all, func(i, j int) bool {
		if all[i].File != all[j].File {
			return all[i].File < all[j].File
		}
		return all[i].Line < all[j].Line
	})
	return all, nil
}

func newGenerator(dir string) (*generator, error) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", dir, err)
	}
	gen := &generator{fset: fset, structs: map[string]*ast.StructType{}, members: map[string][]member{}}
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				genDecl, ok := decl.(*ast.GenDecl)
				if !ok || genDecl.Tok != token.TYPE {
					continue
				}
				for _, spec := range genDecl.Specs {
					typeSpec, ok := spec.(*ast.TypeSpec)
					if !ok {
						continue
					}
					if st, ok := typeSpec.Type.(*ast.StructType); ok {
						gen.structs[typeSpec.Name.Name] = st
					}
				}
			}
		}
	}
	// Second pass: now that every struct is known, index yaml-tagged members.
	for name, st := range gen.structs {
		gen.members[name] = gen.indexMembers(st)
	}
	return gen, nil
}

// indexMembers returns the exported, yaml-tagged members of a struct in source
// order, resolving each field's nested config-struct name (if any).
func (g *generator) indexMembers(st *ast.StructType) []member {
	var out []member
	for _, af := range st.Fields.List {
		if len(af.Names) == 0 {
			continue // embedded: RawConfig/sub-structs use no embeds; skip.
		}
		key, ok := yamlKey(af.Tag)
		if !ok {
			continue
		}
		nested := ""
		if base := baseTypeName(af.Type); base != "" {
			if _, isStruct := g.structs[base]; isStruct {
				nested = base
			}
		}
		for _, n := range af.Names {
			if !n.IsExported() {
				continue
			}
			out = append(out, member{goName: n.Name, key: key, typ: af.Type, nested: nested})
		}
	}
	return out
}

// collect returns the dotted-path field inventory rooted at structName. prefix
// is the yaml path accumulated so far (empty at the entry). seen guards cycles.
func (g *generator) collect(structName, prefix string, seen map[string]bool) ([]field, error) {
	if _, ok := g.structs[structName]; !ok {
		return nil, fmt.Errorf("struct %q not found in config package", structName)
	}
	if seen[structName] {
		return nil, fmt.Errorf("recursive struct %q", structName)
	}
	seen[structName] = true
	defer delete(seen, structName)

	var fields []field
	for _, m := range g.members[structName] {
		path := m.key
		if prefix != "" {
			path = prefix + "." + m.key
		}
		if m.nested != "" {
			nested, err := g.collect(m.nested, path, seen)
			if err != nil {
				return nil, err
			}
			fields = append(fields, nested...)
			continue
		}
		fields = append(fields, field{Path: path, Key: m.key, GoType: g.renderType(m.typ)})
	}
	return fields, nil
}

func parseGoFile(file string) (*ast.File, *token.FileSet, error) {
	src, err := os.ReadFile(file)
	if err != nil {
		return nil, nil, fmt.Errorf("read %s: %w", file, err)
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, src, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("parse %s: %w", file, err)
	}
	return f, fset, nil
}

// assignEvidence returns each `<root>.<sel> = <value>` assignment in file, with
// the selector resolved to a RawConfig yaml leaf path. override.go writes the
// processed *config.Config (flatten=true peels the General/Inbound wrappers
// RawConfig flattens); config_pipeline.go writes *config.RawConfig (flatten=false).
// See assignKind for cleared/forced/normalized.
// assignEvidence scans one file for assignments rooted at the identifier root.
//
// chainPrefix is prepended to every chain before it is resolved, and it exists because
// enforcement written through a POINTER PARAMETER was invisible: overrideTunForIOS takes
// `tun *LC.Tun` and writes tun.Stack, tun.MTU, tun.GSO..., which is rooted at `tun`, not at
// `cfg`. Eleven forced tun fields therefore had no enforcement evidence at all, and because
// nothing backed them they had to be labelled "apple" -- the one disposition exempt from both
// this check and the runtime deviation report. A scanner that cannot see a whole style of
// writing does not report less; it silently reclassifies whatever is written that way.
func (g *generator) assignEvidence(file, root string, flatten bool, chainPrefix []string, excludedFunctions ...string) ([]evidence, error) {
	f, fset, err := parseGoFile(file)
	if err != nil {
		return nil, err
	}
	excludedNames := make(map[string]struct{}, len(excludedFunctions))
	for _, name := range excludedFunctions {
		excludedNames[name] = struct{}{}
	}
	type sourceRange struct{ start, end token.Pos }
	excludedRanges := make([]sourceRange, 0, len(excludedNames))
	for _, declaration := range f.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Body == nil {
			continue
		}
		if _, excluded := excludedNames[function.Name.Name]; excluded {
			excludedRanges = append(excludedRanges, sourceRange{start: function.Body.Pos(), end: function.Body.End()})
		}
	}
	isExcluded := func(position token.Pos) bool {
		for _, source := range excludedRanges {
			if source.start <= position && position <= source.end {
				return true
			}
		}
		return false
	}
	var ev []evidence
	// Guards are tracked because "the old value participated in the decision" is what separates
	// a default from a force, and it is not visible in the assignment alone:
	//
	//	if len(raw.DNS.NameServer) == 0 { raw.DNS.NameServer = defaults }   // fills an absence
	//	tun.MTU = uint32(effectiveTunMTU())                                 // replaces a value
	//
	// Both are calls with no reference to the field in the RHS. Only the first leaves a user who
	// wrote something alone, and a catalog that calls them the same thing is wrong about one of
	// them whichever word it picks.
	// Collected by position rather than by a stack maintained during the walk: ast.Inspect
	// signals the end of EVERY node with a nil call, not just the ones pushed, so a stack popped
	// there unwinds far too often and the guard is gone by the time the assignment is reached.
	// The first version did exactly that and reported two guarded DNS defaults as forces.
	type guardRange struct {
		cond       ast.Expr
		start, end token.Pos
	}
	var guardRanges []guardRange
	ast.Inspect(f, func(n ast.Node) bool {
		if ifStmt, ok := n.(*ast.IfStmt); ok && ifStmt.Body != nil {
			guardRanges = append(guardRanges, guardRange{ifStmt.Cond, ifStmt.Body.Pos(), ifStmt.Body.End()})
		}
		return true
	})
	ast.Inspect(f, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || isExcluded(as.Pos()) || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return true
		}
		guarded := false
		for _, g := range guardRanges {
			if g.start <= as.Pos() && as.Pos() <= g.end && referencesSelector(g.cond, as.Lhs[0]) {
				guarded = true
				break
			}
		}
		chain, ok := selectorChain(as.Lhs[0], root)
		if !ok {
			return true
		}
		if len(chainPrefix) > 0 {
			chain = append(append([]string{}, chainPrefix...), chain...)
		}
		path, resolved := g.resolveSelector(chain, flatten)
		ev = append(ev, evidence{
			Selector: strings.Join(chain, "."),
			Path:     path,
			Kind:     assignKind(as.Lhs[0], as.Rhs[0], guarded),
			Guarded:  guarded,
			Value:    g.renderNode(fset, as.Rhs[0]),
			File:     file,
			Line:     fset.Position(as.Pos()).Line,
			Resolved: resolved,
		})
		return true
	})
	return ev, nil
}

// rejectEvidence returns the RawConfig leaf fields read inside funcName (e.g.
// validateRawNetworkExtensionIntent) — the fields whose presence triggers a hard
// preflight reject. Scoping to the reject function is what makes a `raw.X` read
// mean "reject" rather than the many reads validate.go does merely to validate.
func (g *generator) rejectEvidence(file, funcName string) ([]evidence, error) {
	f, fset, err := parseGoFile(file)
	if err != nil {
		return nil, err
	}
	var fn *ast.FuncDecl
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == funcName {
			fn = fd
			break
		}
	}
	if fn == nil {
		return nil, fmt.Errorf("%s: reject function %q not found", file, funcName)
	}
	seen := map[string]bool{}
	var ev []evidence
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		chain, ok := selectorChain(sel, "raw")
		if !ok {
			return true
		}
		path, resolved := g.resolveSelector(chain, false)
		if !resolved || seen[path] {
			return true
		}
		seen[path] = true
		ev = append(ev, evidence{
			Selector: strings.Join(chain, "."),
			Path:     path,
			Kind:     "reject",
			File:     file,
			Line:     fset.Position(sel.Pos()).Line,
			Resolved: true,
		})
		return true
	})
	return ev, nil
}

// resolveSelector walks a Go field-name chain against RawConfig by name and
// returns the yaml LEAF path. wrapperStructs (General/Inbound) are transparent
// when flatten is set (override.go's processed *config.Config). A chain that
// ends on a nested struct rather than a leaf field resolves to false.
func (g *generator) resolveSelector(chain []string, flatten bool) (string, bool) {
	cur := entryStruct
	var parts []string
	for _, seg := range chain {
		m, ok := findMember(g.members[cur], seg)
		if !ok {
			if flatten && cur == entryStruct && wrapperStructs[seg] {
				continue // flattened wrapper: stay at RawConfig, consume no path part
			}
			return "", false
		}
		parts = append(parts, m.key)
		if m.nested == "" {
			return strings.Join(parts, "."), true // leaf field
		}
		cur = m.nested
	}
	// chain exhausted while still on a struct: not a leaf field.
	return strings.Join(parts, "."), false
}

func findMember(members []member, goName string) (member, bool) {
	for _, m := range members {
		if m.goName == goName {
			return m, true
		}
	}
	return member{}, false
}

// selectorChain returns the field-name chain of a selector rooted at ident
// root (peeling a leading deref), e.g. `*cfg.General.Inbound` -> [General, Inbound]
// for root "cfg", or `raw.Tun.RouteAddressSet` -> [Tun, RouteAddressSet] for "raw".
func selectorChain(expr ast.Expr, root string) ([]string, bool) {
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	var chain []string
	for {
		sel, ok := expr.(*ast.SelectorExpr)
		if !ok {
			break
		}
		chain = append([]string{sel.Sel.Name}, chain...)
		expr = sel.X
	}
	if id, ok := expr.(*ast.Ident); ok && id.Name == root && len(chain) > 0 {
		return chain, true
	}
	return nil, false
}

// assignKind classifies an assignment RHS:
//   - normalized: a call that READS the field it assigns, i.e. `raw.X = filter(raw.X)` — the
//     field is kept and consumed, only its NE-incompatible entries stripped at preflight.
//     Compatible with a "keep" disposition (not a clear/force).
//   - cleared: a zero/empty literal (`0`, `""`, `nil`, `false`, `T{}`).
//   - forced: any other literal, constant, or call that does NOT read the field.
//
// The "reads the field it assigns" half was missing, and it mattered: any call expression
// counted as a normalization, so `tun.MTU = uint32(effectiveTunMTU())` -- which discards the
// user's value entirely -- was recorded as "kept and filtered". A user writing mtu: 1400 gets
// 4064, and the catalog said the field was honoured. Syntax alone cannot tell filtering from
// replacement; whether the old value is an input can.
func assignKind(lhs, rhs ast.Expr, guarded bool) string {
	if _, ok := rhs.(*ast.CallExpr); ok {
		// guarded: the enclosing condition reads the field, so this fills an absence rather than
		// replacing what someone wrote -- upstream's own default arriving late.
		if guarded || referencesSelector(rhs, lhs) {
			return "normalized"
		}
		return "forced"
	}
	if isZeroValue(rhs) {
		return "cleared"
	}
	return "forced"
}

// referencesSelector reports whether expr contains the same selector text as target, which is
// how "the old value is an input to the new one" is decided.
func referencesSelector(expr, target ast.Expr) bool {
	want := selectorText(target)
	if want == "" {
		return false
	}
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if found {
			return false
		}
		if candidate, ok := n.(ast.Expr); ok && selectorText(candidate) == want {
			found = true
			return false
		}
		return true
	})
	return found
}

// selectorText renders a selector chain as dotted text, or "" for anything else.
func selectorText(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		base := selectorText(t.X)
		if base == "" {
			return ""
		}
		return base + "." + t.Sel.Name
	case *ast.StarExpr:
		return selectorText(t.X)
	}
	return ""
}

// isZeroValue reports whether an RHS assigns a zero/empty value (a clear) rather
// than a specific forced value.
func isZeroValue(expr ast.Expr) bool {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name == "false" || t.Name == "nil"
	case *ast.BasicLit:
		return t.Value == "0" || t.Value == `""`
	case *ast.CompositeLit:
		return len(t.Elts) == 0
	}
	return false
}

// baseTypeName peels pointers and slices to the underlying named type; maps,
// selectors (C.DNSMode), generics and everything else are leaves ("").
func baseTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return baseTypeName(t.X)
	case *ast.ArrayType:
		return baseTypeName(t.Elt)
	default:
		return ""
	}
}

func (g *generator) renderType(expr ast.Expr) string { return g.renderNode(g.fset, expr) }

func (g *generator) renderNode(fset *token.FileSet, node ast.Node) string {
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fset, node); err != nil {
		return ""
	}
	return strings.Join(strings.Fields(buf.String()), " ")
}

// yamlKey extracts the yaml tag's key. A missing tag, or `yaml:"-"`, means the
// field is not part of the config surface.
func yamlKey(tag *ast.BasicLit) (string, bool) {
	if tag == nil {
		return "", false
	}
	raw, err := strconv.Unquote(tag.Value)
	if err != nil {
		return "", false
	}
	value, ok := reflect.StructTag(raw).Lookup("yaml")
	if !ok {
		return "", false
	}
	name, _, _ := strings.Cut(value, ",")
	if name == "" || name == "-" {
		return "", false
	}
	return name, true
}
