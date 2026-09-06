// Command gen_protocol_inventory regenerates the proxy-protocol field inventory
// that the iOS client's protocol editor decodes, by parsing the Core outbound
// option structs. Making the inventory a
// generated artifact — rather than a hand-copied one — lets a CI gate catch a
// silently stale catalog when the pinned core is bumped.
//
// Output is a JSON object { "<type>": [ field, ... ] } where each field is
// { "goName", "key", "goType", "required", "nested"? }, matching the client's
// rawJSON shape:
//   - goName  = Go struct field name
//   - key     = proxy:"..." tag key
//   - goType  = the field type exactly as written in source (so C.DNSPrefer,
//     *bool, []string, map[string]any, ECHOptions render verbatim)
//   - required = the tag has no ,omitempty
//   - nested   = present only when the field's (deref/elem) type is a struct
//     defined in the outbound package; map[string]any stays a leaf.
//
// The embedded BasicOption is flattened into each type's top level. SingMuxOption
// (smux) is excluded — the client appends those fields via a separate list.
//
// Which types exist is READ FROM THE PARSER, not kept in a map here: the `switch`
// in adapter/parser.go ParseProxy (and listener/parse.go ParseListener for the
// listener surface) is walked, and each `case "<type>":` clause yields the
// `&pkg.XxxOption{` it decodes into. A hand-kept map is a second copy of that
// switch and it fell behind exactly the way second copies do -- v1.19.30 added
// `zerotier` to the switch and this generator kept emitting 26 types, so the
// gate that compares the client's catalog to "the pinned core's structs" would
// have stayed green with a whole outbound missing. A case the
// walk cannot pair with an option literal is an error, not a skip: the pattern
// changed, so the walk must fail loudly rather than lose a type silently.
//
// Surfaces (--surface): `proxies` (default, the client-facing shape above),
// `listeners` (the same shape for ParseListener over listener/inbound with
// inbound:"..." tags), or `all` -- {"proxies": {...}, "listeners": {...}} -- the
// shape the core-side field inventory golden and its drift/ledger gate use.
// --root points the walk at another checkout of this repository (a base
// revision, say) instead of the cwd.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
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

// surface names one parser switch and the option-struct package it decodes into.
type surface struct {
	name       string
	parserFile string // relative to the repository root
	parserFunc string
	optionPkg  string // the import alias the parser file uses for the option package
	optionDir  string // relative to the repository root
	tagName    string
}

var surfaces = map[string]surface{
	"proxies": {
		name: "proxies", parserFile: "adapter/parser.go", parserFunc: "ParseProxy",
		optionPkg: "outbound", optionDir: "adapter/outbound", tagName: "proxy",
	},
	"listeners": {
		name: "listeners", parserFile: "listener/parse.go", parserFunc: "ParseListener",
		optionPkg: "IN", optionDir: "listener/inbound", tagName: "inbound",
	},
}

// excludedStructs are never flattened as an embed nor expanded as nested.
var excludedStructs = map[string]bool{"SingMuxOption": true}

type inventoryField struct {
	GoName   string           `json:"goName"`
	Key      string           `json:"key"`
	GoType   string           `json:"goType"`
	Required bool             `json:"required"`
	Nested   []inventoryField `json:"nested,omitempty"`
}

type generator struct {
	fset    *token.FileSet
	structs map[string]*ast.StructType
	// constructors maps the option package's top-level functions to the struct
	// they return (`func DefaultXOption() *XOption` -> XOption), for the parser
	// cases that obtain their option through a call instead of a literal.
	constructors map[string]string
	tagName      string
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "gen_protocol_inventory:", err)
		os.Exit(1)
	}
}

func run(args []string, out *os.File) error {
	flags := flag.NewFlagSet("gen_protocol_inventory", flag.ContinueOnError)
	root := flags.String("root", ".", "repository root to read the parser switch and option structs from")
	which := flags.String("surface", "proxies", "proxies | listeners | all")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments %v (use --root)", flags.Args())
	}
	var document any
	switch *which {
	case "proxies", "listeners":
		inventory, err := inventoryFor(*root, surfaces[*which])
		if err != nil {
			return err
		}
		document = inventory
	case "all":
		all := map[string]map[string][]inventoryField{}
		for _, name := range []string{"proxies", "listeners"} {
			inventory, err := inventoryFor(*root, surfaces[name])
			if err != nil {
				return err
			}
			all[name] = inventory
		}
		document = all
	default:
		return fmt.Errorf("unknown --surface %q (proxies | listeners | all)", *which)
	}
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	out.Write(encoded)
	out.Write([]byte("\n"))
	return nil
}

// inventoryFor walks one surface: parser switch -> type/struct roots -> fields.
func inventoryFor(root string, s surface) (map[string][]inventoryField, error) {
	gen, err := newGenerator(filepath.Join(root, s.optionDir), s.tagName)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", s.name, err)
	}
	roots, err := parserRoots(filepath.Join(root, s.parserFile), s.parserFunc, s.optionPkg, gen.constructors)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", s.name, err)
	}
	inventory := map[string][]inventoryField{}
	for typeName, structName := range roots {
		fields, err := gen.collect(structName, map[string]bool{})
		if err != nil {
			return nil, fmt.Errorf("%s: %s (%s): %w", s.name, typeName, structName, err)
		}
		inventory[typeName] = fields
	}
	return inventory, nil
}

// parserRoots reads the `switch` inside funcName in parserFile and returns every
// `case "<type>":` paired with the option struct its clause decodes into. Two
// shapes are recognised, the two the parsers use: the `&pkg.XxxOption{...}`
// composite literal taken by address (every ParseProxy case, most ParseListener
// cases), and a call to a constructor in the option package whose result is a
// pointer to an option struct (`IN.DefaultHysteria2RealmServerOption()`),
// resolved through constructors -- the option package's top-level functions
// mapped to the struct they return. Every case that names a string must pair with
// exactly one struct; the default clause is ignored.
func parserRoots(parserFile, funcName, optionPkg string, constructors map[string]string) (map[string]string, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, parserFile, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", parserFile, err)
	}
	var fn *ast.FuncDecl
	for _, decl := range file.Decls {
		if d, ok := decl.(*ast.FuncDecl); ok && d.Name.Name == funcName && d.Recv == nil {
			fn = d
			break
		}
	}
	if fn == nil || fn.Body == nil {
		return nil, fmt.Errorf("%s: function %s not found", parserFile, funcName)
	}
	roots := map[string]string{}
	var walkErr error
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if walkErr != nil {
			return false
		}
		sw, ok := n.(*ast.SwitchStmt)
		if !ok {
			return true
		}
		for _, stmt := range sw.Body.List {
			clause, ok := stmt.(*ast.CaseClause)
			if !ok || len(clause.List) == 0 {
				continue // default:
			}
			var types []string
			for _, expr := range clause.List {
				lit, ok := expr.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				value, err := strconv.Unquote(lit.Value)
				if err != nil {
					continue
				}
				types = append(types, value)
			}
			if len(types) == 0 {
				continue // a switch on something other than the type string
			}
			structs := optionLiteralsIn(clause.Body, optionPkg)
			if len(structs) == 0 {
				structs = optionConstructorsIn(clause.Body, optionPkg, constructors)
			}
			if len(structs) != 1 {
				walkErr = fmt.Errorf("%s %s: case %q decodes into %d %s.*Option literals, want exactly 1 (%v) -- "+
					"the parser's shape changed; teach parserRoots the new shape rather than letting the type go missing",
					parserFile, funcName, strings.Join(types, ","), len(structs), optionPkg, structs)
				return false
			}
			for _, typeName := range types {
				if previous, dup := roots[typeName]; dup && previous != structs[0] {
					walkErr = fmt.Errorf("%s %s: case %q appears twice with different option structs (%s, %s)", parserFile, funcName, typeName, previous, structs[0])
					return false
				}
				roots[typeName] = structs[0]
			}
		}
		return false // one switch per parser; do not descend into nested ones
	})
	if walkErr != nil {
		return nil, walkErr
	}
	if len(roots) == 0 {
		return nil, fmt.Errorf("%s %s: no `case \"<type>\":` clauses found", parserFile, funcName)
	}
	return roots, nil
}

// optionLiteralsIn lists, in source order and de-duplicated, the struct names of
// `&pkg.Name{...}` expressions in stmts whose selector package is optionPkg.
func optionLiteralsIn(stmts []ast.Stmt, optionPkg string) []string {
	var names []string
	seen := map[string]bool{}
	for _, stmt := range stmts {
		ast.Inspect(stmt, func(n ast.Node) bool {
			unary, ok := n.(*ast.UnaryExpr)
			if !ok || unary.Op != token.AND {
				return true
			}
			lit, ok := unary.X.(*ast.CompositeLit)
			if !ok {
				return true
			}
			sel, ok := lit.Type.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != optionPkg {
				return true
			}
			if !seen[sel.Sel.Name] {
				seen[sel.Sel.Name] = true
				names = append(names, sel.Sel.Name)
			}
			return true
		})
	}
	return names
}

// optionConstructorsIn lists, in source order and de-duplicated, the option structs
// returned by `pkg.F(...)` calls in stmts, for the F that constructors knows.
func optionConstructorsIn(stmts []ast.Stmt, optionPkg string, constructors map[string]string) []string {
	var names []string
	seen := map[string]bool{}
	for _, stmt := range stmts {
		ast.Inspect(stmt, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != optionPkg {
				return true
			}
			if structName, known := constructors[sel.Sel.Name]; known && !seen[structName] {
				seen[structName] = true
				names = append(names, structName)
			}
			return true
		})
	}
	return names
}

func newGenerator(dir, tagName string) (*generator, error) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", dir, err)
	}
	gen := &generator{fset: fset, structs: map[string]*ast.StructType{}, constructors: map[string]string{}, tagName: tagName}
	// Deterministic: walk files in name order so a struct declared twice under
	// different build tags (zerotier.go / zerotier_stub.go) resolves the same way
	// on every run. The stub mirrors the real one field for field by upstream's
	// own discipline; the test pins that they agree.
	for _, pkg := range pkgs {
		names := make([]string, 0, len(pkg.Files))
		for name := range pkg.Files {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			file := pkg.Files[name]
			for _, decl := range file.Decls {
				if fn, ok := decl.(*ast.FuncDecl); ok {
					if fn.Recv == nil && fn.Type.Results != nil && len(fn.Type.Results.List) == 1 {
						if returned := baseTypeName(fn.Type.Results.List[0].Type); returned != "" {
							if _, exists := gen.constructors[fn.Name.Name]; !exists {
								gen.constructors[fn.Name.Name] = returned
							}
						}
					}
					continue
				}
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
						if _, exists := gen.structs[typeSpec.Name.Name]; exists {
							continue
						}
						gen.structs[typeSpec.Name.Name] = st
					}
				}
			}
		}
	}
	return gen, nil
}

// collect returns structName's inventory fields, flattening embedded structs and
// recursing into nested struct-typed fields. seen guards against a struct that
// embeds/nests itself.
func (g *generator) collect(structName string, seen map[string]bool) ([]inventoryField, error) {
	st, ok := g.structs[structName]
	if !ok {
		return nil, fmt.Errorf("struct %q not found in the option package", structName)
	}
	if seen[structName] {
		return nil, fmt.Errorf("recursive struct %q", structName)
	}
	seen[structName] = true
	defer delete(seen, structName)

	var fields []inventoryField
	for _, astField := range st.Fields.List {
		// Embedded field (no names): flatten its fields into this level.
		if len(astField.Names) == 0 {
			embedded := baseTypeName(astField.Type)
			if embedded == "" || excludedStructs[embedded] {
				continue
			}
			if _, ok := g.structs[embedded]; ok {
				nested, err := g.collect(embedded, seen)
				if err != nil {
					return nil, err
				}
				fields = append(fields, nested...)
			}
			continue
		}
		key, required, ok := tagKey(astField.Tag, g.tagName)
		if !ok {
			continue
		}
		goType := g.renderType(astField.Type)
		var nested []inventoryField
		if base := baseTypeName(astField.Type); base != "" && !excludedStructs[base] {
			if _, ok := g.structs[base]; ok {
				var err error
				if nested, err = g.collect(base, seen); err != nil {
					return nil, err
				}
			}
		}
		for _, name := range astField.Names {
			if !name.IsExported() {
				continue
			}
			fields = append(fields, inventoryField{
				GoName: name.Name, Key: key, GoType: goType, Required: required, Nested: nested,
			})
		}
	}
	return fields, nil
}

// tagKey extracts the tag's key and whether the field is required (no
// ,omitempty). A missing tag, or `<tag>:"-"`, means the field is not part of the
// decoded config and is skipped.
func tagKey(tag *ast.BasicLit, tagName string) (key string, required bool, ok bool) {
	if tag == nil {
		return "", false, false
	}
	raw, err := strconv.Unquote(tag.Value)
	if err != nil {
		return "", false, false
	}
	value, present := reflect.StructTag(raw).Lookup(tagName)
	if !present {
		return "", false, false
	}
	name, opts, _ := strings.Cut(value, ",")
	if name == "-" {
		return "", false, false
	}
	return name, !strings.Contains(","+opts+",", ",omitempty,"), true
}

// baseTypeName returns the underlying named type of an expression after peeling
// pointers and slices: Ident -> its name, *T/[]T -> base of T, everything else
// (map, selector like C.DNSPrefer, func, ...) -> "" (a leaf, not a local struct).
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

// renderType prints the field type exactly as written in source.
func (g *generator) renderType(expr ast.Expr) string {
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, g.fset, expr); err != nil {
		return ""
	}
	return buf.String()
}
