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
	"reflect"
	"strconv"
	"strings"
)

// proxyTypeStructs mirrors adapter/parser.go's ParseProxy switch: each proxy
// "type" and the option struct it decodes into.
var proxyTypeStructs = map[string]string{
	"ss": "ShadowSocksOption", "ssr": "ShadowSocksROption", "socks5": "Socks5Option",
	"http": "HttpOption", "vmess": "VmessOption", "vless": "VlessOption",
	"snell": "SnellOption", "trojan": "TrojanOption", "hysteria": "HysteriaOption",
	"hysteria2": "Hysteria2Option", "wireguard": "WireGuardOption", "tuic": "TuicOption",
	"gost-relay": "GostRelayOption", "direct": "DirectOption", "dns": "DnsOption",
	"reject": "RejectOption", "rematch": "RematchOption", "ssh": "SshOption",
	"mieru": "MieruOption", "anytls": "AnyTLSOption", "sudoku": "SudokuOption",
	"masque": "MasqueOption", "trusttunnel": "TrustTunnelOption", "openvpn": "OpenVPNOption",
	"tailscale": "TailscaleOption", "shadowquic": "ShadowQuicOption",
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
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gen_protocol_inventory:", err)
		os.Exit(1)
	}
}

func run() error {
	dir := "adapter/outbound"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	gen, err := newGenerator(dir)
	if err != nil {
		return err
	}
	inventory := map[string][]inventoryField{}
	for proxyType, structName := range proxyTypeStructs {
		fields, err := gen.collect(structName, map[string]bool{})
		if err != nil {
			return fmt.Errorf("%s (%s): %w", proxyType, structName, err)
		}
		inventory[proxyType] = fields
	}
	encoded, err := json.MarshalIndent(inventory, "", "  ")
	if err != nil {
		return err
	}
	os.Stdout.Write(encoded)
	os.Stdout.Write([]byte("\n"))
	return nil
}

func newGenerator(dir string) (*generator, error) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", dir, err)
	}
	gen := &generator{fset: fset, structs: map[string]*ast.StructType{}}
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
	return gen, nil
}

// collect returns structName's inventory fields, flattening embedded structs and
// recursing into nested struct-typed fields. seen guards against a struct that
// embeds/nests itself.
func (g *generator) collect(structName string, seen map[string]bool) ([]inventoryField, error) {
	st, ok := g.structs[structName]
	if !ok {
		return nil, fmt.Errorf("struct %q not found in outbound package", structName)
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
		key, required, ok := proxyTagKey(astField.Tag)
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

// proxyTagKey extracts the proxy tag's key and whether the field is required
// (no ,omitempty). A missing proxy tag, or proxy:"-", means the field is not
// part of the decoded config and is skipped.
func proxyTagKey(tag *ast.BasicLit) (key string, required bool, ok bool) {
	if tag == nil {
		return "", false, false
	}
	raw, err := strconv.Unquote(tag.Value)
	if err != nil {
		return "", false, false
	}
	value, present := reflect.StructTag(raw).Lookup("proxy")
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
