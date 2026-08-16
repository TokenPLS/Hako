// Command go_mobile_api_inventory prints the exported Go surface selected by
// one target's build constraints. It is intentionally dependency-free so the
// Hako/libbox parity review can inventory two unrelated modules reproducibly.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/build"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type symbol struct {
	Kind      string `json:"kind"`
	Owner     string `json:"owner,omitempty"`
	Name      string `json:"name"`
	Signature string `json:"signature"`
	File      string `json:"file"`
}

type inventory struct {
	Package string   `json:"package"`
	GOOS    string   `json:"goos"`
	GOARCH  string   `json:"goarch"`
	Tags    []string `json:"tags,omitempty"`
	Files   []string `json:"files"`
	Symbols []symbol `json:"symbols"`
}

func main() {
	goos := flag.String("goos", "ios", "target GOOS")
	goarch := flag.String("goarch", "arm64", "target GOARCH")
	tagsValue := flag.String("tags", "", "comma-separated build tags")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: go run scripts/go_mobile_api_inventory.go [flags] <package-directory>")
		os.Exit(2)
	}

	directory, err := filepath.Abs(flag.Arg(0))
	check(err)
	tags := splitTags(*tagsValue)
	context := build.Default
	context.GOOS = *goos
	context.GOARCH = *goarch
	context.BuildTags = tags
	context.CgoEnabled = false
	buildPackage, err := context.ImportDir(directory, build.IgnoreVendor)
	check(err)

	files := append([]string{}, buildPackage.GoFiles...)
	files = append(files, buildPackage.CgoFiles...)
	sort.Strings(files)
	fileSet := token.NewFileSet()
	var symbols []symbol
	for _, name := range files {
		path := filepath.Join(directory, name)
		parsed, parseErr := parser.ParseFile(fileSet, path, nil, parser.SkipObjectResolution)
		check(parseErr)
		symbols = append(symbols, exportedSymbols(fileSet, name, parsed)...)
	}
	sort.Slice(symbols, func(i, j int) bool {
		left := symbols[i].Owner + "\x00" + symbols[i].Kind + "\x00" + symbols[i].Name + "\x00" + symbols[i].Signature
		right := symbols[j].Owner + "\x00" + symbols[j].Kind + "\x00" + symbols[j].Name + "\x00" + symbols[j].Signature
		return left < right
	})

	result := inventory{
		Package: buildPackage.ImportPath,
		GOOS:    *goos,
		GOARCH:  *goarch,
		Tags:    tags,
		Files:   files,
		Symbols: symbols,
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	check(encoder.Encode(result))
}

func exportedSymbols(fileSet *token.FileSet, fileName string, file *ast.File) []symbol {
	var result []symbol
	for _, declaration := range file.Decls {
		switch node := declaration.(type) {
		case *ast.FuncDecl:
			if !node.Name.IsExported() {
				continue
			}
			owner := receiverName(node.Recv)
			if owner != "" && !ast.IsExported(owner) {
				continue
			}
			kind := "function"
			if owner != "" {
				kind = "method"
			}
			result = append(result, symbol{kind, owner, node.Name.Name, render(fileSet, node.Type), fileName})
		case *ast.GenDecl:
			for _, specification := range node.Specs {
				switch spec := specification.(type) {
				case *ast.ValueSpec:
					for _, name := range spec.Names {
						if name.IsExported() {
							result = append(result, symbol{strings.ToLower(node.Tok.String()), "", name.Name, render(fileSet, spec), fileName})
						}
					}
				case *ast.TypeSpec:
					if !spec.Name.IsExported() {
						continue
					}
					result = append(result, symbol{"type", "", spec.Name.Name, render(fileSet, spec.Type), fileName})
					result = append(result, exportedMembers(fileSet, fileName, spec.Name.Name, spec.Type)...)
				}
			}
		}
	}
	return result
}

func exportedMembers(fileSet *token.FileSet, fileName, owner string, expression ast.Expr) []symbol {
	var fields *ast.FieldList
	kind := "field"
	switch node := expression.(type) {
	case *ast.StructType:
		fields = node.Fields
	case *ast.InterfaceType:
		fields = node.Methods
		kind = "interface_method"
	default:
		return nil
	}
	var result []symbol
	for _, field := range fields.List {
		if len(field.Names) == 0 {
			name := render(fileSet, field.Type)
			if ast.IsExported(strings.TrimPrefix(name, "*")) {
				result = append(result, symbol{kind, owner, name, name, fileName})
			}
			continue
		}
		for _, name := range field.Names {
			if name.IsExported() {
				result = append(result, symbol{kind, owner, name.Name, render(fileSet, field.Type), fileName})
			}
		}
	}
	return result
}

func receiverName(list *ast.FieldList) string {
	if list == nil || len(list.List) == 0 {
		return ""
	}
	expression := list.List[0].Type
	for {
		switch node := expression.(type) {
		case *ast.StarExpr:
			expression = node.X
		case *ast.IndexExpr:
			expression = node.X
		case *ast.IndexListExpr:
			expression = node.X
		case *ast.Ident:
			return node.Name
		default:
			return ""
		}
	}
}

func render(fileSet *token.FileSet, node any) string {
	var buffer bytes.Buffer
	check(format.Node(&buffer, fileSet, node))
	return buffer.String()
}

func splitTags(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	var result []string
	for _, value := range strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' }) {
		if value != "" {
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
