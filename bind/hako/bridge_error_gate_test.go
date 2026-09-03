package hako

// go_seq_to_objc_string → NSString initWithBytesNoCopy(NSUTF8StringEncoding)，

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// bridgeReturnViolations parses the given files and reports every exported
// bridge surface (exported function, or exported method on an exported
// receiver type) whose error results can escape without bridgeSafeError.
func bridgeReturnViolations(fset *token.FileSet, files []*ast.File) []string {
	var violations []string
	for _, file := range files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			if !isBridgeBoundary(fn) {
				continue
			}
			errIdx := errorResultIndexes(fn.Type.Results)
			strIdx := stringResultIndexes(fn.Type.Results)
			if len(errIdx) == 0 && len(strIdx) == 0 {
				continue
			}
			if hasNamedResultOfType(fn.Type.Results, "error") {
				violations = append(violations, fmt.Sprintf(
					"%s: %s uses a named error result; defer can rewrite it after the return, use explicit returns",
					fset.Position(fn.Pos()), fn.Name.Name))
				continue
			}
			if len(strIdx) > 0 && hasNamedResultOfType(fn.Type.Results, "string") {
				violations = append(violations, fmt.Sprintf(
					"%s: %s uses a named string result; defer can rewrite it after the return, use explicit returns",
					fset.Position(fn.Pos()), fn.Name.Name))
				continue
			}
			total := resultCount(fn.Type.Results)
			for _, ret := range ownReturns(fn.Body) {
				pos := fset.Position(ret.Pos())
				if len(ret.Results) == 0 {
					violations = append(violations, fmt.Sprintf(
						"%s: %s has a bare return", pos, fn.Name.Name))
					continue
				}
				if len(ret.Results) != total {
					violations = append(violations, fmt.Sprintf(
						"%s: %s returns a multi-value call directly; split it so the results pass the bridge helpers",
						pos, fn.Name.Name))
					continue
				}
				for _, idx := range errIdx {
					if !isSanitizedErrorExpr(ret.Results[idx]) {
						violations = append(violations, fmt.Sprintf(
							"%s: %s returns an error that does not pass bridgeSafeError",
							pos, fn.Name.Name))
					}
				}
				for _, idx := range strIdx {
					if !isSanitizedStringExpr(ret.Results[idx]) {
						violations = append(violations, fmt.Sprintf(
							"%s: %s returns a string that does not pass bridgeSafeString",
							pos, fn.Name.Name))
					}
				}
			}
		}
	}
	sort.Strings(violations)
	return violations
}

func isBridgeBoundary(fn *ast.FuncDecl) bool {
	if !fn.Name.IsExported() {
		return false
	}
	if fn.Recv == nil {
		return true
	}
	if len(fn.Recv.List) != 1 {
		return false
	}
	return ast.IsExported(receiverTypeName(fn.Recv.List[0].Type))
}

func receiverTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return receiverTypeName(t.X)
	case *ast.IndexExpr:
		return receiverTypeName(t.X)
	}
	return ""
}

func errorResultIndexes(results *ast.FieldList) []int {
	return typedResultIndexes(results, "error")
}

func stringResultIndexes(results *ast.FieldList) []int {
	return typedResultIndexes(results, "string")
}

func typedResultIndexes(results *ast.FieldList, typeName string) []int {
	if results == nil {
		return nil
	}
	var idx []int
	position := 0
	for _, field := range results.List {
		n := len(field.Names)
		if n == 0 {
			n = 1
		}
		for i := 0; i < n; i++ {
			if ident, ok := field.Type.(*ast.Ident); ok && ident.Name == typeName {
				idx = append(idx, position)
			}
			position++
		}
	}
	return idx
}

func resultCount(results *ast.FieldList) int {
	count := 0
	for _, field := range results.List {
		n := len(field.Names)
		if n == 0 {
			n = 1
		}
		count += n
	}
	return count
}

func hasNamedResultOfType(results *ast.FieldList, typeName string) bool {
	for _, field := range results.List {
		ident, ok := field.Type.(*ast.Ident)
		if !ok || ident.Name != typeName {
			continue
		}
		if len(field.Names) > 0 {
			return true
		}
	}
	return false
}

// ownReturns collects the return statements that belong to the function body
// itself, not to closures nested inside it.
func ownReturns(body *ast.BlockStmt) []*ast.ReturnStmt {
	var returns []*ast.ReturnStmt
	ast.Inspect(body, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt:
			returns = append(returns, n)
		}
		return true
	})
	return returns
}

// A plain string literal is compliant: source files are valid UTF-8, so the
// literal's value is too (escape sequences like \xfe only enter through a
// deliberate edit, which review owns).
func isSanitizedStringExpr(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.BasicLit:
		return e.Kind == token.STRING
	case *ast.CallExpr:
		ident, ok := e.Fun.(*ast.Ident)
		return ok && ident.Name == "bridgeSafeString"
	}
	return false
}

func isSanitizedErrorExpr(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name == "nil"
	case *ast.CallExpr:
		ident, ok := e.Fun.(*ast.Ident)
		return ok && ident.Name == "bridgeSafeError"
	}
	return false
}

// bridgeCallbackClassification is the conscious classification of every
// exported interface that carries a string parameter in a method. An
// interface Swift implements needs a sanitizing decorator (its string
// parameters cross Go→ObjC through the same nil-on-invalid decode); an
// interface Go implements consumes strings and needs none. A new interface
// showing up here unclassified fails the gate until someone decides which
// side of the bridge implements it.
var bridgeCallbackClassification = map[string]string{
	"PlatformInterface":         "decorated",
	"ClashAPIClientHandler":     "decorated",
	"STUNTestHandler":           "decorated",
	"NetworkQualityTestHandler": "decorated",
	"StringIterator":            "go-implemented",
	"InterfaceUpdateListener":   "go-implemented",
}

// bridgeCallbackDecorators names the decorator type behind each interface
// classified "decorated". The fifth arm below checks the decorator overrides
// every string-parameter method of its interface explicitly: embedding
// forwards any method it does not override, so a method added to the
// interface later would satisfy the compiler, satisfy the tests, and cross
// the bridge unsanitized -- the classification arm alone cannot see that
// (found by a live poison: a planted extra string method rode through green).
var bridgeCallbackDecorators = map[string]string{
	"PlatformInterface":         "bridgeSafePlatformDecorator",
	"ClashAPIClientHandler":     "bridgeSafeClashHandlerDecorator",
	"STUNTestHandler":           "bridgeSafeSTUNHandlerDecorator",
	"NetworkQualityTestHandler": "bridgeSafeNQHandlerDecorator",
}

func bridgeStructuralViolations(fset *token.FileSet, files []*ast.File, fileNames map[*ast.File]string) []string {
	var violations []string
	for _, file := range files {
		name := fileNames[file]
		ast.Inspect(file, func(node ast.Node) bool {
			if lit, ok := node.(*ast.CompositeLit); ok && name != "iterator.go" {
				if ident, ok := lit.Type.(*ast.Ident); ok && ident.Name == "StringBox" {
					violations = append(violations, fmt.Sprintf(
						"%s: StringBox built outside WrapString; the literal skips bridgeSafeString",
						fset.Position(lit.Pos())))
				}
			}
			return true
		})
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, spec := range gen.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok || !ts.Name.IsExported() {
					continue
				}
				iface, ok := ts.Type.(*ast.InterfaceType)
				if !ok || !interfaceHasStringParam(iface) {
					continue
				}
				if _, classified := bridgeCallbackClassification[ts.Name.Name]; !classified {
					violations = append(violations, fmt.Sprintf(
						"%s: exported interface %s carries string parameters but is not classified in bridgeCallbackClassification",
						fset.Position(ts.Pos()), ts.Name.Name))
				}
			}
		}
	}
	sort.Strings(violations)
	return violations
}

func bridgeShapeBanViolations(fset *token.FileSet, files []*ast.File) []string {
	var violations []string
	for _, file := range files {
		for _, decl := range file.Decls {
			if gen, ok := decl.(*ast.GenDecl); ok {
				for _, spec := range gen.Specs {
					ts, ok := spec.(*ast.TypeSpec)
					if !ok {
						continue
					}
					if ident, ok := ts.Type.(*ast.Ident); ok && (ident.Name == "error" || ident.Name == "string") {
						violations = append(violations, fmt.Sprintf(
							"%s: type %s renames %s; gomobile binds it by identity while this gate matches the spelling, so the rename is refused",
							fset.Position(ts.Pos()), ts.Name.Name, ident.Name))
					}
					if st, ok := ts.Type.(*ast.StructType); ok && ts.Name.IsExported() {
						for _, field := range st.Fields.List {
							if len(field.Names) != 0 {
								continue
							}
							embedded := embeddedTypeName(field.Type)
							if embedded != "" && !ast.IsExported(embedded) && !isBridgeStdlibName(embedded) {
								violations = append(violations, fmt.Sprintf(
									"%s: exported struct %s embeds unexported %s; its promoted methods would cross the bridge unseen by this gate",
									fset.Position(field.Pos()), ts.Name.Name, embedded))
							}
						}
					}
				}
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			flag := func(ident *ast.Ident) {
				if ident == nil || (ident.Name != "bridgeSafeError" && ident.Name != "bridgeSafeString") {
					return
				}
				violations = append(violations, fmt.Sprintf(
					"%s: %s is redeclared; a shadow satisfies this gate's spelling while sanitizing nothing",
					fset.Position(ident.Pos()), ident.Name))
			}
			switch n := node.(type) {
			case *ast.AssignStmt:
				for _, lhs := range n.Lhs {
					if ident, ok := lhs.(*ast.Ident); ok {
						flag(ident)
					}
				}
			case *ast.ValueSpec:
				for _, name := range n.Names {
					flag(name)
				}
			case *ast.FuncType:
				if n.Params != nil {
					for _, param := range n.Params.List {
						for _, name := range param.Names {
							flag(name)
						}
					}
				}
			}
			return true
		})
	}
	sort.Strings(violations)
	return violations
}

func embeddedTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return embeddedTypeName(t.X)
	}
	return ""
}

// Embedded stdlib-ish lowercase selectors (pkg.Type) return "" above; this
// hook exists for in-package names that are deliberately fine to embed.
func isBridgeStdlibName(string) bool { return false }

func interfaceHasStringParam(iface *ast.InterfaceType) bool {
	return len(interfaceStringParamMethods(iface)) > 0
}

func interfaceStringParamMethods(iface *ast.InterfaceType) []string {
	var names []string
	for _, method := range iface.Methods.List {
		fn, ok := method.Type.(*ast.FuncType)
		if !ok || fn.Params == nil || len(method.Names) == 0 {
			continue
		}
		for _, param := range fn.Params.List {
			if ident, ok := param.Type.(*ast.Ident); ok && ident.Name == "string" {
				names = append(names, method.Names[0].Name)
				break
			}
		}
	}
	return names
}

// bridgeDecoratorCoverageViolations is the fifth arm: every string-parameter
// method of a decorated interface must be overridden by name on its
// decorator. Missing one means the embedded value forwards it raw.
func bridgeDecoratorCoverageViolations(fset *token.FileSet, files []*ast.File) []string {
	interfaces := map[string][]string{}
	overrides := map[string]map[string]bool{}
	positions := map[string]token.Pos{}
	for _, file := range files {
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					ts, ok := spec.(*ast.TypeSpec)
					if !ok {
						continue
					}
					iface, ok := ts.Type.(*ast.InterfaceType)
					if !ok {
						continue
					}
					if _, wanted := bridgeCallbackDecorators[ts.Name.Name]; wanted {
						interfaces[ts.Name.Name] = interfaceStringParamMethods(iface)
						positions[ts.Name.Name] = ts.Pos()
					}
				}
			case *ast.FuncDecl:
				if d.Recv == nil || len(d.Recv.List) != 1 {
					continue
				}
				receiver := receiverTypeName(d.Recv.List[0].Type)
				if overrides[receiver] == nil {
					overrides[receiver] = map[string]bool{}
				}
				overrides[receiver][d.Name.Name] = true
			}
		}
	}
	var violations []string
	for name, decorator := range bridgeCallbackDecorators {
		methods, declared := interfaces[name]
		if !declared {
			violations = append(violations, fmt.Sprintf(
				"decorator registry names %s but no such interface is declared in the package", name))
			continue
		}
		for _, method := range methods {
			if !overrides[decorator][method] {
				violations = append(violations, fmt.Sprintf(
					"%s: %s.%s carries a string parameter but %s does not override it; the embedded value forwards it unsanitized",
					fset.Position(positions[name]), name, method, decorator))
			}
		}
	}
	sort.Strings(violations)
	return violations
}

func TestExportedErrorReturnsPassBridgeSafeError(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var files []*ast.File
	names := map[*ast.File]string{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(fset, filepath.Join(".", name), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files = append(files, parsed)
		names[parsed] = name
	}
	if len(files) == 0 {
		t.Fatal("no package sources found; the gate is aiming at nothing")
	}
	violations := bridgeReturnViolations(fset, files)
	violations = append(violations, bridgeStructuralViolations(fset, files, names)...)
	violations = append(violations, bridgeShapeBanViolations(fset, files)...)
	violations = append(violations, bridgeDecoratorCoverageViolations(fset, files)...)
	for _, v := range violations {
		t.Error(v)
	}
	if len(violations) > 0 {
		t.Errorf("%d exported bridge exits are unsanitized", len(violations))
	}
}

// The checker itself is under test: a gate that cannot see a planted violation
// is not a gate. Each fixture is a tiny source with a known verdict.
func TestBridgeGateCheckerSeesPlantedShapes(t *testing.T) {
	cases := []struct {
		name       string
		src        string
		violations int
	}{
		{"raw error return", `package p
func Exported() error { return doWork() }
func doWork() error { return nil }`, 1},
		{"wrapped return is compliant", `package p
func Exported() error { return bridgeSafeError(doWork()) }
func doWork() error { return nil }`, 0},
		{"nil literal is compliant", `package p
func Exported() error { return nil }`, 0},
		{"value and raw error", `package p
import "errors"
func Exported() (int, error) { return 0, errors.New("x") }`, 1},
		{"closure returns are not the boundary", `package p
func Exported() error {
	f := func() error { return doWork() }
	return bridgeSafeError(f())
}
func doWork() error { return nil }`, 0},
		{"bare return with named error", `package p
func Exported() (err error) { return }`, 1},
		{"direct multi-value call return", `package p
func Exported() (int, error) { return doWork() }
func doWork() (int, error) { return 0, nil }`, 1},
		{"unexported funcs are free", `package p
func internal() error { return doWork() }
func doWork() error { return nil }`, 0},
		{"method on exported receiver", `package p
type Box struct{}
func (b *Box) Fetch() error { return doWork() }
func doWork() error { return nil }`, 1},
		{"method on unexported receiver is free", `package p
type box struct{}
func (b *box) fetch() error { return doWork() }
func doWork() error { return nil }`, 0},
		{"raw string return", `package p
func Exported() string { return compute() }
func compute() string { return "" }`, 1},
		{"wrapped string return is compliant", `package p
func Exported() string { return bridgeSafeString(compute()) }
func compute() string { return "" }`, 0},
		{"string literal return is compliant", `package p
func Exported() string { return "constant" }`, 0},
		{"named string result is refused", `package p
func Exported() (s string) { s = "x"; return s }`, 1},
		{"string and error positions are checked independently", `package p
import "errors"
func Exported() (string, error) { return compute(), errors.New("x") }
func compute() string { return "" }`, 2},
	}
	for _, tc := range cases {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "fixture.go", tc.src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("%s: parse: %v", tc.name, err)
		}
		got := bridgeReturnViolations(fset, []*ast.File{file})
		if len(got) != tc.violations {
			t.Errorf("%s: want %d violations, got %d: %v", tc.name, tc.violations, len(got), got)
		}
	}
}
