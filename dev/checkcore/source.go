package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"slices"
	"strconv"
	"strings"
)

type packageInfo struct {
	Category string   `json:"category"`
	Lines    int      `json:"lines"`
	Imports  []string `json:"imports"`
	Exports  []string `json:"exports"`
	Globals  []string `json:"globals"`
}

type inventory struct {
	Totals     map[string]int          `json:"totals"`
	Packages   map[string]*packageInfo `json:"packages"`
	Modules    []string                `json:"modules"`
	Violations []string                `json:"boundary_violations"`
}

func lines(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	n := bytes.Count(data, []byte("\n"))
	if data[len(data)-1] != '\n' {
		n++
	}
	return n
}

func category(name string) string {
	switch {
	case within(name, "dev"):
		return "tooling"
	case within(name, "cmd") || packages[name].Role == product:
		return "application"
	case packages[name].Role == protocol:
		return "protocols"
	default:
		return "core"
	}
}

func unique(values []string) []string {
	if values == nil {
		return []string{}
	}
	slices.Sort(values)
	return slices.Compact(values)
}

// inspect parses every source file, regardless of build constraints. Generated
// code obeys the same boundaries; tests have their own metrics and may cross them.
func inspect(files map[string][]byte, rules map[string]rule) inventory {
	out := inventory{Totals: map[string]int{}, Packages: map[string]*packageInfo{}}
	for _, metric := range []string{"core", "protocols", "application", "tooling", "tests", "generated_go", "policy", "production_runtime_go"} {
		out.Totals[metric] = 0
	}
	for filename, data := range files {
		if path.Base(filename) == "go.mod" {
			out.Modules = append(out.Modules, path.Dir(filename))
			continue
		}
		if strings.HasSuffix(filename, ".rego") {
			out.Totals["policy"] += lines(data)
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), filename, data, parser.ParseComments)
		if err != nil {
			out.Violations = append(out.Violations, err.Error())
			continue
		}
		name := path.Dir(filename)
		r, known := rules[name]
		test := strings.HasSuffix(filename, "_test.go")
		kind := category(name)
		if ast.IsGenerated(f) {
			kind = "generated_go"
		} else if test {
			kind = "tests"
		}
		out.Totals[kind] += lines(data)
		if rules != nil {
			if !known {
				out.Violations = append(out.Violations, filename+": package is outside the approved dependency graph")
			} else if f.Name.Name != r.packageName(name) && !(test && f.Name.Name == r.packageName(name)+"_test") {
				out.Violations = append(out.Violations, filename+": expected package "+r.packageName(name))
			}
		}
		if test {
			continue
		}
		p := out.Packages[name]
		if p == nil {
			p = &packageInfo{Category: category(name)}
			out.Packages[name] = p
		}
		if !ast.IsGenerated(f) {
			p.Lines += lines(data)
		}
		aliases := map[string]string{}
		for _, imp := range f.Imports {
			dependency, _ := strconv.Unquote(imp.Path.Value)
			p.Imports = append(p.Imports, dependency)
			alias := path.Base(dependency)
			if imp.Name != nil {
				alias = imp.Name.Name
			}
			aliases[alias] = dependency
			if rules != nil {
				if alias == "." {
					out.Violations = append(out.Violations, filename+": dot imports obscure package ownership")
				}
				if reason := checkImport(name, dependency, rules); reason != "" {
					out.Violations = append(out.Violations, filename+": "+reason)
				}
			}
		}
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if rules != nil && !r.composes() && d.Recv == nil && d.Name.Name == "init" {
					out.Violations = append(out.Violations, filename+": implicit initialization belongs to an application")
				}
				if rules != nil && name == "core/facts" && d.Recv != nil && d.Name.Name == "Resolve" {
					out.Violations = append(out.Violations, filename+": facts must not resolve application access")
				}
				if ast.IsExported(d.Name.Name) {
					symbol := d.Name.Name
					if d.Recv != nil {
						symbol = typeName(d.Recv.List[0].Type) + "." + symbol
					}
					p.Exports = append(p.Exports, symbol)
				}
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch s := spec.(type) {
					case *ast.TypeSpec:
						if rules != nil && name == "core/facts" && slices.Contains([]string{"Label", "Context", "Vocabulary", "Obligations"}, s.Name.Name) {
							out.Violations = append(out.Violations, filename+": facts must not define the application's access model")
						}
						if ast.IsExported(s.Name.Name) {
							p.Exports = append(p.Exports, s.Name.Name)
							var fields *ast.FieldList
							switch t := s.Type.(type) {
							case *ast.StructType:
								fields = t.Fields
							case *ast.InterfaceType:
								fields = t.Methods
							}
							if fields != nil {
								for _, field := range fields.List {
									names := field.Names
									if len(names) == 0 {
										names = []*ast.Ident{{Name: typeName(field.Type)}}
									}
									for _, n := range names {
										if ast.IsExported(n.Name) {
											p.Exports = append(p.Exports, s.Name.Name+"."+n.Name)
										}
									}
								}
							}
						}
					case *ast.ValueSpec:
						for _, n := range s.Names {
							if ast.IsExported(n.Name) {
								p.Exports = append(p.Exports, n.Name)
							}
							if d.Tok == token.VAR && n.Name != "_" {
								p.Globals = append(p.Globals, n.Name)
							}
						}
					}
				}
			}
		}
		if rules != nil && !r.composes() {
			ast.Inspect(f, func(node ast.Node) bool {
				selector, ok := node.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				id, ok := selector.X.(*ast.Ident)
				if !ok || id.Obj != nil { // A local variable may shadow an import.
					return true
				}
				dependency, member := aliases[id.Name], selector.Sel.Name
				if dependency == "os" && slices.Contains([]string{"Args", "Environ", "ExpandEnv", "Getenv", "LookupEnv", "Setenv", "Unsetenv", "Clearenv", "Exit"}, member) ||
					dependency == "log" && (strings.HasPrefix(member, "Fatal") || strings.HasPrefix(member, "Panic")) {
					out.Violations = append(out.Violations, fmt.Sprintf("%s: process configuration or exit belongs to an application: %s.%s", filename, dependency, member))
				}
				return true
			})
		}
	}
	for _, p := range out.Packages {
		p.Imports, p.Exports, p.Globals = unique(p.Imports), unique(p.Exports), unique(p.Globals)
	}
	out.Totals["production_runtime_go"] = out.Totals["core"] + out.Totals["protocols"] + out.Totals["application"]
	out.Modules, out.Violations = unique(out.Modules), unique(out.Violations)
	return out
}

func typeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return typeName(t.X)
	case *ast.IndexExpr:
		return typeName(t.X)
	case *ast.IndexListExpr:
		return typeName(t.X)
	case *ast.SelectorExpr:
		return t.Sel.Name
	}
	return ""
}
