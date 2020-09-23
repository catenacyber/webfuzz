package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Expects a go file as arguments\n")
	}

	// Create the AST by parsing src.
	fset := token.NewFileSet() // positions are relative to fset
	f, err := parser.ParseFile(fset, os.Args[1], nil, 0)
	if err != nil {
		panic(err)
	}

	// Inspect the AST and print all identifiers and literals.
	ast.Inspect(f, func(n ast.Node) bool {
		var s string
		switch x := n.(type) {
		case *ast.BasicLit:
			if x.Kind == token.STRING {
				s = x.Value
			}
		}
		if len(s) > 3 {
			name := fset.Position(n.Pos()).String()
			name = strings.Replace(name, ".go", "", 1)
			name = strings.ReplaceAll(name, ":", "_")
			fmt.Printf("%s=%s\n", name, s)
		}
		return true
	})
}
