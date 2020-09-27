package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"unicode"
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
		case *ast.GenDecl:
			if x.Tok == token.IMPORT {
				//exclude imported packages
				return false
			}
		}
		if len(s) > 4 {
			name := fset.Position(n.Pos()).String()
			name = strings.Replace(name, ".go", "", 1)
			name = strings.ReplaceAll(name, ":", "_")
			if s[0] != '"' || s[len(s)-1] != '"' {
				return true
			}
			if strings.Contains(s, "\\") {
				return true
			}
			for i := 0; i < len(s); i++ {
				if s[i] > unicode.MaxASCII {
					return false
				}
			}
			fmt.Printf("%s=%s\n", name, s)
		}
		return true
	})
}
