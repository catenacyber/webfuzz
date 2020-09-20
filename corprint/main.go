package main

import (
	"fmt"
"io/ioutil"
	"net/http/httputil"
	"os"
	"path/filepath"

	"github.com/catenacyber/webfuzz/webfuzz"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Expects only a directory as argument\n")
	}
	var files []string

	err := filepath.Walk(os.Args[1], func(path string, info os.FileInfo, err error) error {
		files = append(files, path)
		return nil
	})
	if err != nil {
		fmt.Printf("Error reading directory %s\n", err)
		panic(err)
	}
	for _, filename := range files {
		data, err := ioutil.ReadFile(filename)
		fmt.Printf("File %s\n", filename)
		if err != nil {
			fmt.Printf("Failed to read corpus file %s\n", err)
			continue
		}
		req, err := webfuzz.UnserializeRequest(data)
		if err != nil {
			fmt.Printf("Error for unserializing request %s\n", err)
			continue
		}
		rData, err := httputil.DumpRequest(req, true)
		if err != nil {
			fmt.Printf("Error for printing request %s\n", err)
			continue
		}
		fmt.Printf("Request:\n %q\n\n\n", rData)
	}
}
