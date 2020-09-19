package webfuzz

//import "C"

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"unsafe"
)

const CoverSize = 0x10000

var CoverTab = new([CoverSize]byte)

var host = "http://localhost:8065/"

//export WebfuzzInitialize
func WebfuzzInitialize(coverTabPtr unsafe.Pointer, coverTabSize uint64) {
	if coverTabSize != CoverSize {
		panic("Incorrect cover tab size")
	}
	CoverTab = (*[CoverSize]byte)(coverTabPtr)
	content, err := ioutil.ReadFile("host.txt")
	if err == nil {
		host = strings.TrimRight(string(content), "\r\n")
	}
}

func unserializeRequest(input []byte) (*http.Request, error) {
	if len(input) < 2 {
		return nil, io.EOF
	}
	method := ""
	offset := 1
	switch input[0] {
	case 0:
		method = "GET"
	case 1:
		method = "POST"
	case 2:
		method = "PUT"
	case 3:
		method = "HEAD"
	default:
		offset = bytes.IndexByte(input[1:], ' ')
		if offset < 0 {
			return nil, io.EOF
		}
		method = string(input[1 : 1+offset])
		offset += 2
	}
	urilen := bytes.IndexByte(input[offset:], '\n')
	if urilen < 0 {
		return nil, io.EOF
	}
	uri := string(input[offset : offset+urilen])
	offset += urilen + 1
	hnames := make([]string, 0, 8)
	hvalues := make([]string, 0, 8)
	for offset < len(input) {
		//TODO allow LF and colon in headers
		hlen := bytes.IndexByte(input[offset:], '\n')
		if hlen < 0 {
			return nil, io.EOF
		} else if hlen == 0 {
			break
		}
		header := string(input[offset : offset+hlen])
		offset += hlen + 1
		nv := strings.Split(header, ":")
		if len(nv) != 2 {
			return nil, io.EOF
		}
		hnames = append(hnames, nv[0])
		hvalues = append(hvalues, nv[1])
	}
	req, err := http.NewRequest(method, host+uri, bytes.NewReader(input[offset:]))
	if err != nil {
		return req, err
	}
	for i := 0; i < len(hnames); i++ {
		req.Header.Add(hnames[i], hvalues[i])
	}
	return req, err
}

//export WebfuzzProcess
func WebfuzzProcess(input []byte) int {
	//show we have some coverage
	CoverTab[0]++
	req, err := unserializeRequest(input)
	if err != nil {
		return -1
	}
	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		//can happen with net/http: invalid header field name "\x00\x00\x00"
		return -2
	}

	computeCoverage(req, resp)

	resp.Body.Close()
	return 0
}

var seenCodes = new([512]bool)

func computeCoverage(req *http.Request, resp *http.Response) {
	//512 counters for status code coverage
	if resp.StatusCode >= 100 && resp.StatusCode < 611 {
		CoverTab[resp.StatusCode-99]++
		if !seenCodes[resp.StatusCode-99] {
			seenCodes[resp.StatusCode-99] = true
			fmt.Printf("NEW webfuzz status code %d\n", resp.StatusCode)
		}
	} else {
		panic(fmt.Sprintf("Unknown response code %d", resp.StatusCode))
	}

	//resp headers coverage

	if resp.StatusCode < 399 {
		//uri coverage
		//resp body coverage
	}
}

//func main() {}
