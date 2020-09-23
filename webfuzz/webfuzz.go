package webfuzz

import (
	"bufio"
	"bytes"
	"fmt"
	"hash/crc32"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"time"
	"unsafe"
)

const CoverSize = 0x10000

var CoverTab = new([CoverSize]byte)

var host = "http://localhost:8065"

var client *http.Client

var debug = false

func WebfuzzInitialize(coverTabPtr unsafe.Pointer, coverTabSize uint64) {
	if coverTabSize != CoverSize {
		panic("Incorrect cover tab size")
	}
	CoverTab = (*[CoverSize]byte)(coverTabPtr)
	client = &http.Client{
		Transport: &http.Transport{
			MaxIdleConnsPerHost: 4,
		},
		Timeout: time.Duration(3) * time.Second,
	}
	content, err := ioutil.ReadFile("host.txt")
	if err == nil {
		host = strings.TrimRight(string(content), "\r\n")
	}
}

func SerializeRequest(req *http.Request) ([]byte, error) {
	req.Host = ""
	rData, err := httputil.DumpRequest(req, true)
	return rData, err
}

func uriNorm(u string) string {
	r := strings.ReplaceAll(u, "/./", "/")
	l := len(r)
	for {
		r = strings.ReplaceAll(r, "//", "/")
		if len(r) >= l {
			break
		}
		l = len(r)
	}
	return r
}

func UnserializeRequest(input []byte) (*http.Request, error) {
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(string(input))))
	if err != nil {
		return nil, err
	}
	req2, err := http.NewRequest(req.Method, host+uriNorm(req.RequestURI), req.Body)
	if err != nil {
		return nil, err
	}
	for name, _ := range req.Header {
		if name != "Content-Length" {
			req2.Header.Add(name, req.Header.Get(name))
		}
	}
	return req2, err
}

func WebfuzzProcess(input []byte) int {
	//show we have some coverage
	CoverTab[0]++
	req, err := UnserializeRequest(input)
	if err != nil {
		return -1
	}
	if debug {
		rData, err := httputil.DumpRequest(req, true)
		if err == nil {
			fmt.Printf("request %q\n", rData)
		}
	}
	var rdr2 io.ReadCloser
	if req.Body != nil {
		buf, err := ioutil.ReadAll(req.Body)
		if err != nil {
			req.Body = nil
		} else {
			rdr1 := ioutil.NopCloser(bytes.NewBuffer(buf))
			rdr2 = ioutil.NopCloser(bytes.NewBuffer(buf))
			req.Body = rdr1
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		//can happen with net/http: invalid header field name "\x00\x00\x00"
		return -2
	}
	CoverTab[0xFFFF]++

	computeCoverage(req, resp, client, rdr2)
	io.Copy(ioutil.Discard, resp.Body)
	resp.Body.Close()
	return 0
}

var seenCodes = new([512]bool)
var reproducibleHeaders = map[string]bool{}
var alreadyCovered = new([65536]bool)
var validUris = map[string]bool{}

func computeCoverage(req *http.Request, resp *http.Response, client *http.Client, rdr io.ReadCloser) {
	//specific bypass
	if resp.ContentLength == 3556 || resp.ContentLength < 0 {
		return
	}
	//512 counters for status code coverage
	if resp.StatusCode >= 100 && resp.StatusCode < 611 {
		CoverTab[resp.StatusCode-99]++
		if !seenCodes[resp.StatusCode-99] {
			seenCodes[resp.StatusCode-99] = true
			fmt.Printf("NEW webfuzz status code %d\n", resp.StatusCode)
		}
	} else {
		fmt.Printf("Unknown response code %d\n", resp.StatusCode)
		panic(fmt.Sprintf("Unknown response code %d", resp.StatusCode))
	}

	//resp headers names coverage
	reproduce := false
	for name, _ := range resp.Header {
		h := crc32.ChecksumIEEE([]byte(name))
		CoverTab[h&0xFFFF]++
		_, seen := reproducibleHeaders[name]
		if !seen {
			fmt.Printf("NEW webfuzz header %s\n", name)
			reproduce = true
		}
	}

	if reproduce {
		req.Body = rdr
		resp2, err := client.Do(req)
		io.Copy(ioutil.Discard, resp2.Body)
		resp2.Body.Close()
		if err != nil {
			fmt.Printf("Cannot reproduce request : %s\n", err)
			for name, _ := range resp.Header {
				reproducibleHeaders[name] = false
			}
			return
		}
		for name, _ := range resp.Header {
			_, seen := reproducibleHeaders[name]
			v1 := resp.Header.Get(name)
			v2 := resp2.Header.Get(name)
			if !seen {
				switch name {
				case "Date", "Content-Length":
					reproducibleHeaders[name] = false
				default:
					reproducibleHeaders[name] = (v1 == v2)
				}
			}
		}
	}

	//resp headers values coverage
	for name, _ := range resp.Header {
		repro, seen := reproducibleHeaders[name]
		if seen && repro {
			value := resp.Header.Get(name)
			h := crc32.ChecksumIEEE([]byte(name + ":" + value))
			CoverTab[h&0xFFFF]++
			cov := alreadyCovered[h&0xFFFF]
			if !cov {
				alreadyCovered[h&0xFFFF] = true
				fmt.Printf("Adding for header %s value %s\n", name, value)
			}
		}
	}

	_, validu := validUris[req.URL.Path]
	if resp.StatusCode < 300 || validu {
		if resp.StatusCode == 200 && !validu {
			fmt.Printf("New valid uri %s\n", req.URL.Path)
			validUris[req.URL.Path] = true
		}
		//uri coverage
		uri := strings.Split(req.URL.Path, "/")
		i := 0
		for _, p := range uri {
			if len(p) == 0 {
				break
			}
			h := crc32.ChecksumIEEE([]byte(strconv.Itoa(i) + p))
			i++
			CoverTab[h&0xFFFF]++
			cov := alreadyCovered[h&0xFFFF]
			if !cov {
				alreadyCovered[h&0xFFFF] = true
				fmt.Printf("Adding for uri %s (%s) status %d\n", req.URL.Path, p, resp.StatusCode)
			}

		}
		hu := crc32.ChecksumIEEE([]byte(req.URL.Path))
		hr := crc32.ChecksumIEEE([]byte(resp.Status))
		CoverTab[(hu^hr)&0xFFFF]++
		for name, _ := range resp.Header {
			hh := crc32.ChecksumIEEE([]byte(name))
			CoverTab[(hu^hh)&0xFFFF]++
		}
		/*if req.Method != "HEAD" && resp.StatusCode < 300 {
			//resp body coverage
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				fmt.Printf("Cannot read response body : %s", err)
				panic(fmt.Sprintf("Cannot read response body : %s", err))
			}
			hb := crc32.ChecksumIEEE(body)
			CoverTab[(hu^hb)&0xFFFF]++
		}*/
	} else if resp.StatusCode == 500 {
		fmt.Printf("Server crashed with %d", resp.StatusCode)
		panic(fmt.Sprintf("Server crashed with %d", resp.StatusCode))
	}
}
