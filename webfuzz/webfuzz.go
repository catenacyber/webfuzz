package webfuzz

import (
	"bufio"
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

var host = "http://localhost:8065/"

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

func UnserializeRequest(input []byte) (*http.Request, error) {
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(string(input))))
	if err != nil {
		return nil, err
	}
	req2, err := http.NewRequest(req.Method, host+req.RequestURI[1:], req.Body)
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
		fmt.Printf("fail1 %s\n", err)
		return -1
	}
	if debug {
		rData, err := httputil.DumpRequest(req, true)
		if err == nil {
			fmt.Printf("request %q\n", rData)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		//can happen with net/http: invalid header field name "\x00\x00\x00"
		fmt.Printf("fail2 %s\n", err)
		return -2
	}

	computeCoverage(req, resp, client)
	io.Copy(ioutil.Discard, resp.Body)
	resp.Body.Close()
	return 0
}

var seenCodes = new([512]bool)
var reproducibleHeaders = map[string]bool{}
var alreadyCovered = new([65536]bool)

func computeCoverage(req *http.Request, resp *http.Response, client *http.Client) {
	//specific bypass
	if resp.ContentLength == 3556 {
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
	hoffset := uint32(512)

	//resp headers names coverage
	reproduce := false
	for name, _ := range resp.Header {
		h := crc32.ChecksumIEEE([]byte(name))
		CoverTab[hoffset+(h&0xFFF)]++
		_, seen := reproducibleHeaders[name]
		if !seen {
			fmt.Printf("NEW webfuzz header %s\n", name)
			reproduce = true
		}
	}
	hoffset += 0x1000

	if reproduce {
		resp2, err := client.Do(req)
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
			CoverTab[hoffset+(h&0xFFF)]++
			cov := alreadyCovered[hoffset+(h&0xFFF)]
			if !cov {
				alreadyCovered[hoffset+(h&0xFFF)] = true
				fmt.Printf("Adding for header %s value %s\n", name, value)
			}
		}
	}
	hoffset += 0x1000

	if resp.StatusCode < 300 {
		//uri coverage
		uri := strings.Split(req.URL.Path, "/")
		i := 0
		for _, p := range uri {
			if len(p) == 0 {
				break
			}
			h := crc32.ChecksumIEEE([]byte(strconv.Itoa(i) + p))
			i++
			CoverTab[hoffset+(h&0x3FFF)]++
			cov := alreadyCovered[hoffset+(h&0x3FFF)]
			if !cov {
				alreadyCovered[hoffset+(h&0x3FFF)] = true
				fmt.Printf("Adding for uri %s (%s) status %d\n", req.URL.Path, p, resp.StatusCode)
			}

		}
		hoffset += 0x4000
		if req.Method != "HEAD" {
			//resp body coverage
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				fmt.Printf("Cannot read response body : %s", err)
				panic(fmt.Sprintf("Cannot read response body : %s", err))
			}
			hu := crc32.ChecksumIEEE([]byte(req.URL.Path))
			hb := crc32.ChecksumIEEE(body)
			CoverTab[hoffset+((hu^hb)&0x7FFF)]++
			hoffset += 0x8000
		}
	} else if resp.StatusCode >= 500 {
		fmt.Printf("Server crashed with %d", resp.StatusCode)
		panic(fmt.Sprintf("Server crashed with %d", resp.StatusCode))
	}
}
