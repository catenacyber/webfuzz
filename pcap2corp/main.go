package main

import (
	"bufio"
	"crypto/sha1"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/catenacyber/webfuzz/webfuzz"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Printf("Expects a pcap file, and output directory as arguments\n")
	}
	if handle, err := pcap.OpenOffline(os.Args[1]); err != nil {
		fmt.Printf("Unable to open pcap file\n")
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		//loop over packets
		for packet := range packetSource.Packets() {
			tcp := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
			if tcp != nil {
				//filter interesting packets
				if tcp.DstPort == 8065 && len(tcp.Payload) > 0 {
					req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(string(tcp.Payload))))
					if err != nil {
						fmt.Printf("Error reading request %s\n", err)
						continue
					}
					data, err := webfuzz.SerializeRequest(req)
					if err != nil {
						fmt.Printf("Failed serializing request\n")
						continue
					}
					fname := os.Args[2] + "/" + fmt.Sprintf("%x", sha1.Sum(data))
					err = ioutil.WriteFile(fname, data, 0644)
					if err != nil {
						fmt.Printf("Failed writing output file %s\n", fname)
						panic(err)
					}
				}
			}
		}
	}
}
