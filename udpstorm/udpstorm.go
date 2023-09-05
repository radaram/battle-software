package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"flag"
	"log"
	"net"
	"syscall"
	"unsafe"
	
	"golang.org/x/net/ipv4"
	//"golang.org/x/net/icmp"

)


type pseudohdr struct {
	Src net.IP
	Dst net.IP
	PlaceHolder int
	Protocol int
	Length int
}

type udphdr struct {
    SrcPort  uint16
    DestPort uint16
    Length   uint16
    Checksum uint16
}


func (u *udphdr) checksum(ip *ipv4.Header) {
	u.Checksum = 0
	phdr := pseudohdr{
		Src: ip.Src,
		Dst: ip.Dst,
		PlaceHolder: 0,
		Protocol: ip.Protocol,
		Length: int(u.Length),
	}
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, &phdr)
	binary.Write(&b, binary.BigEndian, u)
	u.Checksum = checksum(b.Bytes())
}


func main() {
	const on = 1
	var srcAddr, dstAddr *net.IPAddr
	var sport, dport int
	var servAddr syscall.SockaddrInet4
	var udpHdr udphdr
	//pseudoHdr := pseudohdr{}

	srcAddrParam := flag.String("src", "", "src addr")
	srcPortParam := flag.Int("sp", 0, "src port")
	dstAddrParam := flag.String("dst", "", "dst addr")
	dstPortParam := flag.Int("dp", 0, "dst port")
    flag.Parse()
	
	if len(*srcAddrParam) == 0 {
		log.Fatalln("src is required param") 
	}
	
	if *srcPortParam == 0 {
		log.Fatalln("sp is required param")
	}
	
	if len(*dstAddrParam) == 0 {
		log.Fatalln("dst is required param") 
	}
	
	if *dstPortParam == 0 {
		log.Fatalln("dp is required param")
	}

	sd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		log.Fatalln("create socker error:", err)
	}

	srcAddr, err = net.ResolveIPAddr("ip4", *srcAddrParam)
	if err != nil {
        log.Fatalln("resolve ip:", err)
    }
	sport = *srcPortParam

	dstAddr, err = net.ResolveIPAddr("ip4", *dstAddrParam)
	if err != nil {
        log.Fatalln("resolve ip:", err)
    }
	dport = *dstPortParam

	servAddr = ip2sockaddr(dstAddr.IP.String(), dport)

	var ipHdr ipv4.Header
	ipTotalLen := int(unsafe.Sizeof(ipHdr)) + int(unsafe.Sizeof(udpHdr))
	ipHdr = createIPPkt(srcAddr.IP, dstAddr.IP, syscall.IPPROTO_UDP, ipTotalLen)
    

	udpTotalLen := int(unsafe.Sizeof(udpHdr))
    
	udpHdr = udphdr{
		SrcPort: uint16(sport),
		DestPort: uint16(dport),
		Length: uint16(udpTotalLen),
	}

	udpHdr.checksum(&ipHdr)

	fmt.Println(ipHdr)
	fmt.Println(udpHdr)	

	ipBytes, err := ipHdr.Marshal()
    if err != nil {
		log.Fatalln("ip header marsha:", err)
	}
	b := bytes.NewBuffer(ipBytes)

	err = binary.Write(b, binary.BigEndian, &udpHdr)
	if err != nil {
		log.Fatalf("error encoding the UDP header: %v\n", err)
	}
	bb := b.Bytes()

	for {
		fmt.Println("debug")
		err = syscall.Sendto(sd, bb, 0, &servAddr)
		if err != nil {
			log.Fatalln("Sendto() failed:", err)
		}
	}

}


func createIPPkt(srcAddr net.IP, dstAddr net.IP, protocol int, totalLen int) ipv4.Header {
	ipHdr := ipv4.Header{
		Version: 4,
		Len: 20,
		TOS: 0,
		TotalLen: totalLen,
		ID: 0,
		FragOff: 0,
		TTL: 255,
		Protocol: protocol,
		Checksum: 0,
		Src: srcAddr,
		Dst: dstAddr,
	}
	
	ipBytes, err := ipHdr.Marshal()
	if err != nil {
		log.Fatalln("ip header marshal:", err)
	}

    ipHdr.Checksum = int(checksum(ipBytes))
	
	return ipHdr
}


func checksum(b []byte) uint16 {
	csumcv := len(b) - 1 // checksum coverage
	s := uint32(0)
	for i := 0; i < csumcv; i += 2 {
		s += uint32(b[i+1])<<8 | uint32(b[i])
	}
	if csumcv&1 == 0 {
		s += uint32(b[csumcv])
	}
	s = s>>16 + s&0xffff
	s = s + s>>16
	return ^uint16(s)
}


func ip2sockaddr(ip string, optional ...int) syscall.SockaddrInet4 {
	addr := [4]byte{}
	fmt.Sscanf(ip, "%d.%d.%d.%d", &addr[0], &addr[1], &addr[2], &addr[3])

	port := 0

	if len(optional) > 0 {
    	port = optional[0]
    }

	return syscall.SockaddrInet4{
		Port: port,
		Addr: addr,
	}
}


