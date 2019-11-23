package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"syscall"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func main() {
	var portLow, portHigh int
	var ipAddr *net.IPAddr
	var source syscall.SockaddrInet4
	var addr string

	flag.StringVar(&addr, "addr", "", "addr")
	flag.IntVar(&portLow, "plow", 0, "port low")
	flag.IntVar(&portHigh, "phigh", 0, "port high")
	flag.Parse()

	if len(addr) == 0 {
		log.Fatalln("addr is required param")
	}

	if portLow > portHigh {
		log.Fatalln("plow > phigh")
	}

	ipAddr, err := net.ResolveIPAddr("ip4", addr)
	fmt.Println("dest ip:", ipAddr)
	if err != nil {
		log.Fatalln("resolve ip:", err)
	}

	sd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		log.Fatalln("socker error:", err)
	}

	ip, _ := externalIP()
	fmt.Println("source ip:", ip)

	source.Addr = [4]byte{ip[0], ip[1], ip[2], ip[3]}

	for port := portLow; port <= portHigh; port++ {
		fmt.Println("Port: ", port)
		sendPacket(sd, port, source, ipAddr)
		ok := recvPacket(sd)
		if ok {
			fmt.Printf("Open: %d\n", port)
		}
		break
	}
}

func recvPacket(sd int) bool {
	pid := layers.TCPPort(os.Getpid())

	recvbuf := make([]byte, 152)

	fmt.Println("recvfrom start")
	for {
		n, _, err := syscall.Recvfrom(sd, recvbuf, 0)
		if err != nil {
			log.Fatalln("Recvfrom() failed:", err)
		}

		if n < 0 {
			log.Fatalln("Recvfrom() failed")
		}

		p1 := gopacket.NewPacket(recvbuf, layers.LayerTypeTCP, gopacket.Default)
		tcpHdr := p1.Layer(layers.LayerTypeTCP).(*layers.TCP)

		fmt.Printf("From src port %d to dst port %d\n", tcpHdr.SrcPort, tcpHdr.DstPort)
		fmt.Println(tcpHdr.DstPort, pid)
		fmt.Println()

		if int(tcpHdr.DstPort) == int(pid) {
			return tcpHdr.SYN && tcpHdr.ACK
		}
	}
}

func sendPacket(sd int, port int, source syscall.SockaddrInet4, ipAddr *net.IPAddr) {
	var servAddr syscall.SockaddrInet4
	var tcpHdr layers.TCP

	type PseudoHdr struct {
		sourceAddress [4]byte
		destAddress   [4]byte
		placeHolder   int
		protocol      int
		length        int
		tcpHdr        layers.TCP
	}

	servAddr.Port = port
	servAddr.Addr = [4]byte{ipAddr.IP[0], ipAddr.IP[1], ipAddr.IP[2], ipAddr.IP[3]}

	//    type TCP struct {
	//		BaseLayer
	//		SrcPort, DstPort                           TCPPort
	//		Seq                                        uint32
	//		Ack                                        uint32
	//		DataOffset                                 uint8
	//		FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS bool
	//		Window                                     uint16
	//		Checksum                                   uint16
	//		Urgent                                     uint16
	//		sPort, dPort                               []byte
	//		Options                                    []TCPOption
	//		Padding                                    []byte
	//		opts                                       [4]TCPOption
	//		tcpipchecksum
	//    }
	//

	pid := os.Getpid()
	tcpHdr.SrcPort = layers.TCPPort(pid)
	tcpHdr.DstPort = layers.TCPPort(port)
	tcpHdr.Seq = uint32(pid + port)
	tcpHdr.Ack = 0
	tcpHdr.DataOffset = 5
	tcpHdr.FIN = false
	tcpHdr.SYN = true
	tcpHdr.RST = false
	tcpHdr.PSH = false
	tcpHdr.ACK = false
	tcpHdr.URG = false
	tcpHdr.ECE = false
	tcpHdr.CWR = false
	tcpHdr.Window = 128
	tcpHdr.Checksum = 0

	pseudoHdr := PseudoHdr{}
	pseudoHdr.sourceAddress = source.Addr
	pseudoHdr.destAddress = servAddr.Addr
	pseudoHdr.placeHolder = 0
	pseudoHdr.protocol = syscall.IPPROTO_TCP
	pseudoHdr.length = int(unsafe.Sizeof(tcpHdr))
	pseudoHdr.tcpHdr = tcpHdr

	var binPseudoHdr bytes.Buffer
	binary.Write(&binPseudoHdr, binary.BigEndian, pseudoHdr)
	tcpHdr.Checksum = checksum(binPseudoHdr.Bytes())

	var binTcpHdr bytes.Buffer
	binary.Write(&binTcpHdr, binary.BigEndian, tcpHdr)

	err := syscall.Sendto(sd, binTcpHdr.Bytes(), 0, &servAddr)
	if err != nil {
		log.Fatalln("Sendto() failed:", err)
	}
	fmt.Println("sendto ok")
}

func externalIP() (net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue // not an ipv4 address
			}
			return ip, nil
		}
	}
	return nil, errors.New("are you connected to the network?")
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
