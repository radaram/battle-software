package main

import (
	"bytes"
	"flag"
	"fmt"
	"errors"
	"log"
	"net"
	"os"
	"syscall"
	"encoding/binary"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/icmp"
)

const BUFSIZE = 1500
const MAX_TTL = 30  // maximum ttl field value
const NPROBES = 3   // number of trial packages
const DPORT   = 32768 + 666  // receiver's initial port
const PROTOCOL_ICMP = 1
const ICMP_TIMXCEED_INTRANS = 0
const ICMP_UNREACH_PORT = 3

var recvfd int  // raw socket descriptor for receiving icmp messages
var sport  int

var sasend syscall.SockaddrInet4  // package sending structure
var sabind syscall.SockaddrInet4  // sender port binding structure
var hostIP net.IP
var lastHostIP net.IP

var tvrecv syscall.Timeval 


// data structure UDP
type outdata struct {
	outdata_seq int  // serial number
	outdata_ttl int  // TTL value with which the packet is sent
	outdata_tv syscall.Timeval  // package sending time
}


type UDP struct {
    SrcPort  uint16
    DestPort uint16
    Length   uint16
    Checksum uint16
}

func (udp *UDP) Decode(data []byte, ) error {
	if len(data) < 8 {
		return fmt.Errorf("Invalid UDP header. Length %d less than 8", len(data)) 
	}

	udp.SrcPort = binary.BigEndian.Uint16(data[0:2])
	udp.DestPort = binary.BigEndian.Uint16(data[2:4])
	udp.Length = binary.BigEndian.Uint16(data[4:6])
	udp.Checksum = binary.BigEndian.Uint16(data[6:8])

	return nil
}


func main() {
	host := flag.String("host", "", "hostname")
	flag.Parse()

	hp, err := getHostByName(*host)

	if err != nil {
		panic(err)
	}

    //raw-socket for receiving ICMP-messages
	recvfd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
    
	if err != nil {
   		panic(err)
	}

	// datagram socket for sending UDP-packets
	sendfd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)

	if err != nil {
		panic(err)
	}

    PID := os.Getpid()

	sport = (PID & 0xffff) | 0x8000
    
	sasend = ip2sockaddr(hp)
    
	sabind.Port = sport
	err = syscall.Bind(sendfd, &sabind)
	if err != nil {
		panic(err)
	}

	seq := 0
	done := 0

	sendbuf := make([]byte, 256)

	for ttl := 1; ttl <= MAX_TTL && done == 0; ttl++ {
    	syscall.SetsockoptInt(sendfd, syscall.SOL_IP, syscall.IP_TTL, ttl)

		fmt.Printf("%2d  ", ttl)

		for probe := 0; probe < NPROBES; probe++ {
			seq++
			outData := outdata{
				outdata_seq: seq,
				outdata_ttl: ttl,
			}

			syscall.Gettimeofday(&outData.outdata_tv)

			sasend.Port = DPORT + seq 

			err := syscall.Sendto(sendfd, sendbuf, 0, &sasend) 
            if err != nil {
				log.Fatalln("Sendto: ", err)
			}

			code, hostIP := packetOk(seq, &tvrecv)

			if code == -3 {
				fmt.Printf(" *")  // timeout, no response
			} else {
				if !bytes.Equal(hostIP[:], lastHostIP[:]) {
					fmt.Printf(" %s", hostIP)
					lastHostIP = hostIP
				}
                
				tvSub(&tvrecv, &outData.outdata_tv)
				rtt := float32(tvrecv.Sec) * 1000 + float32(tvrecv.Usec) / 1000
                
				fmt.Printf("  %.3f ms", rtt)

				if code == -1 {
					done++
				}
			}

		}

		fmt.Printf("\n")
	}

}


func tvSub(out *syscall.Timeval, in *syscall.Timeval) {
	/** subtracting two timeval structures **/
	out.Usec -= in.Usec
	if out.Usec < 0 {
		out.Sec -= 1
		out.Usec += 1000000
	}

	out.Sec -= in.Sec
}


func getHostByName(name string) (string, error) {
	hp, err := net.LookupHost(name)
	if err != nil {
		return "", err
	}
	if len(hp) == 0 {
		return "", errors.New("Host receive error")
	}
	return hp[0], nil
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

func packetOk(seq int, tv *syscall.Timeval) (int, net.IP) {
	var n int
	fds := &syscall.FdSet{}
	wait := &syscall.Timeval{}
	wait.Sec = 4  //wait for a response no more than 4 seconds
	wait.Usec = 0
    
	recvbuf := make([]byte, 256)

	for {
		FD_ZERO(fds)
		FD_SET(fds, recvfd)
		
		res, err := syscall.Select(recvfd+1, fds, nil, nil, wait)
		if err != nil {
			log.Fatalln(err)
		}

		if res > 0 {
			n, _, err = syscall.Recvfrom(recvfd, recvbuf, 0)
			if err != nil {
				log.Fatalln(err)
	    	}
		} else if !FD_ISSET(fds, recvfd) {
			return -3, nil  // timeout
		} else {
			log.Fatalln("recvfrom() failed")
		}

		syscall.Gettimeofday(tv)
		
		ip, _ := ipv4.ParseHeader(recvbuf)
		
		icmp, err := icmp.ParseMessage(PROTOCOL_ICMP, recvbuf[ip.Len: n]) 
	    if err != nil {
			log.Fatalln(err)
		}

		hip, err := ipv4.ParseHeader(recvbuf[ip.Len + 8: n])

		udp := UDP{}
        
		err = udp.Decode(recvbuf[ip.Len + 8 + hip.Len: n])
		if err != nil {
			log.Fatalln(err)
		}


		if icmp.Type == ipv4.ICMPTypeTimeExceeded && icmp.Code == ICMP_TIMXCEED_INTRANS {
			if hip.Protocol == syscall.IPPROTO_UDP && int(udp.SrcPort) == sport && int(udp.DestPort) == DPORT + seq {
				return -2, ip.Src
			}
			
		}


		if icmp.Type == ipv4.ICMPTypeDestinationUnreachable && icmp.Code == ICMP_UNREACH_PORT {
			if hip.Protocol == syscall.IPPROTO_UDP && int(udp.SrcPort) == sport && int(udp.DestPort) == DPORT + seq {
				return -1, ip.Src
			}
		}
	}
}

func FD_SET(p *syscall.FdSet, i int) {
	p.Bits[i/64] |= 1 << uint(i) % 64
}

func FD_ISSET(p *syscall.FdSet, i int) bool {
	return (p.Bits[i/64] & (1 << uint(i) % 64)) != 0
}

func FD_ZERO(p *syscall.FdSet) {
	for i := range p.Bits {
		p.Bits[i] = 0
	}
}
