package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const ON = 1
const MSG_SIZE = 64
const PROTOCOL_ICMP = 1

var sockaddr syscall.SockaddrInet4

var MESSAGE_ID int = rand.Intn(65535)
var nreceived int = 0          // number of packets received
var tmin float32 = 999999999.0 // minimum time of treatment
var tmax float32 = 0           // maximum time of treatment
var tsum float32 = 0           // sum of all times to calculate average time
var nsent = 0                  // number of packets sent

type packet struct {
	bytes  []byte
	nbytes int
}

func main() {
	host := flag.String("host", "", "hostname")
	flag.Parse()

	hp, err := getHostByName(*host)
	log.Println(hp)

	if err != nil {
		panic(err)
	}

	// processing completion of the program through CTRL+C
	chSignal := make(chan os.Signal)
	signal.Notify(chSignal, os.Interrupt, syscall.SIGTERM)
	go handlerSignal(chSignal)

	sockaddr = ip2sockaddr(hp)

	sd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)

	if err != nil {
		panic(err)
	}

	// enable ability to send broadcast messages
	syscall.SetsockoptInt(sd, syscall.SOL_SOCKET, syscall.SO_BROADCAST, ON)

	//increase the size of receiving buffer
	size := 60 * 1024
	syscall.SetsockoptInt(sd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, size)

	// start the interval timer
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	// sending packages
	go catcher(sd, sockaddr, *ticker)

	fd, _ := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)

	recvbuf := make([]byte, MSG_SIZE)
	tval := syscall.Timeval{}

	for {
		// receiving packages
		n, _, err := syscall.Recvfrom(fd, recvbuf, 0)
		if err != nil {
			panic(err)
		}

		if n < 0 {
			continue
		}

		// determine current system time
		syscall.Gettimeofday(&tval)

		// parsing of received packet
		output(recvbuf, n, PROTOCOL_ICMP, &tval)
	}

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

func pinger(sd int, addr syscall.SockaddrInet4) {
	/** sending a package **/
	p := pkt(addr)
	log.Println("ping")
	err := syscall.Sendto(sd, p, 0, &addr)
	if err != nil {
		log.Println("Sendto:", err)
	}
}

func pkt(addr syscall.SockaddrInet4) []byte {
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

	h := ipv4.Header{
		Version:  4,
		Len:      20,
		TotalLen: 20 + 10, // 20 bytes for IP, 10 for ICMP
		TTL:      64,
		Protocol: PROTOCOL_ICMP, // ICMP
		Dst:      net.IPv4(addr.Addr[0], addr.Addr[1], addr.Addr[1], addr.Addr[2]),
	}

	tv := &syscall.Timeval{}
	// determine current system time
	syscall.Gettimeofday(tv)

	var bin_buf bytes.Buffer
	binary.Write(&bin_buf, binary.BigEndian, *tv)

	nsent += 1

	body := &icmp.Echo{
		ID:   MESSAGE_ID,
		Seq:  nsent,
		Data: bin_buf.Bytes(),
	}

	data := &icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: body,
	}

	out, err := h.Marshal()
	if err != nil {
		log.Fatalln(err)
	}

	icmp, err := data.Marshal(nil)
	if err != nil {
		log.Fatalln(err)
	}

	return append(out, icmp...)
}

func catcher(sd int, addr syscall.SockaddrInet4, ticker time.Ticker) {
	/** signal processing of the timer and sending of ping **/
	for {
		<-ticker.C
		pinger(sd, addr)
	}
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

func output(buf []byte, len int, protocol int, tvrecv *syscall.Timeval) {
	/** Parsing a package and displaying a data **/

	var rtt float32
	h, _ := ipv4.ParseHeader(buf)

	if h.Len < 8 {
		log.Fatalln("icmplen %d < 8", h.Len)
	}

	var m *icmp.Message
	m, err := icmp.ParseMessage(protocol, buf[h.Len:len])
	if err != nil {
		log.Fatalln(err)
	}

	if m.Type != ipv4.ICMPTypeEcho {
		log.Fatalln("ICMP TYPE does not match")
		return
	}

	body := m.Body.(*icmp.Echo)

	if body.ID != MESSAGE_ID {
		log.Println("MESSAGE ID does not match")
		return
	}

	tvsend := &syscall.Timeval{}

	r := bytes.NewReader(body.Data)
	err = binary.Read(r, binary.BigEndian, tvsend)
	if err != nil {
		log.Fatalln(err)
	}

	tvSub(tvrecv, tvsend)

	rtt = float32(tvrecv.Sec)*1000.0 + float32(tvrecv.Usec)/1000.0

	nreceived += 1

	tsum += rtt
	if rtt < tmin {
		tmin = rtt
	}

	if rtt > tmax {
		tmax = rtt
	}

	fmt.Printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.3f ms\n", h.Len, h.Dst, body.Seq, h.TTL, rtt)

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

func handlerSignal(c chan os.Signal) {
	<-c
	fmt.Printf("\n--- %s ping statistics --- \n", sockaddr.Addr[:])
	fmt.Printf("%d packets transmitted, ", nsent)
	fmt.Printf("%d packets received, ", nreceived)

	if nsent > 0 {
		if nreceived > nsent {
			fmt.Printf("-- somebody's printing up packets!")
		} else {
			fmt.Printf("%d%% packet loss", int(((nsent-nreceived)*100)/nsent))
		}
	}

	fmt.Printf("\n")

	if nreceived > 0 {
		fmt.Printf("round-trip min/avg/max = %.3f/%.3f/%.3f ms\n", tmin, tsum/float32(nreceived), tmax)

	}
	os.Exit(1)
}
