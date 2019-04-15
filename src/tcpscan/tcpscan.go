package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"
	"strconv"
	"strings"
	"honnef.co/go/netdb"
)


func main() {
	var port, portLow, portHigh int
    var proto *netdb.Protoent
    var serv *netdb.Servent
    var ipAddr *net.IPAddr
	var fullAddr string

	proto = netdb.GetProtoByName("tcp")
    
	addrParam := flag.String("addr", "", "addr")
	portLowParam := flag.Int("plow", 0, "port low")
	portHighParam := flag.Int("phigh", 0, "port high")
    flag.Parse()
	
	if len(*addrParam) == 0 {
		log.Fatalln("addr is required param") 
	}
	
	if *portLowParam > *portHighParam {
		log.Fatalln("plow > phigh")
	}
	
	portLow = *portLowParam
	portHigh = *portHighParam
   
	ipAddr, err := net.ResolveIPAddr("ip4", *addrParam)
	if err != nil {
        log.Fatalln("resolve ip:", err)
    }
     
	fmt.Fprintf(os.Stderr, "Running scan...\n")

    for port = portLow; port <= portHigh; port ++ {
		fullAddr = strings.Join([]string{ipAddr.IP.String(), strconv.Itoa(port)}, ":")
        fmt.Println(fullAddr)

	    conn, err := net.DialTimeout("tcp", fullAddr, time.Second)
		if err != nil {
			log.Println(err)
			continue
		}

		defer conn.Close()
		
		serv = netdb.GetServByPort(port, proto)
		if serv.Port > 0 {
			fmt.Printf("Open: %d (%s)\n", port, serv.Name)
		} else {
			fmt.Printf("Open: %d (unknown)\n", port)
		}
	}
}

