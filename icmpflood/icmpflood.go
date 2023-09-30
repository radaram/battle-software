package main

import (
	"flag"
	"fmt"
	"golang.org/x/net/ipv4"
	"log"
	"math/rand"
	"net"
	"strconv"
	"strings"
    "os"
    "os/signal"
	"syscall"
    "time"
)


func main() {
    var srcAddr net.IP
	var dstAddr net.IP
	var randIP string
	var servAddr syscall.SockaddrInet4

    // Получение аргумента для указания адреса назначения
	dstParam := flag.String("dst", "", "dst addr")
	flag.Parse()

	if len(*dstParam) == 0 {
		log.Fatalln("dst is required param")
	}

    // Создание "сырого" сокета
	sd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		log.Fatalln("Failed to create raw socket: %s\n", err)
	}
    defer syscall.Close(sd)

	err = syscall.SetsockoptInt(sd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
        log.Fatalln("Failed to set socket options: %v\n", err)
	}

	err = syscall.SetsockoptInt(sd, syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)

	if err != nil {
		log.Fatalln("Failed to set socket options: %v\n", err)
	}

    dstAddr = net.ParseIP(*dstParam)
	if dstAddr == nil {
        log.Fatalln("Failed to parse ip:", *dstParam)
	}
    
    // Конвертация IP в Sockaddr
	servAddr = ip2sockaddr(dstAddr.String())

    signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT)

    // Бесконечный цикл отправки пакетов
    for {
		select {
        case <-signalChannel:
            // Выход по получении SIGINT
            fmt.Println("Received SIGINT, exiting...")
            syscall.Close(sd)
            return
        default:
            // Генерация случайного IP
            randIP = randomIP4()
            srcAddr = net.ParseIP(randIP)
            if srcAddr == nil {
                log.Fatalln("Failed to parse ip:", randIP)
            }
            
            // Создание и отправка пакета
            pkt := createPkt(dstAddr)

            fmt.Println(srcAddr, dstAddr)
            err = syscall.Sendto(sd, pkt, 0, &servAddr)
            if err != nil {
                log.Fatalln("Sendto() failed:", err)
            }
		}
	}
}


// Функция для конвертации IP-адреса в Sockaddr
func ip2sockaddr(ip string) syscall.SockaddrInet4 {
	addr := [4]byte{}
	fmt.Sscanf(ip, "%d.%d.%d.%d", &addr[0], &addr[1], &addr[2], &addr[3])
	sockAddr := syscall.SockaddrInet4{
		Port: 0,
		Addr: addr,
	}

	return sockAddr
}


// Функция для генерации случайного IP-адреса
func randomIP4() string {
	rand.Seed(time.Now().UnixNano())
	blocks := []string{}
	for i := 0; i < 4; i++ {
		number := rand.Intn(255)
		blocks = append(blocks, strconv.Itoa(number))
	}

	return strings.Join(blocks, ".")
}


// Функция для создания пакета
func createPkt(dstAddr net.IP) []byte {
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
		Version:  4,  // Версия протокола IPv4
		Len:      20,  // Длина заголовка
		TotalLen: 20 + 10,  // Общая длина пакета
        TTL:      64,  // Время жизни пакета
		Protocol: 1,  // Протокол (ICMP)
		Dst:      dstAddr,  // Адрес назначения
	}
    
    // Создание ICMP-сообщения	
    icmp := []byte{
        8,  // тип: эхо-запрос
        0,  // код: не используется эхо-запросом
        0,  // контрольная сумма (16 бит), заполним ниже
        0,
        0,  // идентификатор (16 бит). допускается ноль
        0,
        0,  // порядковый номер (16 бит). допускается ноль
        0,
        0xC0,  // Дополнительные данные. ping помещает сюда время отправки пакета
        0xDE,
    }

    // Вычисление контрольной суммы
	cs := csum(icmp)
	icmp[2] = byte(cs)
	icmp[3] = byte(cs >> 8)

    // Объединение заголовка IP и ICMP
	out, err := h.Marshal()
	if err != nil {
		log.Fatal(err)
	}
	return append(out, icmp...)
}


// Функция для вычисления контрольной суммы
func csum(b []byte) uint16 {
	var s uint32
	for i := 0; i < len(b); i += 2 {
		s += uint32(b[i+1])<<8 | uint32(b[i])
	}
	s = s>>16 + s&0xffff
	s = s + s>>16
	return uint16(^s)
}
