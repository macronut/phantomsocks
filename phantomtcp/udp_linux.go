package phantomtcp

import (
	"encoding/binary"
	"math/rand"
	"net"

	"github.com/macronut/go-tproxy"
)

func TProxyUDP(address string) {
	laddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		logPrintln(1, err)
		return
	}
	client, err := tproxy.ListenUDP("udp", laddr)
	if err != nil {
		logPrintln(1, err)
		return
	}
	defer client.Close()

	data := make([]byte, 1500)
	for {
		n, srcAddr, dstAddr, err := tproxy.ReadFromUDP(client, data)
		if err != nil {
			logPrintln(1, err)
			continue
		}

		var host string
		var outbound *Outbound
		dstIP4 := dstAddr.IP.To4()
		if dstIP4 != nil {
			if dstIP4[0] == VirtualAddrPrefix {
				index := int(binary.BigEndian.Uint16(dstIP4[2:4]))
				if index >= len(Nose) {
					logPrintln(4, "TProxy(UDP):", srcAddr, "->", dstAddr, "out of range")
					continue
				}
				host, outbound = GetDNSLie(index)
			} else {
				continue
			}
		} else if dstAddr.IP[0] == 0 {
			index := int(binary.BigEndian.Uint32(dstAddr.IP[12:16]))
			if index >= len(Nose) {
				logPrintln(4, "TProxy(UDP):", srcAddr, "->", dstAddr, "out of range")
				continue
			}
			host, outbound = GetDNSLie(index)
		} else {
			continue
		}

		if outbound.Hint&HINT_UDP == 0 {
			if outbound.Hint&(HINT_HTTP3) == 0 {
				logPrintln(4, "TProxy(UDP):", srcAddr, "->", host, "not allow")
				continue
			}
			if GetQUICVersion(data[:n]) == 0 {
				logPrintln(4, "TProxy(UDP):", srcAddr, "->", host, "not h3")
				continue
			}
		}

		logPrintln(1, "TProxy(UDP):", srcAddr, "->", host, dstAddr.Port, outbound)

		localConn, err := tproxy.DialUDP("udp", dstAddr, srcAddr)
		if err != nil {
			logPrintln(1, err)
			continue
		}

		remoteConn, proxyConn, err := outbound.DialUDPProxy(host, dstAddr.Port)
		if err != nil {
			logPrintln(1, err)
			localConn.Close()
			if proxyConn != nil {
				proxyConn.Close()
			}
			continue
		}

		if outbound.Hint&HINT_ZERO != 0 {
			zero_data := make([]byte, 8+rand.Intn(1024))
			_, err = remoteConn.Write(zero_data)
			if err != nil {
				logPrintln(1, err)
				localConn.Close()
				if proxyConn != nil {
					proxyConn.Close()
				}
				continue
			}
		}

		_, err = remoteConn.Write(data[:n])
		if err != nil {
			logPrintln(1, err)
			localConn.Close()
			if proxyConn != nil {
				proxyConn.Close()
			}
			continue
		}

		go func(localConn, remoteConn, proxyConn net.Conn) {
			relayUDP(localConn, remoteConn)
			remoteConn.Close()
			localConn.Close()
			if proxyConn != nil {
				proxyConn.Close()
			}
		}(localConn, remoteConn, proxyConn)
	}
}
