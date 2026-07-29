package phantomtcp

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

func listenTProxyUDP(network string, laddr *net.UDPAddr) (*net.UDPConn, error) {
	conn, err := net.ListenUDP(network, laddr)
	if err != nil {
		return nil, err
	}

	f, err := conn.File()
	if err != nil {
		conn.Close()
		return nil, err
	}
	defer f.Close()

	fd := int(f.Fd())
	if laddr.IP.To4() != nil && !laddr.IP.IsUnspecified() {
		unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_TRANSPARENT, 1)
		unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1)
	} else if laddr.IP != nil && !laddr.IP.IsUnspecified() {
		unix.SetsockoptInt(fd, unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
		unix.SetsockoptInt(fd, unix.SOL_IPV6, unix.IPV6_RECVORIGDSTADDR, 1)
	} else {
		unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_TRANSPARENT, 1)
		unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1)
		unix.SetsockoptInt(fd, unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
		unix.SetsockoptInt(fd, unix.SOL_IPV6, unix.IPV6_RECVORIGDSTADDR, 1)
	}

	return conn, nil
}

func readFromTProxyUDP(conn *net.UDPConn, b []byte) (int, *net.UDPAddr, *net.UDPAddr, error) {
	oob := make([]byte, 1024)
	n, oobn, _, addr, err := conn.ReadMsgUDP(b, oob)
	if err != nil {
		return 0, nil, nil, err
	}

	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return 0, nil, nil, err
	}

	var dst *net.UDPAddr
	for _, msg := range msgs {
		if msg.Header.Level == unix.SOL_IP && msg.Header.Type == unix.IP_RECVORIGDSTADDR {
			port := int(binary.BigEndian.Uint16(msg.Data[2:4]))
			dst = &net.UDPAddr{IP: net.IP(msg.Data[4:8]), Port: port}
		} else if msg.Header.Level == unix.SOL_IPV6 && msg.Header.Type == unix.IPV6_RECVORIGDSTADDR {
			port := int(binary.BigEndian.Uint16(msg.Data[2:4]))
			dst = &net.UDPAddr{IP: net.IP(msg.Data[8:24]), Port: port}
		}
	}

	if dst == nil {
		return 0, nil, nil, fmt.Errorf("unable to obtain original destination")
	}

	return n, addr, dst, nil
}

func dialTProxyUDP(laddr, raddr *net.UDPAddr) (*net.UDPConn, error) {
	rsock, err := udpSockaddr(raddr)
	if err != nil {
		return nil, err
	}

	lsock, err := udpSockaddr(laddr)
	if err != nil {
		return nil, err
	}

	af := unix.AF_INET6
	if (laddr == nil || laddr.IP.To4() != nil) && (raddr == nil || raddr.IP.To4() != nil) {
		af = unix.AF_INET
	}

	fd, err := unix.Socket(af, unix.SOCK_DGRAM, 0)
	if err != nil {
		return nil, err
	}

	unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	if af == unix.AF_INET6 {
		unix.SetsockoptInt(fd, unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
	} else {
		unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_TRANSPARENT, 1)
	}

	if err = unix.Bind(fd, lsock); err != nil {
		unix.Close(fd)
		return nil, err
	}

	if err = unix.Connect(fd, rsock); err != nil {
		unix.Close(fd)
		return nil, err
	}

	f := os.NewFile(uintptr(fd), fmt.Sprintf("net-udp-dial-%s", raddr.String()))
	defer f.Close()

	c, err := net.FileConn(f)
	if err != nil {
		return nil, err
	}

	return c.(*net.UDPConn), nil
}

func udpSockaddr(addr *net.UDPAddr) (unix.Sockaddr, error) {
	if ip4 := addr.IP.To4(); ip4 != nil {
		var a [4]byte
		copy(a[:], ip4)
		return &unix.SockaddrInet4{Addr: a, Port: addr.Port}, nil
	}

	var a [16]byte
	copy(a[:], addr.IP.To16())
	sa := &unix.SockaddrInet6{Addr: a, Port: addr.Port}
	if addr.Zone != "" {
		zone, err := strconv.ParseUint(addr.Zone, 10, 32)
		if err != nil {
			return nil, err
		}
		sa.ZoneId = uint32(zone)
	}
	return sa, nil
}

func TProxyUDP(address string) {
	laddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		logPrintln(1, err)
		return
	}
	client, err := listenTProxyUDP("udp", laddr)
	if err != nil {
		logPrintln(1, err)
		return
	}
	defer client.Close()

	data := make([]byte, 1500)
	for {
		n, srcAddr, dstAddr, err := readFromTProxyUDP(client, data)
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
				host = dstAddr.IP.String()
				outbound = DefaultProfile.GetOutboundByIP(dstAddr.IP)
			}
		} else if dstAddr.IP[0] == 0 {
			index := int(binary.BigEndian.Uint32(dstAddr.IP[12:16]))
			if index >= len(Nose) {
				logPrintln(4, "TProxy(UDP):", srcAddr, "->", dstAddr, "out of range")
				continue
			}
			host, outbound = GetDNSLie(index)
		} else {
			host = dstAddr.IP.String()
			outbound = DefaultProfile.GetOutboundByIP(dstAddr.IP)
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

		localConn, err := dialTProxyUDP(dstAddr, srcAddr)
		if err != nil {
			logPrintln(1, err)
			continue
		}

		remoteConn, err := outbound.DialUDPProxy(host, dstAddr.Port)
		if err != nil {
			logPrintln(1, err)
			localConn.Close()
			continue
		}

		if outbound.Hint&HINT_ZERO != 0 {
			zero_data := make([]byte, 8+rand.Intn(1024))
			_, err = remoteConn.Write(zero_data)
			if err != nil {
				logPrintln(1, err)
				localConn.Close()
				remoteConn.Close()
				continue
			}
		}

		err = WriteQUICInitial(remoteConn, data[:n], outbound)
		if err != nil {
			logPrintln(1, err)
			localConn.Close()
			remoteConn.Close()
			continue
		}

		go func(localConn, remoteConn net.Conn) {
			relayUDP(localConn, remoteConn)
			remoteConn.Close()
			localConn.Close()
		}(localConn, remoteConn)
	}
}
