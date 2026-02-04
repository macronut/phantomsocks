package phantomtcp

import (
	"encoding/binary"
	"errors"
	"math/rand"
	"net"
	"strings"
	"time"
)

func ComputeUDPChecksum(buffer []byte) uint16 {
	checksum := uint32(binary.BigEndian.Uint16(buffer[12:14]))
	checksum += uint32(binary.BigEndian.Uint16(buffer[14:16]))
	checksum += uint32(binary.BigEndian.Uint16(buffer[16:18]))
	checksum += uint32(binary.BigEndian.Uint16(buffer[18:20]))
	checksum += uint32(17)
	checksum += uint32(binary.BigEndian.Uint16(buffer[24:26]))

	checksum += uint32(binary.BigEndian.Uint16(buffer[20:22]))
	checksum += uint32(binary.BigEndian.Uint16(buffer[22:24]))
	checksum += uint32(binary.BigEndian.Uint16(buffer[24:26]))

	offset := 28
	bufferLen := len(buffer)
	for {
		if offset > bufferLen-2 {
			if offset == bufferLen-1 {
				checksum += uint32(buffer[offset]) << 8
			}
			break
		}
		checksum += uint32(binary.BigEndian.Uint16(buffer[offset : offset+2]))
		offset += 2
	}

	checksum = (checksum & 0xffff) + (checksum >> 16)
	checksum = (checksum & 0xffff) + (checksum >> 16)

	return ^uint16(checksum)
}

func relayUDP(left, right net.Conn) error {
	ch := make(chan error)

	go func() {
		data := make([]byte, 1500)
		for {
			left.SetReadDeadline(time.Now().Add(time.Minute * 2))
			n, err := left.Read(data)
			if err != nil {
				ch <- err
				right.SetDeadline(time.Now())
				left.SetDeadline(time.Now())
				break
			}
			right.Write(data[:n])
		}
	}()

	data := make([]byte, 1500)
	var err error
	for {
		right.SetReadDeadline(time.Now().Add(time.Minute * 2))
		var n int
		n, err = right.Read(data)
		if err != nil {
			right.SetDeadline(time.Now())
			left.SetDeadline(time.Now())
			break
		}
		left.Write(data[:n])
	}

	ch_err := <-ch
	if ch_err != nil {
		err = ch_err
	}

	return err
}

func (outbound *Outbound) DialUDPProxy(host string, port int) (net.Conn, net.Conn, error) {
	raddrs, err := outbound.GetRemoteAddresses(host, port)
	if err != nil {
		return nil, nil, err
	}
	raddr := raddrs[rand.Intn(len(raddrs))]

	proxy_err := errors.New("invalid proxy")
	var tcpConn net.Conn = nil

	switch outbound.Protocol {
	case DIRECT:
		fallthrough
	case REDIRECT:
		fallthrough
	case NAT64:
		var laddr *net.UDPAddr = nil
		if outbound.Device != "" {
			_laddr, err := GetLocalTCPAddr(outbound.Device, raddr.IP.To4() == nil)
			if err != nil {
				return nil, nil, err
			}
			laddr = &net.UDPAddr{IP: _laddr.IP, Port: 0}
		}
		laddr.Port = rand.Intn(raddr.Port-1) + 1
		udpConn, err := net.DialUDP("udp", laddr, &net.UDPAddr{IP: raddr.IP, Port: raddr.Port})
		return udpConn, nil, err
	case SOCKS5:
		var proxy_seq uint32 = 0
		var synpacket *ConnectionInfo
		var hint uint32 = 0

		laddr, err := GetLocalTCPAddr(outbound.Device, raddr.IP.To4() == nil)
		if err != nil {
			return nil, nil, err
		}

		hint = outbound.Hint & HINT_MODIFY
		if hint != 0 {
			tcpConn, synpacket, err = DialConnInfo(laddr, raddr, outbound, nil)
			if err != nil {
				return nil, nil, err
			}

			if synpacket == nil {
				if tcpConn != nil {
					tcpConn.Close()
				}
				return nil, nil, errors.New("connection does not exist")
			}
			synpacket.TCP.Seq++
		} else {
			tcpConn, err = net.DialTCP("tcp", laddr, raddr)
			if err != nil {
				return nil, nil, err
			}
		}

		var b [264]byte
		if hint != 0 {
			err := ModifyAndSendPacket(synpacket, b[:], hint, outbound.TTL, 2)
			if err != nil {
				tcpConn.Close()
				return nil, nil, err
			}
		}

		n, err := tcpConn.Write([]byte{0x05, 0x01, 0x00})
		if err != nil {
			tcpConn.Close()
			return nil, nil, err
		}
		proxy_seq += uint32(n)
		_, err = tcpConn.Read(b[:])
		if err != nil {
			tcpConn.Close()
			return nil, nil, err
		}

		if b[0] != 0x05 {
			tcpConn.Close()
			return nil, nil, proxy_err
		}

		copy(b[:], []byte{0x05, 0x03, 0x00, 0x03})
		hostLen := len(host)
		b[4] = byte(hostLen)
		copy(b[5:], []byte(host))
		binary.BigEndian.PutUint16(b[5+hostLen:], uint16(port))
		n, err = tcpConn.Write(b[:7+hostLen])
		if err != nil {
			tcpConn.Close()
			return nil, nil, err
		}
		proxy_seq += uint32(n)
		n, err = tcpConn.Read(b[:])
		if err != nil {
			tcpConn.Close()
			return nil, nil, err
		}
		if n < 4 || b[0] != 0x05 || b[1] != 0x00 {
			tcpConn.Close()
			return nil, nil, proxy_err
		}
		var udpAddr net.UDPAddr
		switch b[3] {
		case 1:
			port := int(binary.BigEndian.Uint16(b[8:10]))
			udpAddr = net.UDPAddr{IP: net.IP(b[4:8]), Port: port}
		case 4:
			port := int(binary.BigEndian.Uint16(b[20:22]))
			udpAddr = net.UDPAddr{IP: net.IP(b[4:20]), Port: port}
		default:
			tcpConn.Close()
			return nil, nil, proxy_err
		}
		udpConn, err := net.DialUDP("udp", nil, &udpAddr)
		return udpConn, tcpConn, err
	}

	return nil, nil, proxy_err
}

func GetQUICVersion(data []byte) uint32 {
	if len(data) < 5 {
		return 0xffffffff
	}
	if data[0]&0xC0 != 0xC0 {
		return 0xffffffff
	}
	Version := binary.BigEndian.Uint32(data[1:5])
	switch Version {
	case 0xff00001d:
		return Version
	case 0x00000001:
		return Version
	default:
		return 0
	}
}

func GetLocalUDPAddr(name string, ipv6 bool) (*net.UDPAddr, error) {
	if name == "" {
		return nil, nil
	}

	inf, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	addrs, _ := inf.Addrs()
	for _, addr := range addrs {
		localAddr, ok := addr.(*net.IPNet)
		if ok {
			var laddr *net.UDPAddr
			ip4 := localAddr.IP.To4()
			if ipv6 {
				if ip4 != nil || localAddr.IP.IsPrivate() {
					continue
				}
				ip := make([]byte, 16)
				copy(ip[:16], localAddr.IP)
				laddr = &net.UDPAddr{IP: ip[:], Port: 0}
			} else {
				if ip4 == nil {
					continue
				}
				ip := make([]byte, 4)
				copy(ip[:4], ip4)
				laddr = &net.UDPAddr{IP: ip[:], Port: 0}
			}

			return laddr, nil
		}
	}

	return nil, nil
}

func StartHolePunching(inbound InboundConfig) {
	network := "udp6"
	laddr, err := net.ResolveUDPAddr(network, inbound.Address)
	if err != nil {
		logPrintln(1, err)
		return
	}
	sport := laddr.Port
	ipv6 := strings.HasSuffix(network, "6")
	payload := make([]byte, 4)

	for {
		if inbound.Device != "" {
			laddr, err = GetLocalUDPAddr(inbound.Device, ipv6)
			if err != nil {
				logPrintln(1, err)
				continue
			}
			laddr.Port = sport
		}

		for _, peer := range inbound.Peers {
			raddr, err := net.ResolveUDPAddr(network, peer.Endpoint)
			if err == nil {
				err = SendUDPPacket(laddr, raddr, payload, 2)
				logPrintln(3, network, laddr, raddr)
			}
			if err != nil {
				logPrintln(1, err)
			}
		}

		time.Sleep(time.Duration(25 * time.Second))
	}
}
