package phantomtcp

import (
	"encoding/binary"
	"errors"
	"math/rand"
	"net"
	"sync"
	"time"
)

// socksUDPConn wraps the relay socket of a SOCKS5 UDP association, adding the
// request header to every datagram sent and stripping it from every reply.
type socksUDPConn struct {
	net.Conn
	tcpConn net.Conn
	header  []byte
	mutex   sync.Mutex
	wbuf    []byte
	rbuf    []byte
}

func newSocksUDPConn(conn net.Conn, tcpConn net.Conn, host string, port int) *socksUDPConn {
	var header []byte
	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		header = make([]byte, 10)
		header[3] = 0x01
		copy(header[4:8], ip4)
		binary.BigEndian.PutUint16(header[8:10], uint16(port))
	} else if ip != nil {
		header = make([]byte, 22)
		header[3] = 0x04
		copy(header[4:20], ip.To16())
		binary.BigEndian.PutUint16(header[20:22], uint16(port))
	} else {
		hostLen := len(host)
		header = make([]byte, 7+hostLen)
		header[3] = 0x03
		header[4] = byte(hostLen)
		copy(header[5:], host)
		binary.BigEndian.PutUint16(header[5+hostLen:], uint16(port))
	}

	return &socksUDPConn{
		Conn:    conn,
		tcpConn: tcpConn,
		header:  header,
		wbuf:    make([]byte, 2048),
		rbuf:    make([]byte, 2048),
	}
}

func SocksUDPHeaderLen(data []byte) int {
	if len(data) < 4 || data[0] != 0 || data[1] != 0 {
		return 0
	}

	hdrlen := 0
	switch data[3] {
	case 0x01:
		hdrlen = 10
	case 0x03:
		if len(data) < 5 {
			return 0
		}
		hdrlen = 7 + int(data[4])
	case 0x04:
		hdrlen = 22
	default:
		return 0
	}

	if len(data) < hdrlen {
		return 0
	}
	return hdrlen
}

func (conn *socksUDPConn) Write(b []byte) (int, error) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	hdrlen := len(conn.header)
	if hdrlen+len(b) > len(conn.wbuf) {
		conn.wbuf = make([]byte, hdrlen+len(b))
	}
	copy(conn.wbuf, conn.header)
	copy(conn.wbuf[hdrlen:], b)
	if _, err := conn.Conn.Write(conn.wbuf[:hdrlen+len(b)]); err != nil {
		return 0, err
	}

	return len(b), nil
}

func (conn *socksUDPConn) Read(b []byte) (int, error) {
	for {
		n, err := conn.Conn.Read(conn.rbuf)
		if err != nil {
			return 0, err
		}

		// drop malformed, fragmented and empty datagrams
		hdrlen := SocksUDPHeaderLen(conn.rbuf[:n])
		if hdrlen == 0 || conn.rbuf[2] != 0 || n <= hdrlen {
			continue
		}

		return copy(b, conn.rbuf[hdrlen:n]), nil
	}
}

func (conn *socksUDPConn) Close() error {
	err := conn.Conn.Close()
	if conn.tcpConn != nil {
		conn.tcpConn.Close()
	}
	return err
}

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

func (outbound *Outbound) DialUDPProxy(host string, port int) (net.Conn, error) {
	return outbound.dialUDPProxy(host, port, time.Time{})
}

func (outbound *Outbound) dialUDPProxy(host string, port int, deadline time.Time) (net.Conn, error) {
	raddrs, err := outbound.GetRemoteAddresses(host, port)
	if err != nil {
		return nil, err
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
				return nil, err
			}
			laddr = &net.UDPAddr{IP: _laddr.IP, Port: 0}
		}
		return net.DialUDP("udp", laddr, &net.UDPAddr{IP: raddr.IP, Port: raddr.Port})
	case SOCKS5:
		if host == "" {
			return nil, proxy_err
		}

		var synpacket *ConnectionInfo
		var hint uint32 = 0

		laddr, err := GetLocalTCPAddr(outbound.Device, raddr.IP.To4() == nil)
		if err != nil {
			return nil, err
		}

		hint = outbound.Hint & HINT_MODIFY
		if hint != 0 {
			tcpConn, synpacket, err = DialConnInfo(laddr, raddr, outbound, nil)
			if err != nil {
				return nil, err
			}

			if synpacket == nil {
				if tcpConn != nil {
					tcpConn.Close()
				}
				return nil, errors.New("connection does not exist")
			}
			synpacket.AddTCPSeq(1)
		} else {
			dialer := net.Dialer{LocalAddr: laddr, Deadline: deadline}
			tcpConn, err = dialer.Dial("tcp", raddr.String())
			if err != nil {
				return nil, err
			}
		}
		if !deadline.IsZero() {
			if err = tcpConn.SetDeadline(deadline); err != nil {
				tcpConn.Close()
				return nil, err
			}
		}

		var b [264]byte
		if hint != 0 {
			err := ModifyAndSendPacket(synpacket, b[:], hint, outbound.TTL, 2)
			if err != nil {
				tcpConn.Close()
				return nil, err
			}
		}

		if err = socks5Negotiate(tcpConn, "", ""); err != nil {
			tcpConn.Close()
			return nil, proxy_err
		}

		// the client may send from any address, so the request carries 0.0.0.0:0
		if _, err = tcpConn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
			tcpConn.Close()
			return nil, err
		}
		if err = ReadFull(tcpConn, b[:4]); err != nil {
			tcpConn.Close()
			return nil, err
		}
		if b[0] != 0x05 || b[1] != 0x00 {
			tcpConn.Close()
			return nil, proxy_err
		}

		var udpAddr net.UDPAddr
		switch b[3] {
		case 0x01:
			if err = ReadFull(tcpConn, b[4:10]); err != nil {
				tcpConn.Close()
				return nil, err
			}
			udpAddr.IP = net.IP(b[4:8])
			udpAddr.Port = int(binary.BigEndian.Uint16(b[8:10]))
		case 0x03:
			if err = ReadFull(tcpConn, b[4:5]); err != nil {
				tcpConn.Close()
				return nil, err
			}
			hostLen := int(b[4])
			if err = ReadFull(tcpConn, b[5:7+hostLen]); err != nil {
				tcpConn.Close()
				return nil, err
			}
			udpAddr.IP = net.ParseIP(string(b[5 : 5+hostLen]))
			udpAddr.Port = int(binary.BigEndian.Uint16(b[5+hostLen:]))
		case 0x04:
			if err = ReadFull(tcpConn, b[4:22]); err != nil {
				tcpConn.Close()
				return nil, err
			}
			udpAddr.IP = net.IP(b[4:20])
			udpAddr.Port = int(binary.BigEndian.Uint16(b[20:22]))
		default:
			tcpConn.Close()
			return nil, proxy_err
		}

		// a proxy behind NAT may reply with an unspecified address
		if udpAddr.IP == nil || udpAddr.IP.IsUnspecified() {
			udpAddr.IP = raddr.IP
		}

		var uladdr *net.UDPAddr = nil
		if laddr != nil {
			uladdr = &net.UDPAddr{IP: laddr.IP, Port: 0}
		}
		udpConn, err := net.DialUDP("udp", uladdr, &udpAddr)
		if err != nil {
			tcpConn.Close()
			return nil, err
		}

		if err = tcpConn.SetDeadline(time.Time{}); err != nil {
			udpConn.Close()
			tcpConn.Close()
			return nil, err
		}
		return newSocksUDPConn(udpConn, tcpConn, host, port), nil
	}

	return nil, proxy_err
}
