package phantomtcp

import (
	"bytes"
	"encoding/binary"
	"io"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// UDP ASSOCIATE is answered with the address of SocksUDPProxy, which shares the
// port of the socks inbound the client is already connected to.
func socks5Reply(cmd byte, client net.Conn) []byte {
	if cmd != 3 {
		return []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	}

	addr, ok := client.LocalAddr().(*net.TCPAddr)
	if !ok {
		return []byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0}
	}

	if ip4 := addr.IP.To4(); ip4 != nil {
		reply := []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}
		copy(reply[4:8], ip4)
		binary.BigEndian.PutUint16(reply[8:], uint16(addr.Port))
		return reply
	}

	reply := make([]byte, 22)
	reply[0] = 5
	reply[3] = 4
	copy(reply[4:20], addr.IP.To16())
	binary.BigEndian.PutUint16(reply[20:], uint16(addr.Port))
	return reply
}

func SocksProxy(client net.Conn) {
	defer client.Close()

	var cmd byte = 1
	host := ""
	var addr net.IP
	var port int
	{
		var b [1500]byte
		n, err := client.Read(b[:])
		if err != nil || n < 3 {
			logPrintln(1, client.RemoteAddr(), err)
			return
		}

		var reply []byte
		if b[0] == 0x05 {
			client.Write([]byte{0x05, 0x00})
			n, err = client.Read(b[:4])
			if err != nil || n != 4 {
				return
			}
			cmd = b[1]

			switch b[3] {
			case 0x01: //IPv4
				n, err = client.Read(b[:6])
				if n < 6 {
					return
				}
				addr = net.IP(b[:4])
				port = int(binary.BigEndian.Uint16(b[4:6]))
			case 0x03: //Domain
				n, err = client.Read(b[:])
				addrLen := b[0]
				if n < int(addrLen+3) {
					return
				}
				host = string(b[1 : addrLen+1])
				port = int(binary.BigEndian.Uint16(b[n-2:]))
			case 0x04: //IPv6
				n, err = client.Read(b[:])
				if n < 18 {
					return
				}
				addr = net.IP(b[:16])
				port = int(binary.BigEndian.Uint16(b[16:18]))
			default:
				// 0x08: address type not supported
				logPrintln(3, "address type", b[0], "not supported from", client.RemoteAddr())
				client.Write([]byte{5, 9, 0, 1, 0, 0, 0, 0, 0, 0})
				return
			}
			reply = socks5Reply(cmd, client)
		} else if b[0] == 0x04 {
			if n > 8 && b[1] == 1 {
				userEnd := 8 + bytes.IndexByte(b[8:n], 0)
				port = int(binary.BigEndian.Uint16(b[2:4]))
				if b[4]|b[5]|b[6] == 0 {
					hostEnd := bytes.IndexByte(b[userEnd+1:n], 0)
					if hostEnd > 0 {
						host = string(b[userEnd+1 : userEnd+1+hostEnd])
					} else {
						client.Write([]byte{0, 91, 0, 0, 0, 0, 0, 0})
						return
					}
				} else {
					addr = net.IP(b[4:8])
				}

				reply = []byte{0, 90, b[2], b[3], b[4], b[5], b[6], b[7]}
			} else {
				client.Write([]byte{0, 91, 0, 0, 0, 0, 0, 0})
				return
			}
		} else {
			logPrintln(3, "unknow from", client.RemoteAddr())
			return
		}

		if err == nil {
			_, err = client.Write(reply)
		}

		if err != nil {
			logPrintln(1, err)
			return
		}
	}

	switch cmd {
	case 1: // CONNECT
		tcpAddr := net.TCPAddr{IP: addr, Port: port}
		tcp_redirect(client, &tcpAddr, host, nil)
	case 2: // BIND
	case 3: // UDP ASSOCIATE
		// the association lives as long as this connection is held open
		io.Copy(io.Discard, client)
	case 5: // UDP IN TCP
		udpAddr := net.UDPAddr{IP: addr, Port: port}
		udp_redirect(client, &udpAddr)
	}
}

func ReadFull(conn net.Conn, buffer []byte) error {
	buff_len := len(buffer)
	recv_len := 0
	for recv_len < buff_len {
		n, err := conn.Read(buffer[recv_len:])
		if err != nil {
			return err
		}
		recv_len += n
	}
	return nil
}

func udp_redirect(client net.Conn, bindAddr *net.UDPAddr) error {
	defer client.Close()

	var outbound *Outbound = nil
	srcAddr := client.RemoteAddr()

	var domain string
	var addr net.IP
	var port int
	b := make([]byte, quicUDPPacketSize+256)

	err := ReadFull(client, b[:3])
	if err != nil {
		return err
	}
	msglen := int(binary.BigEndian.Uint16(b[0:2]))
	hdrlen := int(b[2])
	if msglen > quicUDPPacketSize || hdrlen < 4 || hdrlen > len(b) {
		return nil
	}
	if err = ReadFull(client, b[3:hdrlen]); err != nil {
		return err
	}

	atype := b[3]
	switch atype {
	case 0x01: //IPv4
		addr = net.IP(b[4:8])
		port = int(binary.BigEndian.Uint16(b[8:10]))
	case 0x03: //Domain
		addrLen := b[4]
		domain = string(b[5 : addrLen+5])
		port = int(binary.BigEndian.Uint16(b[hdrlen-2:]))
	case 0x04: //IPv6
		addr = net.IP(b[4:20])
		port = int(binary.BigEndian.Uint16(b[20:22]))
	default:
		logPrintln(3, "address type", b[0], "not supported from", client.RemoteAddr())
		return nil
	}

	raddr := net.UDPAddr{IP: addr, Port: port}
	if domain == "" {
		switch raddr.IP[0] {
		case 0x00:
			index := int(binary.BigEndian.Uint16(raddr.IP[14:16]))
			if index >= len(Nose) {
				logPrintln(3, index, "in", raddr.IP, "out of range")
				return err
			}
			domain, outbound = GetDNSLie(index)
			raddr.IP = nil
		case VirtualAddrPrefix:
			index := int(binary.BigEndian.Uint16(raddr.IP[2:4]))
			if index >= len(Nose) {
				logPrintln(3, index, "in", raddr.IP, "out of range")
				return err
			}
			domain, outbound = GetDNSLie(index)
			raddr.IP = nil
		default:
			return nil
		}
	}

	if outbound == nil {
		if domain == "" {
			outbound = DefaultProfile.GetOutboundByIP(raddr.IP)
		} else {
			outbound, _ = DefaultProfile.GetOutbound(domain)
		}
	}

	if outbound.Hint&(HINT_UDP|HINT_HTTP3) == 0 {
		return nil
	}

	dialHost := domain
	if dialHost == "" {
		if raddr.IP == nil {
			return nil
		}
		dialHost = raddr.IP.String()
	}

	logPrintln(1, "Socks(UDP):", srcAddr, "->", dialHost, port, outbound)

	conn, err := outbound.DialUDPProxy(dialHost, port)
	if err != nil {
		return err
	}
	defer conn.Close()

	if outbound.Hint&HINT_ZERO != 0 {
		zero_data := make([]byte, 8+rand.Intn(1024))
		if _, err = conn.Write(zero_data); err != nil {
			return err
		}
	}

	msg := make([]byte, quicUDPPacketSize+256)
	copy(msg[:hdrlen], b[:hdrlen])
	var rewriter *quicInitialRewriter
	if outbound.Hint&HINT_HTTP3 != 0 {
		rewriter = &quicInitialRewriter{}
	}
	go func() {
		for {
			n, err := conn.Read(msg[hdrlen:])
			if err != nil {
				return
			}
			reply := msg[hdrlen : hdrlen+n]
			if rewriter != nil {
				reply = rewriter.rewriteServer(reply)
			}
			binary.BigEndian.PutUint16(msg[:], uint16(len(reply)))
			copy(msg[hdrlen:], reply)
			if n, err = client.Write(msg[:hdrlen+len(reply)]); err != nil {
				return
			}
		}
	}()

	if err = ReadFull(client, b[:msglen]); err != nil {
		return err
	}
	if rewriter != nil {
		err = writeQUICDatagram(conn, b[:msglen], outbound, rewriter)
	} else {
		_, err = conn.Write(b[:msglen])
	}
	if err != nil {
		return err
	}

	for {
		err := ReadFull(client, b[:3])
		if err != nil {
			return err
		}
		msglen := int(binary.BigEndian.Uint16(b[0:2]))
		hdrlen := int(b[2])
		if msglen > quicUDPPacketSize || hdrlen > len(b) || hdrlen < 4 {
			return nil
		}
		if err = ReadFull(client, b[3:hdrlen]); err != nil {
			return err
		}

		if err = ReadFull(client, b[:msglen]); err != nil {
			return err
		}
		if rewriter != nil {
			err = writeQUICDatagram(conn, b[:msglen], outbound, rewriter)
		} else {
			_, err = conn.Write(b[:msglen])
		}
		if err != nil {
			return err
		}
	}
}

type socksUDPSession struct {
	conn     net.Conn
	outbound *Outbound
	rewriter *quicInitialRewriter
	// header echoed back to the client, empty for the socks4 format
	header []byte
}

func GetSocksUDPTarget(ip net.IP, host string) (string, *Outbound) {
	var outbound *Outbound = nil

	if host == "" && ip != nil {
		switch ip[0] {
		case 0x00:
			index := int(binary.BigEndian.Uint16(ip[14:16]))
			if index >= len(Nose) {
				logPrintln(3, index, "in", ip, "out of range")
				return "", nil
			}
			host, outbound = GetDNSLie(index)
		case VirtualAddrPrefix:
			index := int(binary.BigEndian.Uint16(ip[2:4]))
			if index >= len(Nose) {
				logPrintln(3, index, "in", ip, "out of range")
				return "", nil
			}
			host, outbound = GetDNSLie(index)
		}
	}

	if outbound == nil {
		if host != "" {
			outbound, _ = DefaultProfile.GetOutbound(host)
		} else if ip != nil {
			outbound = DefaultProfile.GetOutboundByIP(ip)
		}
	}

	if host == "" {
		if ip == nil {
			return "", nil
		}
		host = ip.String()
	}

	return host, outbound
}

func SocksUDPProxy(address string) {
	laddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		logPrintln(1, err)
		return
	}
	local, err := net.ListenUDP("udp", laddr)
	if err != nil {
		logPrintln(1, err)
		return
	}
	defer local.Close()

	var ConnLock sync.Mutex
	var ConnMap map[string]socksUDPSession = make(map[string]socksUDPSession)
	data := make([]byte, quicUDPPacketSize+256)

	for {
		n, srcAddr, err := local.ReadFromUDP(data)
		if err != nil {
			logPrintln(1, err)
			continue
		}

		var host string
		var addr net.IP
		var port int
		var hdrlen int
		var header []byte

		if n > 8 && data[0] == 4 {
			if data[1] != 1 {
				continue
			}
			port = int(binary.BigEndian.Uint16(data[2:4]))
			addr = net.IP(data[4:8])
			hdrlen = 8
		} else {
			hdrlen = SocksUDPHeaderLen(data[:n])
			if hdrlen == 0 || data[2] != 0 || n <= hdrlen {
				continue
			}
			header = append([]byte(nil), data[:hdrlen]...)

			switch data[3] {
			case 0x01: //IPv4
				addr = net.IP(data[4:8])
				port = int(binary.BigEndian.Uint16(data[8:10]))
			case 0x03: //Domain
				addrLen := int(data[4])
				host = string(data[5 : 5+addrLen])
				port = int(binary.BigEndian.Uint16(data[5+addrLen:]))
			case 0x04: //IPv6
				addr = net.IP(data[4:20])
				port = int(binary.BigEndian.Uint16(data[20:22]))
			}
		}

		host, outbound := GetSocksUDPTarget(addr, host)
		if outbound == nil {
			continue
		}

		key := strings.Join([]string{srcAddr.String(), host, strconv.Itoa(port)}, ",")

		ConnLock.Lock()
		session, ok := ConnMap[key]
		ConnLock.Unlock()
		if ok {
			var writeErr error
			if session.rewriter != nil {
				writeErr = writeQUICDatagram(session.conn, data[hdrlen:n], session.outbound, session.rewriter)
			} else {
				_, writeErr = session.conn.Write(data[hdrlen:n])
			}
			if writeErr != nil {
				logPrintln(1, writeErr)
			}
			continue
		}

		if outbound.Hint&(HINT_UDP|HINT_HTTP3) == 0 {
			continue
		}
		if outbound.Hint&HINT_HTTP3 != 0 {
			if GetQUICVersion(data[hdrlen:n]) == 0 {
				continue
			}
		}

		logPrintln(1, "SocksU:", srcAddr, "->", host, port, outbound)

		remoteConn, err := outbound.DialUDPProxy(host, port)
		if err != nil {
			logPrintln(1, err)
			continue
		}

		if outbound.Hint&HINT_ZERO != 0 {
			zero_data := make([]byte, 8+rand.Intn(1024))
			if _, err = remoteConn.Write(zero_data); err != nil {
				logPrintln(1, err)
				remoteConn.Close()
				continue
			}
		}

		var rewriter *quicInitialRewriter
		if outbound.Hint&HINT_HTTP3 != 0 {
			rewriter = &quicInitialRewriter{}
			err = writeQUICDatagram(remoteConn, data[hdrlen:n], outbound, rewriter)
		} else {
			_, err = remoteConn.Write(data[hdrlen:n])
		}
		if err != nil {
			logPrintln(1, err)
			remoteConn.Close()
			continue
		}

		session = socksUDPSession{conn: remoteConn, outbound: outbound, rewriter: rewriter, header: header}
		ConnLock.Lock()
		ConnMap[key] = session
		ConnLock.Unlock()

		go func(srcAddr net.UDPAddr, session socksUDPSession, key string) {
			hdrlen := len(session.header)
			data := make([]byte, quicUDPPacketSize+256)
			copy(data, session.header)

			session.conn.SetReadDeadline(time.Now().Add(time.Minute * 2))
			for {
				n, err := session.conn.Read(data[hdrlen:])
				if err != nil {
					ConnLock.Lock()
					delete(ConnMap, key)
					ConnLock.Unlock()
					session.conn.Close()
					return
				}
				session.conn.SetReadDeadline(time.Now().Add(time.Minute * 2))
				reply := data[hdrlen : hdrlen+n]
				if session.rewriter != nil {
					reply = session.rewriter.rewriteServer(reply)
				}
				copy(data[hdrlen:], reply)
				local.WriteToUDP(data[:hdrlen+len(reply)], &srcAddr)
			}
		}(*srcAddr, session, key)
	}
}
