package phantomtcp

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"net"
)

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
			reply = []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}
			//reply = []byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0}
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
	var b [1500]byte

	err := ReadFull(client, b[:3])
	if err != nil {
		return err
	}
	msglen := int(binary.BigEndian.Uint16(b[0:2]))
	hdrlen := int(b[2])
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

	if raddr.IP == nil {
		logPrintln(1, "Socks(UDP):", srcAddr, "->", domain, raddr.Port, outbound)
		raddrs, err := outbound.GetRemoteAddresses(domain, raddr.Port)
		if err != nil {
			return err
		}
		dst := raddrs[rand.Intn(len(raddrs))]
		raddr.IP = dst.IP
		raddr.Port = dst.Port
	} else {
		logPrintln(1, "Socks(UDP):", srcAddr, "->", raddr, outbound)
	}

	var laddr *net.UDPAddr = nil
	if outbound.Device != "" {
		_laddr, err := GetLocalTCPAddr(outbound.Device, raddr.IP.To4() == nil)
		if err != nil {
			return err
		}
		laddr = &net.UDPAddr{IP: _laddr.IP, Port: 0}
	}

	if outbound.Hint&HINT_HTTP3 != 0 {
		if laddr == nil {
			laddr = &net.UDPAddr{Port: 0}
		}
		laddr.Port = rand.Intn(raddr.Port-1) + 1
	}

	conn, err := net.DialUDP("udp", laddr, &net.UDPAddr{IP: raddr.IP, Port: raddr.Port})
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

	var msg [1500]byte
	copy(msg[:hdrlen], b[:hdrlen])
	go func() {
		for {
			n, err := conn.Read(msg[hdrlen:])
			if err != nil {
				return
			}
			binary.BigEndian.PutUint16(msg[:], uint16(n))
			if n, err = client.Write(msg[:hdrlen+n]); err != nil {
				return
			}
		}
	}()

	if err = ReadFull(client, b[:msglen]); err != nil {
		return err
	}
	if _, err = conn.Write(b[:msglen]); err != nil {
		return err
	}

	for {
		err := ReadFull(client, b[:3])
		if err != nil {
			return err
		}
		msglen := int(binary.BigEndian.Uint16(b[0:2]))
		hdrlen := int(b[2])
		if msglen + hdrlen > 1500 || hdrlen < 4 {
			return nil
		}
		if err = ReadFull(client, b[3:hdrlen]); err != nil {
			return err
		}
		
		if err = ReadFull(client, b[:msglen]); err != nil {
			return err
		}
		if _, err = conn.Write(b[:msglen]); err != nil {
			return err
		}
	}
}