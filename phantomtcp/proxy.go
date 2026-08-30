package phantomtcp

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"
)

func validOptionalPort(port string) bool {
	if port == "" {
		return true
	}
	if port[0] != ':' {
		return false
	}
	for _, b := range port[1:] {
		if b < '0' || b > '9' {
			return false
		}
	}
	return true
}

func splitHostPort(hostport string) (host string, port int) {
	var err error
	host = hostport
	port = 0

	colon := strings.LastIndexByte(host, ':')
	if colon != -1 && validOptionalPort(host[colon:]) {
		port, err = strconv.Atoi(host[colon+1:])
		if err != nil {
			port = 0
		}
		host = host[:colon]
	}

	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}

	return
}

func GetHeader(conn net.Conn) ([]byte, error) {
	buf := make([]byte, 1460)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return nil, err
	}

	if buf[0] == 0x16 {
		recvLen := n
		headerLen := GetHelloLength(buf[:n]) + 5
		if headerLen > recvLen {
			header := make([]byte, headerLen)
			copy(header[:], buf[:recvLen])
			for headerLen > recvLen {
				if n, err = conn.Read(header[recvLen:]); err != nil || n == 0 {
					return header[:recvLen], err
				}
				recvLen += n
			}
			return header, nil
		}
	}

	return buf[:n], err
}

func SNIProxy(client net.Conn) {
	defer client.Close()

	header, err := GetHeader(client)
	if err != nil {
		logPrintln(1, client.RemoteAddr(), err)
	}

	var host string
	var port int
	if header != nil && header[0] == 0x16 {
		offset, length, _ := GetSNI(header)
		if length == 0 {
			return
		}
		host = string(header[offset : offset+length])
		port = 443
	} else {
		offset, length := GetHost(header)
		if length == 0 {
			return
		}
		host = string(header[offset : offset+length])
		portstart := strings.Index(host, ":")
		if portstart == -1 {
			port = 80
		} else {
			port, err = strconv.Atoi(host[portstart+1:])
			if err != nil {
				return
			}
			host = host[:portstart]
		}
		if net.ParseIP(host) != nil {
			return
		}
	}

	tcp_redirect(client, &net.TCPAddr{Port: port}, host, header)
}

func RedirectTCP(address string) {
	var l net.Listener = nil
	l, err := net.Listen("tcp", address)
	if err != nil {
		log.Panic(err)
	}
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Panic(err)
		}

		addr, err := GetOriginalDST(conn.(*net.TCPConn))
		if err != nil {
			conn.Close()
			logPrintln(1, err)
			continue
		}

		ipv4 := addr.IP.To4()
		if ipv4 != nil {
			addr.IP = ipv4
		}

		if addr.IP[0] == VirtualAddrPrefix {
			go tcp_redirect(conn, addr, "", nil)
		} else if addr.String() != conn.LocalAddr().String() {
			go tcp_redirect(conn, addr, "", nil)
		} else {
			conn.Close()
		}
	}
}

func RedirectUDP(address string) {
}

func tcp_redirect(client net.Conn, addr *net.TCPAddr, domain string, header []byte) {
	defer client.Close()

	start_time := time.Now()

	var conn net.Conn
	var err error
	{
		var outbound *Outbound = nil
		port := addr.Port

		if domain == "" {
			switch addr.IP[0] {
			case 0x00:
				index := int(binary.BigEndian.Uint16(addr.IP[14:16]))
				if index >= len(Nose) {
					logPrintln(3, index, "in", addr.IP, "out of range")
					return
				}
				domain, outbound = GetDNSLie(index)
				addr.IP = nil
			case VirtualAddrPrefix:
				index := int(binary.BigEndian.Uint16(addr.IP[2:4]))
				if index >= len(Nose) {
					logPrintln(3, index, "in", addr.IP, "out of range")
					return
				}
				domain, outbound = GetDNSLie(index)
				addr.IP = nil
			}
		}

		if outbound == nil {
			if domain == "" {
				outbound = DefaultProfile.GetOutboundByIP(addr.IP)
				if outbound != nil {
					domain = addr.IP.String()
				}
			} else {
				outbound, _ = DefaultProfile.GetOutbound(domain)
			}
		}

		if outbound != nil && (outbound.Protocol != 0 || outbound.Hint != 0) {
			if outbound.Hint&HINT_NOTCP != 0 {
				time.Sleep(time.Second)
				return
			}

			if header == nil {
				header, err = GetHeader(client)
				if err != nil {
					logPrintln(1, domain, err)
					return
				}
			}

			if header != nil && header[0] == 0x16 {
				offset, length, ech := GetSNI(header)
				if length > 0 {
					sni := string(header[offset : offset+length])
					if domain != sni {
						if ech {
							logPrintln(2, domain, "tls hello with ECH", sni)
						} else if addr.IP == nil {
							outbound, _ = DefaultProfile.GetOutbound(sni)
							if outbound == nil {
								return
							}
							domain = sni
						}
					}

					if outbound.Hint&HINT_TLS1_3 != 0 {
						version := GetTLSVersion(header)
						if version < 0x304 {
							logPrintln(4, domain, "version:", GetTLSVersionString(version))
							return
						}
					}

					if outbound.Hint&HINT_TLSFRAG != 0 {
						header = TLSFragment(header, offset+length/2)
						offset += 2
					}
				}

				retry := 5

			CONNECT:
				logPrintln(1, "Redirect:", client.RemoteAddr(), "->", domain, port, outbound.Device, time.Since(start_time))

				conn, _, err = outbound.dial(domain, port, header, offset, length)
				if err == nil {
					var server_hello [4096]byte
					var helloLen int
					if outbound.Timeout > 0 {
						err = conn.SetReadDeadline(time.Now().Add(time.Millisecond * time.Duration(outbound.Timeout)))
					}

					if err == nil {
						helloLen, err = conn.Read(server_hello[:])
					}

					if (outbound.Hint&HINT_OOB != 0) && retry > 0 {
						if err != nil {
							retry--
							conn.Close()
							goto CONNECT
						} else if helloLen > 5 && server_hello[0] == 0x15 {
							alert_ver := binary.BigEndian.Uint16(server_hello[1:3])
							logPrintln(2, "Alert", GetTLSVersionString(alert_ver))
							retry--
							conn.Close()
							goto CONNECT
						}
					}

					if err == nil {
						if _, err = client.Write(server_hello[:helloLen]); err != nil {
							logPrintln(2, domain, err)
							return
						}
					}

					conn.SetReadDeadline(time.Time{})
				}

				if err != nil {
					if outbound.Fallback != nil {
						outbound = outbound.Fallback
						goto CONNECT
					}
					logPrintln(2, domain, err)
					return
				}
			} else {
				logPrintln(1, "Redirect:", client.RemoteAddr(), "->", domain, port, outbound.Device, time.Since(start_time))
				if outbound.Hint&HINT_HTTP3 != 0 {
					HttpMove(client, "h3", header)
					return
				} else if outbound.Hint&HINT_HTTPS != 0 {
					HttpMove(client, "https", header)
					return
				} else if outbound.Hint&HINT_MOVE != 0 {
					HttpMove(client, outbound.Address, header)
					return
				} else if outbound.Hint&HINT_STRIP != 0 {
					if outbound.Hint&HINT_FRONTING != 0 {
						conn, err = outbound.DialStrip(domain, "")
						domain = ""
					} else {
						conn, err = outbound.DialStrip(domain, domain)
					}

					if err != nil {
						logPrintln(1, err)
						return
					}
					_, err = conn.Write(header)
					if err != nil {
						logPrintln(1, err)
						return
					}
				} else {
					var info *ConnectionInfo
					conn, info, err = outbound.dial(domain, port, header, 0, 0)
					if err != nil && outbound.Fallback != nil {
						outbound = outbound.Fallback
						logPrintln(1, "Redirect:", client.RemoteAddr(), "->", domain, port, outbound.Device, time.Since(start_time))
						conn, _, err = outbound.dial(domain, port, header, 0, 0)
					}

					if err != nil {
						logPrintln(2, domain, err)
						return
					}

					if info != nil {
						outbound.Keep(client, conn, info)
						return
					}
				}
			}
		} else if addr.IP != nil {
			logPrintln(1, "Redirect:", client.RemoteAddr(), "->", addr)
			conn, err = net.DialTCP("tcp", nil, addr)
			if err != nil {
				logPrintln(1, domain, err)
				return
			}
			if header != nil {
				conn.Write(header)
			}
		} else {
			logPrintln(1, "Redirect:", client.RemoteAddr(), "->", domain, port)
			conn, err = net.Dial("tcp", domain+":"+strconv.Itoa(port))
			if err != nil {
				logPrintln(1, domain, err)
				return
			}
			if header != nil {
				conn.Write(header)
			}
		}
	}

	if conn == nil {
		return
	}

	defer conn.Close()

	err = relay(client, conn)
	if err != nil {
		if err, ok := err.(net.Error); ok && err.Timeout() {
			return // ignore i/o timeout
		}
		logPrintln(1, "relay error:", err)
	}
}

func Netcat(client net.Conn) {
	defer client.Close()

	for {
		var b [1460]byte
		n, err := client.Read(b[:])
		if err != nil {
			logPrintln(2, client.RemoteAddr(), err)
			return
		}
		if n == 0 {
			return
		}

		cmd := strings.Fields(string(b[:n]))
		if len(cmd) > 0 {
			log.Println(client.RemoteAddr(), cmd)
			cmdlen := len(cmd)
			switch cmd[0] {
			case "host":
				if cmdlen > 1 {
					domain := cmd[1]
					outbound, _ := DefaultProfile.GetOutbound(domain)
					_, addrs := outbound.NSLookup(domain, 0)
					for _, addr := range addrs {
						client.Write([]byte(addr.String() + "\n"))
					}
				}
			case "load":
				if cmdlen > 1 {
					err := LoadProfile(cmd[1])
					if err != nil {
						logPrintln(1, err)
					}
				}
			case "flush":
				if cmdlen > 1 {
					if cmd[1] == "all" {
						for _, records := range DNSCache {
							if records.IPv4Hint.TTL != 0 {
								records.IPv4Hint = nil
							}
							if records.IPv6Hint.TTL != 0 {
								records.IPv6Hint = nil
							}
						}
					} else {
						records, ok := DNSCache[cmd[1]]
						if ok {
							if records.IPv4Hint.TTL != 0 {
								records.IPv4Hint = nil
							}
							if records.IPv6Hint.TTL != 0 {
								records.IPv6Hint = nil
							}
						}
					}
				}
			}
		}
	}
}

func (outbound *Outbound) ProxyHandshake(conn net.Conn, synpacket *ConnectionInfo, host string, port int) (net.Conn, error) {
	var err error
	proxy_err := errors.New("invalid proxy")

	hint := outbound.Hint & HINT_MODIFY
	var proxy_seq uint32 = 0
	switch outbound.Protocol {
	case DIRECT:
	case REDIRECT:
	case NAT64:
	case HTTP:
		{
			header := fmt.Sprintf("CONNECT %s HTTP/1.1\r\n", net.JoinHostPort(host, strconv.Itoa(port)))
			if outbound.Authorization != "" {
				header += fmt.Sprintf("Authorization: Basic %s\r\n", outbound.Authorization)
			}
			header += "\r\n"
			request := []byte(header)
			fakepayload := make([]byte, len(request))
			var n int = 0
			if synpacket != nil {
				if hint&HINT_TCPFRAG != 0 {
					n, err = conn.Write(request[:4])
					if err != nil {
						return conn, err
					}
				} else if hint&HINT_REVERSE != 0 {
					n, err = conn.Write(request[:10])
					if err != nil {
						return conn, err
					}
				}

				proxy_seq += uint32(n)
				err = ModifyAndSendPacket(synpacket, fakepayload, hint, outbound.TTL, 2)
				if err != nil {
					return conn, err
				}

				if hint&HINT_TCPFRAG != 0 {
					n, err = conn.Write(request[4:])
				} else if hint&HINT_REVERSE != 0 {
					n, err = conn.Write(request[10:])
				} else {
					n, err = conn.Write(request)
				}
				if err != nil {
					return conn, err
				}
				proxy_seq += uint32(n)
			} else {
				n, err = conn.Write(request)
				if err != nil || n == 0 {
					return conn, err
				}
			}
			var response [128]byte
			n, err = conn.Read(response[:])
			if err != nil || !strings.HasPrefix(string(response[:n]), "HTTP/1.1 200 ") {
				return conn, errors.New("failed to connect to proxy")
			}
		}
	case HTTPS:
		{
			var b [264]byte
			if synpacket != nil {
				err := ModifyAndSendPacket(synpacket, b[:], hint, outbound.TTL, 2)
				if err != nil {
					return conn, err
				}
			}
			conf := &tls.Config{
				InsecureSkipVerify: true,
			}
			conn = tls.Client(conn, conf)
			header := fmt.Sprintf("CONNECT %s HTTP/1.1\r\n", net.JoinHostPort(host, strconv.Itoa(port)))
			if outbound.Authorization != "" {
				header += fmt.Sprintf("Authorization: Basic %s\r\n", outbound.Authorization)
			}
			header += "\r\n"
			request := []byte(header)
			n, err := conn.Write(request)
			if err != nil || n == 0 {
				return conn, err
			}
			var response [128]byte
			n, err = conn.Read(response[:])
			if err != nil || !strings.HasPrefix(string(response[:n]), "HTTP/1.1 200 ") {
				return conn, errors.New("failed to connect to proxy")
			}
		}
	case SOCKS4:
		{
			var b [264]byte
			if synpacket != nil {
				err := ModifyAndSendPacket(synpacket, b[:], hint, outbound.TTL, 2)
				if err != nil {
					return conn, err
				}
			}

			copy(b[:], []byte{0x04, 0x01})
			binary.BigEndian.PutUint16(b[2:], uint16(port))

			requestLen := 0
			ip := net.ParseIP(host).To4()
			if ip != nil {
				copy(b[4:], ip[:4])
				b[8] = 0
				requestLen = 9
			} else {
				copy(b[4:], []byte{0, 0, 0, 1, 0})
				copy(b[9:], []byte(host))
				requestLen = 9 + len(host)
				b[requestLen] = 0
				requestLen++
			}
			n, err := conn.Write(b[:requestLen])
			if err != nil {
				return conn, err
			}
			proxy_seq += uint32(n)
			n, err = conn.Read(b[:8])
			if err != nil {
				return conn, err
			}
			if n < 8 || b[0] != 0 || b[1] != 90 {
				return conn, proxy_err
			}
		}
	case SOCKS5:
		{
			var b [264]byte
			if synpacket != nil {
				err := ModifyAndSendPacket(synpacket, b[:], hint, outbound.TTL, 2)
				if err != nil {
					return conn, err
				}
			}

			n, err := conn.Write([]byte{0x05, 0x01, 0x00})
			if err != nil {
				return conn, err
			}
			proxy_seq += uint32(n)
			_, err = conn.Read(b[:])
			if err != nil {
				return conn, err
			}

			if b[0] != 0x05 {
				return nil, proxy_err
			}

			if outbound.DNS != "" {
				_, ips := outbound.NSLookup(host, 0)
				if ips != nil {
					ip := ips[rand.Intn(len(ips))]
					ip4 := ip.To4()
					if ip4 != nil {
						copy(b[:], []byte{0x05, 0x01, 0x00, 0x01})
						copy(b[4:], ip4[:4])
						binary.BigEndian.PutUint16(b[8:], uint16(port))
						n, err = conn.Write(b[:10])
					} else {
						copy(b[:], []byte{0x05, 0x01, 0x00, 0x04})
						copy(b[4:], ip[:16])
						binary.BigEndian.PutUint16(b[20:], uint16(port))
						n, err = conn.Write(b[:22])
					}
					host = ""
				}
			}

			if host != "" {
				copy(b[:], []byte{0x05, 0x01, 0x00, 0x03})
				hostLen := len(host)
				b[4] = byte(hostLen)
				copy(b[5:], []byte(host))
				binary.BigEndian.PutUint16(b[5+hostLen:], uint16(port))
				n, err = conn.Write(b[:7+hostLen])
			}

			if err != nil {
				return conn, err
			}

			proxy_seq += uint32(n)

			n, err = conn.Read(b[:])
			if err != nil {
				return conn, err
			}
			if n < 2 || b[0] != 0x05 || b[1] != 0x00 {
				return nil, proxy_err
			}
		}
	}

	if synpacket != nil {
		synpacket.AddTCPSeq(proxy_seq)
	}

	return conn, err
}
