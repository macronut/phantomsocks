package phantomtcp

import (
	"bytes"
	"encoding/binary"
	"io"
	"log"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"
)

func ReadAtLeast() {

}

func SocksProxy(client net.Conn) {
	defer client.Close()

	var server PhantomServer
	var ok bool

	var conn net.Conn
	{
		var b [1500]byte
		n, err := client.Read(b[:])
		if err != nil || n < 3 {
			logPrintln(1, client.RemoteAddr(), err)
			return
		}

		host := ""
		var ip net.IP
		port := 0
		var reply []byte
		if b[0] == 0x05 {
			client.Write([]byte{0x05, 0x00})
			n, err = client.Read(b[:4])
			if n != 4 {
				return
			}
			switch b[3] {
			case 0x01: //IPv4
				n, err = client.Read(b[:6])
				if n < 6 {
					return
				}
				ip = net.IP(b[:4])
				port = int(binary.BigEndian.Uint16(b[4:6]))
			case 0x03: //Domain
				n, err = client.Read(b[:])
				addrLen := b[0]
				host = string(b[1 : addrLen+1])
				port = int(binary.BigEndian.Uint16(b[n-2:]))
			case 0x04: //IPv6
				n, err = client.Read(b[:])
				ip = net.IP(b[:16])
				port = int(binary.BigEndian.Uint16(b[16:18]))
			default:
				logPrintln(1, "not supported")
				return
			}
			reply = []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}
		} else if b[0] == 0x04 {
			userEnd := bytes.IndexByte(b[:n], 0)
			if userEnd >= 8 && b[1] == 1 {
				port = int(binary.BigEndian.Uint16(b[2:4]))
				if n > userEnd && b[4]|b[5]|b[6] == 0 {
					hostEnd := bytes.IndexByte(b[userEnd+1:n], 0)
					if hostEnd > 0 {
						host = string(b[userEnd+1 : userEnd+1+hostEnd])
					} else {
						client.Write([]byte{0, 91, 0, 0, 0, 0, 0, 0})
						return
					}
				} else {
					if b[0] == VirtualAddrPrefix {
						index := int(binary.BigEndian.Uint32(b[6:8]))
						if index >= len(Nose) {
							return
						}
						host = Nose[index]
					} else {
						ip = net.IP(b[4:8])
					}
				}

				reply = []byte{0, 90, b[2], b[3], b[4], b[5], b[6], b[7]}
			} else {
				client.Write([]byte{0, 91, 0, 0, 0, 0, 0, 0})
				return
			}
		} else {
			return
		}

		if err != nil {
			logPrintln(1, err)
			return
		}

		if host != "" {
			server, ok = ConfigLookup(host)
			if ok {
				if server.Option&OPT_PROXY == 0 {
					logPrintln(1, "Socks:", host, port, server)

					_, ips := NSLookup(host, server.Option, server.Server)
					if len(ips) == 0 {
						logPrintln(1, host, "no such host")
						return
					}

					if server.Option == 0 {
						conn, err = server.Dial(ips, port, nil)
						if err != nil {
							logPrintln(1, err)
							return
						}

						n, err = client.Write(reply)
						if err != nil {
							conn.Close()
							logPrintln(1, err)
							return
						}
					} else {
						n, err = client.Write(reply)
						if err != nil {
							logPrintln(1, err)
							return
						}

						n, err = client.Read(b[:])
						if err != nil {
							logPrintln(1, err)
							return
						}

						if b[0] != 0x16 {
							if server.Option&OPT_HTTPS != 0 {
								HttpMove(client, "https", b[:n])
								return
							} else if server.Option&OPT_MOVE != 0 {
								HttpMove(client, server.Server, b[:n])
								return
							} else if server.Option&OPT_STRIP != 0 {
								rand.Seed(time.Now().UnixNano())
								ipaddr := ips[rand.Intn(len(ips))]
								if server.Option&OPT_FRONTING != 0 {
									host = ""
								}
								conn, err = DialStrip(ipaddr.String(), host)
								if err != nil {
									logPrintln(1, err)
									return
								}
								_, err = conn.Write(b[:n])
							} else {
								conn, err = server.HTTP(client, ips, port, b[:n])
								if err != nil {
									logPrintln(1, err)
									return
								}
								io.Copy(client, conn)
								return
							}
						} else {
							conn, err = server.Dial(ips, port, b[:n])
							if err != nil {
								logPrintln(1, host, err)
								return
							}
						}
					}
				} else {
					logPrintln(1, "SocksoverProxy:", client.RemoteAddr(), "->", host, port, server)

					if server.Option&OPT_MODIFY != 0 {
						n, err = client.Write(reply)
						if err != nil {
							conn.Close()
							logPrintln(1, err)
							return
						}

						n, err = client.Read(b[:])
						if err != nil {
							logPrintln(1, err)
							return
						}

						conn, err = server.DialProxy(net.JoinHostPort(host, strconv.Itoa(port)), b[:n])
					} else {
						conn, err = server.DialProxy(net.JoinHostPort(host, strconv.Itoa(port)), nil)
						if err != nil {
							logPrintln(1, host, err)
							return
						}

						n, err = client.Write(reply)
					}
				}
			} else {
				addr := net.JoinHostPort(host, strconv.Itoa(port))
				logPrintln(1, "Socks:", addr)
				conn, err = net.Dial("tcp", addr)
				if err != nil {
					logPrintln(1, err)
					return
				}
				_, err = client.Write(reply)
			}
		} else {
			if ip.To4() != nil {
				server, ok := ConfigLookup(ip.String())
				addr := net.TCPAddr{IP: ip, Port: port, Zone: ""}
				if ok {
					logPrintln(1, "Socks:", addr.IP.String(), addr.Port, server)
					client.Write(reply)
					n, err = client.Read(b[:])

					ip := addr.IP
					result, ok := ACache.Load(ip.String())
					var addresses []net.IP
					if ok {
						addresses = make([]net.IP, len(result.(DomainIP).Addresses))
						copy(addresses, result.(DomainIP).Addresses)
					} else {
						addresses = []net.IP{ip}
					}
					conn, err = server.Dial(addresses, port, b[:n])
				} else {
					logPrintln(1, "Socks:", addr.IP.String(), addr.Port)

					conn, err = net.DialTCP("tcp", nil, &addr)
					client.Write(reply)
				}
			} else {
				addr := net.TCPAddr{IP: ip, Port: port, Zone: ""}
				logPrintln(1, "Socks:", addr.IP.String(), addr.Port)
				conn, err = net.DialTCP("tcp", nil, &addr)
				client.Write(reply)
			}
		}

		if err != nil {
			logPrintln(1, err)
			return
		}
	}

	defer conn.Close()

	_, _, err := relay(client, conn)
	if err != nil {
		if err, ok := err.(net.Error); ok && err.Timeout() {
			return
		}
		logPrintln(1, "relay error:", err)
	}
}

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

func SNIProxy(client net.Conn) {
	defer client.Close()

	var conn net.Conn
	{
		var b [1500]byte
		n, err := client.Read(b[:])
		if err != nil {
			log.Println(err)
			return
		}

		var host string
		var port int
		if b[0] == 0x16 {
			offset, length := GetSNI(b[:n])
			if length == 0 {
				return
			}
			host = string(b[offset : offset+length])
			port = 443
		} else {
			offset, length := GetHost(b[:n])
			if length == 0 {
				return
			}
			host = string(b[offset : offset+length])
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

		server, ok := ConfigLookup(host)

		if ok {
			logPrintln(1, "SNI:", host, port, server)

			_, ips := NSLookup(host, server.Option, server.Server)
			if len(ips) == 0 {
				logPrintln(1, host, "no such host")
				return
			}

			if b[0] == 0x16 {
				conn, err = server.Dial(ips, port, b[:n])
				if err != nil {
					logPrintln(1, host, err)
					return
				}
			} else {
				if server.Option&OPT_HTTPS != 0 {
					HttpMove(client, "https", b[:n])
					return
				} else if server.Option&OPT_MOVE != 0 {
					HttpMove(client, server.Server, b[:n])
					return
				} else if server.Option&OPT_STRIP != 0 {
					ip := ips[rand.Intn(len(ips))]
					if server.Option&OPT_FRONTING != 0 {
						host = ""
					}
					conn, err = DialStrip(ip.String(), host)
					if err != nil {
						logPrintln(1, err)
						return
					}
					_, err = conn.Write(b[:n])
				} else {
					conn, err = server.HTTP(client, ips, port, b[:n])
					if err != nil {
						logPrintln(1, err)
						return
					}
					io.Copy(client, conn)
					return
				}
			}
		} else {
			host = net.JoinHostPort(host, strconv.Itoa(port))
			logPrintln(1, host)

			conn, err = net.Dial("tcp", host)
			if err != nil {
				logPrintln(1, err)
				return
			}
			_, err = conn.Write(b[:n])
			if err != nil {
				logPrintln(1, err)
				return
			}
		}
	}

	defer conn.Close()

	_, _, err := relay(client, conn)
	if err != nil {
		if err, ok := err.(net.Error); ok && err.Timeout() {
			return
		}
		logPrintln(1, "relay error:", err)
	}
}

func RedirectProxy(client net.Conn) {
	defer client.Close()

	var conn net.Conn
	{
		var host string
		var port int
		var ips []net.IP = nil
		addr, err := GetOriginalDST(client.(*net.TCPConn))
		if err != nil {
			logPrintln(1, err)
			return
		}

		switch addr.IP[0] {
		case 0x00:
			index := int(binary.BigEndian.Uint32(addr.IP[12:16]))
			if index >= len(Nose) {
				return
			}
			host = Nose[index]
		case VirtualAddrPrefix:
			index := int(binary.BigEndian.Uint16(addr.IP[2:4]))
			if index >= len(Nose) {
				return
			}
			host = Nose[index]
		default:
			if addr.String() == client.LocalAddr().String() {
				return
			}
			host = addr.IP.String()
			ips = []net.IP{addr.IP}
		}
		port = addr.Port

		server, ok := ConfigLookup(host)

		if ok {
			if server.Option&OPT_PROXY == 0 {
				if ips == nil {
					_, ips = NSLookup(host, server.Option, server.Server)
					if len(ips) == 0 {
						logPrintln(1, host, "no such host")
						return
					}
				}

				if server.Option == 0 {
					conn, err = server.Dial(ips, port, nil)
					if err != nil {
						logPrintln(1, err)
						return
					}
				} else {
					var b [1500]byte
					n, err := client.Read(b[:])
					if err != nil {
						logPrintln(1, err)
						return
					}

					if b[0] == 0x16 {
						offset, length := GetSNI(b[:n])
						if length > 0 {
							host = string(b[offset : offset+length])
							_server, ok := ConfigLookup(host)
							if ok {
								server = _server
							}
						}

						logPrintln(1, "Redirect:", client.RemoteAddr(), "->", host, port, server)

						conn, err = server.Dial(ips, port, b[:n])
						if err != nil {
							logPrintln(1, host, err)
							return
						}
					} else {
						logPrintln(1, "Redirect:", client.RemoteAddr(), "->", host, port, server)
						if server.Option&OPT_HTTPS != 0 {
							HttpMove(client, "https", b[:n])
							return
						} else if server.Option&OPT_MOVE != 0 {
							HttpMove(client, server.Server, b[:n])
							return
						} else if server.Option&OPT_STRIP != 0 {
							ip := ips[rand.Intn(len(ips))]
							if server.Option&OPT_FRONTING != 0 {
								host = ""
							}
							conn, err = DialStrip(ip.String(), host)
							if err != nil {
								logPrintln(1, err)
								return
							}
							_, err = conn.Write(b[:n])
						} else {
							conn, err = server.HTTP(client, ips, port, b[:n])
							if err != nil {
								logPrintln(1, err)
								return
							}
							io.Copy(client, conn)
							return
						}
					}
				}
			} else {
				logPrintln(1, "RedirectProxy:", client.RemoteAddr(), "->", host, port, server)

				if server.Option == OPT_PROXY {
					conn, err = server.DialProxy(net.JoinHostPort(host, strconv.Itoa(port)), nil)
				} else {
					var b [1500]byte
					n, err := client.Read(b[:])
					if err != nil {
						logPrintln(1, err)
						return
					}

					conn, err = server.DialProxy(net.JoinHostPort(host, strconv.Itoa(port)), b[:n])
				}

				if err != nil {
					logPrintln(1, host, err)
					return
				}
			}
		} else if ips != nil {
			logPrintln(1, "RedirectProxy:", client.RemoteAddr(), "->", addr)
			conn, err = net.DialTCP("tcp", nil, addr)
			if err != nil {
				logPrintln(1, host, err)
				return
			}
		}
	}

	if conn == nil {
		return
	}

	defer conn.Close()

	//go io.Copy(client, conn)
	//io.Copy(conn, client)
	_, _, err := relay(client, conn)
	if err != nil {
		if err, ok := err.(net.Error); ok && err.Timeout() {
			return // ignore i/o timeout
		}
		logPrintln(1, "relay error:", err)
	}
}
