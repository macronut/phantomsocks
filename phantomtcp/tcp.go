package phantomtcp

import (
	"crypto/rand"
	"errors"
	"io"
	mathrand "math/rand"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type ConnectionInfo struct {
	Link gopacket.LinkLayer
	IP   gopacket.NetworkLayer
	TCP  layers.TCP
}

type SynInfo struct {
	Number uint32
	Option uint32
}

var ConnSyn sync.Map
var ConnInfo4 [65536]chan *ConnectionInfo
var ConnInfo6 [65536]chan *ConnectionInfo
var TFOCookies sync.Map
var TFOPayload [64][]byte
var TFOSynID uint8 = 0

const domainBytes = "abcdefghijklmnopqrstuvwxyz0123456789-"

func IsAddressInUse(err error) bool {
	//return errors.Is(err, syscall.EADDRINUSE)
	errOpError, ok := err.(*net.OpError)
	if !ok {
		return false
	}
	errSyscallError, ok := errOpError.Err.(*os.SyscallError)
	if !ok {
		return false
	}
	errErrno, ok := errSyscallError.Err.(syscall.Errno)
	if !ok {
		return false
	}
	if errErrno == syscall.EADDRINUSE {
		return true
	}
	return false
}

func IsNormalError(err error) bool {
	errOpError, ok := err.(*net.OpError)
	if !ok {
		return false
	}
	switch e := errOpError.Err.(type) {
	case *os.SyscallError:
		errErrno, ok := e.Err.(syscall.Errno)
		if !ok {
			return false
		}

		if errErrno == syscall.ETIMEDOUT ||
			errErrno == syscall.ECONNREFUSED ||
			errErrno == syscall.ECONNRESET {
			return true
		}
	default:
		//logPrintln(2, reflect.TypeOf(e))
		return true
	}

	return false
}

func AddConn(synAddr string, option uint32) {
	result, ok := ConnSyn.LoadOrStore(synAddr, SynInfo{1, option})
	if ok {
		info := result.(SynInfo)
		info.Number++
		info.Option = option
		ConnSyn.Store(synAddr, info)
	}
}

func DelConn(synAddr string) {
	result, ok := ConnSyn.Load(synAddr)
	if ok {
		info := result.(SynInfo)
		if info.Number > 1 {
			info.Number--
			ConnSyn.Store(synAddr, info)
		} else {
			ConnSyn.Delete(synAddr)
		}
	}
}

func GetLocalAddr(name string, ipv6 bool) (*net.TCPAddr, error) {
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
			var laddr *net.TCPAddr
			ip4 := localAddr.IP.To4()
			if ipv6 {
				if ip4 != nil || localAddr.IP.IsPrivate() {
					continue
				}
				ip := make([]byte, 16)
				copy(ip[:16], localAddr.IP)
				laddr = &net.TCPAddr{IP: ip[:], Port: 0}
			} else {
				if ip4 == nil {
					continue
				}
				ip := make([]byte, 4)
				copy(ip[:4], ip4)
				laddr = &net.TCPAddr{IP: ip[:], Port: 0}
			}

			return laddr, nil
		}
	}

	return nil, nil
}

func (pface *PhantomInterface) Dial(conn net.Conn, host string, port int, b []byte) (net.Conn, *ConnectionInfo, error) {
	connect_err := errors.New("connection does not exist")
	raddrs, err := pface.GetRemoteAddresses(host, port)
	if err != nil {
		return nil, nil, err
	}

	device := pface.Device
	hint := pface.Hint

	if hint&HINT_MODIFY == 0 {
		if conn == nil {
			raddr := raddrs[mathrand.Intn(len(raddrs))]
			var laddr *net.TCPAddr = nil
			if device != "" {
				laddr, err = GetLocalAddr(device, raddr.IP.To4() == nil)
				if err != nil {
					return nil, nil, err
				}
			}

			conn, err = net.DialTCP("tcp", laddr, raddr)
		}

		if err == nil {
			proxyConn, err := pface.ProxyHandshake(conn, nil, host, port, b)
			if err != nil {
				conn.Close()
				return nil, nil, err
			}
			conn = proxyConn
		}

		return conn, nil, err
	} else {
		offset := 0
		length := 0

		if b != nil {
			if hint&HINT_TFO != 0 {
				length = len(b)
			} else {
				if b[0] == 0x16 {
					offset, length, _ = GetSNI(b)
				} else {
					offset, length = GetHost(b)
				}
			}
		}

		send_magic_packet := func(connInfo *ConnectionInfo, payload []byte, hint uint32, ttl uint8, count int) error {
			var mss uint32 = 1220
			var segment uint32 = 0
			var totalLen uint32 = uint32(len(payload))
			initSeq := connInfo.TCP.Seq
			for totalLen-segment > 1220 {
				err := ModifyAndSendPacket(connInfo, payload[segment:segment+mss], hint, ttl, count)
				if err != nil {
					return err
				}
				segment += mss
				connInfo.TCP.Seq += mss
				time.Sleep(10 * time.Millisecond)
			}
			err = ModifyAndSendPacket(connInfo, payload[segment:], hint, ttl, count)
			connInfo.TCP.Seq = initSeq
			time.Sleep(10 * time.Millisecond)
			return err
		}

		if PassiveMode {
			raddr := raddrs[mathrand.Intn(len(raddrs))]

			var laddr *net.TCPAddr = nil
			if device != "" {
				laddr, err = GetLocalAddr(device, raddr.IP.To4() == nil)
				if err != nil {
					return nil, nil, err
				}
			}

			conn, err = net.DialTCP("tcp", laddr, raddr)
			if err == nil {
				conn, err = pface.ProxyHandshake(conn, nil, host, port, nil)
			}

			if err == nil && b != nil {
				if length > 0 {
					cut := offset + length/2
					tos := 1 << 2
					if hint&HINT_TTL != 0 {
						tos = int(pface.TTL) << 2
					}
					if SendWithOption(conn, b[:cut], tos, 1) == nil {
						_, err = conn.Write(b[cut:])
					}
				} else {
					_, err = conn.Write(b)
				}
			}

			if err != nil {
				conn.Close()
				return nil, nil, err
			}

			return conn, nil, err
		} else {
			start_time := time.Now()

			if offset == 0 {
				length = len(b)
				hint |= HINT_RAND
			}

			fakepaylen := len(b)
			fakepayload := make([]byte, fakepaylen)
			copy(fakepayload, b[:fakepaylen])

			cut := offset + length/2
			var tfo_payload []byte = nil
			if (hint & (HINT_TFO | HINT_HTFO)) != 0 {
				if (hint & HINT_TFO) != 0 {
					tfo_payload = b
				} else {
					tfo_payload = b[:cut]
				}
			} else if hint&HINT_RAND != 0 {
				_, err = rand.Read(fakepayload)
				if err != nil {
					logPrintln(1, err)
				}
			} else {
				min_dot := offset + length
				max_dot := offset
				for i := offset; i < offset+length; i++ {
					if fakepayload[i] == '.' {
						if i < min_dot {
							min_dot = i
						}
						if i > max_dot {
							max_dot = i
						}
					} else {
						fakepayload[i] = domainBytes[mathrand.Intn(len(domainBytes))]
					}
				}
				if min_dot == max_dot {
					min_dot = offset
				}

				cut = (min_dot + max_dot) / 2
			}

			var synpacket *ConnectionInfo
			for i := 0; i < len(raddrs); i++ {
				raddr := raddrs[i]
				laddr, err := GetLocalAddr(device, raddr.IP.To4() == nil)
				if err != nil {
					return nil, nil, errors.New("invalid device")
				}

				conn, synpacket, err = DialConnInfo(laddr, raddr, pface, tfo_payload)
				if err != nil {
					if IsNormalError(err) {
						continue
					}
					return nil, nil, err
				}

				break
			}

			if synpacket == nil {
				if conn != nil {
					conn.Close()
				}
				return nil, nil, connect_err
			}

			logPrintln(3, host, conn.RemoteAddr(), "connected", time.Since(start_time))

			if (hint & HINT_DELAY) != 0 {
				time.Sleep(time.Second)
			}

			synpacket.TCP.Seq++

			if pface.Protocol != 0 {
				conn, err = pface.ProxyHandshake(conn, synpacket, host, port, nil)
				if err != nil {
					conn.Close()
					return nil, nil, err
				}
				if pface.Protocol == HTTPS {
					conn.Write(b)
					return conn, synpacket, nil
				}
			}

			count := 1
			if (hint & (HINT_TFO | HINT_HTFO)) != 0 {
				if (hint & HINT_HTFO) != 0 {
					_, err = conn.Write(b[cut:])
					if err != nil {
						conn.Close()
						return nil, nil, err
					}
				}
				synpacket.TCP.Seq += uint32(len(b))
			} else {
				if hint&HINT_MODE2 != 0 {
					synpacket.TCP.Seq += uint32(cut)
					fakepayload = fakepayload[cut:]
					count = 2
				} else {
					err = send_magic_packet(synpacket, fakepayload, hint, pface.TTL, count)
					if err != nil {
						conn.Close()
						return nil, nil, err
					}
				}

				SegOffset := 0
				if hint&(HINT_SSEG|HINT_1SEG) != 0 {
					if hint&HINT_1SEG != 0 {
						SegOffset = 1
					} else {
						SegOffset = 4
					}
					_, err = conn.Write(b[:SegOffset])
					if err != nil {
						conn.Close()
						return nil, nil, err
					}
				}

				_, err = conn.Write(b[SegOffset:cut])
				if err != nil {
					conn.Close()
					return nil, nil, err
				}

				err = send_magic_packet(synpacket, fakepayload, hint, pface.TTL, count)
				if err != nil {
					conn.Close()
					return nil, nil, err
				}

				_, err = conn.Write(b[cut:])
				if err != nil {
					conn.Close()
					return nil, nil, err
				}

				synpacket.TCP.Seq += uint32(len(b))
				if hint&HINT_SAT != 0 {
					_, err = rand.Read(fakepayload)
					if err != nil {
						conn.Close()
						return nil, nil, err
					}
					err = send_magic_packet(synpacket, fakepayload, hint, pface.TTL, 2)
				}
			}

			return conn, synpacket, err
		}
	}
}

func (server *PhantomInterface) Keep(client, conn net.Conn, connInfo *ConnectionInfo) {
	fakepayload := make([]byte, 1500)

	go func() {
		var b [1460]byte
		for {
			n, err := client.Read(b[:])
			if err != nil {
				conn.Close()
				return
			}

			err = ModifyAndSendPacket(connInfo, fakepayload, server.Hint, server.TTL, 2)
			if err != nil {
				conn.Close()
				return
			}
			_, err = conn.Write(b[:n])
			if err != nil {
				conn.Close()
				return
			}
			connInfo.TCP.Seq += uint32(n)
		}
	}()

	io.Copy(client, conn)
}

func (pface *PhantomInterface) GetRemoteAddresses(host string, port int) ([]*net.TCPAddr, error) {
	switch pface.Protocol {
	case DIRECT:
		return pface.ResolveTCPAddrs(host, port)
	case REDIRECT:
		if pface.Address != "" {
			var str_port string
			var err error
			host, str_port, err = net.SplitHostPort(pface.Address)
			if err != nil {
				return nil, err
			}
			port, err = strconv.Atoi(str_port)
			if err != nil {
				return nil, err
			}
		}
		return pface.ResolveTCPAddrs(host, port)
	case NAT64:
		addrs, err := pface.ResolveTCPAddrs(host, port)
		if err != nil {
			return nil, err
		}
		tcpAddrs := make([]*net.TCPAddr, len(addrs))
		for i, addr := range addrs {
			proxy := pface.Address + addr.IP.String()
			tcpAddrs[i] = &net.TCPAddr{IP: net.ParseIP(proxy), Port: port}
		}
		return tcpAddrs, nil
	default:
		host, str_port, err := net.SplitHostPort(pface.Address)
		if err != nil {
			return nil, err
		}
		port, err := strconv.Atoi(str_port)
		if err != nil {
			return nil, err
		}
		pface, _ := DefaultProfile.GetInterface(host)
		return pface.ResolveTCPAddrs(host, port)
	}
}

func relay(left, right net.Conn) (int64, int64, error) {
	type res struct {
		N   int64
		Err error
	}
	ch := make(chan res)

	go func() {
		n, err := io.Copy(right, left)
		right.SetDeadline(time.Now())
		left.SetDeadline(time.Now())
		ch <- res{n, err}
	}()

	n, err := io.Copy(left, right)
	right.SetDeadline(time.Now())
	left.SetDeadline(time.Now())
	rs := <-ch

	if err == nil {
		err = rs.Err
	}
	return n, rs.N, err
}
