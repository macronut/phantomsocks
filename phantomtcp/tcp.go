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
	Hint   uint32
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

func AddConn(synAddr string, hint uint32) {
	result, ok := ConnSyn.LoadOrStore(synAddr, SynInfo{1, hint})
	if ok {
		info := result.(SynInfo)
		info.Number++
		info.Hint = hint
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

func GetLocalTCPAddr(name string, ipv6 bool) (*net.TCPAddr, error) {
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

func (outbound *Outbound) dial(host string, port int, b []byte, offset int, length int) (net.Conn, *ConnectionInfo, error) {
	var conn net.Conn
	raddrs, err := outbound.GetRemoteAddresses(host, port)
	if err != nil {
		return nil, nil, err
	}

	connect_err := errors.New("connection does not exist")
	device := outbound.Device
	hint := outbound.Hint

	if hint&HINT_FAKE == 0 {
		if conn == nil {
			raddr := raddrs[mathrand.Intn(len(raddrs))]
			var laddr *net.TCPAddr = nil
			if device != "" {
				laddr, err = GetLocalTCPAddr(device, raddr.IP.To4() == nil)
				if err != nil {
					return nil, nil, err
				}
			}

			conn, err = net.DialTCP("tcp", laddr, raddr)
			if err != nil {
				return nil, nil, err
			}
		}

		proxyConn, err := outbound.ProxyHandshake(conn, nil, host, port, b)
		if err != nil {
			conn.Close()
			return nil, nil, err
		}
		return proxyConn, nil, err
	} else {
		if b != nil {
			if hint&HINT_TFO != 0 {
				length = len(b)
			} else if offset == 0 {
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
				laddr, err = GetLocalTCPAddr(device, raddr.IP.To4() == nil)
				if err != nil {
					return nil, nil, err
				}
			}

			conn, err = net.DialTCP("tcp", laddr, raddr)
			if err == nil {
				conn, err = outbound.ProxyHandshake(conn, nil, host, port, nil)
			}

			if err == nil && b != nil {
				if length > 0 {
					cut := offset + length/2
					tos := 1 << 2
					if hint&HINT_TTL != 0 {
						tos = int(outbound.TTL) << 2
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
				laddr, err := GetLocalTCPAddr(device, raddr.IP.To4() == nil)
				if err != nil {
					return nil, nil, errors.New("invalid device")
				}

				conn, synpacket, err = DialConnInfo(laddr, raddr, outbound, tfo_payload)
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

			if outbound.Protocol != 0 {
				conn, err = outbound.ProxyHandshake(conn, synpacket, host, port, nil)
				if err != nil {
					conn.Close()
					return nil, nil, err
				}
				if outbound.Protocol == HTTPS {
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
					err = send_magic_packet(synpacket, fakepayload, hint, outbound.TTL, count)
					if err != nil {
						conn.Close()
						return nil, nil, err
					}
				}

				SegOffset := 0
				if hint&(HINT_TCPFRAG) != 0 && cut > 4 {
					SegOffset = 4
					_, err = conn.Write(b[:1])
					if err == nil {
						_, err = conn.Write(b[1:4])
					}
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

				err = send_magic_packet(synpacket, fakepayload, hint, outbound.TTL, count)
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
					err = send_magic_packet(synpacket, fakepayload, hint, outbound.TTL, 2)
				}
			}

			return conn, synpacket, err
		}
	}
}

func (outbound *Outbound) Keep(client, conn net.Conn, connInfo *ConnectionInfo) {
	fakepayload := make([]byte, 1500)

	go func() {
		var b [1460]byte
		for {
			n, err := client.Read(b[:])
			if err != nil {
				conn.Close()
				return
			}

			err = ModifyAndSendPacket(connInfo, fakepayload, outbound.Hint, outbound.TTL, 2)
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

func (outbound *Outbound) GetRemoteAddresses(host string, port int) ([]*net.TCPAddr, error) {
	switch outbound.Protocol {
	case DIRECT:
		return outbound.ResolveTCPAddrs(host, port)
	case REDIRECT:
		if outbound.Address != "" {
			var str_port string
			var err error
			host, str_port, err = net.SplitHostPort(outbound.Address)
			if err != nil {
				return nil, err
			}
			port, err = strconv.Atoi(str_port)
			if err != nil {
				return nil, err
			}
		}
		return outbound.ResolveTCPAddrs(host, port)
	case NAT64:
		addrs, err := outbound.ResolveTCPAddrs(host, port)
		if err != nil {
			return nil, err
		}
		tcpAddrs := make([]*net.TCPAddr, len(addrs))
		for i, addr := range addrs {
			proxy := outbound.Address + addr.IP.String()
			tcpAddrs[i] = &net.TCPAddr{IP: net.ParseIP(proxy), Port: port}
		}
		return tcpAddrs, nil
	default:
		host, str_port, err := net.SplitHostPort(outbound.Address)
		if err != nil {
			return nil, err
		}
		port, err := strconv.Atoi(str_port)
		if err != nil {
			return nil, err
		}
		outbound, _ := DefaultProfile.GetOutbound(host)
		return outbound.ResolveTCPAddrs(host, port)
	}
}

func (profile *PhantomProfile) Dial(network, address string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	outbound, _ := profile.GetOutbound(host)
	if outbound != nil {
		return outbound.PhantomDial(network, address)
	}

	return net.Dial(network, address)
}

func (outbound *Outbound) PhantomDial(network, address string) (net.Conn, error) {
	connect_err := errors.New("connection does not exist")
	c := &phantomConn{conn: nil, hint: outbound.Hint, info: nil, header: nil}
	host, str_port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(str_port)
	if err != nil {
		return nil, err
	}
	raddrs, err := outbound.GetRemoteAddresses(host, port)
	if err != nil {
		return nil, err
	}

	for i := 0; i < len(raddrs); i++ {
		raddr := raddrs[mathrand.Intn(len(raddrs))]
		laddr, err := GetLocalTCPAddr(outbound.Device, raddr.IP.To4() == nil)
		if err != nil {
			return nil, errors.New("invalid device")
		}

		if outbound.Hint&HINT_FAKE != 0 {
			c.conn, c.info, err = DialConnInfo(laddr, raddr, outbound, nil)
		} else {
			c.conn, err = net.DialTCP("tcp", laddr, raddr)
		}

		if err != nil {
			if IsNormalError(err) {
				continue
			}
			return nil, err
		}

		break
	}

	if outbound.Hint&HINT_FAKE != 0 {
		if c.info == nil {
			if c.conn != nil {
				c.conn.Close()
			}
			return nil, connect_err
		}

		c.info.TCP.Seq++
	}

	if (outbound.Hint & HINT_DELAY) != 0 {
		time.Sleep(time.Second)
	}

	return c, nil
}

type phantomConn struct {
	conn   net.Conn
	hint   uint32
	info   *ConnectionInfo
	header []byte
}

func (c *phantomConn) Read(b []byte) (int, error) {
	return c.conn.Read(b)
}

func (c *phantomConn) Write(b []byte) (int, error) {
	if c.hint != 0 {
		header := b
		payloadLen := len(b)
		if c.header == nil {
			if header[0] == 0x16 {
				headerLen := GetHelloLength(header) + 5
				if payloadLen < headerLen {
					c.header = make([]byte, payloadLen)
					copy(c.header, b[:])
					return payloadLen, nil
				}
			}
		} else if c.header[0] == 0x16 {
			headerLen := GetHelloLength(header) + 5
			if len(c.header)+payloadLen >= headerLen {
				header = make([]byte, len(c.header)+payloadLen)
				copy(header, c.header)
				copy(header[len(c.header):], b)
				c.header = nil
			}
		}

		if header[0] == 0x16 {
			offset, length, _ := GetSNI(header)
			if length > 0 {
				if c.hint&HINT_TLSFRAG != 0 {
					header = TLSFragment(header, offset+length/2)
				}
			}
		}

		if c.hint&HINT_TCPFRAG != 0 && payloadLen > 4 {
			c.hint = 0
			n1, err := c.conn.Write(header[:4])
			if err != nil {
				return n1, err
			}
			n2, err := c.conn.Write(header[4:])
			return n1 + n2, err
		}

		c.hint = 0
		return c.conn.Write(header)
	}

	return c.conn.Write(b)
}

func (c *phantomConn) Close() error {
	return c.conn.Close()
}

func (c *phantomConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *phantomConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *phantomConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *phantomConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *phantomConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func relay(left, right net.Conn) error {
	errch := make(chan error, 2)

	go func() {
		_, err := io.Copy(right, left)
		errch <- err
	}()
	go func() {
		_, err := io.Copy(left, right)
		errch <- err
	}()

	return <-errch
}
