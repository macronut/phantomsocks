package phantomtcp

import (
	"log"
	"net"
	"syscall"
	"time"

	"github.com/macronut/go-tproxy"
)

func DialWithOption(laddr, raddr *net.TCPAddr, ttl, mss int, tcpfastopen, keepalive bool, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout, LocalAddr: laddr,
		Control: func(network, address string, c syscall.RawConn) error {
			err := c.Control(func(fd uintptr) {
				if mss > 0 {
					syscall.SetsockoptInt(int(fd), syscall.SOL_TCP, syscall.TCP_MAXSEG, mss)
					//syscall.SetsockoptInt(int(fd), syscall.SOL_TCP, syscall.TCP_MSS, mss)
				}
				if tcpfastopen {
					// #define TCP_FASTOPEN_CONNECT 30
					syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, 30, 1)
				}
				if ttl > 0 {
					//syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TOS, 0)
					syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
				}
				if keepalive {
					syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1)
				}
			})
			return err
		}}

	return d.Dial("tcp", raddr.String())
}

func DialConnInfo(laddr, raddr *net.TCPAddr, outbound *Outbound, payload []byte) (net.Conn, *ConnectionInfo, error) {
	addr := raddr.String()
	timeout := time.Millisecond * time.Duration(outbound.Timeout)

	AddConn(addr, outbound.Hint)

	conn, err := DialWithOption(
		laddr, raddr, 
		int(outbound.MaxTTL), int(outbound.MTU), 
		(outbound.Hint & HINT_TFO) != 0, (outbound.Hint & HINT_KEEPALIVE) != 0, 
		timeout)
		
	if err != nil {
		DelConn(raddr.String())
		return nil, nil, err
	}

	laddr = conn.LocalAddr().(*net.TCPAddr)
	ip4 := raddr.IP.To4()
	var connInfo *ConnectionInfo = nil
	if ip4 != nil {
		select {
		case connInfo = <-ConnInfo4[laddr.Port]:
		case <-time.After(time.Second):
		}
	} else {
		select {
		case connInfo = <-ConnInfo6[laddr.Port]:
		case <-time.After(time.Second):
		}
	}
	DelConn(raddr.String())

	if (payload != nil) || (outbound.MaxTTL != 0) {
		if connInfo == nil {
			conn.Close()
			return nil, nil, nil
		}
		f, err := conn.(*net.TCPConn).File()
		if err != nil {
			conn.Close()
			return nil, nil, err
		}
		fd := int(f.Fd())
		err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TOS, 0)
		if err != nil {
			conn.Close()
			return nil, nil, err
		}
		if outbound.MaxTTL != 0 {
			err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TTL, int(outbound.MaxTTL))
		} else {
			err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TTL, 64)
		}
		if err != nil {
			conn.Close()
			return nil, nil, err
		}
		f.Close()
	}

	return conn, connInfo, nil
}

const (
	SO_ORIGINAL_DST      = 80
	IP6T_SO_ORIGINAL_DST = 80
)

func GetOriginalDST(conn *net.TCPConn) (*net.TCPAddr, error) {
	file, err := conn.File()
	if err != nil {
		return nil, err
	}
	defer file.Close()

	LocalAddr := conn.LocalAddr()
	LocalTCPAddr, err := net.ResolveTCPAddr(LocalAddr.Network(), LocalAddr.String())
	if err != nil {
		return nil, err
	}

	if LocalTCPAddr.IP.To4() == nil {
		mtuinfo, err := syscall.GetsockoptIPv6MTUInfo(int(file.Fd()), syscall.IPPROTO_IPV6, IP6T_SO_ORIGINAL_DST)
		if err != nil {
			return nil, err
		}

		raw := mtuinfo.Addr
		var ip net.IP = raw.Addr[:]

		port := int(raw.Port&0xFF)<<8 | int(raw.Port&0xFF00)>>8
		TCPAddr := net.TCPAddr{IP: ip, Port: port, Zone: ""}

		if TCPAddr.IP.Equal(LocalTCPAddr.IP) {
			return nil, nil
		}

		return &TCPAddr, nil
	} else {
		raw, err := syscall.GetsockoptIPv6Mreq(int(file.Fd()), syscall.IPPROTO_IP, SO_ORIGINAL_DST)
		if err != nil {
			return nil, err
		}

		var ip net.IP = raw.Multiaddr[4:8]
		port := int(raw.Multiaddr[2])<<8 | int(raw.Multiaddr[3])
		TCPAddr := net.TCPAddr{IP: ip, Port: port, Zone: ""}

		if TCPAddr.IP.Equal(LocalTCPAddr.IP) {
			return nil, nil
		}

		return &TCPAddr, nil
	}
}

func SendWithOption(conn net.Conn, payload, oob []byte, tos int, ttl int) error {
	f, err := conn.(*net.TCPConn).File()
	if err != nil {
		return err
	}
	defer f.Close()
	fd := int(f.Fd())
	if tos != 0 {
		err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TOS, tos)
		if err != nil {
			return err
		}
	}

	if ttl != 0 {
		err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
		if err != nil {
			return err
		}
	}

	if oob != nil {
		buf := make([]byte, len(payload)+1)
		copy(buf, payload)
		buf[len(payload)] = oob[0]
		err = syscall.Sendto(fd, buf, syscall.MSG_OOB, nil)
	} else {
		_, err = conn.Write(payload)
	}

	if err != nil {
		return err
	}

	if tos != 0 {
		err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TOS, 0)
		if err != nil {
			return err
		}
	}

	if ttl != 0 {
		err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TTL, 64)
		if err != nil {
			return err
		}
	}

	return nil
}

func TProxyTCP(address string) {
	laddr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		log.Panic(err)
	}
	l, err := tproxy.ListenTCP("tcp", laddr)
	if err != nil {
		log.Panic(err)
	}
	for {
		conn, err := l.Accept()
		if err != nil {
			logPrintln(1, err)
			continue
		}
		go func(conn net.Conn) {
			addr := conn.LocalAddr().(*net.TCPAddr)
			raddr := conn.RemoteAddr().(*net.TCPAddr)
			if addr.IP.Equal(raddr.IP) {
				conn.Close()
				return
			}

			TCPAddr := net.TCPAddr{IP: addr.IP, Port: addr.Port, Zone: ""}
			ip4 := addr.IP.To4()
			if ip4 != nil {
				TCPAddr.IP = ip4
			}

			tcp_redirect(conn, &TCPAddr, "", nil)
		}(conn)
	}
}
