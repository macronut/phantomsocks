package phantomtcp

import (
	"net"
	"syscall"
	"time"
)

func DialConnInfo(laddr, raddr *net.TCPAddr, server *Outbound, payload []byte) (net.Conn, *ConnectionInfo, error) {
	var conn net.Conn
	var err error

	addr := raddr.String()
	timeout := time.Millisecond * time.Duration(server.Timeout)

	tfo_id := 0
	if payload != nil {
		tfo_id = int(TFOSynID) % 64
		TFOSynID++
		TFOPayload[tfo_id] = payload
		defer func() {
			TFOPayload[tfo_id] = nil
		}()
	}

	AddConn(addr, server.Hint)

	if (server.Hint & (HINT_TFO | HINT_HTFO | HINT_KEEPALIVE)) != 0 {
		d := net.Dialer{Timeout: timeout, LocalAddr: laddr,
			Control: func(network, address string, c syscall.RawConn) error {
				err := c.Control(func(fd uintptr) {
					f := syscall.Handle(fd)
					if (server.Hint & (HINT_TFO | HINT_HTFO)) != 0 {
						if server.Hint&HINT_IPV6 != 0 {
							syscall.SetsockoptInt(f, syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, tfo_id|64)
						} else {
							syscall.SetsockoptInt(f, syscall.IPPROTO_IP, syscall.IP_TTL, tfo_id|64)
						}
					}
					if (server.Hint & HINT_KEEPALIVE) != 0 {
						syscall.SetsockoptInt(f, syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1)
					}
				})
				return err
			}}
		conn, err = d.Dial("tcp", addr)
	} else {
		d := net.Dialer{Timeout: timeout, LocalAddr: laddr}
		conn, err = d.Dial("tcp", addr)
	}

	if err != nil {
		DelConn(raddr.String())
		return nil, nil, err
	}

	laddr = conn.LocalAddr().(*net.TCPAddr)
	var connInfo *ConnectionInfo = nil
	if raddr.IP.To4() != nil {
		select {
		case connInfo = <-ConnInfo4[laddr.Port]:
			DelConn(raddr.String())
			return conn, connInfo, nil
		case <-time.After(time.Second):
		}
	} else {
		select {
		case connInfo = <-ConnInfo6[laddr.Port]:
			DelConn(raddr.String())
			return conn, connInfo, nil
		case <-time.After(time.Second):
		}
	}

	DelConn(raddr.String())

	if (payload != nil) || (server.MaxTTL != 0) {
		if connInfo == nil {
			conn.Close()
			return nil, nil, nil
		}
		f, err := conn.(*net.TCPConn).File()
		if err != nil {
			conn.Close()
			return nil, nil, err
		}
		fd := syscall.Handle(f.Fd())
		err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TOS, 0)
		if err != nil {
			conn.Close()
			return nil, nil, err
		}
		if server.MaxTTL != 0 {
			err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TTL, int(server.MaxTTL))
		} else {
			err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TTL, 64)
		}
		if err != nil {
			conn.Close()
			return nil, nil, err
		}
		f.Close()
	}

	return conn, nil, nil
}

func GetOriginalDST(conn *net.TCPConn) (*net.TCPAddr, error) {
	LocalAddr := conn.LocalAddr()
	LocalTCPAddr := LocalAddr.(*net.TCPAddr)

	if ip4 := LocalTCPAddr.IP.To4(); ip4 != nil {
		if ip4[0] == 127 && ip4[1] == 255 {
			ip4[0] = VirtualAddrPrefix
			ip4[1] = 0
			LocalTCPAddr.IP = ip4
			RemoteTCPAddr := conn.RemoteAddr().(*net.TCPAddr).IP.To4()
			LocalTCPAddr.Port = int(RemoteTCPAddr[2])<<8 | int(RemoteTCPAddr[3])
		}
	}

	return LocalTCPAddr, nil
}

func SendWithOption(conn net.Conn, payload []byte, tos, ttl int) error {
	return nil
}

func TProxyTCP(address string) {
}
