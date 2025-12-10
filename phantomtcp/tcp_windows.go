package phantomtcp

import (
	"net"
	"syscall"
	"time"
)

func DialWithOption(laddr, raddr *net.TCPAddr, ttl, mss int, tcpfastopen, keepalive bool, timeout time.Duration) (net.Conn, error) {
	if tcpfastopen || keepalive {
		d := net.Dialer{Timeout: timeout, LocalAddr: laddr,
			Control: func(network, address string, c syscall.RawConn) error {
				err := c.Control(func(fd uintptr) {
					f := syscall.Handle(fd)
					if tcpfastopen {
						if raddr.IP.To4() == nil {
							syscall.SetsockoptInt(f, syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, int(TFOSynID)|64)
						} else {
							syscall.SetsockoptInt(f, syscall.IPPROTO_IP, syscall.IP_TTL, int(TFOSynID)|64)
						}
						TFOSynID++
					}
					if keepalive {
						syscall.SetsockoptInt(f, syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1)
					}
				})
				return err
			}}
		return d.Dial("tcp", raddr.String())
	} else {
		d := net.Dialer{Timeout: timeout, LocalAddr: laddr}
		return d.Dial("tcp", raddr.String())
	}
}

func DialConnInfo(laddr, raddr *net.TCPAddr, outbound *Outbound, payload []byte) (net.Conn, *ConnectionInfo, error) {
	addr := raddr.String()
	timeout := time.Millisecond * time.Duration(outbound.Timeout)

	tfo_id := 0
	if payload != nil {
		tfo_id = int(TFOSynID) % 64
		TFOPayload[tfo_id] = payload
		defer func() {
			TFOPayload[tfo_id] = nil
		}()
	}

	AddConn(addr, outbound.Hint)

	conn, err := DialWithOption(
		laddr, raddr,
		int(outbound.MaxTTL), int(outbound.MTU),
		(outbound.Hint&HINT_TFO) != 0, (outbound.Hint&HINT_KEEPALIVE) != 0,
		timeout)

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

func SendWithOption(conn net.Conn, payload, oob []byte, tos, ttl int) error {
	return nil
}

func TProxyTCP(address string) {
}
