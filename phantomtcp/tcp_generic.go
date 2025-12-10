//go:build !linux && !windows
// +build !linux,!windows

package phantomtcp

import (
	"net"
	"time"
)

func DialWithOption(laddr, raddr *net.TCPAddr, ttl, mss int, tcpfastopen, keepalive bool, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout, LocalAddr: laddr}
	return d.Dial("tcp", raddr.String())
}

func DialConnInfo(laddr, raddr *net.TCPAddr, outbound *Outbound, payload []byte) (net.Conn, *ConnectionInfo, error) {
	addr := raddr.String()
	timeout := time.Millisecond * time.Duration(outbound.Timeout)

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
	ip4 := raddr.IP.To4()
	if ip4 != nil {
		select {
		case connInfo := <-ConnInfo4[laddr.Port]:
			DelConn(raddr.String())
			return conn, connInfo, nil
		case <-time.After(time.Second):
		}
	} else {
		select {
		case connInfo := <-ConnInfo6[laddr.Port]:
			DelConn(raddr.String())
			return conn, connInfo, nil
		case <-time.After(time.Second):
		}
	}

	DelConn(raddr.String())
	return conn, nil, nil
}

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

	return LocalTCPAddr, err
}

func SendWithOption(conn net.Conn, payload, oob []byte, tos, ttl int) error {
	return nil
}

func TProxyTCP(address string) {
}
