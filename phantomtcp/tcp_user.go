//go:build !pcap && !rawsocket && !windivert

package phantomtcp

import (
	"errors"
	mathrand "math/rand"
	"net"
	"time"
)

var HintMap = map[string]uint32{
	"none": HINT_NONE,

	"https": HINT_HTTPS,
	"h2":    HINT_HTTP2,
	"h3":    HINT_HTTP3,

	"ipv4":   HINT_IPV4,
	"ipv6":   HINT_IPV6,
	"fakeip": HINT_FAKEIP,

	"move":     HINT_MOVE,
	"strip":    HINT_STRIP,
	"fronting": HINT_FRONTING,
	"tls1.3":   HINT_TLS1_3,

	"tfo": 	HINT_TFO,
	"oob": 	HINT_OOB,
	"ttl": 	HINT_TTL,
	"wmd5": HINT_WMD5,

	"udp":    HINT_UDP,
	"no-tcp": HINT_NOTCP,
	"delay":  HINT_DELAY,

	"tcp-frag":   HINT_TCPFRAG,
	"tls-frag":   HINT_TLSFRAG,
	"keep-alive": HINT_KEEPALIVE,
}

func (outbound *Outbound) dial(host string, port int, header []byte, offset int, length int) (net.Conn, *ConnectionInfo, error) {
	var conn net.Conn
	raddrs, err := outbound.GetRemoteAddresses(host, port)
	if err != nil {
		return nil, nil, err
	}

	device := outbound.Device
	hint := outbound.Hint
	tfo := hint&HINT_TFO != 0
	keepalive := hint&HINT_KEEPALIVE != 0
	timeout := time.Millisecond * time.Duration(outbound.Timeout)
	headerLen := len(header)

	var raddr *net.TCPAddr = nil
	var laddr *net.TCPAddr = nil
	raddr_index := mathrand.Intn(len(raddrs))
	raddrs_len := len(raddrs)
	for i := 0; i < raddrs_len; i++ {
		raddr = raddrs[(i + raddr_index) % raddrs_len]
		if device != "" {
			if laddr, err = GetLocalTCPAddr(device, raddr.IP.To4() == nil); err != nil {
				return nil, nil, err
			}
		}

		conn, err = DialWithOption(laddr, raddr, 0, int(outbound.MTU), tfo, keepalive, timeout)
		if err == nil || !IsNormalError(err) {
			break
		}
	}

	if err != nil {
		return nil, nil, err
	}

	if hint&HINT_TLS1_3 != 0 {
		header[2] = 0x4
	}

	if tfo {
		var state uint8
		if state, err = GetTCPState(conn); err != nil {
			conn.Close()
			return nil, nil, err
		}

		//TCP_ESTABLISHED = 1
		if state == 1 {
			conn.Close()
			time.Sleep(50 * time.Millisecond)
			conn, err = DialWithOption(laddr, raddr, 0, 0, tfo, keepalive, timeout)
			if state, err = GetTCPState(conn); err != nil {
				conn.Close()
				return nil, nil, err
			}
			if state == 1 {
				conn.Close()
				return nil, nil, errors.New("fastopen connect failed")
			}
		}
		
		TFOLen := headerLen
		if hint&(HINT_TCPFRAG) != 0 {
			TFOLen = offset + length/2
		}

		if TFOLen > 1220 {
			TFOLen = 1220
		}

		if _, err = conn.Write(header[:TFOLen]); err != nil {
			conn.Close()
			return nil, nil, err
		}

		if TFOLen < headerLen {
			_, err = conn.Write(header[TFOLen:])
		}

		return conn, nil, err
	} else if hint&(HINT_OOB) != 0 {
		SegOffset := 0
		cut := offset + length/2
		if hint&(HINT_TTL) != 0 {
			oob := []byte{0}
			err = SendWithOption(conn, header[:offset], header[offset:offset+1], 0, int(outbound.TTL))
			err = SendWithOption(conn, header[offset+1:cut], oob, 0, 64)
			SegOffset = cut
		} else if hint&(HINT_TCPFRAG) != 0 {
			oob := [2]byte{header[offset], 0}
			_, err = conn.Write(header[:1])
			time.Sleep(time.Millisecond)
			err = SendWithOption(conn, header[1:offset], oob[:], 0, 0)
			SegOffset = offset + 1
		} else {
			oob := [2]byte{header[2], 0}
			err = SendWithOption(conn, header[:2], oob[:], 0, 0)
			SegOffset = 3
		}

		if err == nil {
			_, err = conn.Write(header[SegOffset:])
		}

		return conn, nil, err
	} else if hint & (HINT_TTL|HINT_WMD5) != 0 {
		fakepayload, cut := outbound.GetFakePayload(header, offset, length) 
		fakepaylen := len(fakepayload)
		if fakepaylen > cut {
			fakepaylen = cut
		}

		if err = outbound.SendWithFakePayload(conn, fakepayload[:fakepaylen], header[:fakepaylen]); err != nil {
			conn.Close()
			return nil, nil, err
		}

		if fakepaylen < headerLen {
			_, err = conn.Write(header[fakepaylen:])
		}

		return conn, nil, err
	} else if hint&(HINT_TCPFRAG) != 0 {
		SegOffset := 0
		cut := offset + length/2
		if cut > 4 {
			if _, err = conn.Write(header[:1]); err == nil {	
				_, err = conn.Write(header[1:4])
			}
			SegOffset += 4
		}

		if err == nil {
			_, err = conn.Write(header[SegOffset:])
		}

		return conn, nil, err
	} else {
		proxyConn, err := outbound.ProxyHandshake(conn, nil, host, port)
		if err == nil {
			_, err = conn.Write(header)
		}
		return proxyConn, nil, err
	}
}

func (outbound *Outbound) Keep(client, conn net.Conn, connInfo *ConnectionInfo) {
}

var ConnInfo4 [65536]chan *ConnectionInfo
var ConnInfo6 [65536]chan *ConnectionInfo

type ConnectionInfo struct {
}

func ConnectionMonitor(devices []string) bool {
	return false
}

func ModifyAndSendPacket(connInfo *ConnectionInfo, payload []byte, hint uint32, ttl uint8, count int) error {
	return nil
}

func (synpacket *ConnectionInfo)AddTCPSeq(seq uint32) {
}

func AddConn(synAddr string, hint uint32) {
}

func DelConn(synAddr string) {
}

func Redirect(dst string, to_port int, forward bool) {
}

func RedirectDNS() {
}

func SendUDPPacket(laddr *net.UDPAddr, raddr *net.UDPAddr, payload []byte, ttl uint8) error {
	return nil
}
