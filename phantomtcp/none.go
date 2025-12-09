//go:build !pcap && !rawsocket && !windivert
// +build !pcap,!rawsocket,!windivert

package phantomtcp

import (
	"net"
)

var HintMap = map[string]uint32{
	"none": HINT_NONE,

	"https": HINT_HTTPS,
	"h2":    HINT_HTTP2,
	"h3":    HINT_HTTP3,

	"ipv4"   : HINT_IPV4,
	"ipv6"   : HINT_IPV6,
	"fakeip" : HINT_FAKEIP,

	"move":     HINT_MOVE,
	"strip":    HINT_STRIP,
	"fronting": HINT_FRONTING,
	"tls1.3":   HINT_TLS1_3,
	
	"oob":    HINT_OOB,

	"udp":    HINT_UDP,
	"no-tcp": HINT_NOTCP,
	"delay":  HINT_DELAY,

	"tcp-frag": HINT_TCPFRAG,
	"tls-frag": HINT_TLSFRAG,
}

func DevicePrint() {
}

func ConnectionMonitor(devices []string) bool {
	return false
}

func ModifyAndSendPacket(connInfo *ConnectionInfo, payload []byte, hint uint32, ttl uint8, count int) error {
	return nil
}

func Redirect(dst string, to_port int, forward bool) {
}

func RedirectDNS() {
}

func SendUDPPacket(laddr *net.UDPAddr, raddr *net.UDPAddr, payload []byte, ttl uint8) error {
	return nil
}
