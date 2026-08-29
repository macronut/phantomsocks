//go:build linux && rawsocket

package phantomtcp

import (
	"encoding/binary"
	"net"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"
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

	"ttl":    HINT_TTL,
	"w-md5":  HINT_WMD5,
	"n-ack":  HINT_NACK,
	"w-ack":  HINT_WACK,
	"w-csum": HINT_WCSUM,
	"w-seq":  HINT_WSEQ,
	"w-time": HINT_WTIME,
	"oob":    HINT_OOB,

	"tfo":    HINT_TFO,
	"udp":    HINT_UDP,
	"no-tcp": HINT_NOTCP,
	"delay":  HINT_DELAY,

	"reverse":    HINT_REVERSE,
	"df":         HINT_DF,
	"sat":        HINT_SAT,
	"rand":       HINT_RAND,
	"tcp-frag":   HINT_TCPFRAG,
	"tls-frag":   HINT_TLSFRAG,
	"keep-alive": HINT_KEEPALIVE,
	"synx2":      HINT_SYNX2,
	"zero":       HINT_ZERO,
}

func GetDefaultDev() string { return "" }

func ConnectionMonitor(devices []string) bool {
	return false
}

func ModifyAndSendPacket(connInfo *ConnectionInfo, payload []byte, hint uint32, ttl uint8, count int) error {
	ipLayer := connInfo.IP

	tcpLayer := &layers.TCP{
		SrcPort:    connInfo.TCP.SrcPort,
		DstPort:    connInfo.TCP.DstPort,
		Seq:        connInfo.TCP.Seq,
		Ack:        connInfo.TCP.Ack,
		DataOffset: 5,
		ACK:        true,
		PSH:        true,
		Window:     connInfo.TCP.Window,
	}

	if hint&HINT_WMD5 != 0 {
		tcpLayer.Options = []layers.TCPOption{
			layers.TCPOption{
				OptionType:   19,
				OptionLength: 16,
				OptionData:   []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			},
		}
	} else if hint&HINT_WTIME != 0 {
		tcpLayer.Options = connInfo.TCP.Options
	}

	if hint&HINT_NACK != 0 {
		tcpLayer.ACK = false
		tcpLayer.Ack = 0
	} else if hint&HINT_WACK != 0 {
		tcpLayer.Ack += uint32(tcpLayer.Window)
	}

	// And create the packet with the layers
	buffer := gopacket.NewSerializeBuffer()
	var options gopacket.SerializeOptions
	options.FixLengths = true

	if hint&HINT_WCSUM == 0 {
		options.ComputeChecksums = true
	}

	if hint&HINT_WSEQ != 0 {
		tcpLayer.Seq--
		fakepayload := make([]byte, len(payload)+1)
		fakepayload[0] = 0xFF
		copy(fakepayload[1:], payload)
		payload = fakepayload
	}

	var network string
	var laddr net.IPAddr
	var raddr net.IPAddr
	switch ip := ipLayer.(type) {
	case *layers.IPv4:
		laddr = net.IPAddr{IP: ip.SrcIP, Zone: ""}
		raddr = net.IPAddr{IP: ip.DstIP, Zone: ""}
		network = "ip4:tcp"
	case *layers.IPv6:
		laddr = net.IPAddr{IP: ip.SrcIP, Zone: ""}
		raddr = net.IPAddr{IP: ip.DstIP, Zone: ""}
		network = "ip6:tcp"
	}

	conn, err := net.DialIP(network, &laddr, &raddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	if hint&HINT_TTL != 0 {
		f, err := conn.File()
		if err != nil {
			return err
		}
		defer f.Close()
		fd := int(f.Fd())
		if network == "ip6:tcp" {
			err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, int(ttl))
		} else {
			err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TTL, int(ttl))
		}
		if err != nil {
			return err
		}
	}

	tcpLayer.SetNetworkLayerForChecksum(ipLayer)
	gopacket.SerializeLayers(buffer, options,
		tcpLayer, gopacket.Payload(payload),
	)
	outgoingPacket := buffer.Bytes()
	for i := 0; i < count; i++ {
		_, err = conn.Write(outgoingPacket)
		if err != nil {
			return err
		}
	}

	return nil
}

func SendUDPPacket(laddr *net.UDPAddr, raddr *net.UDPAddr, payload []byte, ttl uint8) error {
	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(laddr.Port),
		DstPort: layers.UDPPort(raddr.Port),
	}

	buffer := gopacket.NewSerializeBuffer()
	var options gopacket.SerializeOptions
	options.FixLengths = true
	options.ComputeChecksums = true

	var network string
	ip4 := laddr.IP.To4()
	if ip4 != nil {
		ipLayer := &layers.IPv4{
			SrcIP:    laddr.IP,
			DstIP:    raddr.IP,
			TTL:      ttl,
			Protocol: layers.IPProtocolUDP,
		}
		network = "ip4:udp"

		udpLayer.SetNetworkLayerForChecksum(ipLayer)
		gopacket.SerializeLayers(buffer, options,
			udpLayer, gopacket.Payload(payload),
		)
	} else {
		ipLayer := &layers.IPv6{
			SrcIP:      laddr.IP,
			DstIP:      raddr.IP,
			HopLimit:   ttl,
			NextHeader: layers.IPProtocolUDP,
		}
		network = "ip6:udp"

		udpLayer.SetNetworkLayerForChecksum(ipLayer)
		gopacket.SerializeLayers(buffer, options,
			udpLayer, gopacket.Payload(payload),
		)
	}

	conn, err := net.DialIP(network,
		&net.IPAddr{IP: laddr.IP, Zone: ""},
		&net.IPAddr{IP: raddr.IP, Zone: ""},
	)
	if err != nil {
		return err
	}
	defer conn.Close()

	if ttl != 0 {
		f, err := conn.File()
		if err != nil {
			return err
		}
		defer f.Close()
		fd := int(f.Fd())
		if network == "ip6:udp" {
			err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, int(ttl))
		} else {
			err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TTL, int(ttl))
		}
		if err != nil {
			return err
		}
	}

	outgoingPacket := buffer.Bytes()
	_, err = conn.Write(outgoingPacket)
	return err
}

func DialConnInfo(laddr, raddr *net.TCPAddr, outbound *Outbound, payload []byte) (net.Conn, *ConnectionInfo, error) {
	timeout := time.Millisecond * time.Duration(outbound.Timeout)
	conn, err := DialWithOption(
		laddr, raddr,
		int(outbound.MaxTTL), int(outbound.MTU),
		(outbound.Hint&HINT_TFO) != 0, (outbound.Hint&HINT_KEEPALIVE) != 0,
		timeout)

	if err != nil {
		return nil, nil, err
	}

	laddr = conn.LocalAddr().(*net.TCPAddr)
	f, err := conn.(*net.TCPConn).File()
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	fd := int(f.Fd())
	var connInfo ConnectionInfo

	if raddr.IP.To4() == nil {
		var ip layers.IPv6
		ip.Version = 6
		ip.TrafficClass = 5
		ip.FlowLabel = 0
		ip.Length = 0
		ip.NextHeader = 6
		ip.HopLimit = 64
		ip.SrcIP = laddr.IP
		ip.DstIP = raddr.IP
		ip.HopByHop = nil

		connInfo.IP = &ip
	} else {
		var ip layers.IPv4
		ip.Version = 4
		ip.IHL = 5
		ip.TOS = 0
		ip.Length = 0
		ip.Id = 0
		ip.Flags = 0
		ip.FragOffset = 0
		ip.TTL = 64
		ip.Protocol = 6
		ip.Checksum = 0
		ip.SrcIP = laddr.IP
		ip.DstIP = raddr.IP
		ip.Options = nil
		ip.Padding = nil

		connInfo.IP = &ip
	}

	connInfo.TCP.DstPort = layers.TCPPort(raddr.Port)
	connInfo.TCP.SrcPort = layers.TCPPort(laddr.Port)

	timestamp, err := unix.GetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_TIMESTAMP)
	var optionData [8]byte
	binary.BigEndian.PutUint32(optionData[:], uint32(timestamp)-3600000)
	connInfo.TCP.Options = []layers.TCPOption{
		layers.TCPOption{
			OptionType:   layers.TCPOptionKindTimestamps,
			OptionLength: 8,
			OptionData:   optionData[:],
		},
	}

	err = unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR, unix.TCP_REPAIR_ON)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}

	defer unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR, unix.TCP_REPAIR_OFF)

	err = unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR_QUEUE, 2)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}

	seq, err := unix.GetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_QUEUE_SEQ)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	connInfo.TCP.Seq = uint32(seq) - 1

	err = unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR_QUEUE, 1)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}

	ack, err := unix.GetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_QUEUE_SEQ)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	connInfo.TCP.Ack = uint32(ack)

	connInfo.TCP.Window = 32767

	return conn, &connInfo, nil
}
