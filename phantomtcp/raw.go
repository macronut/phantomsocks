//go:build linux && rawsocket
// +build linux,rawsocket

package phantomtcp

import (
	"fmt"
	"net"
	"strconv"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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
	"oob":    HINT_OOB,

	"udp":    HINT_UDP,
	"no-tcp": HINT_NOTCP,
	"delay":  HINT_DELAY,

	"mode2":      HINT_MODE2,
	"df":         HINT_DF,
	"sat":        HINT_SAT,
	"rand":       HINT_RAND,
	"tcp-frag":   HINT_TCPFRAG,
	"tls-frag":   HINT_TLSFRAG,
	"keep-alive": HINT_KEEPALIVE,
	"synx2":      HINT_SYNX2,
	"zero":       HINT_ZERO,
}

func connectionMonitor(device string, ipv6 bool) {
	localaddr, err := GetLocalTCPAddr(device, ipv6)
	if err != nil {
		logPrintln(1, device, err)
		return
	}

	var handle *net.IPConn
	if ipv6 {
		if localaddr == nil {
			logPrintln(1, "Device:", device, "no IPv6")
			return
		}
		handle, err = net.ListenIP("ip6:tcp", &net.IPAddr{IP: localaddr.IP, Zone: ""})
	} else {
		if localaddr == nil {
			logPrintln(1, "Device:", device, "no IPv4")
			return
		}
		handle, err = net.ListenIP("ip4:tcp", &net.IPAddr{IP: localaddr.IP, Zone: ""})
	}

	fmt.Printf("Device: %v (%s)\n", device, localaddr.IP.String())

	if err != nil {
		fmt.Printf("sockraw open failed: %v", err)
		return
	}
	defer handle.Close()

	buf := make([]byte, 1500)
	for {
		n, addr, err := handle.ReadFrom(buf)
		if err != nil {
			logPrintln(1, err)
			continue
		}
		if buf[13] != 18 {
			continue
		}

		var tcp layers.TCP
		tcp.DecodeFromBytes(buf[:n], gopacket.NilDecodeFeedback)
		srcPort := tcp.DstPort
		synAddr := net.JoinHostPort(addr.String(), strconv.Itoa(int(tcp.SrcPort)))
		_, ok := ConnSyn.Load(synAddr)
		if ok {
			if ipv6 {
				var ip layers.IPv6
				ip.Version = 6
				ip.TrafficClass = 5
				ip.FlowLabel = 0
				ip.Length = 0
				ip.NextHeader = 6
				ip.HopLimit = 64
				ip.SrcIP = localaddr.IP
				ip.DstIP = net.ParseIP(addr.String())
				ip.HopByHop = nil

				tcp.DstPort = tcp.SrcPort
				tcp.SrcPort = srcPort
				ack := tcp.Seq + 1
				tcp.Seq = tcp.Ack - 1
				tcp.Ack = ack

				ch := ConnInfo6[srcPort]
				connInfo := ConnectionInfo{nil, &ip, tcp}
				go func(info *ConnectionInfo) {
					select {
					case ch <- info:
					case <-time.After(time.Second * 2):
					}
				}(&connInfo)

				buf = make([]byte, 1500)
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
				ip.SrcIP = localaddr.IP
				ip.DstIP = net.ParseIP(addr.String())
				ip.Options = nil
				ip.Padding = nil

				tcp.DstPort = tcp.SrcPort
				tcp.SrcPort = srcPort
				ack := tcp.Seq + 1
				tcp.Seq = tcp.Ack - 1
				tcp.Ack = ack

				ch := ConnInfo4[srcPort]
				connInfo := ConnectionInfo{nil, &ip, tcp}
				go func(info *ConnectionInfo) {
					select {
					case ch <- info:
					case <-time.After(time.Second * 2):
					}
				}(&connInfo)

				buf = make([]byte, 1500)
			}
		}
	}
}

func ICMPMonitor(device string, ipv6 bool) {
	fmt.Printf("Device: %v\n", device)

	var err error
	localaddr, err := GetLocalTCPAddr(device, ipv6)
	if err != nil {
		logPrintln(1, err)
		return
	}

	var handle *net.IPConn
	if ipv6 {
		if localaddr == nil {
			logPrintln(1, "no IPv6 on", device)
			return
		}
		handle, err = net.ListenIP("ip6:icmp", &net.IPAddr{IP: localaddr.IP, Zone: ""})
	} else {
		if localaddr == nil {
			logPrintln(1, "no IPv4 on", device)
			return
		}
		handle, err = net.ListenIP("ip4:icmp", &net.IPAddr{IP: localaddr.IP, Zone: ""})
	}

	if err != nil {
		fmt.Printf("sockraw open failed: %v", err)
		return
	}
	defer handle.Close()

	var connInfo ConnectionInfo
	data := make([]byte, 1500)
	fakepayload := make([]byte, 1024)
	df := gopacket.NilDecodeFeedback
	for {
		n, _, err := handle.ReadFrom(data)
		if err != nil {
			logPrintln(1, err)
			continue
		}
		if len(data) < 8 || !(data[0] == 11 && data[1] == 0) {
			continue
		}

		if ipv6 {
			var icmp layers.ICMPv6
			icmp.DecodeFromBytes(data[:n], df)
			var ip layers.IPv6
			if ip.DecodeFromBytes(icmp.Payload, df) == nil && ip.NextHeader == layers.IPProtocolTCP && ip.TrafficClass > 0 {
				var tcp layers.TCP
				if tcp.DecodeFromBytes(ip.Payload, df) == nil {
					ip.TrafficClass = 0
					connInfo.IP = &ip
					connInfo.TCP = tcp
					ttl := uint8(64)
					if ip.TrafficClass > 4 {
						ttl = ip.TrafficClass >> 2
					}
					ModifyAndSendPacket(&connInfo, fakepayload, HINT_TTL|HINT_WMD5, ttl, 2)
					ModifyAndSendPacket(&connInfo, connInfo.TCP.Payload, HINT_TTL, 64, 1)
				}
			}
		} else {
			var icmp layers.ICMPv4
			icmp.DecodeFromBytes(data[:n], df)
			var ip layers.IPv4
			if ip.DecodeFromBytes(icmp.Payload, df) == nil && ip.Protocol == layers.IPProtocolTCP && ip.TOS > 0 {
				var tcp layers.TCP
				if tcp.DecodeFromBytes(ip.Payload, df) == nil {
					ip.TOS = 0
					connInfo.IP = &ip
					connInfo.TCP = tcp
					ttl := uint8(64)
					if ip.TOS > 4 {
						ttl = ip.TOS >> 2
					}
					ModifyAndSendPacket(&connInfo, fakepayload, HINT_TTL|HINT_WMD5, ttl, 2)
					ModifyAndSendPacket(&connInfo, connInfo.TCP.Payload, HINT_TTL, 64, 1)
				}
			}
		}
	}
}

func ConnectionMonitor(devices []string) bool {
	if PassiveMode {
		for i := 0; i < len(devices); i++ {
			go ICMPMonitor(devices[i], false)
		}
	} else {
		for i := 0; i < 65536; i++ {
			ConnInfo4[i] = make(chan *ConnectionInfo)
			ConnInfo6[i] = make(chan *ConnectionInfo)
		}

		for i := 0; i < len(devices); i++ {
			go connectionMonitor(devices[i], false)
			go connectionMonitor(devices[i], true)
		}
	}

	return true
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
			layers.TCPOption{19, 16, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		}
	} else if hint&HINT_WTIME != 0 {
		tcpLayer.Options = []layers.TCPOption{
			layers.TCPOption{8, 8, []byte{0, 0, 0, 0, 0, 0, 0, 0}},
		}
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
		laddr = net.IPAddr{ip.SrcIP, ""}
		raddr = net.IPAddr{ip.DstIP, ""}
		network = "ip4:tcp"
	case *layers.IPv6:
		laddr = net.IPAddr{ip.SrcIP, ""}
		raddr = net.IPAddr{ip.DstIP, ""}
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

	conn, err := net.DialIP(network, &net.IPAddr{laddr.IP, ""}, &net.IPAddr{raddr.IP, ""})
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
