//go:build windows && windivert
// +build windows,windivert

package phantomtcp

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/macronut/godivert"
)

var HintMap = map[string]uint32{
	"none": HINT_NONE,

	"https": HINT_HTTPS,
	"h2":    HINT_HTTP2,
	"h3":    HINT_HTTP3,

	"ipv4": HINT_IPV4,
	"ipv6": HINT_IPV6,

	"move":     HINT_MOVE,
	"strip":    HINT_STRIP,
	"fronting": HINT_FRONTING,

	"ttl":    HINT_TTL,
	"w-md5":  HINT_WMD5,
	"n-ack":  HINT_NACK,
	"w-ack":  HINT_WACK,
	"w-csum": HINT_WCSUM,
	"w-seq":  HINT_WSEQ,
	"w-time": HINT_WTIME,

	"tfo":    HINT_TFO,
	"udp":    HINT_UDP,
	"no-tcp": HINT_NOTCP,
	"delay":  HINT_DELAY,

	"mode2":      HINT_MODE2,
	"df":         HINT_DF,
	"sat":        HINT_SAT,
	"rand":       HINT_RAND,
	"tcp-frag":   HINT_TCPFRAG,
	"tls-frag":   HINT_TLSFRAG,
	"half-tfo":   HINT_HTFO,
	"keep-alive": HINT_KEEPALIVE,
	"synx2":      HINT_SYNX2,
	"zero":       HINT_ZERO,
}

var ConnWait4 [65536]uint32
var ConnWait6 [65536]uint32
var winDivertLock sync.Mutex
var winDivert *godivert.WinDivertHandle

func DevicePrint() {
}

func connectionMonitor(layer uint8) {
	filter := "tcp.Syn"

	var err error
	winDivertLock.Lock()
	winDivert, err = godivert.WinDivertOpen(filter, layer, 1, 0)
	winDivertLock.Unlock()
	if err != nil {
		fmt.Printf("winDivert open failed: %v", err)
		return
	}
	defer winDivert.Close()

	for {
		divertpacket, err := winDivert.Recv()
		if err != nil {
			logPrintln(1, err)
			continue
		}

		ipv6 := divertpacket.Raw[0]>>4 == 6
		var packet gopacket.Packet
		if ipv6 {
			packet = gopacket.NewPacket(divertpacket.Raw, layers.LayerTypeIPv6, gopacket.Default)
		} else {
			packet = gopacket.NewPacket(divertpacket.Raw, layers.LayerTypeIPv4, gopacket.Default)
		}

		ip := packet.NetworkLayer()
		tcp := packet.TransportLayer().(*layers.TCP)
		synack := tcp.SYN && tcp.ACK

		switch ip := ip.(type) {
		case *layers.IPv4:
			var srcPort layers.TCPPort
			var synAddr string
			var hint uint32 = 0
			if synack {
				hint = ConnWait4[tcp.DstPort]
				if hint == 0 {
					winDivert.Send(divertpacket)
					continue
				}
				srcPort = tcp.DstPort
				addr := net.TCPAddr{IP: ip.SrcIP, Port: int(tcp.SrcPort)}
				synAddr = addr.String()
			} else {
				srcPort = tcp.SrcPort
				addr := net.TCPAddr{IP: ip.DstIP, Port: int(tcp.DstPort)}
				synAddr = addr.String()
				result, ok := ConnSyn.Load(synAddr)
				if ok {
					hint = result.(SynInfo).Hint
				}
			}

			if hint != 0 {
				if synack {
					srcIP := ip.DstIP
					ip.DstIP = ip.SrcIP
					ip.SrcIP = srcIP
					ip.TTL = 128

					tcp.DstPort = tcp.SrcPort
					tcp.SrcPort = srcPort
					ack := tcp.Seq + 1
					tcp.Seq = tcp.Ack - 1
					tcp.Ack = ack
				}

				ch := ConnInfo4[srcPort]
				connInfo := &ConnectionInfo{nil, ip, *tcp}

				if hint&(HINT_TFO|HINT_HTFO|HINT_SYNX2) != 0 {
					if synack {
						if hint&(HINT_TFO|HINT_HTFO) != 0 {
							for _, op := range tcp.Options {
								if op.OptionType == 34 {
									TFOCookies.Store(ip.DstIP.String(), op.OptionData)
								}
							}
						}
						ConnWait4[srcPort] = 0
					} else if hint&(HINT_TFO|HINT_HTFO) != 0 {
						if ip.TTL < 128 {
							count := 1
							if hint&HINT_SYNX2 != 0 {
								count = 2
							}

							tfo_id := ip.TTL & 63
							ip.TTL = 128
							if tcp.SYN == true {
								payload := TFOPayload[tfo_id]
								if payload != nil {
									ip.TOS = 0
									ModifyAndSendPacket(connInfo, payload, HINT_TFO, 0, count)
									ConnWait4[srcPort] = hint
								} else {
									connInfo = nil
								}
							} else {
								ip.TOS = 0
								ModifyAndSendPacket(connInfo, nil, HINT_TFO, 0, count)
								connInfo = nil
							}
						}
					} else if hint&HINT_SYNX2 != 0 {
						winDivert.Send(divertpacket)
						SendPacket(packet)
					}
				} else {
					winDivert.Send(divertpacket)
				}

				go func(info *ConnectionInfo) {
					select {
					case ch <- info:
					case <-time.After(time.Second * 2):
					}
				}(connInfo)
			} else {
				winDivert.Send(divertpacket)
			}
		case *layers.IPv6:
			var srcPort layers.TCPPort
			var synAddr string
			var hint uint32 = 0
			if synack {
				hint = ConnWait6[tcp.DstPort]

				if hint == 0 {
					winDivert.Send(divertpacket)
					continue
				}
				srcPort = tcp.DstPort
				addr := net.TCPAddr{IP: ip.SrcIP, Port: int(tcp.SrcPort)}
				synAddr = addr.String()
			} else {
				srcPort = tcp.SrcPort
				addr := net.TCPAddr{IP: ip.DstIP, Port: int(tcp.DstPort)}
				synAddr = addr.String()
				result, ok := ConnSyn.Load(synAddr)
				if ok {
					hint = result.(SynInfo).Hint
				}
			}
			if hint != 0 {
				if synack {
					srcIP := ip.DstIP
					ip.DstIP = ip.SrcIP
					ip.SrcIP = srcIP
					ip.HopLimit = 64

					tcp.DstPort = tcp.SrcPort
					tcp.SrcPort = srcPort
					ack := tcp.Seq + 1
					tcp.Seq = tcp.Ack - 1
					tcp.Ack = ack
				}

				ch := ConnInfo6[srcPort]
				connInfo := &ConnectionInfo{nil, ip, *tcp}

				if hint&(HINT_TFO|HINT_HTFO|HINT_SYNX2) != 0 {
					if synack {
						if hint&(HINT_TFO|HINT_HTFO) != 0 {
							for _, op := range tcp.Options {
								if op.OptionType == 34 {
									TFOCookies.Store(ip.DstIP.String(), op.OptionData)
								}
							}
						}
						ConnWait6[srcPort] = 0
					} else if hint&(HINT_TFO|HINT_HTFO) != 0 {
						if ip.HopLimit < 128 {
							count := 1
							if hint&HINT_SYNX2 != 0 {
								count = 2
							}

							tfo_id := ip.HopLimit & 63
							ip.HopLimit = 64

							if tcp.SYN == true {
								payload := TFOPayload[tfo_id]
								if payload != nil {
									ip.TrafficClass = 0
									ModifyAndSendPacket(connInfo, payload, HINT_TFO, 0, count)
									ConnWait6[srcPort] = hint
								} else {
									connInfo = nil
								}
							} else {
								ip.TrafficClass = 0
								ModifyAndSendPacket(connInfo, nil, HINT_TFO, 0, count)
								connInfo = nil
							}
						}
					} else if hint&HINT_SYNX2 != 0 {
						winDivert.Send(divertpacket)
						SendPacket(packet)
					}
				} else {
					winDivert.Send(divertpacket)
				}

				go func(info *ConnectionInfo) {
					select {
					case ch <- info:
					case <-time.After(time.Second * 2):
					}
				}(connInfo)
			} else {
				winDivert.Send(divertpacket)
			}
		default:
			winDivert.Send(divertpacket)
		}
	}
}

func ConnectionMonitor(devices []string) bool {
	for i := 0; i < 65536; i++ {
		ConnInfo4[i] = make(chan *ConnectionInfo, 1)
		ConnInfo6[i] = make(chan *ConnectionInfo, 1)
	}

	go connectionMonitor(0)

	return true
}

func SendPacket(packet gopacket.Packet) error {
	payload := packet.LinkLayer().LayerPayload()

	var divertAddr godivert.WinDivertAddress
	var divertpacket godivert.Packet
	divertpacket.Raw = payload
	divertpacket.PacketLen = uint(len(divertpacket.Raw))
	divertpacket.Addr = &divertAddr
	divertpacket.ParseHeaders()

	_, err := winDivert.Send(&divertpacket)
	return err
}

func ModifyAndSendPacket(connInfo *ConnectionInfo, payload []byte, hint uint32, ttl uint8, count int) error {
	ipLayer := connInfo.IP

	var tcpLayer *layers.TCP
	if hint&HINT_TFO != 0 {
		tcpLayer = &connInfo.TCP

		tcpLayer.Seq -= uint32(len(payload))
		var cookie []byte = nil
		switch ip := ipLayer.(type) {
		case *layers.IPv4:
			result, ok := TFOCookies.Load(ip.DstIP.String())
			if ok {
				cookie = result.([]byte)
			} else {
				payload = nil
			}
		case *layers.IPv6:
			result, ok := TFOCookies.Load(ip.DstIP.String())
			logPrintln(5, ip.DstIP.String(), "Cookies:", result)
			if ok {
				cookie = result.([]byte)
			} else {
				payload = nil
			}
		}

		tcpLayer.ECE = false
		tcpLayer.CWR = false
		tcpLayer.Options = append(connInfo.TCP.Options,
			layers.TCPOption{34, uint8(len(cookie)), cookie},
		)
	} else {
		tcpLayer = &layers.TCP{
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

	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	switch ip := ipLayer.(type) {
	case *layers.IPv4:
		if hint&HINT_TTL != 0 {
			ip.TTL = ttl
		}
		gopacket.SerializeLayers(buffer, options,
			ip, tcpLayer, gopacket.Payload(payload),
		)
	case *layers.IPv6:
		if hint&HINT_TTL != 0 {
			ip.HopLimit = ttl
		}
		gopacket.SerializeLayers(buffer, options,
			ip, tcpLayer, gopacket.Payload(payload),
		)
	}

	var divertAddr godivert.WinDivertAddress
	var divertpacket godivert.Packet
	divertpacket.Raw = buffer.Bytes()
	divertpacket.PacketLen = uint(len(divertpacket.Raw))
	divertpacket.Addr = &divertAddr
	divertpacket.ParseHeaders()
	//divertpacket.CalcNewChecksum(winDivert)

	for i := 0; i < count; i++ {
		_, err := winDivert.Send(&divertpacket)
		if err != nil {
			return err
		}
	}

	return nil
}

func Redirect(dst string, to_port int, forward bool) {
	if dst == "" {
		return
	}

	var dstfilter string
	dstip := net.ParseIP(dst).To4()
	if dstip == nil {
		return
	}

	if dstip[2] == 0 && dstip[3] == 0 {
		dstfilter = fmt.Sprintf("ip.DstAddr>=%d.%d.0.0 and ip.DstAddr<%d.%d.255.255 and tcp", dstip[0], dstip[1], dstip[0], dstip[1])
	} else {
		dstfilter = fmt.Sprintf("ip.DstAddr=%s and tcp", dst)
	}

	logPrintln(1, dstfilter)

	filter := fmt.Sprintf("(outbound and %s) or (ip.SrcAddr>127.255.0.0 and ip.SrcAddr<127.255.255.255 and tcp.SrcPort=%s)", dstfilter, strconv.Itoa(to_port))

	winDivertLock.Lock()
	winDivertLocal, err := godivert.WinDivertOpen(filter, 0, 0, 0)
	winDivertLock.Unlock()
	if err != nil {
		fmt.Printf("winDivert open failed: %v with %s", err, filter)
		return
	}
	defer winDivertLocal.Close()

	var winDivertForward *godivert.WinDivertHandle
	if forward {
		winDivertLock.Lock()
		forwardfilter := fmt.Sprintf("(%s) and (ip.SrcAddr>192.168.137.0 and ip.SrcAddr<192.168.137.255)", dstfilter)
		winDivertForward, err = godivert.WinDivertOpen(forwardfilter, 1, 0, 0)
		winDivertLock.Unlock()
		if err != nil {
			fmt.Printf("winDivert open failed: %v with %s", err, forwardfilter)
			return
		}

		go func() {
			defer winDivertForward.Close()

			for {
				packet, err := winDivertForward.Recv()
				if err != nil {
					logPrintln(1, err)
					continue
				}

				srcIP := packet.SrcIP().To4()
				dstIP := packet.DstIP().To4()
				dstPort, _ := packet.DstPort()

				packet.SetSrcIP(net.IPv4(127, srcIP[3], byte(dstPort>>8), byte(dstPort&0xFF)))
				packet.SetDstIP(net.IPv4(127, 255, dstIP[2], dstIP[3]))
				packet.SetDstPort(uint16(to_port))

				packet.CalcNewChecksum(winDivertLocal)
				winDivertLocal.Send(packet)
			}
		}()
	}

	var localIP net.IP
	for {
		packet, err := winDivertLocal.Recv()
		if err != nil {
			logPrintln(1, err)
			continue
		}

		srcIP := packet.SrcIP().To4()
		dstIP := packet.DstIP().To4()
		dstPort, _ := packet.DstPort()

		if srcIP[0] == 127 && dstIP[0] == 127 {
			packet.SetSrcIP(net.IPv4(dstip[0], dstip[1], srcIP[2], srcIP[3]))
			packet.SetSrcPort(uint16(dstIP[2])<<8 | uint16(dstIP[3]))
			if dstIP[1] > 1 {
				packet.SetDstIP(net.IPv4(192, 168, 137, dstIP[1]))
			} else if forward {
				packet.SetDstIP(localIP)
			}
		} else {
			localIP = srcIP.To16()
			packet.SetSrcIP(net.IPv4(127, 0, byte(dstPort>>8), byte(dstPort&0xFF)))
			packet.SetDstIP(net.IPv4(127, 255, dstIP[2], dstIP[3]))
			packet.SetDstPort(uint16(to_port))
		}

		packet.CalcNewChecksum(winDivertLocal)
		winDivertLocal.Send(packet)
	}
}

func RedirectDNS() {
	winDivertLock.Lock()
	winDivert, err := godivert.WinDivertOpen("outbound and udp.DstPort=53", 0, 0, 0)
	winDivertLock.Unlock()
	if err != nil {
		fmt.Printf("winDivert open failed: %v", err)
		return
	}
	defer winDivert.Close()

	rawbuf := make([]byte, 1500)
	for {
		packet, err := winDivert.Recv()
		if err != nil {
			logPrintln(1, err)
			continue
		}
		ipv6 := packet.Raw[0]>>4 == 6

		var ipheadlen int
		if ipv6 {
			ipheadlen = 40
		} else {
			ipheadlen = int(packet.Raw[0]&0xF) * 4
		}
		udpheadlen := 8
		request := packet.Raw[ipheadlen+udpheadlen:]

		qname, _, _ := GetQName(request)
		if qname == "" {
			logPrintln(2, "DNS Segmentation fault")
			continue
		}

		pface, _ := DefaultProfile.GetInterface(qname)
		if pface != nil {
			logPrintln(1, qname, pface)
			_, response := NSRequest(request, true)
			udpsize := len(response) + 8

			var packetsize int
			if ipv6 {
				copy(rawbuf, []byte{96, 12, 19, 68, 0, 98, 17, 128})
				packetsize = 40 + udpsize
				binary.BigEndian.PutUint16(rawbuf[4:], uint16(udpsize))
				copy(rawbuf[8:], packet.Raw[24:40])
				copy(rawbuf[24:], packet.Raw[8:24])
				copy(rawbuf[ipheadlen:], packet.Raw[ipheadlen+2:ipheadlen+4])
				copy(rawbuf[ipheadlen+2:], packet.Raw[ipheadlen:ipheadlen+2])
			} else {
				copy(rawbuf, []byte{69, 0, 1, 32, 141, 152, 64, 0, 64, 17, 150, 46})
				packetsize = 20 + udpsize
				binary.BigEndian.PutUint16(rawbuf[2:], uint16(packetsize))
				copy(rawbuf[12:], packet.Raw[16:20])
				copy(rawbuf[16:], packet.Raw[12:16])
				copy(rawbuf[20:], packet.Raw[ipheadlen+2:ipheadlen+4])
				copy(rawbuf[22:], packet.Raw[ipheadlen:ipheadlen+2])
				ipheadlen = 20
			}

			binary.BigEndian.PutUint16(rawbuf[ipheadlen+4:], uint16(udpsize))
			copy(rawbuf[ipheadlen+8:], response)

			packet.PacketLen = uint(packetsize)
			packet.Raw = rawbuf[:packetsize]
			packet.Addr.Data |= 0x1
			packet.CalcNewChecksum(winDivert)
		}

		_, err = winDivert.Send(packet)
		if err != nil {
			logPrintln(1, err)
			return
		}
	}
}

func SendUDPPacket(laddr *net.UDPAddr, raddr *net.UDPAddr, payload []byte, ttl uint8) error {
	return nil
}
