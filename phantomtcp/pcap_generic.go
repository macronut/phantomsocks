//go:build !linux && pcap

package phantomtcp

import (
	"errors"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func SendPacket(packet gopacket.Packet) error {
	err := pcapHandle.WritePacketData(packet.Data())
	return err
}

func ModifyAndSendPacket(connInfo *ConnectionInfo, payload []byte, hint uint32, ttl uint8, count int) error {
	linkLayer := connInfo.Link
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
			if ok {
				cookie = result.([]byte)
			} else {
				payload = nil
			}
		}

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

	if linkLayer != nil {
		link := linkLayer.(*layers.Ethernet)
		switch ip := ipLayer.(type) {
		case *layers.IPv4:
			if hint&HINT_TTL != 0 {
				ip.TTL = ttl
			}
			gopacket.SerializeLayers(buffer, options,
				link, ip, tcpLayer, gopacket.Payload(payload),
			)
		case *layers.IPv6:
			if hint&HINT_TTL != 0 {
				ip.HopLimit = ttl
			}
			gopacket.SerializeLayers(buffer, options,
				link, ip, tcpLayer, gopacket.Payload(payload),
			)
		}
		outgoingPacket := buffer.Bytes()

		for i := 0; i < count; i++ {
			err := pcapHandle.WritePacketData(outgoingPacket)
			if err != nil {
				return err
			}
		}
	} else {
		return errors.New("Invalid LinkLayer")
	}

	return nil
}

func Redirect(dst string, to_port int, forward bool) {
}

func RedirectDNS() {
}
