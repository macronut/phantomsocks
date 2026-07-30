package phantomtcp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const maxUDPPacketSize = 65535

func listenTProxyUDP(network string, laddr *net.UDPAddr) (*net.UDPConn, error) {
	listenConfig := net.ListenConfig{
		Control: func(_, _ string, rawConn syscall.RawConn) error {
			var optionErr error
			if err := rawConn.Control(func(fd uintptr) {
				sockaddr, err := unix.Getsockname(int(fd))
				if err != nil {
					optionErr = err
					return
				}

				switch sockaddr.(type) {
				case *unix.SockaddrInet4:
					if err = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1); err == nil {
						err = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1)
					}
				case *unix.SockaddrInet6:
					if err = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1); err == nil {
						err = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_RECVORIGDSTADDR, 1)
					}
				default:
					err = fmt.Errorf("unsupported UDP socket address family")
				}
				optionErr = err
			}); err != nil {
				return err
			}
			return optionErr
		},
	}

	packetConn, err := listenConfig.ListenPacket(context.Background(), network, laddr.String())
	if err != nil {
		return nil, err
	}

	conn, ok := packetConn.(*net.UDPConn)
	if !ok {
		packetConn.Close()
		return nil, fmt.Errorf("unexpected UDP listener type %T", packetConn)
	}
	return conn, nil
}

func readFromTProxyUDP(conn *net.UDPConn, b []byte) (int, *net.UDPAddr, *net.UDPAddr, error) {
	oob := make([]byte, 1024)
	n, oobn, flags, addr, err := conn.ReadMsgUDP(b, oob)
	if err != nil {
		return 0, nil, nil, err
	}
	if flags&unix.MSG_TRUNC != 0 {
		return 0, nil, nil, errors.New("udp datagram truncated")
	}

	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return 0, nil, nil, err
	}

	dst, err := parseTProxyUDPOriginalDst(msgs)
	if err != nil {
		return 0, nil, nil, err
	}
	return n, addr, dst, nil
}

func parseTProxyUDPOriginalDst(msgs []unix.SocketControlMessage) (*net.UDPAddr, error) {
	var dst *net.UDPAddr
	for _, msg := range msgs {
		if msg.Header.Level == unix.SOL_IP && msg.Header.Type == unix.IP_RECVORIGDSTADDR {
			if len(msg.Data) < 8 {
				return nil, fmt.Errorf("short IPv4 original destination control message")
			}
			port := int(binary.BigEndian.Uint16(msg.Data[2:4]))
			dst = &net.UDPAddr{IP: append(net.IP(nil), msg.Data[4:8]...), Port: port}
		} else if msg.Header.Level == unix.SOL_IPV6 && msg.Header.Type == unix.IPV6_RECVORIGDSTADDR {
			if len(msg.Data) < 28 {
				return nil, fmt.Errorf("short IPv6 original destination control message")
			}
			port := int(binary.BigEndian.Uint16(msg.Data[2:4]))
			scopeID := nativeEndian().Uint32(msg.Data[24:28])
			dst = &net.UDPAddr{
				IP:   append(net.IP(nil), msg.Data[8:24]...),
				Port: port,
				Zone: zoneName(scopeID),
			}
		}
	}

	if dst == nil {
		return nil, fmt.Errorf("unable to obtain original destination")
	}

	return dst, nil
}

func nativeEndian() binary.ByteOrder {
	value := uint16(1)
	if *(*byte)(unsafe.Pointer(&value)) == 1 {
		return binary.LittleEndian
	}
	return binary.BigEndian
}

func zoneName(zoneID uint32) string {
	if zoneID == 0 {
		return ""
	}
	iface, err := net.InterfaceByIndex(int(zoneID))
	if err == nil {
		return iface.Name
	}
	return strconv.FormatUint(uint64(zoneID), 10)
}

func dialTProxyUDP(laddr, raddr *net.UDPAddr) (*net.UDPConn, error) {
	rsock, err := udpSockaddr(raddr)
	if err != nil {
		return nil, err
	}

	lsock, err := udpSockaddr(laddr)
	if err != nil {
		return nil, err
	}

	af := unix.AF_INET6
	if laddr.IP.To4() != nil && raddr.IP.To4() != nil {
		af = unix.AF_INET
	}

	fd, err := unix.Socket(af, unix.SOCK_DGRAM, 0)
	if err != nil {
		return nil, err
	}

	if err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("set SO_REUSEADDR: %w", err)
	}
	if af == unix.AF_INET6 {
		err = unix.SetsockoptInt(fd, unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
	} else {
		err = unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_TRANSPARENT, 1)
	}
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("set transparent UDP socket option: %w", err)
	}

	if err = unix.Bind(fd, lsock); err != nil {
		unix.Close(fd)
		return nil, err
	}

	if err = unix.Connect(fd, rsock); err != nil {
		unix.Close(fd)
		return nil, err
	}

	f := os.NewFile(uintptr(fd), fmt.Sprintf("net-udp-dial-%s", raddr.String()))
	defer f.Close()

	c, err := net.FileConn(f)
	if err != nil {
		return nil, err
	}

	udpConn, ok := c.(*net.UDPConn)
	if !ok {
		c.Close()
		return nil, fmt.Errorf("unexpected UDP connection type %T", c)
	}
	return udpConn, nil
}

func udpSockaddr(addr *net.UDPAddr) (unix.Sockaddr, error) {
	if addr == nil || addr.IP == nil {
		return nil, fmt.Errorf("missing UDP address")
	}
	if addr.Port < 0 || addr.Port > 65535 {
		return nil, fmt.Errorf("invalid UDP port %d", addr.Port)
	}
	if ip4 := addr.IP.To4(); ip4 != nil {
		var a [4]byte
		copy(a[:], ip4)
		return &unix.SockaddrInet4{Addr: a, Port: addr.Port}, nil
	}

	var a [16]byte
	ip6 := addr.IP.To16()
	if ip6 == nil {
		return nil, fmt.Errorf("invalid UDP IP address %q", addr.IP)
	}
	copy(a[:], ip6)
	sa := &unix.SockaddrInet6{Addr: a, Port: addr.Port}
	if addr.Zone != "" {
		zone, err := strconv.ParseUint(addr.Zone, 10, 32)
		if err != nil {
			iface, ifaceErr := net.InterfaceByName(addr.Zone)
			if ifaceErr != nil {
				return nil, fmt.Errorf("resolve IPv6 zone %q: %w", addr.Zone, ifaceErr)
			}
			zone = uint64(iface.Index)
		}
		sa.ZoneId = uint32(zone)
	}
	return sa, nil
}

const (
	tproxyUDPIdleTimeout    = 2 * time.Minute
	tproxyUDPSetupTimeout   = 15 * time.Second
	tproxyUDPMaxSessions    = 1024
	tproxyUDPMaxPending     = 32
	tproxyUDPMaxPendingSize = 256 * 1024
	tproxyUDPMaxDialWorkers = 64
)

type tproxyUDPSession struct {
	key        tproxyUDPSessionKey
	srcAddr    net.UDPAddr
	dstAddr    net.UDPAddr
	host       string
	outbound   *Outbound
	upstream   chan []byte
	relayError chan error
	done       chan struct{}

	mu         sync.Mutex
	closed     bool
	queuedSize int
	localConn  *net.UDPConn
	remoteConn net.Conn
}

type tproxyUDPSessionManager struct {
	mu       sync.Mutex
	sessions map[tproxyUDPSessionKey]*tproxyUDPSession
	dialSem  chan struct{}
}

type tproxyUDPSessionKey struct {
	src netip.AddrPort
	dst netip.AddrPort
}

func newTProxyUDPSessionManager() *tproxyUDPSessionManager {
	return &tproxyUDPSessionManager{
		sessions: make(map[tproxyUDPSessionKey]*tproxyUDPSession),
		dialSem:  make(chan struct{}, tproxyUDPMaxDialWorkers),
	}
}

func newTProxyUDPSessionKey(srcAddr, dstAddr *net.UDPAddr) tproxyUDPSessionKey {
	return tproxyUDPSessionKey{
		src: udpAddrPort(srcAddr),
		dst: udpAddrPort(dstAddr),
	}
}

func udpAddrPort(addr *net.UDPAddr) netip.AddrPort {
	ip, _ := netip.AddrFromSlice(addr.IP)
	ip = ip.Unmap()
	if addr.Zone != "" && ip.Is6() {
		ip = ip.WithZone(addr.Zone)
	}
	return netip.AddrPortFrom(ip, uint16(addr.Port))
}

func cloneUDPAddr(addr *net.UDPAddr) net.UDPAddr {
	return net.UDPAddr{
		IP:   append(net.IP(nil), addr.IP...),
		Port: addr.Port,
		Zone: addr.Zone,
	}
}

func (manager *tproxyUDPSessionManager) dispatch(srcAddr, dstAddr *net.UDPAddr, data []byte) {
	key := newTProxyUDPSessionKey(srcAddr, dstAddr)

	manager.mu.Lock()
	if session, ok := manager.sessions[key]; ok {
		manager.mu.Unlock()
		if !session.enqueue(data) {
			logPrintln(3, "TProxy(UDP):", srcAddr, "->", dstAddr, "session queue full")
		}
		return
	}
	if len(manager.sessions) >= tproxyUDPMaxSessions {
		manager.mu.Unlock()
		logPrintln(2, "TProxy(UDP): session limit reached")
		return
	}

	host, outbound := getTProxyUDPTarget(dstAddr)
	if outbound == nil {
		manager.mu.Unlock()
		logPrintln(4, "TProxy(UDP):", srcAddr, "->", dstAddr, "no outbound")
		return
	}
	if !tproxyUDPAllowed(outbound, data) {
		manager.mu.Unlock()
		logPrintln(4, "TProxy(UDP):", srcAddr, "->", host, "not allow")
		return
	}

	session := &tproxyUDPSession{
		key:        key,
		srcAddr:    cloneUDPAddr(srcAddr),
		dstAddr:    cloneUDPAddr(dstAddr),
		host:       host,
		outbound:   outbound,
		upstream:   make(chan []byte, tproxyUDPMaxPending),
		relayError: make(chan error, 1),
		done:       make(chan struct{}),
	}
	firstPacket := append([]byte(nil), data...)
	session.upstream <- firstPacket
	session.queuedSize = len(firstPacket)
	manager.sessions[key] = session
	manager.mu.Unlock()

	logPrintln(1, "TProxy(UDP):", srcAddr, "->", host, dstAddr.Port, outbound)
	go manager.run(session)
}

func tproxyUDPAllowed(outbound *Outbound, data []byte) bool {
	if outbound == nil || outbound.Hint&(HINT_UDP|HINT_HTTP3) == 0 {
		return false
	}
	if outbound.Hint&HINT_UDP != 0 {
		return true
	}
	version := GetQUICVersion(data)
	return version != quicVersionNone && version != quicVersionNotLong
}

func (session *tproxyUDPSession) enqueue(data []byte) bool {
	packet := append([]byte(nil), data...)

	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed {
		return false
	}
	if session.queuedSize+len(packet) > tproxyUDPMaxPendingSize {
		return false
	}
	select {
	case session.upstream <- packet:
		session.queuedSize += len(packet)
		return true
	default:
		return false
	}
}

func (session *tproxyUDPSession) nextPacket() []byte {
	packet := <-session.upstream
	session.mu.Lock()
	session.queuedSize -= len(packet)
	session.mu.Unlock()
	return packet
}

func (manager *tproxyUDPSessionManager) remove(session *tproxyUDPSession) {
	session.mu.Lock()
	if session.closed {
		session.mu.Unlock()
		return
	}
	session.closed = true
	close(session.done)
	session.mu.Unlock()

	manager.mu.Lock()
	if manager.sessions[session.key] == session {
		delete(manager.sessions, session.key)
	}
	manager.mu.Unlock()

	if session.remoteConn != nil {
		session.remoteConn.Close()
	}
	if session.localConn != nil {
		session.localConn.Close()
	}
}

func (manager *tproxyUDPSessionManager) run(session *tproxyUDPSession) {
	defer manager.remove(session)

	queueTimer := time.NewTimer(tproxyUDPSetupTimeout)
	defer queueTimer.Stop()
	select {
	case manager.dialSem <- struct{}{}:
	case <-queueTimer.C:
		logPrintln(2, "TProxy(UDP): setup queue timeout:", session.srcAddr, "->", session.dstAddr)
		return
	}

	var err error
	session.localConn, err = dialTProxyUDP(&session.dstAddr, &session.srcAddr)
	if err != nil {
		<-manager.dialSem
		logPrintln(1, err)
		return
	}
	deadline := time.Now().Add(tproxyUDPSetupTimeout)
	session.remoteConn, err = session.outbound.dialUDPProxy(session.host, session.dstAddr.Port, deadline)
	if err != nil {
		<-manager.dialSem
		logPrintln(1, err)
		return
	}
	<-manager.dialSem

	if session.outbound.Hint&HINT_ZERO != 0 {
		zeroData := make([]byte, 8+rand.Intn(1024))
		if _, err = session.remoteConn.Write(zeroData); err != nil {
			logPrintln(1, err)
			return
		}
	}

	firstPacket := session.nextPacket()
	if err = WriteQUICInitial(session.remoteConn, firstPacket, session.outbound); err != nil {
		logPrintln(1, err)
		return
	}

	if err = session.refreshDeadline(); err != nil {
		logPrintln(2, "TProxy(UDP): set deadline:", err)
		return
	}
	go session.relayReplies()

	for {
		select {
		case packet := <-session.upstream:
			session.mu.Lock()
			session.queuedSize -= len(packet)
			session.mu.Unlock()
			if _, err = session.remoteConn.Write(packet); err != nil {
				logPrintln(2, "TProxy(UDP): upstream write:", err)
				return
			}
			if err = session.refreshDeadline(); err != nil {
				logPrintln(2, "TProxy(UDP): set deadline:", err)
				return
			}
		case err = <-session.relayError:
			if err != nil {
				logPrintln(2, "TProxy(UDP): reply relay:", err)
			}
			return
		}
	}
}

func (session *tproxyUDPSession) refreshDeadline() error {
	return session.remoteConn.SetReadDeadline(time.Now().Add(tproxyUDPIdleTimeout))
}

func (session *tproxyUDPSession) relayReplies() {
	data := make([]byte, maxUDPPacketSize)
	for {
		n, err := session.remoteConn.Read(data)
		if err == nil {
			_, err = session.localConn.Write(data[:n])
		}
		if err != nil {
			select {
			case session.relayError <- err:
			case <-session.done:
			}
			return
		}
		if err = session.refreshDeadline(); err != nil {
			select {
			case session.relayError <- err:
			case <-session.done:
			}
			return
		}
	}
}

func getTProxyUDPTarget(dstAddr *net.UDPAddr) (string, *Outbound) {
	if ip4 := dstAddr.IP.To4(); ip4 != nil {
		if ip4[0] == VirtualAddrPrefix {
			index := int(binary.BigEndian.Uint16(ip4[2:4]))
			NoseLock.Lock()
			if index >= len(Nose) {
				NoseLock.Unlock()
				return "", nil
			}
			lie := Nose[index]
			NoseLock.Unlock()
			return lie.Name, lie.Interface
		}
		if DefaultProfile == nil {
			return dstAddr.IP.String(), nil
		}
		return dstAddr.IP.String(), DefaultProfile.GetOutboundByIP(dstAddr.IP)
	}
	if DefaultProfile == nil {
		return dstAddr.IP.String(), nil
	}
	return dstAddr.IP.String(), DefaultProfile.GetOutboundByIP(dstAddr.IP)
}

func TProxyUDP(address string) {
	laddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		logPrintln(1, err)
		return
	}
	client, err := listenTProxyUDP("udp", laddr)
	if err != nil {
		logPrintln(1, err)
		return
	}
	defer client.Close()

	manager := newTProxyUDPSessionManager()
	data := make([]byte, maxUDPPacketSize)
	for {
		n, srcAddr, dstAddr, err := readFromTProxyUDP(client, data)
		if err != nil {
			logPrintln(1, err)
			continue
		}
		manager.dispatch(srcAddr, dstAddr, data[:n])
	}
}
