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

	"golang.org/x/sys/unix"
)

func listenTProxyUDP(network string, laddr *net.UDPAddr) (*net.UDPConn, error) {
	listenConfig := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var err error
			if ctlErr := c.Control(func(fd uintptr) {
				sa, saErr := unix.Getsockname(int(fd))
				if saErr != nil {
					err = saErr
					return
				}
				switch sa.(type) {
				case *unix.SockaddrInet4:
					if err = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1); err == nil {
						err = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1)
					}
				case *unix.SockaddrInet6:
					if err = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1); err == nil {
						err = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_RECVORIGDSTADDR, 1)
					}
				default:
					err = fmt.Errorf("unsupported UDP socket family")
				}
			}); ctlErr != nil {
				return ctlErr
			}
			return err
		},
	}

	pc, err := listenConfig.ListenPacket(context.Background(), network, laddr.String())
	if err != nil {
		return nil, err
	}
	conn, ok := pc.(*net.UDPConn)
	if !ok {
		pc.Close()
		return nil, fmt.Errorf("unexpected UDP listener type %T", pc)
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

	dst, err := parseOrigDst(msgs)
	if err != nil {
		return 0, nil, nil, err
	}
	return n, addr, dst, nil
}

func parseOrigDst(msgs []unix.SocketControlMessage) (*net.UDPAddr, error) {
	for _, msg := range msgs {
		sa, err := unix.ParseOrigDstAddr(&msg)
		if err != nil {
			continue
		}
		switch addr := sa.(type) {
		case *unix.SockaddrInet4:
			return &net.UDPAddr{IP: net.IP(addr.Addr[:]), Port: addr.Port}, nil
		case *unix.SockaddrInet6:
			return &net.UDPAddr{
				IP:   net.IP(addr.Addr[:]),
				Port: addr.Port,
				Zone: zoneName(addr.ZoneId),
			}, nil
		}
	}
	return nil, errors.New("no original destination")
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

func dialTProxyUDP(laddr *net.UDPAddr) (*net.UDPConn, error) {
	lsock, err := udpSockaddr(laddr)
	if err != nil {
		return nil, err
	}

	af := unix.AF_INET6
	if laddr.IP.To4() != nil {
		af = unix.AF_INET
	}

	fd, err := unix.Socket(af, unix.SOCK_DGRAM, 0)
	if err != nil {
		return nil, err
	}

	if err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if af == unix.AF_INET6 {
		err = unix.SetsockoptInt(fd, unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
	} else {
		err = unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_TRANSPARENT, 1)
	}
	if err != nil {
		unix.Close(fd)
		return nil, err
	}

	if err = unix.Bind(fd, lsock); err != nil {
		unix.Close(fd)
		return nil, err
	}

	f := os.NewFile(uintptr(fd), fmt.Sprintf("net-udp-bind-%s", laddr.String()))
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
	outbound   *Outbound
	rewriter   *quicInitialRewriter
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
	pending  map[tproxyUDPSessionKey]*tproxyPendingSession
	dialSem  chan struct{}
}

type tproxyPendingSession struct {
	srcAddr net.UDPAddr
	dstAddr net.UDPAddr
	quicInitialPending
}

type tproxyUDPSessionKey struct {
	src netip.AddrPort
	dst netip.AddrPort
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
	key := tproxyUDPSessionKey{src: udpAddrPort(srcAddr), dst: udpAddrPort(dstAddr)}

	manager.mu.Lock()
	if session, ok := manager.sessions[key]; ok {
		manager.mu.Unlock()
		if !session.enqueue(data) {
			logPrintln(3, "TProxy(UDP):", srcAddr, "->", dstAddr, "queue full")
		}
		return
	}

	now := time.Now()
	if pending, ok := manager.pending[key]; ok {
		manager.mu.Unlock()
		manager.continuePending(key, pending, data, now)
		return
	}
	if len(manager.sessions)+len(manager.pending) >= tproxyUDPMaxSessions {
		manager.mu.Unlock()
		logPrintln(2, "TProxy(UDP): session limit")
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

	if outbound.Hint&HINT_HTTP3 != 0 && isQUICInitialDatagram(data) {
		manager.pending[key] = &tproxyPendingSession{
			srcAddr: cloneUDPAddr(srcAddr),
			dstAddr: cloneUDPAddr(dstAddr),
		}
		pending := manager.pending[key]
		manager.mu.Unlock()
		manager.continuePending(key, pending, data, now)
		return
	}

	datagrams := [][]byte{append([]byte(nil), data...)}
	if !manager.startSession(key, srcAddr, dstAddr, host, outbound, datagrams) {
		manager.mu.Unlock()
		return
	}
	manager.mu.Unlock()
}

func (manager *tproxyUDPSessionManager) continuePending(
	key tproxyUDPSessionKey,
	pending *tproxyPendingSession,
	data []byte,
	now time.Time,
) {
	manager.mu.Lock()
	if manager.pending[key] != pending {
		manager.mu.Unlock()
		return
	}
	if pending.expired(now) {
		delete(manager.pending, key)
		manager.mu.Unlock()
		logPrintln(4, "TProxy(UDP): Initial timeout", pending.srcAddr, "->", pending.dstAddr)
		return
	}

	sni, err := pending.add(data, now)
	if err != nil {
		delete(manager.pending, key)
		manager.mu.Unlock()
		logPrintln(4, "TProxy(UDP): Initial collect:", err)
		return
	}
	if pending.overLimit() {
		delete(manager.pending, key)
		manager.mu.Unlock()
		logPrintln(3, "TProxy(UDP): Initial pending limit", pending.srcAddr)
		return
	}
	if sni == "" {
		n, contiguous := pending.stats()
		logPrintln(4, "TProxy(UDP): waiting ClientHello", pending.srcAddr, "packets", n, "contiguous", contiguous)
		manager.mu.Unlock()
		return
	}

	datagrams := pending.datagrams()
	srcAddr := pending.srcAddr
	dstAddr := pending.dstAddr
	delete(manager.pending, key)

	host, outbound := getTProxyUDPTarget(&dstAddr)
	if outbound == nil {
		manager.mu.Unlock()
		logPrintln(4, "TProxy(UDP):", srcAddr, "->", dstAddr, "no outbound")
		return
	}
	if !manager.startSession(key, &srcAddr, &dstAddr, host, outbound, datagrams) {
		manager.mu.Unlock()
		return
	}
	manager.mu.Unlock()
}

func (manager *tproxyUDPSessionManager) startSession(
	key tproxyUDPSessionKey,
	srcAddr, dstAddr *net.UDPAddr,
	host string,
	outbound *Outbound,
	initialDatagrams [][]byte,
) bool {
	if len(initialDatagrams) == 0 {
		return false
	}
	if _, ok := manager.sessions[key]; ok {
		return false
	}
	if len(manager.sessions) >= tproxyUDPMaxSessions {
		logPrintln(2, "TProxy(UDP): session limit")
		return false
	}

	session := &tproxyUDPSession{
		key:        key,
		srcAddr:    cloneUDPAddr(srcAddr),
		dstAddr:    cloneUDPAddr(dstAddr),
		outbound:   outbound,
		upstream:   make(chan []byte, tproxyUDPMaxPending),
		relayError: make(chan error, 1),
		done:       make(chan struct{}),
	}
	if outbound.Hint&HINT_HTTP3 != 0 {
		session.rewriter = &quicInitialRewriter{}
	}
	manager.sessions[key] = session
	logPrintln(1, "TProxy(UDP):", srcAddr, "->", host, dstAddr.Port, outbound, "initials", len(initialDatagrams))
	go manager.run(session, host, initialDatagrams)
	return true
}

func tproxyUDPAllowed(outbound *Outbound, data []byte) bool {
	if outbound == nil {
		return false
	}
	if outbound.Hint&HINT_UDP != 0 {
		return true
	}
	return outbound.Hint&HINT_HTTP3 != 0 && isQUICInitialDatagram(data)
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

func (session *tproxyUDPSession) writeUpstream(packet []byte) error {
	if session.rewriter != nil {
		return writeQUICDatagram(session.remoteConn, packet, session.outbound, session.rewriter)
	}
	_, err := session.remoteConn.Write(packet)
	return err
}

func (session *tproxyUDPSession) flushUpstream() error {
	for {
		select {
		case packet := <-session.upstream:
			session.mu.Lock()
			session.queuedSize -= len(packet)
			session.mu.Unlock()
			if err := session.writeUpstream(packet); err != nil {
				return err
			}
			if err := session.refreshDeadline(); err != nil {
				return err
			}
		default:
			return nil
		}
	}
}

func (manager *tproxyUDPSessionManager) run(session *tproxyUDPSession, host string, initialDatagrams [][]byte) {
	defer manager.remove(session)

	timer := time.NewTimer(tproxyUDPSetupTimeout)
	defer timer.Stop()
	select {
	case manager.dialSem <- struct{}{}:
	case <-timer.C:
		logPrintln(2, "TProxy(UDP): setup timeout", session.srcAddr, "->", session.dstAddr)
		return
	}

	var err error
	session.localConn, err = dialTProxyUDP(&session.dstAddr)
	if err != nil {
		<-manager.dialSem
		logPrintln(1, err)
		return
	}
	deadline := time.Now().Add(tproxyUDPSetupTimeout)
	session.remoteConn, err = session.outbound.dialUDPProxy(host, session.dstAddr.Port, deadline)
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

	for _, packet := range initialDatagrams {
		if err = session.writeUpstream(packet); err != nil {
			logPrintln(1, err)
			return
		}
	}
	if err = session.flushUpstream(); err != nil {
		logPrintln(1, err)
		return
	}
	if err = session.refreshDeadline(); err != nil {
		logPrintln(1, err)
		return
	}

	go session.relayReplies()

	for {
		select {
		case packet := <-session.upstream:
			session.mu.Lock()
			session.queuedSize -= len(packet)
			session.mu.Unlock()
			if err = session.writeUpstream(packet); err != nil {
				logPrintln(1, err)
				return
			}
			if err = session.refreshDeadline(); err != nil {
				logPrintln(1, err)
				return
			}
		case err = <-session.relayError:
			if err != nil {
				logPrintln(1, err)
			}
			return
		}
	}
}

func (session *tproxyUDPSession) refreshDeadline() error {
	return session.remoteConn.SetReadDeadline(time.Now().Add(tproxyUDPIdleTimeout))
}

func (session *tproxyUDPSession) relayReplies() {
	b := make([]byte, quicUDPPacketSize)
	for {
		n, err := session.remoteConn.Read(b)
		if err == nil {
			reply := b[:n]
			if session.rewriter != nil {
				reply = session.rewriter.rewriteServer(reply)
			}
			_, err = session.localConn.WriteToUDP(reply, &session.srcAddr)
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
	ip := dstAddr.IP
	if ip4 := ip.To4(); ip4 != nil && ip4[0] == VirtualAddrPrefix {
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

	host := ip.String()
	if DefaultProfile == nil {
		return host, nil
	}
	return host, DefaultProfile.GetOutboundByIP(ip)
}

func TProxyUDP(address string) {
	laddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		logPrintln(1, err)
		return
	}
	network := "udp4"
	if laddr.IP != nil && laddr.IP.To4() == nil {
		network = "udp6"
	}
	client, err := listenTProxyUDP(network, laddr)
	if err != nil {
		logPrintln(1, err)
		return
	}
	defer client.Close()

	manager := &tproxyUDPSessionManager{
		sessions: make(map[tproxyUDPSessionKey]*tproxyUDPSession),
		pending:  make(map[tproxyUDPSessionKey]*tproxyPendingSession),
		dialSem:  make(chan struct{}, tproxyUDPMaxDialWorkers),
	}
	b := make([]byte, quicUDPPacketSize)
	for {
		n, srcAddr, dstAddr, err := readFromTProxyUDP(client, b)
		if err != nil {
			logPrintln(1, err)
			continue
		}
		manager.dispatch(srcAddr, dstAddr, b[:n])
	}
}
