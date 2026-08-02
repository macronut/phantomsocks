package phantomtcp

import (
	"bytes"
	"encoding/binary"
	"io"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// UDP ASSOCIATE is answered with the address of SocksUDPProxy, which shares the
// port of the socks inbound the client is already connected to.
func socks5Reply(cmd byte, client net.Conn) []byte {
	if cmd != 3 {
		return []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	}

	addr, ok := client.LocalAddr().(*net.TCPAddr)
	if !ok {
		return []byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0}
	}

	if ip4 := addr.IP.To4(); ip4 != nil {
		reply := []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}
		copy(reply[4:8], ip4)
		binary.BigEndian.PutUint16(reply[8:], uint16(addr.Port))
		return reply
	}

	reply := make([]byte, 22)
	reply[0] = 5
	reply[3] = 4
	copy(reply[4:20], addr.IP.To16())
	binary.BigEndian.PutUint16(reply[20:], uint16(addr.Port))
	return reply
}

func SocksProxy(client net.Conn) {
	defer client.Close()

	var cmd byte = 1
	host := ""
	var addr net.IP
	var port int
	{
		var b [1500]byte
		n, err := client.Read(b[:])
		if err != nil || n < 3 {
			logPrintln(1, client.RemoteAddr(), err)
			return
		}

		var reply []byte
		if b[0] == 0x05 {
			client.Write([]byte{0x05, 0x00})
			n, err = client.Read(b[:4])
			if err != nil || n != 4 {
				return
			}
			cmd = b[1]

			switch b[3] {
			case 0x01: //IPv4
				n, err = client.Read(b[:6])
				if n < 6 {
					return
				}
				addr = net.IP(b[:4])
				port = int(binary.BigEndian.Uint16(b[4:6]))
			case 0x03: //Domain
				n, err = client.Read(b[:])
				addrLen := b[0]
				if n < int(addrLen+3) {
					return
				}
				host = string(b[1 : addrLen+1])
				port = int(binary.BigEndian.Uint16(b[n-2:]))
			case 0x04: //IPv6
				n, err = client.Read(b[:])
				if n < 18 {
					return
				}
				addr = net.IP(b[:16])
				port = int(binary.BigEndian.Uint16(b[16:18]))
			default:
				// 0x08: address type not supported
				logPrintln(3, "address type", b[0], "not supported from", client.RemoteAddr())
				client.Write([]byte{5, 9, 0, 1, 0, 0, 0, 0, 0, 0})
				return
			}
			reply = socks5Reply(cmd, client)
		} else if b[0] == 0x04 {
			if n > 8 && b[1] == 1 {
				userEnd := 8 + bytes.IndexByte(b[8:n], 0)
				port = int(binary.BigEndian.Uint16(b[2:4]))
				if b[4]|b[5]|b[6] == 0 {
					hostEnd := bytes.IndexByte(b[userEnd+1:n], 0)
					if hostEnd > 0 {
						host = string(b[userEnd+1 : userEnd+1+hostEnd])
					} else {
						client.Write([]byte{0, 91, 0, 0, 0, 0, 0, 0})
						return
					}
				} else {
					addr = net.IP(b[4:8])
				}

				reply = []byte{0, 90, b[2], b[3], b[4], b[5], b[6], b[7]}
			} else {
				client.Write([]byte{0, 91, 0, 0, 0, 0, 0, 0})
				return
			}
		} else {
			logPrintln(3, "unknow from", client.RemoteAddr())
			return
		}

		if err == nil {
			_, err = client.Write(reply)
		}

		if err != nil {
			logPrintln(1, err)
			return
		}
	}

	switch cmd {
	case 1: // CONNECT
		tcpAddr := net.TCPAddr{IP: addr, Port: port}
		tcp_redirect(client, &tcpAddr, host, nil)
	case 2: // BIND
	case 3: // UDP ASSOCIATE
		// the association lives as long as this connection is held open
		io.Copy(io.Discard, client)
	case 5: // UDP IN TCP
		udp_redirect(client)
	}
}

func ReadFull(conn net.Conn, buffer []byte) error {
	buff_len := len(buffer)
	recv_len := 0
	for recv_len < buff_len {
		n, err := conn.Read(buffer[recv_len:])
		if err != nil {
			return err
		}
		recv_len += n
	}
	return nil
}

func uotSessionKey(host string, port int) string {
	return strings.Join([]string{host, strconv.Itoa(port)}, ",")
}

func readUoTFrame(conn net.Conn, buf []byte) (header []byte, payload []byte, err error) {
	if err = ReadFull(conn, buf[:3]); err != nil {
		return nil, nil, err
	}
	msglen := int(binary.BigEndian.Uint16(buf[0:2]))
	hdrlen := int(buf[2])
	if msglen > quicUDPPacketSize || hdrlen < 5 || hdrlen > len(buf) {
		return nil, nil, io.ErrUnexpectedEOF
	}
	if err = ReadFull(conn, buf[3:hdrlen]); err != nil {
		return nil, nil, err
	}
	header = append([]byte(nil), buf[:hdrlen]...)
	payload = make([]byte, msglen)
	if err = ReadFull(conn, payload); err != nil {
		return nil, nil, err
	}
	return header, payload, nil
}

func parseUoTTarget(header []byte) (host string, port int, outbound *Outbound) {
	if len(header) < 5 {
		return "", 0, nil
	}
	hdrlen := int(header[2])
	if hdrlen > len(header) {
		return "", 0, nil
	}

	var addr net.IP
	var domain string
	switch header[3] {
	case 0x01: // IPv4
		if hdrlen < 10 {
			return "", 0, nil
		}
		addr = net.IP(header[4:8])
		port = int(binary.BigEndian.Uint16(header[8:10]))
	case 0x03: // Domain
		addrLen := int(header[4])
		if hdrlen < 7+addrLen {
			return "", 0, nil
		}
		domain = string(header[5 : 5+addrLen])
		port = int(binary.BigEndian.Uint16(header[5+addrLen:]))
	case 0x04: // IPv6
		if hdrlen < 22 {
			return "", 0, nil
		}
		addr = net.IP(header[4:20])
		port = int(binary.BigEndian.Uint16(header[20:22]))
	default:
		return "", 0, nil
	}

	host, outbound = GetSocksUDPTarget(addr, domain)
	if outbound == nil {
		return "", 0, nil
	}
	return host, port, outbound
}

func writeUoTFrame(conn net.Conn, header []byte, payload []byte, mu *sync.Mutex) error {
	hdrlen := len(header)
	frame := make([]byte, hdrlen+len(payload))
	copy(frame, header)
	binary.BigEndian.PutUint16(frame[:2], uint16(len(payload)))
	copy(frame[hdrlen:], payload)
	if mu != nil {
		mu.Lock()
		defer mu.Unlock()
	}
	_, err := conn.Write(frame)
	return err
}

type uotSession struct {
	conn     net.Conn
	outbound *Outbound
	rewriter *quicInitialRewriter
	header   []byte
}

type uotPending struct {
	quicInitialPending
	header   []byte
	dialHost string
	port     int
	outbound *Outbound
}

type uotConn struct {
	client   net.Conn
	mu       sync.Mutex
	sessions map[string]*uotSession
	pending  map[string]*uotPending
}

func (state *uotConn) writeUpstream(session *uotSession, payload []byte) error {
	if session.rewriter != nil {
		return writeQUICDatagram(session.conn, payload, session.outbound, session.rewriter)
	}
	_, err := session.conn.Write(payload)
	return err
}

func (state *uotConn) flushInitial(session *uotSession, datagrams [][]byte) error {
	for _, datagram := range datagrams {
		if err := state.writeUpstream(session, datagram); err != nil {
			return err
		}
	}
	return nil
}

func (state *uotConn) runSession(key string, session *uotSession) {
	buf := make([]byte, quicUDPPacketSize)
	defer func() {
		state.mu.Lock()
		if cur, ok := state.sessions[key]; ok && cur == session {
			delete(state.sessions, key)
		}
		state.mu.Unlock()
		session.conn.Close()
	}()

	session.conn.SetReadDeadline(time.Now().Add(time.Minute * 2))
	for {
		n, err := session.conn.Read(buf)
		if err != nil {
			return
		}
		session.conn.SetReadDeadline(time.Now().Add(time.Minute * 2))
		reply := buf[:n]
		if session.rewriter != nil {
			reply = session.rewriter.rewriteServer(reply)
		}

		state.mu.Lock()
		header := append([]byte(nil), session.header...)
		state.mu.Unlock()

		if err := writeUoTFrame(state.client, header, reply, &state.mu); err != nil {
			return
		}
	}
}

func (state *uotConn) startSession(key string, header []byte, host string, port int, outbound *Outbound, initialDatagrams [][]byte, srcAddr net.Addr) error {
	if len(initialDatagrams) == 0 {
		return nil
	}

	state.mu.Lock()
	if _, ok := state.sessions[key]; ok {
		state.mu.Unlock()
		return nil
	}
	if len(state.sessions)+len(state.pending) >= quicPendingLimit {
		state.mu.Unlock()
		logPrintln(3, "Socks(UDP): session limit", srcAddr)
		return nil
	}
	state.mu.Unlock()

	conn, err := outbound.DialUDPProxy(host, port)
	if err != nil {
		logPrintln(1, err)
		return err
	}

	if outbound.Hint&HINT_ZERO != 0 {
		zeroData := make([]byte, 8+rand.Intn(1024))
		if _, err = conn.Write(zeroData); err != nil {
			conn.Close()
			return err
		}
	}

	var rewriter *quicInitialRewriter
	if outbound.Hint&HINT_HTTP3 != 0 {
		rewriter = &quicInitialRewriter{}
	}

	session := &uotSession{
		conn:     conn,
		outbound: outbound,
		rewriter: rewriter,
		header:   append([]byte(nil), header...),
	}

	state.mu.Lock()
	state.sessions[key] = session
	state.mu.Unlock()

	go state.runSession(key, session)

	if err = state.flushInitial(session, initialDatagrams); err != nil {
		state.mu.Lock()
		if cur, ok := state.sessions[key]; ok && cur == session {
			delete(state.sessions, key)
		}
		state.mu.Unlock()
		conn.Close()
		logPrintln(1, err)
		return err
	}

	logPrintln(1, "Socks(UDP):", srcAddr, "->", host, port, outbound, "initials", len(initialDatagrams))
	return nil
}

func (state *uotConn) continuePending(key string, pending *uotPending, header []byte, payload []byte, now time.Time, srcAddr net.Addr) error {
	state.mu.Lock()
	if state.pending[key] != pending {
		state.mu.Unlock()
		return nil
	}
	if pending.expired(now) {
		delete(state.pending, key)
		state.mu.Unlock()
		logPrintln(4, "Socks(UDP): Initial timeout", srcAddr, "->", pending.dialHost, pending.port)
		return nil
	}
	state.mu.Unlock()

	if !isQUICInitialDatagram(payload) {
		datagrams := pending.datagrams()
		datagrams = append(datagrams, append([]byte(nil), payload...))
		state.mu.Lock()
		delete(state.pending, key)
		state.mu.Unlock()
		return state.startSession(key, header, pending.dialHost, pending.port, pending.outbound, datagrams, srcAddr)
	}

	datagrams, waiting, err := pending.accumulate(payload, now)
	if err != nil {
		state.mu.Lock()
		delete(state.pending, key)
		state.mu.Unlock()
		logPrintln(4, "Socks(UDP): Initial collect:", err)
		return nil
	}
	if waiting {
		packetCount, contiguous := pending.stats()
		logPrintln(4, "Socks(UDP): waiting ClientHello", srcAddr, "->", pending.dialHost, pending.port,
			"packets", packetCount, "contiguous", contiguous)
		return nil
	}

	state.mu.Lock()
	delete(state.pending, key)
	state.mu.Unlock()
	return state.startSession(key, header, pending.dialHost, pending.port, pending.outbound, datagrams, srcAddr)
}

func (state *uotConn) handleFrame(header []byte, payload []byte, srcAddr net.Addr) error {
	host, port, outbound := parseUoTTarget(header)
	if outbound == nil || outbound.Hint&(HINT_UDP|HINT_HTTP3) == 0 {
		return nil
	}
	key := uotSessionKey(host, port)

	state.mu.Lock()
	if session, ok := state.sessions[key]; ok {
		session.header = append([]byte(nil), header...)
		state.mu.Unlock()
		return state.writeUpstream(session, payload)
	}

	now := time.Now()
	if pending, ok := state.pending[key]; ok {
		state.mu.Unlock()
		return state.continuePending(key, pending, header, payload, now, srcAddr)
	}
	state.mu.Unlock()

	if outbound.Hint&HINT_HTTP3 != 0 && isQUICInitialDatagram(payload) {
		state.mu.Lock()
		if len(state.sessions)+len(state.pending) >= quicPendingLimit {
			state.mu.Unlock()
			logPrintln(3, "Socks(UDP): pending session limit", srcAddr)
			return nil
		}
		pending := &uotPending{
			header:   append([]byte(nil), header...),
			dialHost: host,
			port:     port,
			outbound: outbound,
		}
		state.pending[key] = pending
		state.mu.Unlock()
		return state.continuePending(key, pending, header, payload, now, srcAddr)
	}

	return state.startSession(key, header, host, port, outbound, [][]byte{append([]byte(nil), payload...)}, srcAddr)
}

func udp_redirect(client net.Conn) error {
	defer client.Close()

	state := &uotConn{
		client:   client,
		sessions: make(map[string]*uotSession),
		pending:  make(map[string]*uotPending),
	}
	srcAddr := client.RemoteAddr()
	buf := make([]byte, quicUDPPacketSize+256)

	for {
		header, payload, err := readUoTFrame(client, buf)
		if err != nil {
			return err
		}
		if err = state.handleFrame(header, payload, srcAddr); err != nil {
			return err
		}
	}
}

type socksUDPSession struct {
	conn     net.Conn
	outbound *Outbound
	rewriter *quicInitialRewriter
	// header echoed back to the client, empty for the socks4 format
	header []byte
}

type socksUDPPending struct {
	quicInitialPending
	srcAddr  net.UDPAddr
	header   []byte
	host     string
	port     int
	outbound *Outbound
}

func socksUDPWriteUpstream(session *socksUDPSession, payload []byte) error {
	if session.rewriter != nil {
		return writeQUICDatagram(session.conn, payload, session.outbound, session.rewriter)
	}
	_, err := session.conn.Write(payload)
	return err
}

func socksUDPFlushInitial(session *socksUDPSession, datagrams [][]byte) error {
	for _, datagram := range datagrams {
		if err := socksUDPWriteUpstream(session, datagram); err != nil {
			return err
		}
	}
	return nil
}

func socksUDPRunSession(local *net.UDPConn, srcAddr net.UDPAddr, key string, session socksUDPSession, connLock *sync.Mutex, connMap map[string]socksUDPSession) {
	hdrlen := len(session.header)
	data := make([]byte, quicUDPPacketSize+256)
	copy(data, session.header)

	session.conn.SetReadDeadline(time.Now().Add(time.Minute * 2))
	for {
		n, err := session.conn.Read(data[hdrlen:])
		if err != nil {
			connLock.Lock()
			delete(connMap, key)
			connLock.Unlock()
			session.conn.Close()
			return
		}
		session.conn.SetReadDeadline(time.Now().Add(time.Minute * 2))
		reply := data[hdrlen : hdrlen+n]
		if session.rewriter != nil {
			reply = session.rewriter.rewriteServer(reply)
		}
		copy(data[hdrlen:], reply)
		local.WriteToUDP(data[:hdrlen+len(reply)], &srcAddr)
	}
}

func socksUDPStartSession(local *net.UDPConn, srcAddr net.UDPAddr, key string, header []byte, host string, port int, outbound *Outbound, initialDatagrams [][]byte, connLock *sync.Mutex, connMap map[string]socksUDPSession) {
	if len(initialDatagrams) == 0 {
		return
	}

	connLock.Lock()
	if _, ok := connMap[key]; ok {
		connLock.Unlock()
		return
	}
	connLock.Unlock()

	remoteConn, err := outbound.DialUDPProxy(host, port)
	if err != nil {
		logPrintln(1, err)
		return
	}

	if outbound.Hint&HINT_ZERO != 0 {
		zeroData := make([]byte, 8+rand.Intn(1024))
		if _, err = remoteConn.Write(zeroData); err != nil {
			logPrintln(1, err)
			remoteConn.Close()
			return
		}
	}

	var rewriter *quicInitialRewriter
	if outbound.Hint&HINT_HTTP3 != 0 {
		rewriter = &quicInitialRewriter{}
	}

	session := socksUDPSession{
		conn:     remoteConn,
		outbound: outbound,
		rewriter: rewriter,
		header:   append([]byte(nil), header...),
	}

	connLock.Lock()
	connMap[key] = session
	connLock.Unlock()

	go socksUDPRunSession(local, srcAddr, key, session, connLock, connMap)

	if err = socksUDPFlushInitial(&session, initialDatagrams); err != nil {
		logPrintln(1, err)
		connLock.Lock()
		delete(connMap, key)
		connLock.Unlock()
		remoteConn.Close()
		return
	}

	logPrintln(1, "SocksU:", srcAddr, "->", host, port, outbound, "initials", len(initialDatagrams))
}

func socksUDPContinuePending(local *net.UDPConn, key string, pending *socksUDPPending, payload []byte, now time.Time, connLock *sync.Mutex, connMap map[string]socksUDPSession, pendingMap map[string]*socksUDPPending) {
	connLock.Lock()
	if pendingMap[key] != pending {
		connLock.Unlock()
		return
	}
	if pending.expired(now) {
		delete(pendingMap, key)
		connLock.Unlock()
		logPrintln(4, "SocksU: Initial timeout", pending.srcAddr, "->", pending.host, pending.port)
		return
	}
	connLock.Unlock()

	if !isQUICInitialDatagram(payload) {
		datagrams := pending.datagrams()
		datagrams = append(datagrams, append([]byte(nil), payload...))
		connLock.Lock()
		delete(pendingMap, key)
		connLock.Unlock()
		socksUDPStartSession(local, pending.srcAddr, key, pending.header, pending.host, pending.port, pending.outbound, datagrams, connLock, connMap)
		return
	}

	datagrams, waiting, err := pending.accumulate(payload, now)
	if err != nil {
		connLock.Lock()
		delete(pendingMap, key)
		connLock.Unlock()
		logPrintln(4, "SocksU: Initial collect:", err)
		return
	}
	if waiting {
		packetCount, contiguous := pending.stats()
		logPrintln(4, "SocksU: waiting ClientHello", pending.srcAddr, "->", pending.host, pending.port,
			"packets", packetCount, "contiguous", contiguous)
		return
	}

	connLock.Lock()
	delete(pendingMap, key)
	connLock.Unlock()
	socksUDPStartSession(local, pending.srcAddr, key, pending.header, pending.host, pending.port, pending.outbound, datagrams, connLock, connMap)
}

func GetSocksUDPTarget(ip net.IP, host string) (string, *Outbound) {
	var outbound *Outbound = nil

	if host == "" && ip != nil {
		switch ip[0] {
		case 0x00:
			index := int(binary.BigEndian.Uint16(ip[14:16]))
			if index >= len(Nose) {
				logPrintln(3, index, "in", ip, "out of range")
				return "", nil
			}
			host, outbound = GetDNSLie(index)
		case VirtualAddrPrefix:
			index := int(binary.BigEndian.Uint16(ip[2:4]))
			if index >= len(Nose) {
				logPrintln(3, index, "in", ip, "out of range")
				return "", nil
			}
			host, outbound = GetDNSLie(index)
		}
	}

	if outbound == nil {
		if host != "" {
			outbound, _ = DefaultProfile.GetOutbound(host)
		} else if ip != nil {
			outbound = DefaultProfile.GetOutboundByIP(ip)
		}
	}

	if host == "" {
		if ip == nil {
			return "", nil
		}
		host = ip.String()
	}

	return host, outbound
}

func SocksUDPProxy(address string) {
	laddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		logPrintln(1, err)
		return
	}
	local, err := net.ListenUDP("udp", laddr)
	if err != nil {
		logPrintln(1, err)
		return
	}
	defer local.Close()

	var ConnLock sync.Mutex
	var ConnMap map[string]socksUDPSession = make(map[string]socksUDPSession)
	var pendingMap map[string]*socksUDPPending = make(map[string]*socksUDPPending)
	data := make([]byte, quicUDPPacketSize+256)

	for {
		n, srcAddr, err := local.ReadFromUDP(data)
		if err != nil {
			logPrintln(1, err)
			continue
		}

		var host string
		var addr net.IP
		var port int
		var hdrlen int
		var header []byte

		if n > 8 && data[0] == 4 {
			if data[1] != 1 {
				continue
			}
			port = int(binary.BigEndian.Uint16(data[2:4]))
			addr = net.IP(data[4:8])
			hdrlen = 8
		} else {
			hdrlen = SocksUDPHeaderLen(data[:n])
			if hdrlen == 0 || data[2] != 0 || n <= hdrlen {
				continue
			}
			header = append([]byte(nil), data[:hdrlen]...)

			switch data[3] {
			case 0x01: //IPv4
				addr = net.IP(data[4:8])
				port = int(binary.BigEndian.Uint16(data[8:10]))
			case 0x03: //Domain
				addrLen := int(data[4])
				host = string(data[5 : 5+addrLen])
				port = int(binary.BigEndian.Uint16(data[5+addrLen:]))
			case 0x04: //IPv6
				addr = net.IP(data[4:20])
				port = int(binary.BigEndian.Uint16(data[20:22]))
			}
		}

		host, outbound := GetSocksUDPTarget(addr, host)
		if outbound == nil {
			continue
		}

		key := strings.Join([]string{srcAddr.String(), host, strconv.Itoa(port)}, ",")
		payload := append([]byte(nil), data[hdrlen:n]...)

		ConnLock.Lock()
		session, ok := ConnMap[key]
		if ok {
			ConnLock.Unlock()
			if writeErr := socksUDPWriteUpstream(&session, payload); writeErr != nil {
				logPrintln(1, writeErr)
			}
			continue
		}

		now := time.Now()
		if pending, ok := pendingMap[key]; ok {
			ConnLock.Unlock()
			socksUDPContinuePending(local, key, pending, payload, now, &ConnLock, ConnMap, pendingMap)
			continue
		}
		ConnLock.Unlock()

		if outbound.Hint&(HINT_UDP|HINT_HTTP3) == 0 {
			continue
		}

		if outbound.Hint&HINT_HTTP3 != 0 && isQUICInitialDatagram(payload) {
			ConnLock.Lock()
			if len(ConnMap)+len(pendingMap) >= quicPendingLimit {
				ConnLock.Unlock()
				logPrintln(3, "SocksU: pending session limit", srcAddr)
				continue
			}
			pending := &socksUDPPending{
				srcAddr:  *srcAddr,
				header:   append([]byte(nil), header...),
				host:     host,
				port:     port,
				outbound: outbound,
			}
			pendingMap[key] = pending
			ConnLock.Unlock()
			socksUDPContinuePending(local, key, pending, payload, now, &ConnLock, ConnMap, pendingMap)
			continue
		}

		socksUDPStartSession(local, *srcAddr, key, header, host, port, outbound, [][]byte{payload}, &ConnLock, ConnMap)
	}
}
