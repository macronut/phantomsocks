package phantomtcp

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/rand"
	"net"
	"sort"
	"sync"
	"time"
)

var (
	quicV1Salt      = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	quicDraft29Salt = []byte{0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99}
	quicV2Salt      = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}
)

const (
	quicVersionNone    uint32 = 0
	quicVersionNotLong uint32 = 0xffffffff
	quicVersion1       uint32 = 0x00000001
	quicVersionDraft29 uint32 = 0xff00001d
	quicVersion2       uint32 = 0x6b3343cf
	quicVersionGoogle  uint32 = 0xfffffffe

	quicMinimumInitialDatagramSize = 1200
	quicUDPPacketSize              = 65535
	quicPendingTimeout             = 5 * time.Second
	quicPendingLimit               = 1024
	quicPendingBytes               = 256 * 1024
)

func quicVersionSalt(version uint32) []byte {
	switch version {
	case quicVersion1:
		return quicV1Salt
	case quicVersionDraft29:
		return quicDraft29Salt
	case quicVersion2:
		return quicV2Salt
	default:
		return nil
	}
}

func readVarint(b []byte) (uint64, int, error) {
	if len(b) == 0 {
		return 0, 0, errors.New("short varint")
	}
	first := b[0]
	switch first >> 6 {
	case 0:
		return uint64(first & 0x3f), 1, nil
	case 1:
		if len(b) < 2 {
			return 0, 0, errors.New("short varint")
		}
		return uint64(first&0x3f)<<8 | uint64(b[1]), 2, nil
	case 2:
		if len(b) < 4 {
			return 0, 0, errors.New("short varint")
		}
		return uint64(first&0x3f)<<24 | uint64(b[1])<<16 | uint64(b[2])<<8 | uint64(b[3]), 4, nil
	default:
		if len(b) < 8 {
			return 0, 0, errors.New("short varint")
		}
		return binary.BigEndian.Uint64(b) & 0x3fffffffffffffff, 8, nil
	}
}

func writeVarint(v uint64) []byte {
	switch {
	case v <= 0x3f:
		return []byte{byte(v)}
	case v <= 0x3fff:
		return []byte{byte(0x40 | (v >> 8)), byte(v)}
	case v <= 0x3fffffff:
		return []byte{
			byte(0x80 | (v >> 24)),
			byte(v >> 16),
			byte(v >> 8),
			byte(v),
		}
	default:
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], v)
		b[0] = 0xc0 | (b[0] & 0x3f)
		return b[:]
	}
}

func hkdfExtract(salt, ikm []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

func hkdfExpandLabel(secret []byte, label string, length int) []byte {
	fullLabel := "tls13 " + label
	info := make([]byte, 0, 2+1+len(fullLabel)+1)
	info = append(info, byte(length>>8), byte(length))
	info = append(info, byte(len(fullLabel)))
	info = append(info, []byte(fullLabel)...)
	info = append(info, 0)

	out := make([]byte, length)
	counter := byte(1)
	var generated int
	var block []byte
	for generated < length {
		mac := hmac.New(sha256.New, secret)
		if len(block) > 0 {
			mac.Write(block)
		}
		mac.Write(info)
		mac.Write([]byte{counter})
		block = mac.Sum(nil)
		n := copy(out[generated:], block)
		generated += n
		counter++
	}
	return out
}

func initialSecrets(version uint32, dcid []byte, server bool) (key, iv, hp []byte, ok bool) {
	salt := quicVersionSalt(version)
	if salt == nil {
		return nil, nil, nil, false
	}
	initial := hkdfExtract(salt, dcid)
	perspective := "client in"
	if server {
		perspective = "server in"
	}
	secret := hkdfExpandLabel(initial, perspective, 32)
	keyLabel, ivLabel, hpLabel := "quic key", "quic iv", "quic hp"
	if version == quicVersion2 {
		keyLabel, ivLabel, hpLabel = "quicv2 key", "quicv2 iv", "quicv2 hp"
	}
	return hkdfExpandLabel(secret, keyLabel, 16),
		hkdfExpandLabel(secret, ivLabel, 12),
		hkdfExpandLabel(secret, hpLabel, 16),
		true
}

func quicInitialSecrets(version uint32, dcid []byte) (key, iv, hp []byte, ok bool) {
	return initialSecrets(version, dcid, false)
}

type initialParse struct {
	version    uint32
	dcid       []byte
	scid       []byte
	token      []byte
	pnOffset   int
	payloadLen int
	packetLen  int
}

func quicLongPacketType(first byte, version uint32) byte {
	packetType := (first >> 4) & 0x03
	if version == quicVersion2 {
		switch packetType {
		case 0:
			return 3
		case 1:
			return 0
		case 2:
			return 1
		default:
			return 2
		}
	}
	return packetType
}

func parseInitialPacket(data []byte) (*initialParse, error) {
	if len(data) < 7 || data[0]&0x80 == 0 {
		return nil, errors.New("not long header")
	}
	version := binary.BigEndian.Uint32(data[1:5])
	if quicLongPacketType(data[0], version) != 0 {
		return nil, errors.New("not initial")
	}
	pos := 5
	dcidLen := int(data[pos])
	pos++
	if pos+dcidLen > len(data) {
		return nil, errors.New("short dcid")
	}
	dcid := data[pos : pos+dcidLen]
	pos += dcidLen
	if pos >= len(data) {
		return nil, errors.New("short scid len")
	}
	scidLen := int(data[pos])
	pos++
	if pos+scidLen > len(data) {
		return nil, errors.New("short scid")
	}
	scid := data[pos : pos+scidLen]
	pos += scidLen
	tokenLen, n, err := readVarint(data[pos:])
	if err != nil {
		return nil, err
	}
	pos += n
	if pos+int(tokenLen) > len(data) {
		return nil, errors.New("short token")
	}
	token := data[pos : pos+int(tokenLen)]
	pos += int(tokenLen)
	payloadLen, n, err := readVarint(data[pos:])
	if err != nil {
		return nil, err
	}
	pos += n
	pnOffset := pos
	if pnOffset+int(payloadLen) > len(data) {
		return nil, errors.New("short payload")
	}
	packetLen := pnOffset + int(payloadLen)
	return &initialParse{
		version:    version,
		dcid:       append([]byte(nil), dcid...),
		scid:       append([]byte(nil), scid...),
		token:      append([]byte(nil), token...),
		pnOffset:   pnOffset,
		payloadLen: int(payloadLen),
		packetLen:  packetLen,
	}, nil
}

func removeHeaderProtection(packet []byte, pnOffset int, hpKey []byte) (int, error) {
	if pnOffset+20 > len(packet) {
		return 0, errors.New("short header for hp sample")
	}
	block, err := aes.NewCipher(hpKey)
	if err != nil {
		return 0, err
	}
	sample := packet[pnOffset+4 : pnOffset+20]
	mask := make([]byte, 16)
	block.Encrypt(mask, sample)
	packet[0] ^= mask[0] & 0x0f
	pnLen := int(packet[0]&0x03) + 1
	if pnOffset+pnLen > len(packet) {
		return 0, errors.New("short packet number")
	}
	for i := 0; i < pnLen; i++ {
		packet[pnOffset+i] ^= mask[1+i]
	}
	return pnLen, nil
}

func applyHeaderProtection(header []byte, pnOffset, pnLen int, hpKey []byte) error {
	if pnOffset+4+16 > len(header) {
		return errors.New("short header for hp sample")
	}
	block, err := aes.NewCipher(hpKey)
	if err != nil {
		return err
	}
	sample := header[pnOffset+4 : pnOffset+20]
	mask := make([]byte, 16)
	block.Encrypt(mask, sample)
	header[0] ^= mask[0] & 0x0f
	for i := 0; i < pnLen; i++ {
		header[pnOffset+i] ^= mask[1+i]
	}
	return nil
}

func decodePacketNumber(header []byte, pnOffset, pnLen int, expected uint64) uint64 {
	var truncated uint64
	for i := 0; i < pnLen; i++ {
		truncated = truncated<<8 | uint64(header[pnOffset+i])
	}
	pnWindow := uint64(1) << (8 * pnLen)
	pnHalfWindow := pnWindow / 2
	pnMask := pnWindow - 1
	candidate := (expected & ^pnMask) | truncated
	const maxPacketNumber = uint64(1)<<62 - 1
	if candidate+pnHalfWindow <= expected && candidate <= maxPacketNumber-pnWindow {
		return candidate + pnWindow
	}
	if candidate > expected+pnHalfWindow && candidate >= pnWindow {
		return candidate - pnWindow
	}
	return candidate
}

func encodePacketNumber(pn uint64, pnLen int) []byte {
	b := make([]byte, pnLen)
	for i := pnLen - 1; i >= 0; i-- {
		b[i] = byte(pn)
		pn >>= 8
	}
	return b
}

func packetNumberLen(pn uint64) int {
	switch {
	case pn <= 0xff:
		return 1
	case pn <= 0xffff:
		return 2
	case pn <= 0xffffff:
		return 3
	default:
		return 4
	}
}

func quicNonce(iv []byte, pn uint64) []byte {
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], pn)
	for i := range nonce {
		nonce[i] ^= iv[i]
	}
	return nonce
}

func decryptInitialWithExpected(data []byte, key, iv, hp []byte, expected uint64) (plaintext []byte, pn uint64, pnLen int, err error) {
	pkt, err := parseInitialPacket(data)
	if err != nil {
		return nil, 0, 0, err
	}
	packet := append([]byte(nil), data[:pkt.packetLen]...)
	pnLen, err = removeHeaderProtection(packet, pkt.pnOffset, hp)
	if err != nil {
		return nil, 0, 0, err
	}
	headerEnd := pkt.pnOffset + pnLen
	if headerEnd+pkt.payloadLen-pnLen > len(packet) {
		return nil, 0, 0, errors.New("short ciphertext")
	}
	pn = decodePacketNumber(packet, pkt.pnOffset, pnLen, expected)
	aad := packet[:headerEnd]
	ciphertext := packet[headerEnd : pkt.pnOffset+pkt.payloadLen]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, 0, 0, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, 0, 0, err
	}
	plaintext, err = aead.Open(nil, quicNonce(iv, pn), ciphertext, aad)
	if err != nil {
		return nil, 0, 0, err
	}
	return plaintext, pn, pnLen, nil
}

func decryptInitial(data []byte, key, iv, hp []byte) (plaintext []byte, pn uint64, err error) {
	plaintext, pn, _, err = decryptInitialWithExpected(data, key, iv, hp, 0)
	return plaintext, pn, err
}

func encryptInitialWithPNLen(version uint32, dcid, scid, token []byte, pn uint64, pnLen int, plaintext []byte, key, iv, hp []byte) ([]byte, error) {
	if pnLen < 1 || pnLen > 4 {
		pnLen = packetNumberLen(pn)
	}
	pnBytes := encodePacketNumber(pn, pnLen)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	var header []byte
	first := byte(0xc0 | byte(pnLen-1))
	if version == quicVersion2 {
		first |= 0x10
	}
	header = append(header, first)
	vb := make([]byte, 4)
	binary.BigEndian.PutUint32(vb, version)
	header = append(header, vb...)
	header = append(header, byte(len(dcid)))
	header = append(header, dcid...)
	header = append(header, byte(len(scid)))
	header = append(header, scid...)
	header = append(header, writeVarint(uint64(len(token)))...)
	header = append(header, token...)
	header = append(header, writeVarint(uint64(pnLen+len(plaintext)+16))...)
	pnOffset := len(header)
	header = append(header, pnBytes...)

	ciphertext := aead.Seal(nil, quicNonce(iv, pn), plaintext, header)
	buf := append(header, ciphertext...)
	if err := applyHeaderProtection(buf, pnOffset, pnLen, hp); err != nil {
		return nil, err
	}
	return buf, nil
}

func encryptInitial(version uint32, dcid, scid, token []byte, pn uint64, plaintext []byte, key, iv, hp []byte) ([]byte, error) {
	return encryptInitialWithPNLen(version, dcid, scid, token, pn, packetNumberLen(pn), plaintext, key, iv, hp)
}

func extractCryptoStream(frames []byte) ([]byte, error) {
	var stream []byte
	for off := 0; off < len(frames); {
		start := off
		frameType := frames[start]
		end, err := frameEnd(frames, start)
		if err != nil {
			return nil, err
		}
		off = end
		if frameType != 0x06 {
			continue
		}
		pos := start + 1
		offset, err := varintAt(frames, &pos)
		if err != nil {
			return nil, err
		}
		length, err := varintAt(frames, &pos)
		if err != nil || length > uint64(end-pos) {
			return nil, errors.New("short crypto frame")
		}
		streamEnd := offset + length
		if streamEnd < offset || streamEnd > quicUDPPacketSize {
			return nil, errors.New("invalid crypto frame range")
		}
		if int(streamEnd) > len(stream) {
			extended := make([]byte, int(streamEnd))
			copy(extended, stream)
			stream = extended
		}
		copy(stream[int(offset):], frames[pos:pos+int(length)])
	}
	return stream, nil
}

func clientHelloComplete(clientHello []byte) bool {
	if len(clientHello) < 4 || clientHello[0] != 0x01 {
		return false
	}
	bodyLen := int(clientHello[1])<<16 | int(clientHello[2])<<8 | int(clientHello[3])
	if bodyLen < 0 {
		return false
	}
	return len(clientHello) >= 4+bodyLen
}

func sniHostNameRange(clientHello []byte) (offset, length int, ok bool) {
	headerLen := len(clientHello)
	offset = 4 + 2 + 32
	if offset+1 > headerLen || clientHello[0] != 0x01 {
		return 0, 0, false
	}
	SessionIDLength := clientHello[offset]
	offset += 1 + int(SessionIDLength)
	if offset+2 > headerLen {
		return 0, 0, false
	}
	CipherSuitersLength := binary.BigEndian.Uint16(clientHello[offset : offset+2])
	offset += 2 + int(CipherSuitersLength)
	if offset+1 > headerLen {
		return 0, 0, false
	}
	CompressionMethodsLength := clientHello[offset]
	offset += 1 + int(CompressionMethodsLength)
	if offset+2 > headerLen {
		return 0, 0, false
	}
	ExtensionsLength := binary.BigEndian.Uint16(clientHello[offset : offset+2])
	offset += 2
	ExtensionsEnd := offset + int(ExtensionsLength)
	if ExtensionsEnd > headerLen {
		ExtensionsEnd = headerLen
	}
	for offset+4 <= ExtensionsEnd {
		ExtensionType := binary.BigEndian.Uint16(clientHello[offset : offset+2])
		ExtensionLength := int(binary.BigEndian.Uint16(clientHello[offset+2 : offset+4]))
		offset += 4
		extEnd := offset + ExtensionLength
		if extEnd > ExtensionsEnd {
			return 0, 0, false
		}
		if ExtensionType == 0 && ExtensionLength >= 5 {
			ServerNameLength := int(binary.BigEndian.Uint16(clientHello[offset+3 : offset+5]))
			nameStart := offset + 5
			if ServerNameLength > 0 && nameStart+ServerNameLength <= extEnd {
				return nameStart, ServerNameLength, true
			}
			return 0, 0, false
		}
		offset = extEnd
	}
	return 0, 0, false
}

func getIETFQUICSNI(b []byte) string {
	if GetQUICVersion(b) == 0 {
		return ""
	}
	var collector quicInitialCollector
	sni, _, err := collector.add(b)
	if err != nil {
		logPrintln(4, "QUIC Initial:", err)
		return ""
	}
	return sni
}

func getGQUIC043SNI(b []byte) string {
	if !(len(b) > 23 && string(b[9:13]) == "Q043") {
		return ""
	}
	if !(len(b) > 26 && b[26] == 0xa0) {
		return ""
	}
	if !(len(b) > 38 && string(b[30:34]) == "CHLO") {
		return ""
	}
	return getGQUICCHLOSNI(b, 38, 34)
}

func getGQUIC046SNI(b []byte) string {
	if !(len(b) > 31 && b[30] == 0xa0) {
		return ""
	}
	if !(len(b) > 42 && string(b[34:38]) == "CHLO") {
		return ""
	}
	return getGQUICCHLOSNI(b, 42, 38)
}

func getGQUICCHLOSNI(b []byte, baseOffset, tagNumOffset int) string {
	tagNum := int(binary.LittleEndian.Uint16(b[tagNumOffset : tagNumOffset+2]))
	dataOffset := baseOffset + 8*tagNum
	if !(len(b) > dataOffset) {
		return ""
	}
	var sniOffset uint16
	for i := 0; i < tagNum; i++ {
		offset := baseOffset + i*8
		tagName := b[offset : offset+4]
		offsetEnd := binary.LittleEndian.Uint16(b[offset+4 : offset+6])
		if bytes.Equal(tagName, []byte{'S', 'N', 'I', 0}) {
			if len(b[dataOffset:]) < int(offsetEnd) {
				return ""
			}
			return string(b[dataOffset:][sniOffset:offsetEnd])
		}
		sniOffset = offsetEnd
	}
	return ""
}

func GetQUICVersion(data []byte) uint32 {
	if len(data) < 5 {
		return quicVersionNotLong
	}
	if data[0] == 0x0d {
		if len(data) > 13 && string(data[9:13]) == "Q043" {
			return quicVersionGoogle
		}
		return quicVersionNone
	}
	if data[0]&0xC0 != 0xC0 {
		return quicVersionNotLong
	}
	version := binary.BigEndian.Uint32(data[1:5])
	switch version {
	case quicVersion1, quicVersionDraft29, quicVersion2:
		if quicLongPacketType(data[0], version) != 0 {
			return quicVersionNone
		}
		return version
	}
	switch string(data[1:5]) {
	case "Q046", "Q050":
		return quicVersionGoogle
	}
	return quicVersionNone
}

func isQUICInitialDatagram(data []byte) bool {
	version := GetQUICVersion(data)
	return version != quicVersionNone && version != quicVersionNotLong
}

func GetQUICSNI(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	if b[0] == 0x0d {
		return getGQUIC043SNI(b)
	}
	if b[0]&0xc0 == 0xc0 {
		if len(b) > 5 {
			switch string(b[1:5]) {
			case "Q046", "Q050":
				return getGQUIC046SNI(b)
			}
		}
		return getIETFQUICSNI(b)
	}
	return ""
}

func buildCryptoFrame(offset uint64, data []byte) []byte {
	frame := []byte{0x06}
	frame = append(frame, writeVarint(offset)...)
	frame = append(frame, writeVarint(uint64(len(data)))...)
	return append(frame, data...)
}

type ackRange struct {
	smallest uint64
	largest  uint64
}

type ackFrame struct {
	frameType byte
	delay     uint64
	ranges    []ackRange
	ecn       [3]uint64
}

func varintAt(data []byte, off *int) (uint64, error) {
	if *off >= len(data) {
		return 0, errors.New("short varint")
	}
	value, n, err := readVarint(data[*off:])
	if err != nil {
		return 0, err
	}
	*off += n
	return value, nil
}

func parseAckFrame(data []byte, off int, frameType byte) (ackFrame, int, error) {
	var ack ackFrame
	ack.frameType = frameType

	largest, err := varintAt(data, &off)
	if err != nil {
		return ack, off, err
	}
	ack.delay, err = varintAt(data, &off)
	if err != nil {
		return ack, off, err
	}
	rangeCount, err := varintAt(data, &off)
	if err != nil {
		return ack, off, err
	}
	if rangeCount > uint64(len(data)-off) {
		return ack, off, errors.New("invalid ACK range count")
	}
	firstRange, err := varintAt(data, &off)
	if err != nil || firstRange > largest {
		return ack, off, errors.New("invalid ACK first range")
	}
	ack.ranges = append(ack.ranges, ackRange{smallest: largest - firstRange, largest: largest})
	for i := uint64(0); i < rangeCount; i++ {
		gap, err := varintAt(data, &off)
		if err != nil {
			return ack, off, err
		}
		span, err := varintAt(data, &off)
		if err != nil {
			return ack, off, err
		}
		previous := ack.ranges[len(ack.ranges)-1].smallest
		if gap > previous || previous-gap < 2 {
			return ack, off, errors.New("invalid ACK gap")
		}
		nextLargest := previous - gap - 2
		if span > nextLargest {
			return ack, off, errors.New("invalid ACK range")
		}
		ack.ranges = append(ack.ranges, ackRange{
			smallest: nextLargest - span,
			largest:  nextLargest,
		})
	}
	if frameType == 0x03 {
		for i := range ack.ecn {
			ack.ecn[i], err = varintAt(data, &off)
			if err != nil {
				return ack, off, err
			}
		}
	}
	return ack, off, nil
}

func appendAckFrame(dst []byte, ack ackFrame) ([]byte, error) {
	if len(ack.ranges) == 0 {
		return nil, errors.New("ACK has no ranges")
	}
	for _, r := range ack.ranges {
		if r.smallest > r.largest {
			return nil, errors.New("invalid ACK range")
		}
	}
	dst = append(dst, ack.frameType)
	dst = append(dst, writeVarint(ack.ranges[0].largest)...)
	dst = append(dst, writeVarint(ack.delay)...)
	dst = append(dst, writeVarint(uint64(len(ack.ranges)-1))...)
	dst = append(dst, writeVarint(ack.ranges[0].largest-ack.ranges[0].smallest)...)
	for i := 1; i < len(ack.ranges); i++ {
		previous := ack.ranges[i-1]
		current := ack.ranges[i]
		if current.largest+2 > previous.smallest {
			return nil, errors.New("overlapping ACK ranges")
		}
		dst = append(dst, writeVarint(previous.smallest-current.largest-2)...)
		dst = append(dst, writeVarint(current.largest-current.smallest)...)
	}
	if ack.frameType == 0x03 {
		for _, count := range ack.ecn {
			dst = append(dst, writeVarint(count)...)
		}
	}
	return dst, nil
}

func mapAckPN(pn, first uint64) uint64 {
	switch {
	case pn == first || pn == first+1:
		return first
	case pn > first+1:
		return pn - 1
	default:
		return pn
	}
}

func remapAck(ack ackFrame, first uint64) ackFrame {
	mapped := make([]ackRange, 0, len(ack.ranges))
	for _, r := range ack.ranges {
		current := ackRange{
			smallest: mapAckPN(r.smallest, first),
			largest:  mapAckPN(r.largest, first),
		}
		if len(mapped) > 0 && current.largest+1 >= mapped[len(mapped)-1].smallest {
			if current.smallest < mapped[len(mapped)-1].smallest {
				mapped[len(mapped)-1].smallest = current.smallest
			}
			continue
		}
		mapped = append(mapped, current)
	}
	ack.ranges = mapped
	return ack
}

func skipVarints(data []byte, off *int, count int) error {
	for i := 0; i < count; i++ {
		if _, err := varintAt(data, off); err != nil {
			return err
		}
	}
	return nil
}

func frameEnd(data []byte, start int) (int, error) {
	if start >= len(data) {
		return start, errors.New("short frame")
	}
	frameType := data[start]
	off := start + 1
	switch {
	case frameType == 0x00 || frameType == 0x01 || frameType == 0x1e:
		return off, nil
	case frameType == 0x02 || frameType == 0x03:
		_, end, err := parseAckFrame(data, off, frameType)
		return end, err
	case frameType == 0x04:
		err := skipVarints(data, &off, 3)
		return off, err
	case frameType == 0x05:
		err := skipVarints(data, &off, 2)
		return off, err
	case frameType == 0x06 || frameType == 0x07:
		if frameType == 0x06 {
			if _, err := varintAt(data, &off); err != nil {
				return off, err
			}
		}
		length, err := varintAt(data, &off)
		if err != nil || length > uint64(len(data)-off) {
			return off, errors.New("short frame")
		}
		return off + int(length), nil
	case frameType >= 0x08 && frameType <= 0x0f:
		if _, err := varintAt(data, &off); err != nil {
			return off, err
		}
		if frameType&0x04 != 0 {
			if _, err := varintAt(data, &off); err != nil {
				return off, err
			}
		}
		if frameType&0x02 == 0 {
			return len(data), nil
		}
		length, err := varintAt(data, &off)
		if err != nil || length > uint64(len(data)-off) {
			return off, errors.New("short STREAM frame")
		}
		return off + int(length), nil
	case frameType == 0x10 || frameType == 0x12 || frameType == 0x13 ||
		frameType == 0x14 || frameType == 0x16 || frameType == 0x17 ||
		frameType == 0x19:
		err := skipVarints(data, &off, 1)
		return off, err
	case frameType == 0x11 || frameType == 0x15:
		err := skipVarints(data, &off, 2)
		return off, err
	case frameType == 0x18:
		if err := skipVarints(data, &off, 2); err != nil {
			return off, err
		}
		if off >= len(data) {
			return off, errors.New("short NEW_CONNECTION_ID frame")
		}
		cidLen := int(data[off])
		off++
		if cidLen > 20 || off+cidLen+16 > len(data) {
			return off, errors.New("short NEW_CONNECTION_ID frame")
		}
		return off + cidLen + 16, nil
	case frameType == 0x1a || frameType == 0x1b:
		if off+8 > len(data) {
			return off, errors.New("short PATH frame")
		}
		return off + 8, nil
	case frameType == 0x1c || frameType == 0x1d:
		if _, err := varintAt(data, &off); err != nil {
			return off, err
		}
		if frameType == 0x1c {
			if _, err := varintAt(data, &off); err != nil {
				return off, err
			}
		}
		reasonLen, err := varintAt(data, &off)
		if err != nil || reasonLen > uint64(len(data)-off) {
			return off, errors.New("short CONNECTION_CLOSE frame")
		}
		return off + int(reasonLen), nil
	case frameType == 0x30 || frameType == 0x31:
		if frameType == 0x30 {
			return len(data), nil
		}
		length, err := varintAt(data, &off)
		if err != nil || length > uint64(len(data)-off) {
			return off, errors.New("short DATAGRAM frame")
		}
		return off + int(length), nil
	default:
		return off, errors.New("unsupported frame")
	}
}

func rewriteAckFrames(plaintext []byte, first uint64) ([]byte, error) {
	out := make([]byte, 0, len(plaintext))
	for off := 0; off < len(plaintext); {
		start := off
		frameType := plaintext[off]
		if frameType == 0x02 || frameType == 0x03 {
			ack, end, err := parseAckFrame(plaintext, off+1, frameType)
			if err != nil {
				return nil, err
			}
			out, err = appendAckFrame(out, remapAck(ack, first))
			if err != nil {
				return nil, err
			}
			off = end
			continue
		}
		end, err := frameEnd(plaintext, start)
		if err != nil {
			return nil, err
		}
		out = append(out, plaintext[start:end]...)
		off = end
	}
	return out, nil
}

func mergeInitialCryptoFrames(plaintext []byte, stream *[]byte, covered *[]bool) error {
	for off := 0; off < len(plaintext); {
		start := off
		frameType := plaintext[start]
		end, err := frameEnd(plaintext, start)
		if err != nil {
			return err
		}
		off = end
		if frameType != 0x06 {
			continue
		}
		pos := start + 1
		offset, err := varintAt(plaintext, &pos)
		if err != nil {
			return err
		}
		length, err := varintAt(plaintext, &pos)
		if err != nil || length > uint64(end-pos) || offset+length < offset ||
			offset+length > quicUDPPacketSize {
			return errors.New("invalid CRYPTO frame")
		}
		streamEnd := int(offset + length)
		if streamEnd > len(*stream) {
			extended := make([]byte, streamEnd)
			copy(extended, *stream)
			*stream = extended
			extendedCoverage := make([]bool, streamEnd)
			copy(extendedCoverage, *covered)
			*covered = extendedCoverage
		}
		for index, value := range plaintext[pos : pos+int(length)] {
			target := int(offset) + index
			if (*covered)[target] && (*stream)[target] != value {
				return errors.New("conflicting CRYPTO data")
			}
			(*stream)[target] = value
			(*covered)[target] = true
		}
	}
	return nil
}

func contiguousCryptoStream(stream []byte, covered []bool) []byte {
	end := 0
	for end < len(covered) && covered[end] {
		end++
	}
	return stream[:end]
}

func splitInitialCryptoFrames(plaintext []byte) (first, second []byte, ok bool) {
	type cryptoSegment struct {
		offset uint64
		data   []byte
	}
	var segments []cryptoSegment
	var streamLength uint64
	for off := 0; off < len(plaintext); {
		start := off
		frameType := plaintext[off]
		end, err := frameEnd(plaintext, start)
		if err != nil {
			return nil, nil, false
		}
		off = end
		switch frameType {
		case 0x00:
			continue
		case 0x06:
			pos := start + 1
			offset, err := varintAt(plaintext, &pos)
			if err != nil {
				return nil, nil, false
			}
			length, err := varintAt(plaintext, &pos)
			if err != nil || length > uint64(end-pos) {
				return nil, nil, false
			}
			if offset > ^uint64(0)-length {
				return nil, nil, false
			}
			segmentEnd := offset + length
			if segmentEnd > streamLength {
				streamLength = segmentEnd
			}
			segments = append(segments, cryptoSegment{
				offset: offset,
				data:   plaintext[pos : pos+int(length)],
			})
		default:
			first = append(first, plaintext[start:end]...)
		}
	}
	if len(segments) == 0 || streamLength > uint64(len(plaintext)) {
		return nil, nil, false
	}
	stream := make([]byte, int(streamLength))
	covered := make([]bool, int(streamLength))
	for _, segment := range segments {
		start := int(segment.offset)
		for i, value := range segment.data {
			index := start + i
			if covered[index] && stream[index] != value {
				return nil, nil, false
			}
			stream[index] = value
			covered[index] = true
		}
	}
	for _, present := range covered {
		if !present {
			return nil, nil, false
		}
	}
	sniStart, sniLength, found := sniHostNameRange(stream)
	if !found || sniLength <= 1 {
		return nil, nil, false
	}
	split := sniStart + sniLength/2
	if split <= 0 || split >= len(stream) {
		return nil, nil, false
	}
	first = append(first, buildCryptoFrame(0, stream[:split])...)
	second = buildCryptoFrame(uint64(split), stream[split:])
	return first, second, true
}

type quicInitialRewriter struct {
	mu sync.Mutex

	initialized    bool
	version        uint32
	clientDCID     []byte
	firstClientPN  uint64
	clientExpected uint64
	serverExpected uint64
}

type quicInitialCollector struct {
	version  uint32
	dcid     []byte
	expected uint64
	stream   []byte
	covered  []bool
}

func (collector *quicInitialCollector) reset() {
	collector.version = 0
	collector.dcid = nil
	collector.expected = 0
	collector.stream = nil
	collector.covered = nil
}

func (collector *quicInitialCollector) add(data []byte) (sni string, lowestPN uint64, err error) {
	lowestPN = ^uint64(0)
	foundInitial := false
	for off := 0; off < len(data); {
		if data[off]&0x80 == 0 {
			break
		}
		packetType, packetEnd, err := quicLongPacketEnd(data[off:])
		if err != nil {
			return "", 0, err
		}
		if packetType == 3 {
			collector.reset()
			return "", 0, errors.New("QUIC Retry")
		}
		if packetType == 0 {
			foundInitial = true
			packet := data[off : off+packetEnd]
			pkt, err := parseInitialPacket(packet)
			if err != nil {
				return "", 0, err
			}
			if collector.version != 0 &&
				(pkt.version != collector.version || !bytes.Equal(pkt.dcid, collector.dcid)) {
				collector.reset()
			}
			key, iv, hp, ok := quicInitialSecrets(pkt.version, pkt.dcid)
			if !ok {
				return "", 0, errors.New("unsupported QUIC version")
			}
			plain, pn, _, err := decryptInitialWithExpected(packet, key, iv, hp, collector.expected)
			if err != nil {
				return "", 0, err
			}
			if collector.version == 0 {
				collector.version = pkt.version
				collector.dcid = append([]byte(nil), pkt.dcid...)
			}
			if pn < lowestPN {
				lowestPN = pn
			}
			if pn >= collector.expected {
				collector.expected = pn + 1
			}
			if err := mergeInitialCryptoFrames(plain, &collector.stream, &collector.covered); err != nil {
				return "", 0, err
			}
		}
		off += packetEnd
	}
	if !foundInitial {
		return "", 0, errors.New("QUIC Initial not found")
	}
	stream := contiguousCryptoStream(collector.stream, collector.covered)
	if start, length, ok := sniHostNameRange(stream); ok && clientHelloComplete(stream) {
		return string(stream[start : start+length]), lowestPN, nil
	}
	return "", lowestPN, nil
}

type quicPendingPacket struct {
	pn   uint64
	data []byte
}

type quicInitialPending struct {
	collector quicInitialCollector
	packets   []quicPendingPacket
	size      int
	updated   time.Time
}

func (pending *quicInitialPending) expired(now time.Time) bool {
	if pending.updated.IsZero() {
		return false
	}
	return now.Sub(pending.updated) > quicPendingTimeout
}

func (pending *quicInitialPending) add(data []byte, now time.Time) (sni string, err error) {
	sni, pn, err := pending.collector.add(data)
	if err != nil {
		return "", err
	}
	pending.packets = append(pending.packets, quicPendingPacket{
		pn:   pn,
		data: append([]byte(nil), data...),
	})
	pending.size += len(data)
	pending.updated = now
	return sni, nil
}

func (pending *quicInitialPending) overLimit() bool {
	return pending.size > quicPendingBytes
}

func (pending *quicInitialPending) datagrams() [][]byte {
	packets := append([]quicPendingPacket(nil), pending.packets...)
	sort.SliceStable(packets, func(i, j int) bool {
		return packets[i].pn < packets[j].pn
	})
	datagrams := make([][]byte, 0, len(packets))
	for _, packet := range packets {
		datagrams = append(datagrams, packet.data)
	}
	return datagrams
}

func (pending *quicInitialPending) stats() (packetCount, contiguous int) {
	stream := contiguousCryptoStream(pending.collector.stream, pending.collector.covered)
	return len(pending.packets), len(stream)
}

func (pending *quicInitialPending) clientHelloReady() bool {
	stream := contiguousCryptoStream(pending.collector.stream, pending.collector.covered)
	return clientHelloComplete(stream)
}

func (pending *quicInitialPending) accumulate(data []byte, now time.Time) (datagrams [][]byte, waiting bool, err error) {
	if _, err = pending.add(data, now); err != nil {
		return nil, false, err
	}
	if pending.overLimit() {
		return nil, false, errors.New("QUIC Initial pending data limit reached")
	}
	if !pending.clientHelloReady() {
		return nil, true, nil
	}
	return pending.datagrams(), false, nil
}

func (rewriter *quicInitialRewriter) resetLocked() {
	rewriter.initialized = false
	rewriter.version = 0
	rewriter.clientDCID = nil
	rewriter.firstClientPN = 0
	rewriter.clientExpected = 0
	rewriter.serverExpected = 0
}

func quicLongPacketEnd(data []byte) (packetType byte, end int, err error) {
	if len(data) < 7 || data[0]&0x80 == 0 {
		return 0, 0, errors.New("not long header")
	}
	version := binary.BigEndian.Uint32(data[1:5])
	pos := 5
	dcidLen := int(data[pos])
	pos++
	if dcidLen > 20 || pos+dcidLen >= len(data) {
		return 0, 0, errors.New("short dcid")
	}
	pos += dcidLen
	scidLen := int(data[pos])
	pos++
	if scidLen > 20 || pos+scidLen > len(data) {
		return 0, 0, errors.New("short scid")
	}
	pos += scidLen
	if version == 0 {
		return 0xff, len(data), nil
	}
	packetType = quicLongPacketType(data[0], version)
	if packetType == 3 {
		return packetType, len(data), nil
	}
	if packetType == 0 {
		tokenLen, n, err := readVarint(data[pos:])
		if err != nil {
			return 0, 0, err
		}
		pos += n
		if tokenLen > uint64(len(data)-pos) {
			return 0, 0, errors.New("short token")
		}
		pos += int(tokenLen)
	}
	payloadLen, n, err := readVarint(data[pos:])
	if err != nil {
		return 0, 0, err
	}
	pos += n
	if payloadLen > uint64(len(data)-pos) {
		return 0, 0, errors.New("short payload")
	}
	return packetType, pos + int(payloadLen), nil
}

func locateQUICInitial(data []byte) (prefix, packet, suffix []byte, retry bool, err error) {
	for off := 0; off < len(data); {
		if data[off]&0x80 == 0 {
			return nil, nil, nil, false, errors.New("Initial not found")
		}
		packetType, end, err := quicLongPacketEnd(data[off:])
		if err != nil {
			return nil, nil, nil, false, err
		}
		end += off
		if packetType == 3 {
			return nil, nil, nil, true, nil
		}
		if packetType == 0 {
			return data[:off], data[off:end], data[end:], false, nil
		}
		off = end
	}
	return nil, nil, nil, false, errors.New("Initial not found")
}

func encryptPaddedInitial(pkt *initialParse, pn uint64, pnLen int, plaintext, key, iv, hp []byte, otherDatagramBytes int) ([]byte, error) {
	padding := 0
	for attempts := 0; attempts < 3; attempts++ {
		padded := make([]byte, len(plaintext)+padding)
		copy(padded, plaintext)
		encrypted, err := encryptInitialWithPNLen(
			pkt.version, pkt.dcid, pkt.scid, pkt.token, pn, pnLen, padded, key, iv, hp,
		)
		if err != nil {
			return nil, err
		}
		missing := quicMinimumInitialDatagramSize - otherDatagramBytes - len(encrypted)
		if missing <= 0 {
			return encrypted, nil
		}
		padding += missing
	}
	return nil, errors.New("unable to pad Initial")
}

func encryptInitialToPacketSize(pkt *initialParse, pn uint64, pnLen int, plaintext, key, iv, hp []byte, targetSize int) ([]byte, error) {
	padding := 0
	for attempts := 0; attempts < 8; attempts++ {
		padded := make([]byte, len(plaintext)+padding)
		copy(padded, plaintext)
		encrypted, err := encryptInitialWithPNLen(
			pkt.version, pkt.dcid, pkt.scid, pkt.token, pn, pnLen, padded, key, iv, hp,
		)
		if err != nil {
			return nil, err
		}
		if len(encrypted) == targetSize {
			return encrypted, nil
		}
		adjustment := targetSize - len(encrypted)
		if padding+adjustment < 0 {
			return nil, errors.New("rewritten Initial exceeds packet size")
		}
		padding += adjustment
	}
	return nil, errors.New("unable to preserve Initial packet size")
}

func fragmentClientInitial(prefix, packet, suffix []byte, pkt *initialParse, plaintext []byte, pn uint64, pnLen int, key, iv, hp []byte) ([][]byte, error) {
	firstPlain, secondPlain, ok := splitInitialCryptoFrames(plaintext)
	if !ok {
		return nil, errors.New("CRYPTO frame cannot be split")
	}
	firstPacket, err := encryptPaddedInitial(pkt, pn, pnLen, firstPlain, key, iv, hp, len(prefix))
	if err != nil {
		return nil, err
	}
	secondPNLen := pnLen
	if packetNumberLen(pn+1) > secondPNLen {
		secondPNLen = packetNumberLen(pn + 1)
	}
	secondPacket, err := encryptPaddedInitial(pkt, pn+1, secondPNLen, secondPlain, key, iv, hp, len(suffix))
	if err != nil {
		return nil, err
	}
	firstDatagram := make([]byte, 0, len(prefix)+len(firstPacket))
	firstDatagram = append(firstDatagram, prefix...)
	firstDatagram = append(firstDatagram, firstPacket...)
	secondDatagram := make([]byte, 0, len(secondPacket)+len(suffix))
	secondDatagram = append(secondDatagram, secondPacket...)
	secondDatagram = append(secondDatagram, suffix...)
	return [][]byte{firstDatagram, secondDatagram}, nil
}

func (rewriter *quicInitialRewriter) rewriteClient(data []byte) [][]byte {
	original := [][]byte{data}
	if rewriter == nil {
		return original
	}

	rewriter.mu.Lock()
	defer rewriter.mu.Unlock()

	prefix, packet, suffix, _, err := locateQUICInitial(data)
	if err != nil {
		return original
	}
	pkt, err := parseInitialPacket(packet)
	if err != nil {
		return original
	}
	key, iv, hp, ok := initialSecrets(pkt.version, pkt.dcid, false)
	if !ok {
		return original
	}
	expected := uint64(0)
	if rewriter.initialized {
		expected = rewriter.clientExpected
	}
	plaintext, pn, pnLen, err := decryptInitialWithExpected(packet, key, iv, hp, expected)
	if err != nil {
		return original
	}

	if !rewriter.initialized {
		datagrams, splitErr := fragmentClientInitial(prefix, packet, suffix, pkt, plaintext, pn, pnLen, key, iv, hp)
		if splitErr != nil {
			return original
		}
		rewriter.initialized = true
		rewriter.version = pkt.version
		rewriter.clientDCID = append([]byte(nil), pkt.dcid...)
		rewriter.firstClientPN = pn
		rewriter.clientExpected = pn + 1
		rewriter.serverExpected = 0
		return datagrams
	}

	if pkt.version != rewriter.version || !bytes.Equal(pkt.dcid, rewriter.clientDCID) {
		return original
	}
	if pn == rewriter.firstClientPN {
		datagrams, splitErr := fragmentClientInitial(prefix, packet, suffix, pkt, plaintext, pn, pnLen, key, iv, hp)
		if splitErr == nil {
			return datagrams
		}
		return original
	}
	if pn <= rewriter.firstClientPN {
		return original
	}

	rewrittenPN := pn + 1
	if packetNumberLen(rewrittenPN) > pnLen {
		pnLen = packetNumberLen(rewrittenPN)
	}
	rewrittenPacket, err := encryptPaddedInitial(pkt, rewrittenPN, pnLen, plaintext, key, iv, hp, len(prefix)+len(suffix))
	if err != nil {
		return original
	}
	datagram := make([]byte, 0, len(prefix)+len(rewrittenPacket)+len(suffix))
	datagram = append(datagram, prefix...)
	datagram = append(datagram, rewrittenPacket...)
	datagram = append(datagram, suffix...)
	if pn >= rewriter.clientExpected {
		rewriter.clientExpected = pn + 1
	}
	return [][]byte{datagram}
}

func (rewriter *quicInitialRewriter) rewriteServer(data []byte) []byte {
	if rewriter == nil {
		return data
	}

	rewriter.mu.Lock()
	defer rewriter.mu.Unlock()

	prefix, packet, suffix, retry, err := locateQUICInitial(data)
	if retry {
		rewriter.resetLocked()
		return data
	}
	if err != nil || !rewriter.initialized {
		return data
	}
	pkt, err := parseInitialPacket(packet)
	if err != nil || pkt.version != rewriter.version {
		return data
	}
	key, iv, hp, ok := initialSecrets(pkt.version, rewriter.clientDCID, true)
	if !ok {
		return data
	}
	plaintext, pn, pnLen, err := decryptInitialWithExpected(packet, key, iv, hp, rewriter.serverExpected)
	if err != nil {
		return data
	}
	rewrittenPlaintext, err := rewriteAckFrames(plaintext, rewriter.firstClientPN)
	if err != nil {
		return data
	}
	if pn >= rewriter.serverExpected {
		rewriter.serverExpected = pn + 1
	}
	if bytes.Equal(plaintext, rewrittenPlaintext) {
		return data
	}
	targetPacketSize := pkt.packetLen
	if len(data) < quicMinimumInitialDatagramSize {
		targetPacketSize += quicMinimumInitialDatagramSize - len(data)
	}
	rewrittenPacket, err := encryptInitialToPacketSize(
		pkt, pn, pnLen, rewrittenPlaintext, key, iv, hp, targetPacketSize,
	)
	if err != nil {
		return data
	}
	datagram := make([]byte, 0, len(prefix)+len(rewrittenPacket)+len(suffix))
	datagram = append(datagram, prefix...)
	datagram = append(datagram, rewrittenPacket...)
	datagram = append(datagram, suffix...)
	return datagram
}

func writeQUICDatagram(conn net.Conn, data []byte, outbound *Outbound, rewriter *quicInitialRewriter) error {
	datagrams := rewriter.rewriteClient(data)
	if outbound != nil && outbound.Hint&HINT_REVERSE != 0 {
		for i := len(datagrams) - 1; i >= 0; i-- {
			if _, err := conn.Write(datagrams[i]); err != nil {
				return err
			}
		}
		return nil
	}
	for _, datagram := range datagrams {
		if _, err := conn.Write(datagram); err != nil {
			return err
		}
	}
	return nil
}

func FragmentQUICInitial(data []byte) [][]byte {
	return (&quicInitialRewriter{}).rewriteClient(data)
}

func WriteQUICInitial(conn net.Conn, data []byte, outbound *Outbound) error {
	return writeQUICDatagram(conn, data, outbound, &quicInitialRewriter{})
}

type quicProxySession struct {
	conn     net.Conn
	outbound *Outbound
	rewriter *quicInitialRewriter
}

func quicProxyWriteUpstream(session *quicProxySession, payload []byte) error {
	if session.rewriter != nil {
		return writeQUICDatagram(session.conn, payload, session.outbound, session.rewriter)
	}
	_, err := session.conn.Write(payload)
	return err
}

func quicProxyFlushInitial(session *quicProxySession, datagrams [][]byte) error {
	for _, datagram := range datagrams {
		if err := quicProxyWriteUpstream(session, datagram); err != nil {
			return err
		}
	}
	return nil
}

func quicProxyRunSession(client *net.UDPConn, clientAddr *net.UDPAddr, clientKey string, session quicProxySession, connLock *sync.Mutex, connMap map[string]quicProxySession) {
	buf := make([]byte, quicUDPPacketSize)
	session.conn.SetReadDeadline(time.Now().Add(time.Minute * 2))
	for {
		n, err := session.conn.Read(buf)
		if err != nil {
			connLock.Lock()
			delete(connMap, clientKey)
			connLock.Unlock()
			session.conn.Close()
			return
		}
		session.conn.SetReadDeadline(time.Now().Add(time.Minute * 2))
		reply := buf[:n]
		if session.rewriter != nil {
			reply = session.rewriter.rewriteServer(reply)
		}
		client.WriteToUDP(reply, clientAddr)
	}
}

func QUICProxy(address string) {
	client, err := ListenUDP(address)
	if err != nil {
		logPrintln(1, err)
		return
	}
	defer client.Close()

	var connLock sync.Mutex
	connMap := make(map[string]quicProxySession)
	pendingMap := make(map[string]*quicInitialPending)
	data := make([]byte, quicUDPPacketSize)

	for {
		n, clientAddr, err := client.ReadFromUDP(data)
		if err != nil {
			logPrintln(1, err)
			return
		}

		clientKey := clientAddr.String()
		connLock.Lock()
		session, ok := connMap[clientKey]
		connLock.Unlock()

		if ok {
			if writeErr := quicProxyWriteUpstream(&session, data[:n]); writeErr != nil {
				logPrintln(1, writeErr)
			}
			continue
		}

		now := time.Now()
		connLock.Lock()
		pending := pendingMap[clientKey]
		if pending == nil || pending.expired(now) {
			if len(pendingMap) >= quicPendingLimit {
				for key, candidate := range pendingMap {
					if candidate.expired(now) {
						delete(pendingMap, key)
					}
				}
			}
			if len(pendingMap) >= quicPendingLimit {
				connLock.Unlock()
				logPrintln(3, "QUIC:", clientKey, "pending session limit")
				continue
			}
			pending = &quicInitialPending{}
			pendingMap[clientKey] = pending
		}
		sni, collectErr := pending.add(data[:n], now)
		if collectErr != nil {
			delete(pendingMap, clientKey)
			connLock.Unlock()
			logPrintln(4, "QUIC:", clientKey, "Initial collect:", collectErr)
			continue
		}
		if pending.overLimit() {
			delete(pendingMap, clientKey)
			connLock.Unlock()
			logPrintln(3, "QUIC:", clientKey, "Initial pending limit")
			continue
		}
		if sni == "" {
			packetCount, contiguous := pending.stats()
			logPrintln(4, "QUIC:", clientKey, "waiting ClientHello", "packets", packetCount, "contiguous", contiguous)
			connLock.Unlock()
			continue
		}
		datagrams := pending.datagrams()
		delete(pendingMap, clientKey)
		connLock.Unlock()

		if DefaultProfile == nil {
			continue
		}
		outbound, _ := DefaultProfile.GetOutbound(sni)
		if outbound == nil || outbound.Hint&HINT_UDP == 0 {
			continue
		}

		logPrintln(1, "QUIC:", clientAddr, sni)

		remoteConn, err := outbound.DialUDPProxy(sni, 443)
		if err != nil {
			logPrintln(1, err)
			continue
		}

		if outbound.Hint&HINT_ZERO != 0 {
			zeroData := make([]byte, 8+rand.Intn(1024))
			if _, err = remoteConn.Write(zeroData); err != nil {
				logPrintln(1, err)
				remoteConn.Close()
				continue
			}
		}

		var rewriter *quicInitialRewriter
		if outbound.Hint&HINT_HTTP3 != 0 {
			rewriter = &quicInitialRewriter{}
		}
		session = quicProxySession{
			conn:     remoteConn,
			outbound: outbound,
			rewriter: rewriter,
		}
		connLock.Lock()
		connMap[clientKey] = session
		connLock.Unlock()

		if err = quicProxyFlushInitial(&session, datagrams); err != nil {
			logPrintln(1, err)
			connLock.Lock()
			delete(connMap, clientKey)
			connLock.Unlock()
			remoteConn.Close()
			continue
		}

		go quicProxyRunSession(client, clientAddr, clientKey, session, &connLock, connMap)
	}
}
