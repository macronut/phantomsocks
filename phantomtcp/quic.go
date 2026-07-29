package phantomtcp

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
)

var (
	quicV1Salt      = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0x6a, 0xe4, 0x6a, 0x79, 0xbc, 0xf0, 0x00, 0x00, 0x00}
	quicDraft29Salt = []byte{0xaf, 0xbf, 0xec, 0x31, 0x19, 0xfd, 0x60, 0x22, 0x80, 0x83, 0x69, 0x8c, 0xc4, 0x83, 0x29, 0x97}
)

const (
	quicVersionNone    uint32 = 0
	quicVersionNotLong uint32 = 0xffffffff
	quicVersion1       uint32 = 0x00000001
	quicVersionDraft29 uint32 = 0xff00001d
	quicVersion2       uint32 = 0x6b3343cf
	quicVersionGoogle  uint32 = 0xfffffffe
)

func quicVersionSalt(version uint32) []byte {
	switch version {
	case 0x00000001:
		return quicV1Salt
	case 0xff00001d:
		return quicDraft29Salt
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
	info := make([]byte, 0, 2+6+len(label)+1)
	info = append(info, byte(length>>8), byte(length))
	info = append(info, []byte("tls13 ")...)
	info = append(info, []byte(label)...)
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

func quicInitialSecrets(version uint32, dcid []byte) (key, iv, hp []byte, ok bool) {
	salt := quicVersionSalt(version)
	if salt == nil {
		return nil, nil, nil, false
	}
	initial := hkdfExtract(salt, dcid)
	clientSecret := hkdfExpandLabel(initial, "client in", 32)
	return hkdfExpandLabel(clientSecret, "quic key", 16),
		hkdfExpandLabel(clientSecret, "quic iv", 12),
		hkdfExpandLabel(clientSecret, "quic hp", 16),
		true
}

type initialParse struct {
	version    uint32
	dcid       []byte
	scid       []byte
	token      []byte
	pnOffset   int
	payloadLen int
}

func parseInitialPacket(data []byte) (*initialParse, error) {
	if len(data) < 7 || data[0]&0x80 == 0 {
		return nil, errors.New("not long header")
	}
	if data[0]&0x30 != 0 {
		return nil, errors.New("not initial")
	}
	version := binary.BigEndian.Uint32(data[1:5])
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
	return &initialParse{
		version:    version,
		dcid:       append([]byte(nil), dcid...),
		scid:       append([]byte(nil), scid...),
		token:      append([]byte(nil), token...),
		pnOffset:   pnOffset,
		payloadLen: int(payloadLen),
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
	mask := uint64(1<<(8*pnLen)) - 1
	return (expected & ^mask) | truncated
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

func decryptInitial(data []byte, key, iv, hp []byte) (plaintext []byte, pn uint64, err error) {
	pkt, err := parseInitialPacket(data)
	if err != nil {
		return nil, 0, err
	}
	packet := append([]byte(nil), data...)
	pnLen, err := removeHeaderProtection(packet, pkt.pnOffset, hp)
	if err != nil {
		return nil, 0, err
	}
	headerEnd := pkt.pnOffset + pnLen
	if headerEnd+pkt.payloadLen-pnLen > len(packet) {
		return nil, 0, errors.New("short ciphertext")
	}
	pn = decodePacketNumber(packet, pkt.pnOffset, pnLen, 0)
	aad := packet[:headerEnd]
	ciphertext := packet[headerEnd : pkt.pnOffset+pkt.payloadLen]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, 0, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, 0, err
	}
	plaintext, err = aead.Open(nil, quicNonce(iv, pn), ciphertext, aad)
	if err != nil {
		return nil, 0, err
	}
	return plaintext, pn, nil
}

func encryptInitial(version uint32, dcid, scid, token []byte, pn uint64, plaintext []byte, key, iv, hp []byte) ([]byte, error) {
	pnLen := packetNumberLen(pn)
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
	header = append(header, byte(0xc0|byte(pnLen-1)))
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

func countCryptoFrames(frames []byte) int {
	count := 0
	off := 0
	for off < len(frames) {
		frameType := frames[off]
		off++
		switch frameType {
		case 0x00:
			continue
		case 0x06:
			count++
			_, n, err := readVarint(frames[off:])
			if err != nil {
				return count
			}
			off += n
			length, n, err := readVarint(frames[off:])
			if err != nil {
				return count
			}
			off += n
			off += int(length)
		default:
			return count
		}
	}
	return count
}

func extractCryptoStream(frames []byte) ([]byte, error) {
	var stream []byte
	off := 0
	for off < len(frames) {
		frameType := frames[off]
		off++
		switch frameType {
		case 0x00:
			continue
		case 0x06:
			offset, n, err := readVarint(frames[off:])
			if err != nil {
				return nil, err
			}
			off += n
			length, n, err := readVarint(frames[off:])
			if err != nil {
				return nil, err
			}
			off += n
			data := frames[off : off+int(length)]
			off += int(length)
			end := int(offset) + int(length)
			if end > len(stream) {
				ext := make([]byte, end)
				copy(ext, stream)
				stream = ext
			}
			copy(stream[offset:], data)
		default:
			return nil, errors.New("unexpected frame")
		}
	}
	return stream, nil
}

func sniHostNameRange(clientHello []byte) (start, length int, ok bool) {
	if len(clientHello) < 4 || clientHello[0] != 0x01 {
		return 0, 0, false
	}
	pos := 4 + 2 + 32
	if pos >= len(clientHello) {
		return 0, 0, false
	}
	sidLen := int(clientHello[pos])
	pos += 1 + sidLen
	if pos+2 > len(clientHello) {
		return 0, 0, false
	}
	cipherLen := int(binary.BigEndian.Uint16(clientHello[pos : pos+2]))
	pos += 2 + cipherLen
	if pos+1 > len(clientHello) {
		return 0, 0, false
	}
	compLen := int(clientHello[pos])
	pos += 1 + compLen
	if pos+2 > len(clientHello) {
		return 0, 0, false
	}
	extLen := int(binary.BigEndian.Uint16(clientHello[pos : pos+2]))
	pos += 2
	extEnd := pos + extLen
	if extEnd > len(clientHello) {
		return 0, 0, false
	}
	for pos+4 <= extEnd {
		extType := binary.BigEndian.Uint16(clientHello[pos : pos+2])
		extDataLen := int(binary.BigEndian.Uint16(clientHello[pos+2 : pos+4]))
		pos += 4
		if pos+extDataLen > extEnd {
			return 0, 0, false
		}
		if extType == 0x0000 && extDataLen >= 5 {
			nameLen := int(binary.BigEndian.Uint16(clientHello[pos+3 : pos+5]))
			nameStart := pos + 5
			if nameStart+nameLen <= pos+extDataLen && nameLen > 0 {
				return nameStart, nameLen, true
			}
			return 0, 0, false
		}
		pos += extDataLen
	}
	return 0, 0, false
}

func getIETFQUICSNI(b []byte) string {
	if GetQUICVersion(b) == 0 {
		return ""
	}
	pkt, err := parseInitialPacket(b)
	if err != nil {
		return ""
	}
	key, iv, hp, ok := quicInitialSecrets(pkt.version, pkt.dcid)
	if !ok {
		return ""
	}
	plain, _, err := decryptInitial(b, key, iv, hp)
	if err != nil {
		return ""
	}
	stream, err := extractCryptoStream(plain)
	if err != nil || len(stream) == 0 || stream[0] != 0x01 {
		return ""
	}
	start, length, ok := sniHostNameRange(stream)
	if !ok {
		return ""
	}
	return string(stream[start : start+length])
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
	if (data[0] & 0x30) != 0 {
		return quicVersionNone
	}
	version := binary.BigEndian.Uint32(data[1:5])
	switch version {
	case quicVersion1, quicVersionDraft29, quicVersion2:
		return version
	}
	switch string(data[1:5]) {
	case "Q046", "Q050":
		return quicVersionGoogle
	}
	return quicVersionNone
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
	var frame []byte
	frame = append(frame, 0x06)
	frame = append(frame, writeVarint(offset)...)
	frame = append(frame, writeVarint(uint64(len(data)))...)
	frame = append(frame, data...)
	return frame
}

func FragmentQUICInitial(data []byte) [][]byte {
	pkts := [][]byte{data}
	if GetQUICVersion(data) == 0 {
		return pkts
	}
	pkt, err := parseInitialPacket(data)
	if err != nil {
		return pkts
	}
	key, iv, hp, ok := quicInitialSecrets(pkt.version, pkt.dcid)
	if !ok {
		return pkts
	}
	plaintext, pn, err := decryptInitial(data, key, iv, hp)
	if err != nil {
		return pkts
	}
	if countCryptoFrames(plaintext) >= 2 {
		return pkts
	}
	stream, err := extractCryptoStream(plaintext)
	if err != nil {
		return pkts
	}
	start, length, ok := sniHostNameRange(stream)
	if !ok || length <= 1 {
		return pkts
	}
	split := start + length/2
	if split <= 0 || split >= len(stream) {
		return pkts
	}
	first, err := encryptInitial(pkt.version, pkt.dcid, pkt.scid, pkt.token, pn, buildCryptoFrame(0, stream[:split]), key, iv, hp)
	if err != nil {
		return pkts
	}
	second, err := encryptInitial(pkt.version, pkt.dcid, pkt.scid, pkt.token, pn+1, buildCryptoFrame(uint64(split), stream[split:]), key, iv, hp)
	if err != nil {
		return pkts
	}
	return [][]byte{first, second}
}

func WriteQUICInitial(conn net.Conn, data []byte, outbound *Outbound) error {
	pkts := [][]byte{data}
	if outbound != nil && outbound.Hint&HINT_HTTP3 != 0 && GetQUICVersion(data) != 0 {
		pkts = FragmentQUICInitial(data)
	}
	if outbound != nil && outbound.Hint&HINT_REVERSE != 0 {
		for i := len(pkts) - 1; i >= 0; i-- {
			if _, err := conn.Write(pkts[i]); err != nil {
				return err
			}
		}
		return nil
	}
	for _, pkt := range pkts {
		if _, err := conn.Write(pkt); err != nil {
			return err
		}
	}
	return nil
}
