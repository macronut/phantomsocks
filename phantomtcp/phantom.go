package phantomtcp

import (
	"bufio"
	"bytes"
	"container/list"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
)

type PhantomServer struct {
	Option uint32
	TTL    byte
	MAXTTL byte
	MSS    uint16
	Server string
	Device string
}

var DomainMap map[string]*PhantomServer
var IpMap map[*net.IPNet]*PhantomServer
var ipList list.List

var SubdomainDepth = 2
var LogLevel = 0
var Forward bool = false

const (
	OPT_NONE  = 0x0
	OPT_TTL   = 0x1 << 0
	OPT_MSS   = 0x1 << 1
	OPT_WMD5  = 0x1 << 2
	OPT_NACK  = 0x1 << 3
	OPT_WACK  = 0x1 << 4
	OPT_WCSUM = 0x1 << 5
	OPT_WSEQ  = 0x1 << 6
	OPT_WTIME = 0x1 << 7

	OPT_TFO       = 0x1 << 8
	OPT_HTFO      = 0x1 << 9
	OPT_KEEPALIVE = 0x1 << 10
	OPT_SYNX2     = 0x1 << 11

	OPT_HTTP     = 0x1 << 16
	OPT_HTTPS    = 0x1 << 17
	OPT_MOVE     = 0x1 << 18
	OPT_STRIP    = 0x1 << 19
	OPT_FRONTING = 0x1 << 20
	OPT_IPV4     = 0x1 << 21
	OPT_IPV6     = 0x1 << 22
	OPT_MODE2    = 0x1 << 23
	OPT_DF       = 0x1 << 24
	OPT_SAT      = 0x1 << 25
	OPT_RAND     = 0x1 << 26
	OPT_SSEG     = 0x1 << 27
	OPT_1SEG     = 0x1 << 28

	OPT_PROXY = 0x1 << 31
)

const OPT_FAKE = OPT_TTL | OPT_WMD5 | OPT_NACK | OPT_WACK | OPT_WCSUM | OPT_WSEQ | OPT_WTIME
const OPT_MODIFY = OPT_FAKE | OPT_SSEG | OPT_TFO | OPT_HTFO | OPT_MODE2

var MethodMap = map[string]uint32{
	"none":   OPT_NONE,
	"ttl":    OPT_TTL,
	"mss":    OPT_MSS,
	"w-md5":  OPT_WMD5,
	"n-ack":  OPT_NACK,
	"w-ack":  OPT_WACK,
	"w-csum": OPT_WCSUM,
	"w-seq":  OPT_WSEQ,
	"w-time": OPT_WTIME,

	"tfo":        OPT_TFO,
	"half-tfo":   OPT_HTFO,
	"keep-alive": OPT_KEEPALIVE,
	"synx2":      OPT_SYNX2,

	"http":     OPT_HTTP,
	"https":    OPT_HTTPS,
	"move":     OPT_MOVE,
	"strip":    OPT_STRIP,
	"fronting": OPT_FRONTING,
	"ipv4":     OPT_IPV4,
	"ipv6":     OPT_IPV6,
	"mode2":    OPT_MODE2,
	"df":       OPT_DF,
	"sat":      OPT_SAT,
	"rand":     OPT_RAND,
	"s-seg":    OPT_SSEG,
	"1-seg":    OPT_1SEG,

	"proxy": OPT_PROXY,
}

var Logger *log.Logger

func logPrintln(level int, v ...interface{}) {
	if LogLevel >= level {
		fmt.Println(v...)
	}
}

func ConfigLookup(name string) (PhantomServer, bool) {
	config, ok := DomainMap[name]
	if ok {
		return *config, true
	}

	offset := 0
	for i := 0; i < SubdomainDepth; i++ {
		off := strings.Index(name[offset:], ".")
		if off == -1 {
			break
		}
		offset += off
		config, ok = DomainMap[name[offset:]]
		if ok {
			return *config, true
		}
		offset++
	}

	ip := net.ParseIP(name)
	if ip != nil {
		for i := ipList.Back(); i != nil; i = i.Prev() {
			ipNet := i.Value.(*net.IPNet)
			if ipNet.Contains(ip) {
				return *IpMap[ipNet], true
			}
		}
	}

	return PhantomServer{0, 0, 0, 0, "", ""}, false
}

func GetConfig(name string) (PhantomServer, bool) {
	config, ok := DomainMap[name]
	if ok {
		return *config, true
	}

	return PhantomServer{0, 0, 0, 0, "", ""}, false
}

func GetHost(b []byte) (offset int, length int) {
	offset = bytes.Index(b, []byte("Host: "))
	if offset == -1 {
		return 0, 0
	}
	offset += 6
	length = bytes.Index(b[offset:], []byte("\r\n"))
	if length == -1 {
		return 0, 0
	}

	return
}

func GetSNI(b []byte) (offset int, length int) {
	offset = 11 + 32
	if offset+1 > len(b) {
		return 0, 0
	}
	if b[0] != 0x16 {
		return 0, 0
	}
	Version := binary.BigEndian.Uint16(b[1:3])
	if (Version & 0xFFF8) != 0x0300 {
		return 0, 0
	}
	Length := binary.BigEndian.Uint16(b[3:5])
	if len(b) <= int(Length)-5 {
		return 0, 0
	}
	SessionIDLength := b[offset]
	offset += 1 + int(SessionIDLength)
	if offset+2 > len(b) {
		return 0, 0
	}
	CipherSuitersLength := binary.BigEndian.Uint16(b[offset : offset+2])
	offset += 2 + int(CipherSuitersLength)
	if offset >= len(b) {
		return 0, 0
	}
	CompressionMethodsLenght := b[offset]
	offset += 1 + int(CompressionMethodsLenght)
	if offset+2 > len(b) {
		return 0, 0
	}
	ExtensionsLength := binary.BigEndian.Uint16(b[offset : offset+2])
	offset += 2
	ExtensionsEnd := offset + int(ExtensionsLength)
	if ExtensionsEnd > len(b) {
		return 0, 0
	}
	for offset < ExtensionsEnd {
		ExtensionType := binary.BigEndian.Uint16(b[offset : offset+2])
		offset += 2
		ExtensionLength := binary.BigEndian.Uint16(b[offset : offset+2])
		offset += 2
		if ExtensionType == 0 {
			offset += 2
			offset++
			ServerNameLength := binary.BigEndian.Uint16(b[offset : offset+2])
			offset += 2
			return offset, int(ServerNameLength)
		} else {
			offset += int(ExtensionLength)
		}
	}
	return 0, 0
}

func HttpMove(conn net.Conn, host string, b []byte) bool {
	data := make([]byte, 1460)
	n := 0
	if host == "" {
		copy(data[:], []byte("HTTP/1.1 200 OK"))
		n += 15
	} else if host == "https" {
		copy(data[:], []byte("HTTP/1.1 302 Found\r\nLocation: https://"))
		n += 38

		header := string(b)
		start := strings.Index(header, "Host: ")
		if start < 0 {
			return false
		}
		start += 6
		end := strings.Index(header[start:], "\r\n")
		if end < 0 {
			return false
		}
		end += start
		copy(data[n:], []byte(header[start:end]))
		n += end - start

		start = 4
		end = strings.Index(header[start:], " ")
		if end < 0 {
			return false
		}
		end += start
		copy(data[n:], []byte(header[start:end]))
		n += end - start
	} else {
		copy(data[:], []byte("HTTP/1.1 302 Found\r\nLocation: "))
		n += 30
		copy(data[n:], []byte(host))
		n += len(host)

		start := 4
		if start >= len(b) {
			return false
		}
		header := string(b)
		end := strings.Index(header[start:], " ")
		if end < 0 {
			return false
		}
		end += start
		copy(data[n:], []byte(header[start:end]))
		n += end - start
	}

	copy(data[n:], []byte("\r\nCache-Control: private\r\nServer: pinocchio\r\nContent-Length: 0\r\n\r\n"))
	n += 66
	conn.Write(data[:n])
	return true
}

func DialStrip(host string, fronting string) (*tls.Conn, error) {
	var conf *tls.Config
	if fronting == "" {
		conf = &tls.Config{
			InsecureSkipVerify: true,
		}
	} else {
		conf = &tls.Config{
			ServerName:         fronting,
			InsecureSkipVerify: true,
		}
	}

	conn, err := tls.Dial("tcp", net.JoinHostPort(host, "443"), conf)
	return conn, err
}

func getMyIPv6() net.IP {
	s, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	for _, a := range s {
		strIP := strings.SplitN(a.String(), "/", 2)
		if strIP[1] == "128" && strIP[0] != "::1" {
			ip := net.ParseIP(strIP[0])
			ip4 := ip.To4()
			if ip4 == nil {
				return ip
			}
		}
	}
	return nil
}

func Init() {
	DomainMap = make(map[string]*PhantomServer)
	IpMap = make(map[*net.IPNet]*PhantomServer)
}

func LoadConfig(filename string) error {
	conf, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer conf.Close()

	br := bufio.NewReader(conf)

	var option uint32 = 0
	var minTTL byte = 0
	var maxTTL byte = 0
	var syncMSS uint16 = 0
	server := ""
	device := ""

	DNS = ""

	var CurrentServer *PhantomServer = &PhantomServer{option, minTTL, maxTTL, syncMSS, server, device}

	for {
		line, _, err := br.ReadLine()
		if err == io.EOF {
			break
		}

		if len(line) > 0 {
			if line[0] != '#' {
				l := strings.SplitN(string(line), "#", 2)[0]
				keys := strings.SplitN(l, "=", 2)
				if len(keys) > 1 {
					if keys[0] == "server" {
						logPrintln(2, string(line))
						if DNS == "" {
							DNS = keys[1]
						}
						server = keys[1]

						CurrentServer = &PhantomServer{option, minTTL, maxTTL, syncMSS, server, device}
					} else if keys[0] == "dns-min-ttl" {
						logPrintln(2, string(line))
						ttl, err := strconv.Atoi(keys[1])
						if err != nil {
							log.Println(string(line), err)
							return err
						}
						DNSMinTTL = uint32(ttl)

						CurrentServer = &PhantomServer{option, minTTL, maxTTL, syncMSS, server, device}
					} else if keys[0] == "method" {
						logPrintln(2, string(line))

						option = OPT_NONE
						methods := strings.Split(keys[1], ",")
						for _, m := range methods {
							method, ok := MethodMap[m]
							if ok {
								option |= method
							} else {
								logPrintln(1, "unsupported method: "+m)
							}
						}

						CurrentServer = &PhantomServer{option, minTTL, maxTTL, syncMSS, server, device}
					} else if keys[0] == "ttl" {
						logPrintln(2, string(line))

						ttl, err := strconv.Atoi(keys[1])
						if err != nil {
							log.Println(string(line), err)
							return err
						}
						minTTL = byte(ttl)

						CurrentServer = &PhantomServer{option, minTTL, maxTTL, syncMSS, server, device}
					} else if keys[0] == "mss" {
						logPrintln(2, string(line))

						mss, err := strconv.Atoi(keys[1])
						if err != nil {
							log.Println(string(line), err)
							return err
						}
						syncMSS = uint16(mss)

						CurrentServer = &PhantomServer{option, minTTL, maxTTL, syncMSS, server, device}
					} else if keys[0] == "max-ttl" {
						logPrintln(2, string(line))

						ttl, err := strconv.Atoi(keys[1])
						if err != nil {
							log.Println(string(line), err)
							return err
						}
						maxTTL = byte(ttl)

						CurrentServer = &PhantomServer{option, minTTL, maxTTL, syncMSS, server, device}
					} else if keys[0] == "device" {
						logPrintln(2, string(line))

						if keys[1] == "default" {
							device = ""
						} else {
							device = keys[1]
						}

						CurrentServer = &PhantomServer{option, minTTL, maxTTL, syncMSS, server, device}
					} else if keys[0] == "subdomain" {
						SubdomainDepth, err = strconv.Atoi(keys[1])
						if err != nil {
							log.Println(string(line), err)
							return err
						}
					} else if keys[0] == "tcpmapping" {
						mapping := strings.SplitN(keys[1], ">", 2)
						go TCPMapping(mapping[0], mapping[1])
					} else if keys[0] == "udpmapping" {
						mapping := strings.SplitN(keys[1], ">", 2)
						go UDPMapping(mapping[0], mapping[1])
					} else {
						ip := net.ParseIP(keys[0])
						var RecordA DomainIP
						var RecordAAAA DomainIP
						if strings.HasPrefix(keys[1], "[") {
							result, hasACache := ACache.Load(keys[1][1 : len(keys[1])-1])
							if hasACache {
								RecordA = result.(DomainIP)
							}

							result, hasAAAACache := AAAACache.Load(keys[1][1 : len(keys[1])-1])
							if hasAAAACache {
								RecordAAAA = result.(DomainIP)
							}

							if !(hasACache || hasAAAACache) {
								DomainMap[keys[0]] = CurrentServer
								return nil
							}
						} else {
							index := 0
							if option != 0 {
								index = len(Nose)
								Nose = append(Nose, keys[0])
							}
							RecordA.Index = index
							RecordAAAA.Index = index
							ips := strings.Split(keys[1], ",")
							for i := 0; i < len(ips); i++ {
								ip := net.ParseIP(ips[i])
								if ip == nil {
									log.Println(ips[i], "bad ip")
								}
								DomainMap[ips[i]] = CurrentServer
								ip4 := ip.To4()
								if ip4 != nil {
									RecordA.Addresses = append(RecordA.Addresses, ip4)
								} else {
									RecordAAAA.Addresses = append(RecordAAAA.Addresses, ip)
								}
							}
						}

						if ip == nil {
							DomainMap[keys[0]] = CurrentServer
							ACache.Store(keys[0], RecordA)
							AAAACache.Store(keys[0], RecordAAAA)
							if option&OPT_HTTPS != 0 {
								if option&OPT_IPV6 == 0 {
									HTTPSCache.Store(keys[0], RecordA)
								} else {
									HTTPSCache.Store(keys[0], RecordAAAA)
								}
							} else {
								HTTPSCache.Store(keys[0], DomainIP{0, 0, nil})
							}
						} else {
							DomainMap[ip.String()] = CurrentServer
							ACache.Store(ip.String(), RecordA)
							AAAACache.Store(ip.String(), RecordAAAA)
						}
					}
				} else {
					if strings.Index(keys[0], "/") > 0 {
						_, ipnet, err := net.ParseCIDR(keys[0])
						if err == nil {
							IpMap[ipnet] = CurrentServer
							ipList.PushBack(ipnet)
							DomainMap[ipnet.String()] = CurrentServer
						}
					} else {
						DomainMap[keys[0]] = CurrentServer
					}
				}
			}
		}
	}

	logPrintln(1, filename)

	return nil
}

func LoadHosts(filename string) error {
	hosts, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer hosts.Close()

	br := bufio.NewReader(hosts)

	for {
		line, _, err := br.ReadLine()
		if err == io.EOF {
			break
		}
		if err != nil {
			logPrintln(1, err)
		}

		if len(line) == 0 || line[0] == '#' {
			continue
		}

		k := strings.SplitN(string(line), "\t", 2)
		if len(k) == 2 {
			name := k[1]
			_, ok := ACache.Load(name)
			if ok {
				continue
			}
			_, ok = AAAACache.Load(name)
			if ok {
				continue
			}
			offset := 0
			for i := 0; i < SubdomainDepth; i++ {
				off := strings.Index(name[offset:], ".")
				if off == -1 {
					break
				}
				offset += off
				result, ok := ACache.Load(name[offset:])
				if ok {
					ACache.Store(name, result.(DomainIP))
					continue
				}
				result, ok = AAAACache.Load(name[offset:])
				if ok {
					AAAACache.Store(name, result.(DomainIP))
					continue
				}
				offset++
			}

			conf, ok := ConfigLookup(name)
			index := 0
			if ok && conf.Option != 0 {
				index = len(Nose)
				Nose = append(Nose, name)
			}
			ip := net.ParseIP(k[0])
			if ip == nil {
				fmt.Println(ip, "bad ip address")
				continue
			}
			ip4 := ip.To4()
			if ip4 != nil {
				ACache.Store(name, DomainIP{index, 0, []net.IP{ip4}})
				AAAACache.Store(name, DomainIP{0, 0, nil})
			} else {
				AAAACache.Store(name, DomainIP{index, 0, []net.IP{ip}})
				ACache.Store(name, DomainIP{0, 0, nil})
			}
		}
	}

	return nil
}

func GetPAC(address string) string {
	rule := ""
	for host := range DomainMap {
		rule += fmt.Sprintf("\"%s\":1,\n", host)
	}
	Context := `var proxy = 'SOCKS %s';
var rules = {
%s}
function FindProxyForURL(url, host) {
	if (rules[host] != undefined) {
		return proxy;
	}
	for (var i = 0; i < %d; i++){
		var dot = host.indexOf(".");
		if (dot == -1) {return 'DIRECT';}
		host = host.slice(dot);
		if (rules[host] != undefined) {return proxy;}
		host = host.slice(1);
	}
	return 'DIRECT';
}
`
	return fmt.Sprintf(Context, address, rule, SubdomainDepth)
}
