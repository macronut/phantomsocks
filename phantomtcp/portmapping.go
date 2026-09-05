package phantomtcp

import (
	"errors"
	"io"
	"log"
	"math/rand"
	"net"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

type SocksListenConfig struct {
	ProxyHost string
	ProxyPort int
	User      string
	Password  string
	BindIP    net.IP
	BindPort  int
}

func IsSocksListen(listen string) bool {
	u, err := url.Parse(listen)
	if err != nil {
		return false
	}
	switch u.Scheme {
	case "socks5", "socks":
		return u.Host != ""
	default:
		return false
	}
}

func parseBindAddr(bind string) (net.IP, int, error) {
	if bind == "" {
		return net.IPv4zero, 0, nil
	}
	if strings.HasPrefix(bind, ":") {
		port, err := strconv.Atoi(bind[1:])
		if err != nil {
			return nil, 0, err
		}
		return net.IPv4zero, port, nil
	}
	if !strings.Contains(bind, ":") {
		port, err := strconv.Atoi(bind)
		if err != nil {
			return nil, 0, err
		}
		return net.IPv4zero, port, nil
	}
	host, portStr, err := net.SplitHostPort(bind)
	if err != nil {
		return nil, 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, 0, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, 0, errors.New("invalid bind address")
	}
	return ip, port, nil
}

func ParseSocksListen(listen string) (*SocksListenConfig, error) {
	u, err := url.Parse(listen)
	if err != nil {
		return nil, err
	}
	switch u.Scheme {
	case "socks5", "socks":
	default:
		return nil, errors.New("not a socks listen URL")
	}
	if u.Host == "" {
		return nil, errors.New("missing proxy host")
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	cfg := &SocksListenConfig{
		ProxyHost: host,
		ProxyPort: port,
	}
	if u.User != nil {
		cfg.User = u.User.Username()
		cfg.Password, _ = u.User.Password()
	}
	cfg.BindIP, cfg.BindPort, err = parseBindAddr(u.Query().Get("bind"))
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

func IsIPv6(addr string) bool {
	return addr[0] == '['
}

func GetAddressFromInterface(iface string, ipv6 bool) (string, error) {
	inf, err := net.InterfaceByName(iface)
	if err != nil {
		return "", err
	}

	addr := ""
	addrs, _ := inf.Addrs()
	for _, _addr := range addrs {
		bindaddr, ok := _addr.(*net.IPNet)
		if ok {
			if ipv6 {
				if bindaddr.IP.To4() == nil {
					ip := bindaddr.IP.String()
					if !strings.HasPrefix(ip, "fe80::") {
						addr = "[" + ip + "]"
					}
				}
			} else {
				if bindaddr.IP.To4() != nil {
					addr = bindaddr.IP.String()
				}
			}
		}
	}

	return addr, nil
}

func ListenUDP(address string) (*net.UDPConn, error) {
	_address := strings.SplitN(address, "@", 2)

	addr := _address[0]
	ipv6 := addr[0] == '['

	if len(_address) == 2 {
		iface := _address[1]
		inf, err := net.InterfaceByName(iface)
		if err != nil {
			return nil, err
		}
		addrs, _ := inf.Addrs()

		for _, _addr := range addrs {
			bindaddr, ok := _addr.(*net.IPNet)
			if ok {
				if ipv6 {
					if bindaddr.IP.To4() == nil {
						ip := bindaddr.IP.String()
						if !strings.HasPrefix(ip, "fe80::") {
							port := addr[strings.Index(addr, "]:"):]
							addr = "[" + ip + port
							continue
						}
					}
				} else {
					if bindaddr.IP.To4() != nil {
						port := addr[strings.IndexByte(addr, ':'):]
						addr = bindaddr.IP.String() + port
						continue
					}
				}
			}
		}
	}

	serverAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	var conn *net.UDPConn
	if ipv6 {
		conn, err = net.ListenUDP("udp6", serverAddr)
	} else {
		conn, err = net.ListenUDP("udp", serverAddr)
	}

	return conn, err
}

func DialUDP(address string) (net.Conn, error) {
	_address := strings.SplitN(address, "@", 2)
	if len(_address) == 2 {
		str_laddr, err := GetAddressFromInterface(_address[1], IsIPv6(_address[0]))
		if err != nil {
			return nil, err
		}
		laddr, err := net.ResolveUDPAddr("udp", str_laddr+":0")
		if err != nil {
			return nil, err
		}
		raddr, err := net.ResolveUDPAddr("udp", _address[0])
		if err != nil {
			return nil, err
		}

		return net.DialUDP("udp", laddr, raddr)
	} else {
		return net.Dial("udp", address)
	}
}

func DialTCP(address string, device string) (net.Conn, error) {
	if device == "" {
		return net.Dial("tcp", address)
	} else {
		str_laddr, err := GetAddressFromInterface(device, IsIPv6(address))
		if err != nil {
			return nil, err
		}
		laddr, err := net.ResolveTCPAddr("tcp", str_laddr+":0")
		if err != nil {
			return nil, err
		}
		raddr, err := net.ResolveTCPAddr("tcp", address)
		if err != nil {
			return nil, err
		}
		return net.DialTCP("tcp", laddr, raddr)
	}
}

func parseAddresses(list string) []string {
	var addresses []string
	for _, addr := range strings.Split(list, ",") {
		if addr != "" {
			addresses = append(addresses, addr)
		}
	}
	return addresses
}

func UDPMapping(Address string, Target string) error {
	addresses := parseAddresses(Target)
	if len(addresses) == 0 {
		return nil
	}
	Target = addresses[0]

	logPrintln(1, "UDPMapping:", Address, Target)

	localPort, err := strconv.Atoi(Address)
	if err == nil {
		serverAddr := net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: localPort, Zone: ""}
		localConn, err := net.ListenUDP("udp", &serverAddr)
		if err != nil {
			return err
		}

		var SrcAddr *net.UDPAddr = nil
		conn, err := DialUDP(Target)
		if err != nil {
			return err
		}

		go func(raddr **net.UDPAddr, conn net.Conn) {
			data := make([]byte, 1500)
			for {
				n, err := conn.Read(data)
				if err != nil {
					log.Println(err)
					continue
				}
				if *raddr != nil {
					localConn.WriteToUDP(data[:n], *raddr)
				}
			}
		}(&SrcAddr, conn)

		data := make([]byte, 1500)
		for {
			var n int
			n, SrcAddr, err = localConn.ReadFromUDP(data)
			if err != nil {
				SrcAddr = nil
				logPrintln(1, err)
				continue
			}
			conn.Write(data[:n])
		}
	} else {
		localConn, err := ListenUDP(Address)
		if err != nil {
			log.Println(err)
			return err
		}
		defer localConn.Close()

		var UDPLock sync.Mutex
		var UDPMap map[string]net.Conn = make(map[string]net.Conn)
		data := make([]byte, 1500)

		for {
			n, clientAddr, err := localConn.ReadFromUDP(data)
			if err != nil {
				logPrintln(1, err)
				continue
			}

			UDPLock.Lock()
			udpConn, ok := UDPMap[clientAddr.String()]

			if ok {
				udpConn.Write(data[:n])
				UDPLock.Unlock()
			} else {
				logPrintln(1, "[UDP]", clientAddr.String(), Target)
				UDPLock.Unlock()
				remoteConn, err := DialUDP(Target)
				if err != nil {
					log.Println(err)
					continue
				}
				UDPLock.Lock()
				UDPMap[clientAddr.String()] = remoteConn
				_, err = remoteConn.Write(data[:n])
				UDPLock.Unlock()
				if err != nil {
					logPrintln(1, err)
					continue
				}

				go func(clientAddr net.UDPAddr, remoteConn net.Conn) {
					data := make([]byte, 1500)
					remoteConn.SetReadDeadline(time.Now().Add(time.Minute * 2))
					for {
						n, err := remoteConn.Read(data)
						if err != nil {
							UDPLock.Lock()
							delete(UDPMap, clientAddr.String())
							UDPLock.Unlock()
							remoteConn.Close()
							return
						}
						remoteConn.SetReadDeadline(time.Now().Add(time.Minute * 2))
						localConn.WriteToUDP(data[:n], &clientAddr)
					}
				}(*clientAddr, remoteConn)
			}
		}
	}
}

func tcpMappingRelay(incoming net.Conn, address string, script string) {
	defer incoming.Close()

	if script != "" {
		args := strings.Fields(script)
		cmd := exec.Command(args[0])
		cmd.Args = args
		out, err := cmd.CombinedOutput()
		if err != nil {
			logPrintln(0, err, cmd, string(out))
			return
		}
	}

	remote, err := net.Dial("tcp", address)
	if err != nil {
		logPrintln(1, err)
		return
	}
	defer remote.Close()

	go io.Copy(remote, incoming)
	_, err = io.Copy(incoming, remote)
	if err != nil {
		return
	}
}

func TCPMapping(Listen string, Address string, Script string) error {
	addresses := parseAddresses(Address)
	if len(addresses) == 0 {
		return nil
	}

	if IsSocksListen(Listen) {
		cfg, err := ParseSocksListen(Listen)
		if err != nil {
			return err
		}

		for {
			ctrl, bnd, err := DialTCPBind(cfg)
			if err != nil {
				return err
			}

			logPrintln(1, "[TCP-BIND]", bnd, "waiting")

			peer, err := SocksBindWaitInbound(ctrl)
			if err != nil {
				ctrl.Close()
				return err
			}

			address := addresses[rand.Intn(len(addresses))]
			logPrintln(3, "[TCP-BIND]", peer, "->", address)
			go tcpMappingRelay(ctrl, address, Script)
		}
	}

	var listener net.Listener
	var err error
	if Listen[0] == '[' {
		listener, err = net.Listen("tcp6", Listen)
	} else {
		listener, err = net.Listen("tcp", Listen)
	}
	if err != nil {
		return err
	}
	defer listener.Close()

	for {
		client, err := listener.Accept()
		if err != nil {
			log.Println(err)
			return err
		}

		address := addresses[rand.Intn(len(addresses))]
		logPrintln(3, "[TCP]", client.RemoteAddr().String(), address)
		go tcpMappingRelay(client, address, Script)
	}
}
