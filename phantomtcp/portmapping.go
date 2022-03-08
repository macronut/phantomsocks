package phantomtcp

import (
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"
)

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

func UDPMapping(Address, Host string) error {
	client, err := ListenUDP(Address)
	if err != nil {
		log.Println(err)
		return err
	}
	defer client.Close()

	logPrintln(1, "UDPMapping:", Address, Host)

	var UDPLock sync.Mutex
	var UDPMap map[string]net.Conn
	UDPMap = make(map[string]net.Conn)
	data := make([]byte, 1500)

	for {
		n, clientAddr, err := client.ReadFromUDP(data)
		if err != nil {
			log.Println(err)
			return err
		}

		udpConn, ok := UDPMap[clientAddr.String()]

		if ok {
			udpConn.Write(data[:n])
		} else {
			if len(Host) > 0 {
				_host := strings.SplitN(Host, "@", 2)
				if len(_host) == 2 {
					str_laddr, err := GetAddressFromInterface(_host[1], IsIPv6(_host[0]))
					if err != nil {
						log.Println(err)
						continue
					}
					laddr, err := net.ResolveUDPAddr("udp", str_laddr+":0")
					if err != nil {
						log.Println(err)
						continue
					}
					raddr, err := net.ResolveUDPAddr("udp", _host[0])
					if err != nil {
						log.Println(err)
						continue
					}

					laddr.Port = raddr.Port

					logPrintln(1, "[UDP]", clientAddr.String(), _host[0], str_laddr)

					udpConn, err = net.DialUDP("udp", laddr, raddr)
				} else {
					logPrintln(1, "[UDP]", clientAddr.String(), Host)

					udpConn, err = net.Dial("udp", Host)
				}

				if err != nil {
					log.Println(err)
					continue
				}

				UDPMap[clientAddr.String()] = udpConn
				_, err = udpConn.Write(data[:n])
				if err != nil {
					log.Println(err)
					continue
				}

				go func(clientAddr net.UDPAddr) {
					data := make([]byte, 1500)
					udpConn.SetReadDeadline(time.Now().Add(time.Minute * 2))
					for {
						n, err := udpConn.Read(data)
						if err != nil {
							UDPLock.Lock()
							delete(UDPMap, clientAddr.String())
							UDPLock.Unlock()
							udpConn.Close()

							return
						}
						udpConn.SetReadDeadline(time.Now().Add(time.Minute * 2))
						client.WriteToUDP(data[:n], &clientAddr)
					}
				}(*clientAddr)
			}
		}
	}
}

func TCPMapping(Address string, Hosts string) error {
	serverAddr, err := net.ResolveTCPAddr("tcp", Address)
	if err != nil {
		log.Println(err)
		return err
	}

	var l *net.TCPListener
	if Address[0] == '[' {
		l, err = net.ListenTCP("tcp6", serverAddr)
	} else {
		l, err = net.ListenTCP("tcp", serverAddr)
	}

	if err != nil {
		log.Println(err)
		return err
	}
	defer l.Close()

	logPrintln(1, "TCPMapping:", Address, Hosts)

	HostList := strings.Split(Hosts, ",")

	for {
		client, err := l.AcceptTCP()
		if err != nil {
			log.Println(err)
			return err
		}

		Host := HostList[rand.Intn(len(HostList))]

		logPrintln(3, "[TCP]", client.RemoteAddr().String(), Host)

		go func() {
			remote, err := net.Dial("tcp", Host)
			if err != nil {
				fmt.Println(err)
				return
			}

			go io.Copy(client, remote)
			_, err = io.Copy(remote, client)
			if err != nil {
				fmt.Println(err)
				return
			}
		}()
	}
}
