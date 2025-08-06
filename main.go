package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"

	ptcp "github.com/macronut/phantomsocks/phantomtcp"
	proxy "github.com/macronut/phantomsocks/proxy"
)

var ConfigFile string = "config.json"
var LogLevel int = 0
var MaxProcs int = 1
var PassiveMode bool = false
var allowlist map[string]bool = nil

func ListenAndServe(addr string, key string, serve func(net.Conn)) {
	var l net.Listener = nil
	keys := strings.Split(key, ",")
	if len(keys) == 2 {
		cer, err := tls.LoadX509KeyPair(keys[0], keys[1])
		if err != nil {
			fmt.Println("TLS", err)
			return
		}
		config := &tls.Config{Certificates: []tls.Certificate{cer}}
		l, err = tls.Listen("tcp", addr, config)
		if err != nil {
			fmt.Println("TLS:", err)
			return
		}
	} else {
		var err error
		l, err = net.Listen("tcp", addr)
		if err != nil {
			fmt.Println("Serve:", err)
		}
	}

	if allowlist != nil {
		for {
			client, err := l.Accept()
			if err != nil {
				log.Panic(err)
			}
			err = proxy.SetKeepAlive(client)
			if err != nil {
				log.Panic(err)
			}

			remoteAddr := client.RemoteAddr()
			remoteTCPAddr, _ := net.ResolveTCPAddr(remoteAddr.Network(), remoteAddr.String())
			_, ok := allowlist[remoteTCPAddr.IP.String()]
			if ok {
				go serve(client)
			} else {
				client.Close()
			}
		}
	} else {
		for {
			client, err := l.Accept()
			if err != nil {
				log.Panic(err)
			}
			err = proxy.SetKeepAlive(client)
			if err != nil {
				log.Panic(err)
			}

			go serve(client)
		}
	}
}

func PACServer(listenAddr string, profile string, proxyAddr string) {
	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Panic(err)
	}
	pac := ptcp.GetPAC(proxyAddr, profile)
	response := []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length:%d\r\n\r\n%s", len(pac), pac))
	fmt.Println("PACServer:", listenAddr)
	for {
		client, err := l.Accept()
		if err != nil {
			log.Panic(err)
		}

		go func() {
			defer client.Close()
			var b [1024]byte
			_, err := client.Read(b[:])
			if err != nil {
				return
			}
			_, err = client.Write(response)
			if err != nil {
				return
			}
		}()
	}
}

func StartService() {
	conf, err := os.Open(ConfigFile)
	if err != nil {
		fmt.Println(err)
		return
	}

	bytes, err := io.ReadAll(conf)
	if err != nil {
		log.Panic(err)
	}
	conf.Close()

	var ProxyConfig struct {
		VirtualAddrPrefix int    `json:"vaddrprefix,omitempty"`
		SystemProxy       string `json:"proxy,omitempty"`
		HostsFile         string `json:"hosts,omitempty"`

		Clients   []string              `json:"clients,omitempty"`
		Profiles  []string              `json:"profiles,omitempty"`
		Inbounds  []ptcp.InboundConfig  `json:"inbounds,omitempty"`
		Outbounds []ptcp.OutboundConfig `json:"outbounds,omitempty"`
	}

	err = json.Unmarshal(bytes, &ProxyConfig)
	if err != nil {
		log.Panic(err)
	}

	if MaxProcs > 0 {
		runtime.GOMAXPROCS(MaxProcs)
	}

	ptcp.LogLevel = LogLevel
	ptcp.PassiveMode = PassiveMode
	devices := ptcp.CreateOutbounds(ProxyConfig.Outbounds)

	for _, filename := range ProxyConfig.Profiles {
		err := ptcp.LoadProfile(filename)
		if err != nil {
			if ptcp.LogLevel > 0 {
				log.Println(err)
			}
			return
		}
	}

	if ProxyConfig.HostsFile != "" {
		err := ptcp.LoadHosts(ProxyConfig.HostsFile)
		if err != nil {
			if ptcp.LogLevel > 0 {
				log.Println(err)
			}
			return
		}
	}

	if len(ProxyConfig.Clients) > 0 {
		allowlist = make(map[string]bool)
		list := ProxyConfig.Clients
		for _, c := range list {
			allowlist[c] = true
		}
	}

	default_proxy := ""
	for _, inbound := range ProxyConfig.Inbounds {
		switch inbound.Protocol {
		case "dns":
			fmt.Println("DNS:", inbound.Address)
			go func(addr string) {
				err := ptcp.DNSServer(addr)
				if err != nil {
					fmt.Println("DNS:", err)
				}
			}(inbound.Address)
			go ListenAndServe(inbound.Address, "", ptcp.DNSTCPServer)
		case "doh":
			go func(addr string, certs []string) {
				fmt.Println("DoH:", addr)
				http.HandleFunc("/dns-query", ptcp.DoHServer)
				err := http.ListenAndServeTLS(addr, certs[0], certs[1], nil)
				if err != nil {
					fmt.Println("DoH:", err)
				}
			}(inbound.Address, strings.Split(inbound.PrivateKey, ","))
		case "http":
			fmt.Println("HTTP:", inbound.Address)
			go ListenAndServe(inbound.Address, inbound.PrivateKey, ptcp.HTTPProxy)
			default_proxy = "HTTP " + inbound.Address
		case "socks5":
			fallthrough
		case "socks":
			fmt.Println("Socks:", inbound.Address)
			go ListenAndServe(inbound.Address, inbound.PrivateKey, ptcp.SocksProxy)
			go ptcp.SocksUDPProxy(inbound.Address)
			default_proxy = strings.ToUpper(inbound.Protocol) + " " + inbound.Address
		case "redirect":
			fmt.Println("Redirect:", inbound.Address)
			go ptcp.RedirectTCP(inbound.Address)
			go ptcp.RedirectUDP(inbound.Address)
		case "tproxy":
			fmt.Println("TProxy:", inbound.Address)
			go ptcp.TProxyTCP(inbound.Address)
			go ptcp.TProxyUDP(inbound.Address)
		case "tcp":
			fmt.Println("TCP:", inbound.Address, inbound.Peers[0].Endpoint)
			var l net.Listener
			keys := strings.Split(inbound.PrivateKey, ",")
			if len(keys) == 2 {
				var cer tls.Certificate
				cer, err = tls.LoadX509KeyPair(keys[0], keys[1])
				if err == nil {
					config := &tls.Config{Certificates: []tls.Certificate{cer}}
					l, err = tls.Listen("tcp", inbound.Address, config)
				}
			} else {
				if inbound.Address[0] == '[' {
					l, err = net.Listen("tcp6", inbound.Address)
				} else {
					l, err = net.Listen("tcp", inbound.Address)
				}
			}
			if err != nil {
				log.Println(err)
				continue
			}

			go ptcp.TCPMapping(l, inbound.Peers)
		case "udp":
			go ptcp.UDPMapping(inbound.Address, inbound.Peers[0].Endpoint)
		case "pac":
			if default_proxy != "" {
				go PACServer(inbound.Address, "", default_proxy)
			}
		case "reverse":
			fmt.Println("Reverse:", inbound.Address)
			go ListenAndServe(inbound.Address, inbound.PrivateKey, ptcp.SNIProxy)
			go ptcp.QUICProxy(inbound.Address)
		}
	}

	if ProxyConfig.SystemProxy != "" {
		for _, dev := range devices {
			err := proxy.SetProxy(dev, ProxyConfig.SystemProxy, true)
			if err != nil {
				fmt.Println(err)
			}
		}
	}

	if ProxyConfig.VirtualAddrPrefix != 0 {
		ptcp.VirtualAddrPrefix = byte(ProxyConfig.VirtualAddrPrefix)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, os.Kill)
	s := <-c
	fmt.Println(s)

	if ProxyConfig.SystemProxy != "" {
		for _, dev := range devices {
			err := proxy.SetProxy(dev, ProxyConfig.SystemProxy, false)
			if err != nil {
				fmt.Println(err)
			}
		}
	}
}

func main() {
	//log.SetFlags(log.LstdFlags | log.Lshortfile)

	var flagServiceInstall bool
	var flagServiceRemove bool
	var flagServiceStart bool
	var flagServiceStop bool

	if len(os.Args) > 1 {
		flag.StringVar(&ConfigFile, "c", "config.json", "Config file")
		flag.IntVar(&LogLevel, "log", 0, "Log level")
		flag.IntVar(&MaxProcs, "maxprocs", 0, "Max processes")
		flag.BoolVar(&PassiveMode, "passive", false, "Passive mode")
		flag.BoolVar(&flagServiceInstall, "install", false, "Install service")
		flag.BoolVar(&flagServiceRemove, "remove", false, "Remove service")
		flag.BoolVar(&flagServiceStart, "start", false, "Start service")
		flag.BoolVar(&flagServiceStop, "stop", false, "Stop service")
		flag.Parse()

		if flagServiceInstall {
			proxy.InstallService()
			return
		}

		if flagServiceRemove {
			proxy.RemoveService()
			return
		}

		if flagServiceStart {
			proxy.StartService()
			return
		}

		if flagServiceStop {
			proxy.StopService()
			return
		}
	} else {
		if proxy.RunAsService(StartService) {
			return
		}
	}

	StartService()
}
