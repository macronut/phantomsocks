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

	var ServiceConfig struct {
		VirtualAddrPrefix int    `json:"vaddrprefix,omitempty"`
		SystemProxy       string `json:"proxy,omitempty"`
		HostsFile         string `json:"hosts,omitempty"`

		Clients    []string               `json:"clients,omitempty"`
		Profiles   []string               `json:"profiles,omitempty"`
		Services   []ptcp.ServiceConfig   `json:"services,omitempty"`
		Interfaces []ptcp.InterfaceConfig `json:"interfaces,omitempty"`
	}

	err = json.Unmarshal(bytes, &ServiceConfig)
	if err != nil {
		log.Panic(err)
	}

	if MaxProcs > 0 {
		runtime.GOMAXPROCS(MaxProcs)
	}

	ptcp.LogLevel = LogLevel
	ptcp.PassiveMode = PassiveMode
	devices := ptcp.CreateInterfaces(ServiceConfig.Interfaces)

	for _, filename := range ServiceConfig.Profiles {
		err := ptcp.LoadProfile(filename)
		if err != nil {
			if ptcp.LogLevel > 0 {
				log.Println(err)
			}
			return
		}
	}

	if ServiceConfig.HostsFile != "" {
		err := ptcp.LoadHosts(ServiceConfig.HostsFile)
		if err != nil {
			if ptcp.LogLevel > 0 {
				log.Println(err)
			}
			return
		}
	}

	if len(ServiceConfig.Clients) > 0 {
		allowlist = make(map[string]bool)
		list := ServiceConfig.Clients
		for _, c := range list {
			allowlist[c] = true
		}
	}

	default_proxy := ""
	for _, service := range ServiceConfig.Services {
		switch service.Protocol {
		case "dns":
			fmt.Println("DNS:", service.Address)
			go func(addr string) {
				err := ptcp.DNSServer(addr)
				if err != nil {
					fmt.Println("DNS:", err)
				}
			}(service.Address)
			go ListenAndServe(service.Address, "", ptcp.DNSTCPServer)
		case "doh":
			go func(addr string, certs []string) {
				fmt.Println("DoH:", addr)
				http.HandleFunc("/dns-query", ptcp.DoHServer)
				err := http.ListenAndServeTLS(addr, certs[0], certs[1], nil)
				if err != nil {
					fmt.Println("DoH:", err)
				}
			}(service.Address, strings.Split(service.PrivateKey, ","))
		case "http":
			fmt.Println("HTTP:", service.Address)
			go ListenAndServe(service.Address, service.PrivateKey, ptcp.HTTPProxy)
			default_proxy = "HTTP " + service.Address
		case "socks5":
			fallthrough
		case "socks":
			fmt.Println("Socks:", service.Address)
			go ListenAndServe(service.Address, service.PrivateKey, ptcp.SocksProxy)
			go ptcp.SocksUDPProxy(service.Address)
			default_proxy = strings.ToUpper(service.Protocol) + " " + service.Address
		case "redirect":
			fmt.Println("Redirect:", service.Address)
			go ListenAndServe(service.Address, service.PrivateKey, ptcp.RedirectProxy)
		case "tproxy":
			fmt.Println("TProxy:", service.Address)
			go ptcp.TProxyTCP(service.Address)
			go ptcp.TProxyUDP(service.Address)
		case "tcp":
			fmt.Println("TCP:", service.Address, service.Peers[0].Endpoint)
			var l net.Listener
			keys := strings.Split(service.PrivateKey, ",")
			if len(keys) == 2 {
				var cer tls.Certificate
				cer, err = tls.LoadX509KeyPair(keys[0], keys[1])
				if err == nil {
					config := &tls.Config{Certificates: []tls.Certificate{cer}}
					l, err = tls.Listen("tcp", service.Address, config)
				}
			} else {
				if service.Address[0] == '[' {
					l, err = net.Listen("tcp6", service.Address)
				} else {
					l, err = net.Listen("tcp", service.Address)
				}
			}
			if err != nil {
				log.Println(err)
				continue
			}

			go ptcp.TCPMapping(l, service.Peers)
		case "udp":
			go ptcp.UDPMapping(service.Address, service.Peers[0].Endpoint)
		case "pac":
			if default_proxy != "" {
				go PACServer(service.Address, "", default_proxy)
			}
		case "reverse":
			fmt.Println("Reverse:", service.Address)
			go ListenAndServe(service.Address, service.PrivateKey, ptcp.SNIProxy)
			go ptcp.QUICProxy(service.Address)
		}
	}

	if ServiceConfig.SystemProxy != "" {
		for _, dev := range devices {
			err := proxy.SetProxy(dev, ServiceConfig.SystemProxy, true)
			if err != nil {
				fmt.Println(err)
			}
		}
	}

	if ServiceConfig.VirtualAddrPrefix != 0 {
		ptcp.VirtualAddrPrefix = byte(ServiceConfig.VirtualAddrPrefix)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, os.Kill)
	s := <-c
	fmt.Println(s)

	if ServiceConfig.SystemProxy != "" {
		for _, dev := range devices {
			err := proxy.SetProxy(dev, ServiceConfig.SystemProxy, false)
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
