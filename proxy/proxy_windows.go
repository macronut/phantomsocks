package proxy

import (
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/chai2010/winsvc"
	"golang.org/x/sys/windows/registry"

	ptcp "github.com/macronut/phantomsocks/phantomtcp"
)

func SetProxy(dev, address string, state bool) error {
	u, err := url.Parse(address)
	if err != nil {
		return err
	}

	if state {
		switch u.Scheme {
		case "redirect":
			if state {
				proxyTCPAddr, err := net.ResolveTCPAddr("tcp", u.Host)
				if err != nil {
					return err
				}

				go ptcp.Redirect(proxyTCPAddr.IP.String(), proxyTCPAddr.Port, true)
				go ptcp.RedirectDNS()
			}

			arg := []string{"/flushdns"}
			cmd := exec.Command("ipconfig", arg...)
			_, err := cmd.CombinedOutput()
			if err != nil {
				return err
			}
		case "socks":
			proxyTCPAddr, err := net.ResolveTCPAddr("tcp", u.Host)
			if err != nil {
				return err
			}
			key, _, _ := registry.CreateKey(registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.ALL_ACCESS)
			key.SetStringValue(`ProxyServer`, "socks="+u.Host)
			key.SetDWordValue(`ProxyEnable`, uint32(1))
			defer key.Close()

			q := u.Query()
			ifs, ok := q["if"]
			if ok {
				for _, netif := range ifs {
					arg := []string{"interface", "ip", "set", "dnsservers", netif, "static", proxyTCPAddr.IP.String(), "primary"}
					cmd := exec.Command("netsh", arg...)
					_, err := cmd.CombinedOutput()
					if err != nil {
						return err
					}
				}
			}
		case "dns":
			q := u.Query()
			ifs, ok := q["if"]
			if ok {
				for _, netif := range ifs {
					arg := []string{"interface", "ip", "set", "dnsservers", netif, "static", u.Host, "primary"}
					cmd := exec.Command("netsh", arg...)
					_, err := cmd.CombinedOutput()
					if err != nil {
						return err
					}
				}
			}
			arg := []string{"/flushdns"}
			cmd := exec.Command("ipconfig", arg...)
			_, err := cmd.CombinedOutput()
			if err != nil {
				return err
			}
		default:
			return nil
		}
	} else {
		switch u.Scheme {
		case "socks":
			key, _, _ := registry.CreateKey(registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.ALL_ACCESS)
			key.SetDWordValue(`ProxyEnable`, uint32(0))
			defer key.Close()

			q := u.Query()
			ifs, ok := q["if"]
			if ok {
				for _, netinterface := range ifs {
					arg := []string{"interface", "ip", "set", "dnsservers", netinterface, "dhcp"}
					cmd := exec.Command("netsh", arg...)
					_, err := cmd.CombinedOutput()
					if err != nil {
						return err
					}
				}
			}
		case "dns":
			q := u.Query()
			ifs, ok := q["if"]
			if ok {
				for _, netif := range ifs {
					arg := []string{"interface", "ip", "set", "dnsservers", netif, "dhcp"}
					cmd := exec.Command("netsh", arg...)
					_, err := cmd.CombinedOutput()
					if err != nil {
						return err
					}
				}
			}
		default:
			return nil
		}
	}

	return nil
}

func SetKeepAlive(conn net.Conn) error {
	return nil
}

var ServiceName string = "PhantomSocks"

func InstallService() {
	appPath, err := winsvc.GetAppPath()
	log.Println("Installing", appPath)
	if err != nil {
		log.Fatal(err)
	}
	if err := winsvc.InstallService(appPath, ServiceName, ""); err != nil {
		log.Fatalf("installService(%s, %s): %v\n", ServiceName, "", err)
	}
	log.Printf(ServiceName, "installed\n")
}

func RemoveService() {
	if err := winsvc.RemoveService(ServiceName); err != nil {
		log.Fatalln("removeService:", err)
	}
	log.Printf(ServiceName, "removed\n")
}

func StartService() {
	if err := winsvc.StartService(ServiceName); err != nil {
		log.Fatalln("startService:", err)
	}
	log.Printf(ServiceName, "started\n")
}

func StopService() {
	if err := winsvc.StopService(ServiceName); err != nil {
		log.Fatalln("stopService:", err)
	}
	log.Printf(ServiceName, "stopped\n")
}

func RunAsService(start func()) bool {
	if !winsvc.IsAnInteractiveSession() {
		log.Println("main:", "runService")

		appPath, err := winsvc.GetAppPath()
		if err != nil {
			log.Fatal(err)
		}

		if err := os.Chdir(filepath.Dir(appPath)); err != nil {
			log.Fatal(err)
		}

		stop := func() {
			arg := []string{"/flushdns"}
			cmd := exec.Command("ipconfig", arg...)
			d, err := cmd.CombinedOutput()
			if err != nil {
				log.Println(string(d), err)
			}

			os.Exit(0)
		}

		if err := winsvc.RunAsService(ServiceName, start, stop, false); err != nil {
			log.Fatalf("svc.Run: %v\n", err)
		}
		return true
	}

	return false
}
