package proxy

import (
	"bytes"
	"net"
	"net/url"
	"os"
	"syscall"
	"time"
)

var SystemProxy string = ""

func SetProxy(dev, address string, state bool) error {
	u, err := url.Parse(address)
	if err != nil {
		return err
	}

	if state {
		SystemProxy = address
		switch u.Scheme {
		case "dns":
			go func(nameserver, path string) {
				resolv_content := []byte("nameserver " + nameserver)
				for SystemProxy != "" {
					content, err := os.ReadFile(path)
					if err == nil && !bytes.Equal(content, resolv_content) {
						os.WriteFile(path, resolv_content, 0644)
					}
					time.Sleep(time.Second * 10)
				}
			}(u.Host, u.Path)
		}
	} else {
		SystemProxy = ""
	}

	return nil
}

func SetKeepAlive(conn net.Conn) error {
	f, err := conn.(*net.TCPConn).File()
	if err != nil {
		return err
	}
	defer f.Close()
	fd := int(f.Fd())
	err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1)
	if err != nil {
		return err
	}
	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_KEEPIDLE, 10)
	if err != nil {
		return err
	}
	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_KEEPCNT, 3)
	if err != nil {
		return err
	}
	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_KEEPINTVL, 5)
	if err != nil {
		return err
	}
	return nil
}

func InstallService() {
}

func RemoveService() {
}

func StartService() {
}

func StopService() {
}

func RunAsService(start func()) bool {
	return false
}
