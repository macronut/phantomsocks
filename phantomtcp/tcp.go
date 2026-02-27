package phantomtcp

import (
	"io"
	"net"
	"os"
	"crypto/rand"
	"strconv"
	"syscall"
	mathrand "math/rand"
)

const domainBytes = "abcdefghijklmnopqrstuvwxyz0123456789-"

func IsAddressInUse(err error) bool {
	//return errors.Is(err, syscall.EADDRINUSE)
	errOpError, ok := err.(*net.OpError)
	if !ok {
		return false
	}
	errSyscallError, ok := errOpError.Err.(*os.SyscallError)
	if !ok {
		return false
	}
	errErrno, ok := errSyscallError.Err.(syscall.Errno)
	if !ok {
		return false
	}
	if errErrno == syscall.EADDRINUSE {
		return true
	}
	return false
}

func IsNormalError(err error) bool {
	errOpError, ok := err.(*net.OpError)
	if !ok {
		return false
	}
	switch e := errOpError.Err.(type) {
	case *os.SyscallError:
		errErrno, ok := e.Err.(syscall.Errno)
		if !ok {
			return false
		}

		if errErrno == syscall.ETIMEDOUT ||
			errErrno == syscall.ECONNREFUSED ||
			errErrno == syscall.ECONNRESET {
			return true
		}
	default:
		//logPrintln(2, reflect.TypeOf(e))
		return true
	}

	return false
}

func GetLocalTCPAddr(name string, ipv6 bool) (*net.TCPAddr, error) {
	if name == "" {
		return nil, nil
	}

	inf, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	addrs, _ := inf.Addrs()
	for _, addr := range addrs {
		localAddr, ok := addr.(*net.IPNet)
		if ok {
			var laddr *net.TCPAddr
			ip4 := localAddr.IP.To4()
			if ipv6 {
				if ip4 != nil || localAddr.IP.IsPrivate() {
					continue
				}
				ip := make([]byte, 16)
				copy(ip[:16], localAddr.IP)
				laddr = &net.TCPAddr{IP: ip[:], Port: 0}
			} else {
				if ip4 == nil {
					continue
				}
				ip := make([]byte, 4)
				copy(ip[:4], ip4)
				laddr = &net.TCPAddr{IP: ip[:], Port: 0}
			}

			return laddr, nil
		}
	}

	return nil, nil
}

func (outbound *Outbound) GetRemoteAddresses(host string, port int) ([]*net.TCPAddr, error) {
	switch outbound.Protocol {
	case DIRECT:
		return outbound.ResolveTCPAddrs(host, port)
	case REDIRECT:
		if outbound.Address != "" {
			var str_port string
			var err error
			host, str_port, err = net.SplitHostPort(outbound.Address)
			if err != nil {
				return nil, err
			}
			port, err = strconv.Atoi(str_port)
			if err != nil {
				return nil, err
			}
		}
		return outbound.ResolveTCPAddrs(host, port)
	case NAT64:
		addrs, err := outbound.ResolveTCPAddrs(host, port)
		if err != nil {
			return nil, err
		}
		tcpAddrs := make([]*net.TCPAddr, len(addrs))
		for i, addr := range addrs {
			proxy := outbound.Address + addr.IP.String()
			tcpAddrs[i] = &net.TCPAddr{IP: net.ParseIP(proxy), Port: port}
		}
		return tcpAddrs, nil
	default:
		host, str_port, err := net.SplitHostPort(outbound.Address)
		if err != nil {
			return nil, err
		}
		port, err := strconv.Atoi(str_port)
		if err != nil {
			return nil, err
		}
		outbound, _ := DefaultProfile.GetOutbound(host)
		return outbound.ResolveTCPAddrs(host, port)
	}
}

func (outbound *Outbound) GetFakePayload(header []byte, offset, length int) ([]byte, int) {
	hint := outbound.Hint
	if offset == 0 {
		length = len(header)
		hint |= HINT_RAND
	}

	fakepaylen := len(header)
	fakepayload := make([]byte, fakepaylen)
	copy(fakepayload, header[:fakepaylen])

	cut := offset + length/2
	if hint&HINT_RAND != 0 {
		if _, err := rand.Read(fakepayload); err != nil {
			logPrintln(1, err)
		}
	} else {
		min_dot := offset + length
		max_dot := offset
		for i := offset; i < offset+length; i++ {
			if fakepayload[i] == '.' {
				if i < min_dot {
					min_dot = i
				}
				if i > max_dot {
					max_dot = i
				}
			} else {
				fakepayload[i] = domainBytes[mathrand.Intn(len(domainBytes))]
			}
		}
		if min_dot == max_dot {
			min_dot = offset
		}

		cut = (min_dot + max_dot) / 2
	}

	return fakepayload, cut
}

func relay(left, right net.Conn) error {
	errch := make(chan error, 2)

	go func() {
		_, err := io.Copy(right, left)
		errch <- err
	}()
	go func() {
		_, err := io.Copy(left, right)
		errch <- err
	}()

	return <-errch
}
