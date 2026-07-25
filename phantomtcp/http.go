package phantomtcp

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
)

type aheadConn struct {
	net.Conn
	ahead []byte
	off   int
}

func (c *aheadConn) Read(b []byte) (int, error) {
	if c.off < len(c.ahead) {
		n := copy(b, c.ahead[c.off:])
		c.off += n
		return n, nil
	}
	return c.Conn.Read(b)
}

func parseHTTPProxy(conn net.Conn, initial []byte) (header []byte, client net.Conn, err error) {
	br := bufio.NewReader(io.MultiReader(bytes.NewReader(initial), conn))
	req, err := http.ReadRequest(br)
	if err != nil {
		return nil, nil, err
	}

	body, err := io.ReadAll(req.Body)
	req.Body.Close()
	if err != nil {
		return nil, nil, err
	}
	req.Body = io.NopCloser(bytes.NewReader(body))

	if req.URL == nil || !req.URL.IsAbs() || req.URL.Scheme != "http" {
		return nil, nil, errors.New("bad request")
	}

	if req.Host == "" {
		req.Host = req.URL.Host
	}
	req.RequestURI = ""
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Proxy-Authenticate")
	req.Header.Del("Keep-Alive")
	req.Header.Del("TE")
	req.Header.Del("Trailer")
	req.Header.Del("Transfer-Encoding")
	if !strings.EqualFold(req.Header.Get("Connection"), "upgrade") ||
		!strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		req.Header.Del("Connection")
	}

	var buf bytes.Buffer
	if err = req.Write(&buf); err != nil {
		return nil, nil, err
	}

	leftover := readLeftover(br)
	return buf.Bytes(), &aheadConn{Conn: conn, ahead: leftover}, nil
}

func readLeftover(br *bufio.Reader) []byte {
	if n := br.Buffered(); n > 0 {
		rest := make([]byte, n)
		br.Read(rest)
		return rest
	}
	return nil
}

func HTTPProxy(client net.Conn) {
	defer client.Close()

	var b [1500]byte
	n, err := client.Read(b[:])
	if err != nil {
		logPrintln(1, client.RemoteAddr(), err)
		return
	}

	end := bytes.IndexByte(b[:n], '\n')
	if end < 0 {
		return
	}

	var method, target string
	fmt.Sscanf(string(b[:end]), "%s%s", &method, &target)

	if method == "CONNECT" {
		host, port := splitHostPort(target)
		if port == 0 {
			port = 80
		}
		fmt.Fprint(client, "HTTP/1.1 200 Connection established\r\n\r\n")
		tcp_redirect(client, &net.TCPAddr{Port: port}, host, nil)
		return
	}

	authority := target
	if strings.HasPrefix(authority, "http://") {
		authority = authority[7:]
	}
	if i := strings.IndexByte(authority, '/'); i >= 0 {
		authority = authority[:i]
	}
	host, port := splitHostPort(authority)
	if port == 0 {
		port = 80
	}

	header, proxy, err := parseHTTPProxy(client, b[:n])
	if err != nil {
		return
	}
	tcp_redirect(proxy, &net.TCPAddr{Port: port}, host, header)
}
