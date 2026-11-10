package socks5

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"flicker-vpn/native/internal/config"
	"flicker-vpn/native/internal/tunnel"
)

func testLogger() *log.Logger { return log.New(os.Stderr, "[socks5-test] ", log.LstdFlags) }

// --- helpers: ручной SOCKS5-клиент ---

func socksGreeting(t *testing.T, c net.Conn) {
	t.Helper()
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c, resp); err != nil {
		t.Fatal(err)
	}
	if resp[0] != 5 || resp[1] != 0 {
		t.Fatalf("greeting resp: %v", resp)
	}
}

func socksConnect(t *testing.T, c net.Conn, addr string) byte {
	t.Helper()
	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	for _, ch := range portStr {
		port = port*10 + int(ch-'0')
	}
	req := []byte{5, cmdConnect, 0}
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		req = append(req, atypIPv4)
		req = append(req, ip.To4()...)
	} else {
		req = append(req, atypDomain, byte(len(host)))
		req = append(req, host...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		t.Fatal(err)
	}
	// пропустить BND
	switch head[3] {
	case atypIPv4:
		skip := make([]byte, 6)
		io.ReadFull(c, skip)
	case atypIPv6:
		skip := make([]byte, 18)
		io.ReadFull(c, skip)
	case atypDomain:
		l := make([]byte, 1)
		io.ReadFull(c, l)
		skip := make([]byte, int(l[0])+2)
		io.ReadFull(c, skip)
	}
	return head[1]
}

func startEchoTCP(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					echo := append([]byte("echo:"), buf[:n]...)
					if _, err := c.Write(echo); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func startEchoUDP(t *testing.T) (addr string, stop func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			echo := append([]byte("echo:"), buf[:n]...)
			pc.WriteTo(echo, from)
		}
	}()
	return pc.LocalAddr().String(), func() { pc.Close() }
}

func newTestServer(t *testing.T) (*Server, *tunnel.Counters) {
	t.Helper()
	counters := tunnel.NewCounters()
	drv := tunnelMustDirect(t)
	srv, err := New("127.0.0.1:0", drv, counters, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	return srv, counters
}

func tunnelMustDirect(t *testing.T) tunnel.Driver {
	t.Helper()
	d, err := tunnel.New(&config.ServerConfig{Protocol: "direct", Server: "x", Port: 1}, tunnel.Events{}, tunnel.NewCounters())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestSOCKS5ConnectIPv4(t *testing.T) {
	echoAddr, stopEcho := startEchoTCP(t)
	defer stopEcho()
	srv, counters := newTestServer(t)

	c, err := net.Dial("tcp", srv.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	socksGreeting(t, c)
	if rep := socksConnect(t, c, echoAddr); rep != repOK {
		t.Fatalf("rep=%d", rep)
	}
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "echo:hello" {
		t.Fatalf("got %q", buf[:n])
	}
	if counters.Sent() == 0 || counters.Recv() == 0 {
		t.Fatalf("counters не считаются: sent=%d recv=%d", counters.Sent(), counters.Recv())
	}
}

func TestSOCKS5ConnectDomain(t *testing.T) {
	echoAddr, stopEcho := startEchoTCP(t)
	defer stopEcho()
	srv, _ := newTestServer(t)

	// localhost вместо 127.0.0.1 — проверка доменного ATYP
	host := "localhost"
	_, portStr, _ := net.SplitHostPort(echoAddr)
	addr := net.JoinHostPort(host, portStr)

	c, err := net.Dial("tcp", srv.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	socksGreeting(t, c)
	if rep := socksConnect(t, c, addr); rep != repOK {
		t.Fatalf("rep=%d", rep)
	}
	c.Write([]byte("ping"))
	buf := make([]byte, 64)
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "echo:ping" {
		t.Fatalf("got %q", buf[:n])
	}
}

func TestSOCKS5ConnectRefused(t *testing.T) {
	srv, _ := newTestServer(t)
	// найдём закрытый порт
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := dead.Addr().String()
	dead.Close()

	c, err := net.Dial("tcp", srv.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	socksGreeting(t, c)
	rep := socksConnect(t, c, deadAddr)
	if rep != repConnRefused && rep != repHostUnreach {
		t.Fatalf("ожидали refused/host-unreach, rep=%d", rep)
	}
}

func TestSOCKS5NoCommonAuthMethod(t *testing.T) {
	srv, _ := newTestServer(t)
	c, err := net.Dial("tcp", srv.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// предлагаем только GSSAPI (0x01) — сервер должен ответить 0xFF
	c.Write([]byte{5, 1, 0x01})
	resp := make([]byte, 2)
	io.ReadFull(c, resp)
	if resp[1] != 0xFF {
		t.Fatalf("want 0xFF, got %v", resp)
	}
}

func TestSOCKS5UDPAssociate(t *testing.T) {
	echoAddr, stopEcho := startEchoUDP(t)
	defer stopEcho()
	srv, _ := newTestServer(t)

	// управляющее TCP-соединение
	c, err := net.Dial("tcp", srv.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	socksGreeting(t, c)

	// UDP ASSOCIATE с адреса клиента
	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer clientUDP.Close()

	req := []byte{5, cmdUDPAssociate, 0, atypIPv4}
	req = append(req, clientUDP.LocalAddr().(*net.UDPAddr).IP.To4()...)
	req = append(req, 0, 0)
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		t.Fatal(err)
	}
	if head[1] != repOK {
		t.Fatalf("udp associate rep=%d", head[1])
	}
	bnd := make([]byte, 6)
	io.ReadFull(c, bnd)
	bndAddr := net.JoinHostPort(net.IP(bnd[0:4]).String(), itoa(int(binary.BigEndian.Uint16(bnd[4:6]))))

	// дейтаграмма с SOCKS5 UDP-заголовком на echo-сервер
	host, portStr, _ := net.SplitHostPort(echoAddr)
	port := 0
	for _, ch := range portStr {
		port = port*10 + int(ch-'0')
	}
	pkt := []byte{0, 0, 0, atypIPv4}
	pkt = append(pkt, net.ParseIP(host).To4()...)
	pkt = append(pkt, byte(port>>8), byte(port))
	pkt = append(pkt, "udp-hello"...)
	raddr, _ := net.ResolveUDPAddr("udp", bndAddr)
	if _, err := clientUDP.WriteToUDP(pkt, raddr); err != nil {
		t.Fatal(err)
	}

	_ = clientUDP.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 65535)
	n, _, err := clientUDP.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("нет ответа UDP: %v", err)
	}
	dst, payload, ok := parseUDPHeader(buf[:n])
	if !ok {
		t.Fatalf("битый ответный заголовок: %v", buf[:min(n, 16)])
	}
	if !strings.Contains(dst, ":") || !strings.HasSuffix(string(payload), "udp-hello") {
		t.Fatalf("payload=%q dst=%q", payload, dst)
	}
	if !strings.HasPrefix(string(payload), "echo:") {
		t.Fatalf("payload=%q", payload)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
