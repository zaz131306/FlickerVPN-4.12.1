package tunnel

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	hyServer "github.com/apernet/hysteria/core/v2/server"
	"github.com/apernet/hysteria/extras/v2/obfs"

	"flicker-vpn/native/internal/config"
)

// ---- тестовый Hysteria 2 сервер (реальный QUIC) ----

type staticAuth struct{ password string }

func (a *staticAuth) Authenticate(_ net.Addr, auth string, _ uint64) (bool, string) {
	return auth == a.password, "test-user"
}

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "flicker.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"flicker.test", "cloudflare.com", "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func startHY2Server(t *testing.T, password, obfsPassword string) (port int, stop func()) {
	t.Helper()
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	var conn net.PacketConn = udpConn
	if obfsPassword != "" {
		conn, err = obfs.WrapPacketConnSalamander(udpConn, []byte(obfsPassword))
		if err != nil {
			t.Fatal(err)
		}
	}
	srv, err := hyServer.NewServer(&hyServer.Config{
		TLSConfig:     hyServer.TLSConfig{Certificates: []tls.Certificate{selfSignedCert(t)}},
		Conn:          conn,
		Authenticator: &staticAuth{password: password},
		Outbound:      &defaultOutbound{},
	})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve()
	return udpConn.LocalAddr().(*net.UDPAddr).Port, func() { srv.Close() }
}

// defaultOutbound — разрешает серверу ходить куда угодно (локальные тесты).
type defaultOutbound struct{}

func (o *defaultOutbound) TCP(addr string) (net.Conn, error) {
	return net.DialTimeout("tcp", addr, 5*time.Second)
}
func (o *defaultOutbound) UDP(addr string) (hyServer.UDPConn, error) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	return &outUDPConn{pc: pc}, nil
}
func (o *defaultOutbound) CheckUDP(addr string) error { return nil }

type outUDPConn struct{ pc net.PacketConn }

func (c *outUDPConn) ReadFrom(b []byte) (int, string, error) {
	n, raddr, err := c.pc.ReadFrom(b)
	if err != nil {
		return 0, "", err
	}
	return n, raddr.String(), nil
}
func (c *outUDPConn) WriteTo(b []byte, addr string) (int, error) {
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return 0, err
	}
	return c.pc.WriteTo(b, raddr)
}
func (c *outUDPConn) Close() error { return c.pc.Close() }

// ---- тесты ----

func TestHY2EndToEndTCP(t *testing.T) {
	const password = "test-pass-123"
	port, stop := startHY2Server(t, password, "")
	defer stop()

	// локальный HTTP-бэкенд за туннелем
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello-through-hy2-tunnel")
	}))
	defer backend.Close()

	cfg := &config.ServerConfig{
		Protocol:   "hysteria2",
		Server:     "127.0.0.1",
		Port:       port,
		Auth:       password,
		TLS:        config.TLSConfig{Insecure: true},
		Congestion: config.CongestionConfig{Type: "bbr", UpMbps: 100, DownMbps: 200},
	}

	statusCh := make(chan string, 8)
	drv, err := New(cfg, Events{
		OnStatus: func(status, _ string) { statusCh <- status },
		OnError:  func(err error) { t.Logf("driver error: %v", err) },
	}, NewCounters())
	if err != nil {
		t.Fatal(err)
	}
	defer drv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := drv.Start(ctx); err != nil {
		t.Fatalf("handshake HY2 не удался: %v", err)
	}

	// ждём статус connected
	select {
	case st := <-statusCh:
		if st != "connecting" && st != "connected" {
			t.Fatalf("unexpected status %q", st)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("нет статуса от драйвера")
	}

	// TCP через реальный QUIC-туннель
	conn, err := drv.DialTCP(ctx, strings.TrimPrefix(backend.URL, "http://"))
	if err != nil {
		t.Fatalf("DialTCP через туннель: %v", err)
	}
	defer conn.Close()
	req := "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(io.LimitReader(conn, 4096))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "hello-through-hy2-tunnel") {
		t.Fatalf("тело ответа не прошло через туннель: %q", body)
	}
	if drv.RTT() <= 0 {
		t.Fatal("RTT не измеряется")
	}
}

func TestHY2EndToEndWithObfsAndUDP(t *testing.T) {
	const (
		password     = "pass-obfs"
		obfsPassword = "salamander-secret"
	)
	port, stop := startHY2Server(t, password, obfsPassword)
	defer stop()

	cfg := &config.ServerConfig{
		Protocol: "hysteria2",
		Server:   "127.0.0.1",
		Port:     port,
		Auth:     password,
		Obfs:     config.ObfsConfig{Type: "salamander", Password: obfsPassword, Enabled: true},
		TLS:      config.TLSConfig{Insecure: true},
	}
	drv, err := New(cfg, Events{}, NewCounters())
	if err != nil {
		t.Fatal(err)
	}
	defer drv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := drv.Start(ctx); err != nil {
		t.Fatalf("handshake с obfs: %v", err)
	}

	// UDP-эхо за туннелем
	echo, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	var echoDone atomic.Bool
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := echo.ReadFrom(buf)
			if err != nil {
				return
			}
			echo.WriteTo(append([]byte("echo:"), buf[:n]...), from)
			echoDone.Store(true)
		}
	}()

	sess, err := drv.NewUDPSession(ctx)
	if err != nil {
		t.Fatalf("UDP-сессия: %v", err)
	}
	defer sess.Close()
	echoAddr := echo.LocalAddr().String()
	if _, err := sess.WriteTo([]byte("ping-over-quic"), echoAddr); err != nil {
		t.Fatal(err)
	}
	data, src, err := sess.ReadFrom()
	if err != nil {
		t.Fatalf("нет UDP-ответа через туннель: %v", err)
	}
	if string(data) != "echo:ping-over-quic" || src != echoAddr {
		t.Fatalf("data=%q src=%q", data, src)
	}
}

func TestHY2WrongPassword(t *testing.T) {
	port, stop := startHY2Server(t, "right-pass", "")
	defer stop()
	cfg := &config.ServerConfig{
		Protocol: "hysteria2",
		Server:   "127.0.0.1",
		Port:     port,
		Auth:     "wrong-pass",
		TLS:      config.TLSConfig{Insecure: true},
	}
	drv, err := New(cfg, Events{}, NewCounters())
	if err != nil {
		t.Fatal(err)
	}
	defer drv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := drv.Start(ctx); err == nil {
		t.Fatal("ожидали отказ аутентификации")
	}
}

func TestTUICDriverReportsClearError(t *testing.T) {
	_, err := New(&config.ServerConfig{Protocol: "tuic", Server: "h", Port: 443, UUID: "u"}, Events{}, NewCounters())
	if err == nil {
		t.Fatal("tuic должен давать явную ошибку в этой сборке")
	}
	if !strings.Contains(err.Error(), "tuic") {
		t.Fatalf("сообщение должно упоминать tuic: %v", err)
	}
}

func TestUnknownProtocol(t *testing.T) {
	if _, err := New(&config.ServerConfig{Protocol: "vless"}, Events{}, NewCounters()); err == nil {
		t.Fatal("ожидали ошибку неизвестного протокола")
	}
}
