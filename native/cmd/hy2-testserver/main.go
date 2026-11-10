// hy2-testserver — отдельный Hysteria 2 сервер для live-проверок в браузере.
// Печатает READY-строку с портом и держит сервер до SIGINT/SIGTERM.
//
//	hy2-testserver -port 44377 -password livepass [-obfs-password secret]
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	hyServer "github.com/apernet/hysteria/core/v2/server"
	"github.com/apernet/hysteria/extras/v2/obfs"
)

type staticAuth struct{ password string }

func (a *staticAuth) Authenticate(_ net.Addr, auth string, _ uint64) (bool, string) {
	return auth == a.password, "live-user"
}

type outbound struct{}

func (o *outbound) TCP(addr string) (net.Conn, error) {
	return net.DialTimeout("tcp", addr, 5*time.Second)
}
func (o *outbound) UDP(addr string) (hyServer.UDPConn, error) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	return &udpConn{pc: pc}, nil
}
func (o *outbound) CheckUDP(addr string) error { return nil }

type udpConn struct{ pc net.PacketConn }

func (c *udpConn) ReadFrom(b []byte) (int, string, error) {
	n, raddr, err := c.pc.ReadFrom(b)
	if err != nil {
		return 0, "", err
	}
	return n, raddr.String(), nil
}
func (c *udpConn) WriteTo(b []byte, addr string) (int, error) {
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return 0, err
	}
	return c.pc.WriteTo(b, raddr)
}
func (c *udpConn) Close() error { return c.pc.Close() }

func selfSigned() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "flicker-live.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"flicker-live.test", "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

func main() {
	port := flag.Int("port", 44377, "UDP-порт")
	password := flag.String("password", "livepass", "пароль клиентов")
	obfsPassword := flag.String("obfs-password", "", "salamander obfs (пусто = выкл)")
	flag.Parse()

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: *port})
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		os.Exit(1)
	}
	var conn net.PacketConn = udpConn
	if *obfsPassword != "" {
		conn, err = obfs.WrapPacketConnSalamander(udpConn, []byte(*obfsPassword))
		if err != nil {
			fmt.Fprintln(os.Stderr, "obfs:", err)
			os.Exit(1)
		}
	}
	cert, err := selfSigned()
	if err != nil {
		fmt.Fprintln(os.Stderr, "cert:", err)
		os.Exit(1)
	}
	srv, err := hyServer.NewServer(&hyServer.Config{
		TLSConfig:     hyServer.TLSConfig{Certificates: []tls.Certificate{cert}},
		Conn:          conn,
		Authenticator: &staticAuth{password: *password},
		Outbound:      &outbound{},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "server:", err)
		os.Exit(1)
	}
	fmt.Printf("READY port=%d password=%s\n", udpConn.LocalAddr().(*net.UDPAddr).Port, *password)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		_ = srv.Close()
		os.Exit(0)
	}()
	if err := srv.Serve(); err != nil {
		fmt.Fprintln(os.Stderr, "serve:", err)
		os.Exit(1)
	}
}
