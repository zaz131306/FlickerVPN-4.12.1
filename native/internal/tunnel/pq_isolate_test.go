package tunnel

// pq_isolate_test.go — изоляция PQ-проблемы: кто именно не сходится с
// PQ-only таргетом (Go-клиент / utls-клиент / reality-релей).

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	utls "github.com/metacubex/utls"
)

func pqServer(t *testing.T) (addr string) {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.TLS = &tls.Config{CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}

func TestPQGoStdClient(t *testing.T) {
	addr := pqServer(t)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("Go crypto/tls → PQ-only: %v", err)
	}
	st := conn.ConnectionState()
	t.Logf("Go-клиент: negotiated group=%v (X25519MLKEM768=%v)", st.CurveID, st.CurveID == tls.X25519MLKEM768)
	_ = conn.Close()
}

func TestPQUtlsChromeClient(t *testing.T) {
	addr := pqServer(t)
	raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	host, _, _ := net.SplitHostPort(addr)
	uConn := utls.UClient(raw, &utls.Config{ServerName: host, InsecureSkipVerify: true}, utls.HelloChrome_Auto)
	if err := uConn.Handshake(); err != nil {
		t.Fatalf("utls HelloChrome_Auto → PQ-only: %v", err)
	}
	t.Logf("utls-chrome: версия %x, cipher %x", uConn.ConnectionState().Version, uConn.ConnectionState().CipherSuite)
	_ = uConn.Close()
}

func TestPQUtlsFirefoxClient(t *testing.T) {
	addr := pqServer(t)
	raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	host, _, _ := net.SplitHostPort(addr)
	uConn := utls.UClient(raw, &utls.Config{ServerName: host, InsecureSkipVerify: true}, utls.HelloFirefox_Auto)
	err = uConn.Handshake()
	if err == nil {
		_ = uConn.Close()
		t.Log("firefox тоже прошёл PQ-only — ограничение шире, чем думали")
		return
	}
	t.Logf("ожидаемо: firefox не предлагает PQ → %v", err)
}
