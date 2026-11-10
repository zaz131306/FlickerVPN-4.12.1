package probe

// probe_sing_test.go — проверка TCP/443-стека (vless/trojan) через
// локальные sing-box серверы: воронка TCP → HTTP-through → вердикт.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"

	"flicker-vpn/native/internal/singreg"
)

func startSingServerHere(t *testing.T, configJSON string) {
	t.Helper()
	if out := os.Getenv("FLICKER_SING_SERVER_LOG"); out != "" {
		configJSON = strings.Replace(configJSON,
			`"log": {"disabled": true}`,
			fmt.Sprintf(`"log": {"level": "debug", "output": %q}`, out), 1)
	}
	ctx := singreg.Context(context.Background())
	opts, err := singjson.UnmarshalExtendedContext[option.Options](ctx, []byte(configJSON))
	if err != nil {
		t.Fatalf("разбор серверного конфига: %v", err)
	}
	b, err := box.New(box.Options{Options: opts, Context: ctx})
	if err != nil {
		t.Fatalf("box.New: %v", err)
	}
	if err := b.Start(); err != nil {
		t.Fatalf("box.Start: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
}

func freeTCPPortHere(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return p
}

func localCertPEM(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "probe.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"probe.test", "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return
}

// 204-бэкенд (эталон gstatic) на loopback
func start204Backend(t *testing.T) (host, port string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/generate_204" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)
	h, p, _ := net.SplitHostPort(srv.Listener.Addr().String())
	return h, p
}

func TestProbeSingVlessPlain(t *testing.T) {
	vlessPort := freeTCPPortHere(t)
	bHost, bPort := start204Backend(t)
	const uuid = "11111111-2222-3333-4444-555555555555"

	startSingServerHere(t, fmt.Sprintf(`{
	  "log": {"disabled": true},
	  "inbounds": [{
	    "type": "vless", "tag": "in",
	    "listen": "127.0.0.1", "listen_port": %d,
	    "users": [{"uuid": %q}]
	  }],
	  "outbounds": [{"type": "direct", "tag": "out"}],
	  "route": {"final": "out"}
	}`, vlessPort, uuid))

	opts := Options{Mode: "quick", TCPTimeoutMs: 1000, HTTPTimeoutMs: 6000, DialTimeoutMs: 4000}
	opts.GeoIP = boolPtr(false)
	opts.Targets = &Targets{GstaticHost: bHost, GstaticPort: bPort, GstaticPath: "/generate_204"}

	good := ServerSpec{ID: "vless-ok", Host: "127.0.0.1", Port: vlessPort, Protocol: "vless", UUID: uuid}
	bad := ServerSpec{ID: "vless-bad", Host: "127.0.0.1", Port: vlessPort, Protocol: "vless", UUID: "99999999-9999-9999-9999-999999999999"}

	results := Run(context.Background(), []ServerSpec{good, bad}, opts, nil)
	byID := map[string]Result{}
	for _, r := range results {
		byID[r.ID] = r
	}

	if !byID["vless-ok"].Alive {
		t.Fatalf("рабочий vless должен жить: %+v", byID["vless-ok"])
	}
	if byID["vless-ok"].LatencyMs < 0 {
		t.Fatalf("задержка не измерена: %+v", byID["vless-ok"])
	}
	if byID["vless-ok"].Stages["tcp"] != "ok" || byID["vless-ok"].Stages["quic"] != "skip" {
		t.Fatalf("стадии TCP-протокола: %+v", byID["vless-ok"].Stages)
	}
	if byID["vless-bad"].Alive {
		t.Fatalf("vless с неверным uuid не должен жить: %+v", byID["vless-bad"])
	}
	t.Logf("неверный uuid → класс %q: %s", byID["vless-bad"].ErrClass, byID["vless-bad"].Error)
}

func TestProbeSingTrojanTLS(t *testing.T) {
	port := freeTCPPortHere(t)
	bHost, bPort := start204Backend(t)
	certPEM, keyPEM := localCertPEM(t)

	startSingServerHere(t, fmt.Sprintf(`{
	  "log": {"disabled": true},
	  "inbounds": [{
	    "type": "trojan", "tag": "in",
	    "listen": "127.0.0.1", "listen_port": %d,
	    "users": [{"password": "troj-probe"}],
	    "tls": {"enabled": true, "certificate": [%q], "key": [%q], "server_name": "probe.test"}
	  }],
	  "outbounds": [{"type": "direct", "tag": "out"}],
	  "route": {"final": "out"}
	}`, port, certPEM, keyPEM))

	opts := Options{Mode: "quick", TCPTimeoutMs: 1000, HTTPTimeoutMs: 6000, DialTimeoutMs: 4000}
	opts.GeoIP = boolPtr(false)
	opts.Targets = &Targets{GstaticHost: bHost, GstaticPort: bPort, GstaticPath: "/generate_204"}

	spec := ServerSpec{
		ID: "trojan-ok", Host: "127.0.0.1", Port: port, Protocol: "trojan",
		Auth: "troj-probe", SNI: "probe.test", TLSEnabled: true, Insecure: true,
	}
	results := Run(context.Background(), []ServerSpec{spec}, opts, nil)
	if !results[0].Alive {
		t.Fatalf("trojan+TLS должен жить: %+v", results[0])
	}
}

func TestProbeSingDeadTCPIsFatal(t *testing.T) {
	// закрытый TCP-порт для TCP-протокола — смерть уже на этапе 1 (в отличие
	// от HY2, где TCP-refused не фатален)
	port := freeTCPPortHere(t)
	opts := Options{Mode: "quick", TCPTimeoutMs: 800, HTTPTimeoutMs: 3000}
	spec := ServerSpec{ID: "dead-tcp", Host: "127.0.0.1", Port: port, Protocol: "vless", UUID: "x"}
	results := Run(context.Background(), []ServerSpec{spec}, opts, nil)
	r := results[0]
	if r.Alive || r.ErrClass != ErrRefused {
		t.Fatalf("ожидали отказ на TCP-стадии: %+v", r)
	}
	if r.Stages["http"] != "skip" {
		t.Fatalf("после фатальной TCP-стадии HTTP пропускается: %+v", r.Stages)
	}
}

func boolPtr(b bool) *bool { return &b }
