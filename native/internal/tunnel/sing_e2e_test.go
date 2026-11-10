package tunnel

// sing_e2e_test.go — E2E-проверка TCP/443-стека на локальных sing-box
// серверах (герметично, без внешнего интернета):
//   - Trojan + TLS;
//   - VLESS + Reality + Vision (xtls-rprx-vision) + uTLS chrome;
//   - WireGuard прямой (userspace endpoint, без TUN/root);
//   - WireGuard-«матрёшка»: WG через VLESS-детур (схема из ТЗ).

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
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
	singjson "github.com/sagernet/sing/common/json"

	"github.com/sagernet/sing-box/option"

	"flicker-vpn/native/internal/config"
	"flicker-vpn/native/internal/singreg"
)

// ---------- helpers ----------

func ecdsaP256Key() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func localCertTemplate() *x509.Certificate {
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	return &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "server.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"server.test", "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
}

// x25519Keypair — ключи в wg(8)-формате (стандартный base64 с padding).
func x25519Keypair(t *testing.T) (priv, pub string) {
	t.Helper()
	curve := ecdh.X25519()
	key, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(key.Bytes()),
		base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
}

// realityKeypair — ключи Reality в формате xtls (RawURLEncoding, 43 символа).
func realityKeypair(t *testing.T) (priv, pub string) {
	t.Helper()
	curve := ecdh.X25519()
	key, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(key.Bytes()),
		base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
}

// selfSignedPEM — сертификат для локального TLS/Reality-сервера.
func selfSignedPEM(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsaP256Key()
	if err != nil {
		t.Fatal(err)
	}
	tmpl := localCertTemplate()
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

func startSingServer(t *testing.T, configJSON string) (stop func()) {
	t.Helper()
	if out := os.Getenv("FLICKER_SING_SERVER_LOG"); out != "" {
		level := os.Getenv("FLICKER_SING_SERVER_LEVEL")
		if level == "" {
			level = "debug"
		}
		configJSON = strings.Replace(configJSON,
			`"log": {"disabled": true}`,
			fmt.Sprintf(`"log": {"level": %q, "output": %q}`, level, out), 1)
	}
	ctx := singreg.Context(context.Background())
	opts, err := singjson.UnmarshalExtendedContext[option.Options](ctx, []byte(configJSON))
	if err != nil {
		t.Fatalf("разбор серверного конфига: %v\n%s", err, configJSON)
	}
	b, err := box.New(box.Options{Options: opts, Context: ctx})
	if err != nil {
		t.Fatalf("box.New: %v", err)
	}
	if err := b.Start(); err != nil {
		t.Fatalf("box.Start: %v", err)
	}
	return func() { _ = b.Close() }
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return p
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := c.LocalAddr().(*net.UDPAddr).Port
	_ = c.Close()
	return p
}

// primaryIPv4 — не-loopback адрес машины: WG-тесты идут через него, чтобы
// трафик гарантированно покидал клиентский netstack и проходил весь путь.
func primaryIPv4(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() {
			if v4 := ipn.IP.To4(); v4 != nil {
				return v4.String()
			}
		}
	}
	t.Skip("нет не-loopback IPv4 — тест пропускается")
	return ""
}

func startBackend(t *testing.T, host string) string {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello-through-"+r.Host)
	}))
	srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	return ln.Addr().String()
}

func httpGetThrough(t *testing.T, drv Driver, target string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := drv.DialTCP(ctx, target)
	if err != nil {
		t.Fatalf("DialTCP через туннель: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	host := target
	if i := strings.LastIndex(target, ":"); i > 0 {
		host = target[:i]
	}
	req := "GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write: %v", err)
	}
	body, err := io.ReadAll(io.LimitReader(conn, 8192))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	resp := string(body)
	if !strings.HasPrefix(resp, "HTTP/1.1 200") && !strings.HasPrefix(resp, "HTTP/1.0 200") {
		t.Fatalf("не 200: %.80q", resp)
	}
	return resp
}

func startDriver(t *testing.T, cfg *config.ServerConfig) Driver {
	t.Helper()
	drv, err := New(cfg, Events{
		OnStatus: func(status, reason string) { t.Logf("driver status: %s %s", status, reason) },
		OnError:  func(err error) { t.Logf("driver error: %v", err) },
	}, NewCounters())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := drv.Start(ctx); err != nil {
		_ = drv.Close()
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = drv.Close() })
	return drv
}

// ---------- Trojan + TLS ----------

func TestSingTrojanEndToEnd(t *testing.T) {
	certPEM, keyPEM := selfSignedPEM(t)
	port := freeTCPPort(t)
	backend := startBackend(t, "127.0.0.1")

	stop := startSingServer(t, fmt.Sprintf(`{
	  "log": {"disabled": true},
	  "inbounds": [{
	    "type": "trojan", "tag": "in",
	    "listen": "127.0.0.1", "listen_port": %d,
	    "users": [{"password": "trojpass"}],
	    "tls": {"enabled": true, "certificate": [%q], "key": [%q], "server_name": "server.test"}
	  }],
	  "outbounds": [{"type": "direct", "tag": "out"}],
	  "route": {"final": "out"}
	}`, port, certPEM, keyPEM))
	defer stop()

	drv := startDriver(t, &config.ServerConfig{
		Protocol: "trojan", Server: "127.0.0.1", Port: port,
		Auth: "trojpass", SNI: "server.test",
		TLS: config.TLSConfig{Insecure: true}, // самоподписанный сертификат
	})
	resp := httpGetThrough(t, drv, backend)
	if !strings.Contains(resp, "hello-through-") {
		t.Fatalf("тело не прошло через Trojan-туннель: %.120q", resp)
	}
}

// ---------- VLESS + Reality + Vision ----------

func TestSingVlessRealityVisionEndToEnd(t *testing.T) {
	realityPriv, realityPub := realityKeypair(t)
	port := freeTCPPort(t)
	backend := startBackend(t, "127.0.0.1")
	const uuid = "2f3e4d5c-6b7a-8990-1234-56789abcdef0"

	// Reality-сервер в ходе рукопожатия проксирует ClientHello на «dest»
	// (боевой сайт). Локально роль сайта играет TLS-сервер на loopback.
	fakeSite := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "camouflage")
	}))
	defer fakeSite.Close()
	fakeSitePort := fakeSite.Listener.Addr().(*net.TCPAddr).Port

	stop := startSingServer(t, fmt.Sprintf(`{
	  "log": {"disabled": true},
	  "inbounds": [{
	    "type": "vless", "tag": "in",
	    "listen": "127.0.0.1", "listen_port": %d,
	    "users": [{"uuid": %q, "flow": "xtls-rprx-vision"}],
	    "tls": {
	      "enabled": true,
	      "server_name": "server.test",
	      "reality": {
	        "enabled": true, "private_key": %q, "short_id": ["abc123"],
	        "handshake": {"server": "127.0.0.1", "server_port": %d}
	      }
	    }
	  }],
	  "outbounds": [{"type": "direct", "tag": "out"}],
	  "route": {"final": "out"}
	}`, port, uuid, realityPriv, fakeSitePort))
	defer stop()

	drv := startDriver(t, &config.ServerConfig{
		Protocol: "vless", Server: "127.0.0.1", Port: port,
		UUID: uuid, Flow: "xtls-rprx-vision", Fingerprint: "chrome",
		SNI:     "server.test",
		Reality: &config.RealityClientConfig{PublicKey: realityPub, ShortID: "abc123"},
		TLS:     config.TLSConfig{Insecure: true},
	})
	resp := httpGetThrough(t, drv, backend)
	if !strings.Contains(resp, "hello-through-") {
		t.Fatalf("тело не прошло через VLESS+Reality+Vision: %.120q", resp)
	}
	if drv.RTT() <= 0 {
		t.Fatal("RTT не измеряется")
	}
}

// ---------- WireGuard прямой (userspace, без root) ----------

func TestSingWireguardDirectEndToEnd(t *testing.T) {
	srvPriv, srvPub := x25519Keypair(t)
	cliPriv, cliPub := x25519Keypair(t)
	udpPort := freeUDPPort(t)
	ip := primaryIPv4(t)
	backend := startBackend(t, ip)

	stop := startSingServer(t, fmt.Sprintf(`{
	  "log": {"disabled": true},
	  "endpoints": [{
	    "type": "wireguard", "tag": "wg",
	    "system": false, "mtu": 1280,
	    "address": ["10.98.0.1/24"],
	    "private_key": %q,
	    "listen_port": %d,
	    "peers": [{"public_key": %q, "allowed_ips": ["10.98.0.2/32"]}]
	  }],
	  "outbounds": [{"type": "direct", "tag": "out"}],
	  "route": {"final": "out"}
	}`, srvPriv, udpPort, cliPub))
	defer stop()

	drv := startDriver(t, &config.ServerConfig{
		Protocol: "wireguard", Server: "127.0.0.1", Port: udpPort,
		WireGuard: &config.WireGuardConfig{
			PrivateKey: cliPriv, PeerPublicKey: srvPub,
			Address: []string{"10.98.0.2/32"}, AllowedIPs: []string{"0.0.0.0/0"},
		},
	})
	resp := httpGetThrough(t, drv, backend)
	if !strings.Contains(resp, "hello-through-") {
		t.Fatalf("тело не прошло через WG-туннель: %.120q", resp)
	}
}

// ---------- WireGuard-«матрёшка»: WG через VLESS-детур ----------

func TestSingWireguardMatryoshkaEndToEnd(t *testing.T) {
	srvPriv, srvPub := x25519Keypair(t)
	cliPriv, cliPub := x25519Keypair(t)
	vlessPort := freeTCPPort(t)
	wgPort := freeUDPPort(t)
	ip := primaryIPv4(t)
	backend := startBackend(t, ip)
	const uuid = "aabbccdd-1122-3344-5566-778899aabbcc"

	// Сервер: VLESS-inbound (детур) + WG-endpoint (реальный UDP-сокет) + direct.
	// «Матрёшка» работает так: WG-пакеты клиента приходят ВНУТРЬ vless-потока
	// с целью <адрес сервера>:<wg-порт>; маршрутизатор сервера отправляет их
	// через direct outbound на собственный UDP-сокет wg-endpoint (hairpin),
	// там они расшифровываются, а полезный трафик уходит через final=direct.
	// Ровно эта же топология используется в бою: peer address = публичный IP
	// VPS, detour = тот же VPS:443.
	stop := startSingServer(t, fmt.Sprintf(`{
	  "log": {"disabled": true},
	  "inbounds": [{
	    "type": "vless", "tag": "vless-in",
	    "listen": "127.0.0.1", "listen_port": %d,
	    "users": [{"uuid": %q}]
	  }],
	  "endpoints": [{
	    "type": "wireguard", "tag": "wg",
	    "system": false, "mtu": 1280,
	    "address": ["10.99.0.1/24"],
	    "private_key": %q,
	    "listen_port": %d,
	    "peers": [{"public_key": %q, "allowed_ips": ["10.99.0.2/32"]}]
	  }],
	  "outbounds": [{"type": "direct", "tag": "out"}],
	  "route": {"final": "out"}
	}`, vlessPort, uuid, srvPriv, wgPort, cliPub))
	defer stop()

	// Клиент: WG-endpoint с детуром через VLESS на тот же сервер.
	// Peer-адрес — РЕАЛЬНЫЙ адрес сервера (как в бою: публичный IP VPS):
	// vless-детур доставит UDP-пакет серверу, а тот hairpin-ом вернёт его
	// в собственный wg-endpoint.
	drv := startDriver(t, &config.ServerConfig{
		Protocol: "wireguard", Server: "127.0.0.1", Port: wgPort,
		WireGuard: &config.WireGuardConfig{
			PrivateKey: cliPriv, PeerPublicKey: srvPub,
			Address: []string{"10.99.0.2/32"}, AllowedIPs: []string{"0.0.0.0/0"},
		},
		Detour: &config.DetourConfig{
			Protocol: "vless", Server: "127.0.0.1", Port: vlessPort, UUID: uuid,
		},
	})

	// ВНИМАНИЕ: здесь клиентский драйвер дублирует smokeCheck по детуру.
	// Проверяем полный путь: SOCKS5 → wg-netstack → WG → VLESS-TCP → сервер
	// → wg-endpoint → direct → бэкенд.
	resp := httpGetThrough(t, drv, backend)
	if !strings.Contains(resp, "hello-through-") {
		t.Fatalf("матрёшка не работает: %.120q", resp)
	}
	t.Log("матрёшка WireGuard-в-VLESS подтверждена на локальном стенде")
}

// ---------- Reality + PQ-таргет (X25519MLKEM768) ----------

// startPQOnlyTLSServer — TLS-сервер, который принимает ТОЛЬКО постквантовую
// гибридную группу X25519MLKEM768 (как современные CDN/браузеры по умолчанию).
func startPQOnlyTLSServer(t *testing.T) int {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "pq-camouflage")
	}))
	srv.TLS = &tls.Config{
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().(*net.TCPAddr).Port
}

func runRealityAgainstPQTarget(t *testing.T, fingerprint string) error {
	certPEM, keyPEM := selfSignedPEM(t)
	_ = certPEM
	realityPriv, realityPub := realityKeypair(t)
	port := freeTCPPort(t)
	backend := startBackend(t, "127.0.0.1")
	const uuid = "33333333-4444-5555-6666-777777777777"

	pqPort := startPQOnlyTLSServer(t)

	stop := startSingServer(t, fmt.Sprintf(`{
	  "log": {"disabled": true},
	  "inbounds": [{
	    "type": "vless", "tag": "in",
	    "listen": "127.0.0.1", "listen_port": %d,
	    "users": [{"uuid": %q}],
	    "tls": {
	      "enabled": true, "server_name": "server.test",
	      "reality": {
	        "enabled": true, "private_key": %q, "short_id": ["abc123"],
	        "handshake": {"server": "127.0.0.1", "server_port": %d}
	      }
	    }
	  }],
	  "outbounds": [{"type": "direct", "tag": "out"}],
	  "route": {"final": "out"}
	}`, port, uuid, realityPriv, pqPort))
	defer stop()
	_ = keyPEM

	drv, err := New(&config.ServerConfig{
		Protocol: "vless", Server: "127.0.0.1", Port: port,
		UUID: uuid, Flow: "xtls-rprx-vision", Fingerprint: fingerprint,
		SNI:     "server.test",
		Reality: &config.RealityClientConfig{PublicKey: realityPub, ShortID: "abc123"},
		TLS:     config.TLSConfig{Insecure: true},
	}, Events{}, NewCounters())
	if err != nil {
		return err
	}
	defer drv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := drv.Start(ctx); err != nil {
		return err
	}
	conn, err := drv.DialTCP(ctx, backend)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")); err != nil {
		return err
	}
	body, err := io.ReadAll(io.LimitReader(conn, 4096))
	if err != nil {
		return err
	}
	if !strings.Contains(string(body), "hello-through-") {
		return fmt.Errorf("нет тела: %.80q", body)
	}
	return nil
}

// ДОКУМЕНТИРОВАННОЕ ОГРАНИЧЕНИЕ (проверено 2026-10-07):
// reality-клиент sing-box НАМЕРЕННО вырезает X25519MLKEM768 из
// SupportedCurves и KeyShares hello (common/tls/reality_client.go) —
// reality-аутентификация связывается с чистым X25519-ключом.
// Следствие: таргет (handshake-сайт) reality-сервера ОБЯЗАН принимать
// X25519; PQ-only таргет (CurvePreferences=[X25519MLKEM768]) рвёт
// рукопожатие. Обычные сайты (Cloudflare/Google/Apple/MS) PQ лишь
// ПРЕДПОЧИТАЮТ при наличии у клиента и работают с X25519 — с ними всё ок
// (см. TestSingVlessRealityVisionEndToEnd: Go-таргет с PQ-дефолтом прошёл).
// Чистый utls-chrome PQ поддерживает (TestPQUtlsChromeClient) — ограничение
// именно reality-слоя sing-box, не uTLS.
func TestSingVlessRealityPQOnlyTargetDocumentedLimitation(t *testing.T) {
	err := runRealityAgainstPQTarget(t, "chrome")
	if err == nil {
		t.Skip("PQ-only таргет неожиданно прошёл — sing-box снял фильтр MLKEM768; обновить документацию и README")
	}
	t.Logf("ожидаемо: reality через PQ-only таргет не работает (фильтр MLKEM768 в sing-box): %v", err)
}

// ---------- ошибки конфигурации ----------

func TestSingDriverValidation(t *testing.T) {
	cases := []struct {
		name string
		cfg  *config.ServerConfig
	}{
		{"vless без uuid", &config.ServerConfig{Protocol: "vless", Server: "h", Port: 443}},
		{"trojan без пароля", &config.ServerConfig{Protocol: "trojan", Server: "h", Port: 443}},
		{"wg без ключей", &config.ServerConfig{Protocol: "wireguard", Server: "h", Port: 443,
			WireGuard: &config.WireGuardConfig{}}},
		{"wg без блока", &config.ServerConfig{Protocol: "wireguard", Server: "h", Port: 443}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.cfg, Events{}, NewCounters())
			if err == nil {
				t.Fatal("ожидали ошибку валидации")
			}
		})
	}
}
