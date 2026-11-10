package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	hyServer "github.com/apernet/hysteria/core/v2/server"
	"github.com/apernet/hysteria/extras/v2/obfs"
)

// ---------- тестовый HY2-сервер (реальный QUIC, как в hy2_e2e_test) ----------

type staticAuth struct{ password string }

func (a *staticAuth) Authenticate(_ net.Addr, auth string, _ uint64) (bool, string) {
	return auth == a.password, "probe-test-user"
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
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// startHY2Server поднимает локальный сервер Hysteria 2 (опционально с salamander).
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
		Outbound:      &loopOutbound{},
	})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve()
	return udpConn.LocalAddr().(*net.UDPAddr).Port, func() { srv.Close() }
}

// loopOutbound — серверный outbound: разрешает только loopback-цели,
// чтобы тесты оставались герметичными (без внешнего интернета).
type loopOutbound struct{}

func (o *loopOutbound) TCP(addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if host != "127.0.0.1" && host != "localhost" && host != "::1" {
		return nil, fmt.Errorf("loopOutbound: цель %s вне loopback запрещена тестом", addr)
	}
	return net.DialTimeout("tcp", addr, 3*time.Second)
}
func (o *loopOutbound) UDP(addr string) (hyServer.UDPConn, error) {
	return nil, fmt.Errorf("udp не используется в тестах probe")
}
func (o *loopOutbound) CheckUDP(addr string) error { return nil }

// startUDPSilent — UDP-сокет, который принимает пакеты и молчит («чёрная дыра»):
// имитирует мёртвый сервер или неверный obfs (ICMP не генерируется — сокет занят).
func startUDPSilent(t *testing.T) (port int, stop func()) {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 2048)
		for {
			select {
			case <-done:
				return
			default:
			}
			_ = pc.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			_, _, _ = pc.ReadFrom(buf) // глотаем пакеты, ничего не отвечаем
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).Port, func() { close(done); pc.Close() }
}

// ---------- локальные HTTP-цели (эталонные ответы как у gstatic/cloudflare) ----------

func startTargetServers(t *testing.T) (plain *httptest.Server, secure *httptest.Server) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/generate_204", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/json/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "success", "country": "Netherlands", "countryCode": "NL", "query": "203.0.113.7",
		})
	})
	mux.HandleFunc("/cdn-cgi/trace", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "fl=1\nts=1\nip=203.0.113.7\nloc=AMS\ncolo=AMS\n")
	})
	plain = httptest.NewServer(mux)
	secure = httptest.NewTLSServer(mux)
	t.Cleanup(plain.Close)
	t.Cleanup(secure.Close)
	return plain, secure
}

func portOf(t *testing.T, rawURL string) string {
	t.Helper()
	u := strings.TrimPrefix(strings.TrimPrefix(rawURL, "http://"), "https://")
	_, p, err := net.SplitHostPort(u)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// ---------- этап 1: TCP ----------

func TestProbeTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	ctx := context.Background()

	t.Run("alive", func(t *testing.T) {
		ms, class, err := ProbeTCP(ctx, "127.0.0.1", port, time.Second)
		if err != nil || class != "" {
			t.Fatalf("ожидали успех: ms=%d class=%q err=%v", ms, class, err)
		}
		if ms < 0 {
			t.Fatalf("задержка не измерена: %d", ms)
		}
	})

	t.Run("refused (закрытый порт — не фатально для UDP-сервера)", func(t *testing.T) {
		// занимаем и освобождаем порт, чтобы он точно был закрыт
		tmp, _ := net.Listen("tcp", "127.0.0.1:0")
		closed := tmp.Addr().(*net.TCPAddr).Port
		tmp.Close()
		_, class, err := ProbeTCP(ctx, "127.0.0.1", closed, time.Second)
		if err == nil {
			t.Fatal("ожидали ошибку")
		}
		if class != ErrRefused {
			t.Fatalf("ожидали класс refused, получили %q (%v)", class, err)
		}
	})

	t.Run("dns (битое имя — фатально)", func(t *testing.T) {
		_, class, err := ProbeTCP(ctx, "flicker-nonexistent-host-42.invalid", 443, 3*time.Second)
		if err == nil {
			t.Fatal("ожидали ошибку DNS")
		}
		if class != ErrDNS {
			t.Fatalf("ожидали класс dns, получили %q (%v)", class, err)
		}
	})
}

// ---------- этап 2: QUIC prescan ----------

func TestProbeQUICAlive(t *testing.T) {
	port, stop := startHY2Server(t, "prescan-pass", "")
	defer stop()

	spec := ServerSpec{ID: "alive", Host: "127.0.0.1", Port: port, Auth: "prescan-pass"}
	ctx := context.Background()
	ms, class, responded, err := ProbeQUIC(ctx, spec, 4*time.Second)
	if err != nil {
		t.Fatalf("prescan живого сервера провалился: %v (class=%q)", err, class)
	}
	if !responded || ms < 0 {
		t.Fatalf("ожидали ответ и задержку: responded=%v ms=%d", responded, ms)
	}
}

func TestProbeQUICBlackholeTimeout(t *testing.T) {
	port, stop := startUDPSilent(t)
	defer stop()

	spec := ServerSpec{ID: "blackhole", Host: "127.0.0.1", Port: port, Auth: "x"}
	ctx := context.Background()
	start := time.Now()
	_, class, responded, err := ProbeQUIC(ctx, spec, 1500*time.Millisecond)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("ожидали таймаут от чёрной дыры")
	}
	if responded {
		t.Fatal("чёрная дыра не должна считаться ответившей")
	}
	if class != ErrTimeout {
		t.Fatalf("ожидали класс timeout, получили %q (%v)", class, err)
	}
	if elapsed > 6*time.Second {
		t.Fatalf("prescan не ограничен таймаутом: %s", elapsed)
	}
}

// Неверный obfs-пароль → сервер не может расшифровать пакеты → тишина → таймаут.
// Ровно та семантика, что описана в ТЗ («если obfs-password неверный — будет
// таймаут, как будто сервер мёртв»).
func TestProbeQUICWrongObfsLooksDead(t *testing.T) {
	port, stop := startHY2Server(t, "pass", "right-obfs-secret")
	defer stop()

	spec := ServerSpec{
		ID: "wrong-obfs", Host: "127.0.0.1", Port: port, Auth: "pass",
		ObfsType: "salamander", ObfsPassword: "wrong-obfs-secret",
	}
	ctx := context.Background()
	_, class, responded, err := ProbeQUIC(ctx, spec, 1500*time.Millisecond)
	if err == nil {
		t.Fatal("с неверным obfs-паролем handshake не должен проходить")
	}
	if responded {
		t.Fatal("сервер с obfs не отвечает на нешифрованные/чужие пакеты")
	}
	if class != ErrTimeout {
		t.Fatalf("ожидали timeout (как будто сервер мёртв), получили %q", class)
	}
}

// Верный obfs-пароль → prescan проходит.
func TestProbeQUICRightObfsAlive(t *testing.T) {
	port, stop := startHY2Server(t, "pass", "shared-obfs-secret")
	defer stop()

	spec := ServerSpec{
		ID: "right-obfs", Host: "127.0.0.1", Port: port, Auth: "pass",
		ObfsType: "salamander", ObfsPassword: "shared-obfs-secret",
	}
	ctx := context.Background()
	_, _, responded, err := ProbeQUIC(ctx, spec, 4*time.Second)
	if err != nil {
		t.Fatalf("prescan с верным obfs провалился: %v", err)
	}
	if !responded {
		t.Fatal("ожидали ответ сервера")
	}
}

// ---------- этапы 3+4: HTTP через туннель ----------

func TestProbeHTTPFullThroughTunnel(t *testing.T) {
	hyPort, stop := startHY2Server(t, "http-pass", "")
	defer stop()
	plain, secure := startTargetServers(t)

	opts := Options{Mode: "full", HTTPRetries: 3, HTTPTimeoutMs: 8000}
	opts.Targets = &Targets{
		GstaticHost: "127.0.0.1", GstaticPort: portOf(t, plain.URL), GstaticPath: "/generate_204",
		CloudflareHost: "127.0.0.1", CloudflarePort: portOf(t, secure.URL), CloudflarePath: "/cdn-cgi/trace",
		GeoIPHost: "127.0.0.1", GeoIPPort: portOf(t, plain.URL), GeoIPPath: "/json/",
		InsecureTLS: true, // httptest TLS — самоподписанный
	}
	spec := ServerSpec{ID: "http-full", Host: "127.0.0.1", Port: hyPort, Auth: "http-pass", Insecure: true}

	var stages []StageResult
	res := ProbeHTTP(context.Background(), spec, opts, func(sr StageResult) { stages = append(stages, sr) })

	if !res.Alive {
		t.Fatalf("узел должен быть живым: %+v", res)
	}
	if res.LatencyMs < 0 {
		t.Fatalf("медиана задержки не вычислена: %+v", res)
	}
	if res.Country != "Netherlands" || res.CountryCode != "NL" || res.ExitIP != "203.0.113.7" {
		for _, s := range stages {
			if s.Stage == "geoip" {
				t.Logf("geoip stage: %+v", s)
			}
		}
		t.Fatalf("GeoIP через туннель не сработал: %+v", res)
	}
	if res.Stages["http"] != "ok" || res.Stages["geoip"] != "ok" {
		t.Fatalf("этапы не отмечены: %+v", res.Stages)
	}
	var sawHTTP bool
	for _, s := range stages {
		if s.Stage == "http" && s.OK {
			sawHTTP = true
		}
	}
	if !sawHTTP {
		t.Fatalf("не было стрима этапа http: %+v", stages)
	}
}

func TestProbeHTTPAuthFailure(t *testing.T) {
	hyPort, stop := startHY2Server(t, "right-pass", "")
	defer stop()
	plain, secure := startTargetServers(t)

	opts := Options{Mode: "full", HTTPTimeoutMs: 6000}
	opts.Targets = &Targets{
		GstaticHost: "127.0.0.1", GstaticPort: portOf(t, plain.URL), GstaticPath: "/generate_204",
		CloudflareHost: "127.0.0.1", CloudflarePort: portOf(t, secure.URL), CloudflarePath: "/cdn-cgi/trace",
		GeoIPHost: "127.0.0.1", GeoIPPort: portOf(t, plain.URL), GeoIPPath: "/json/",
		InsecureTLS: true,
	}
	spec := ServerSpec{ID: "auth-fail", Host: "127.0.0.1", Port: hyPort, Auth: "wrong-pass"}

	res := ProbeHTTP(context.Background(), spec, opts, nil)
	if res.Alive {
		t.Fatal("с неверным паролем узел не должен считаться живым")
	}
	if res.ErrClass != ErrAuth {
		t.Fatalf("ожидали класс auth, получили %q (%v)", res.ErrClass, res.Error)
	}
	if !strings.Contains(res.Error, "Неверный пароль сервера") {
		t.Fatalf("сообщение не человеческое: %q", res.Error)
	}
}

// HTTP-цель недоступна через туннель (сервер запрещает outbound) — узел мёртв,
// даже если QUIC-handshake прошёл. «Только узлы, прошедшие HTTP-over-proxy,
// считаются живыми».
func TestProbeHTTPNoEgressIsDead(t *testing.T) {
	hyPort, stop := startHY2Server(t, "pass", "")
	defer stop()

	opts := Options{Mode: "quick", HTTPTimeoutMs: 6000}
	// цели указывают на незадействованные loopback-порты — outbound провалится
	opts.Targets = &Targets{
		GstaticHost: "127.0.0.1", GstaticPort: "1", GstaticPath: "/generate_204",
	}
	spec := ServerSpec{ID: "no-egress", Host: "127.0.0.1", Port: hyPort, Auth: "pass"}

	res := ProbeHTTP(context.Background(), spec, opts, nil)
	if res.Alive {
		t.Fatal("без HTTP-over-proxy узел не жив")
	}
	if res.ErrClass != ErrHTTP {
		t.Fatalf("ожидали класс http, получили %q (%v)", res.ErrClass, res.Error)
	}
}

// ---------- полный pipeline (Run) ----------

func TestRunPipelineMixed(t *testing.T) {
	hyPort, stop := startHY2Server(t, "run-pass", "obfs-run")
	defer stop()
	silentPort, stopSilent := startUDPSilent(t)
	defer stopSilent()
	plain, secure := startTargetServers(t)

	opts := Options{Mode: "full", HTTPRetries: 2, Concurrency: 4, QUICTimeoutMs: 1500, HTTPTimeoutMs: 6000}
	opts.Targets = &Targets{
		GstaticHost: "127.0.0.1", GstaticPort: portOf(t, plain.URL), GstaticPath: "/generate_204",
		CloudflareHost: "127.0.0.1", CloudflarePort: portOf(t, secure.URL), CloudflarePath: "/cdn-cgi/trace",
		GeoIPHost: "127.0.0.1", GeoIPPort: portOf(t, plain.URL), GeoIPPath: "/json/",
		InsecureTLS: true,
	}
	specs := []ServerSpec{
		{ID: "alive", Host: "127.0.0.1", Port: hyPort, Auth: "run-pass", ObfsType: "salamander", ObfsPassword: "obfs-run"},
		{ID: "blackhole", Host: "127.0.0.1", Port: silentPort, Auth: "x"},
		{ID: "bad-dns", Host: "flicker-nonexistent-host-42.invalid", Port: 443, Auth: "x"},
		{ID: "bad-auth", Host: "127.0.0.1", Port: hyPort, Auth: "wrong", ObfsType: "salamander", ObfsPassword: "obfs-run"},
	}

	var mu = make(chan StageResult, 64)
	results := Run(context.Background(), specs, opts, func(sr StageResult) { mu <- sr })

	if len(results) != 4 {
		t.Fatalf("ожидали 4 результата, получили %d", len(results))
	}
	byID := map[string]Result{}
	for _, r := range results {
		byID[r.ID] = r
	}

	if !byID["alive"].Alive {
		t.Fatalf("alive должен жить: %+v", byID["alive"])
	}
	if byID["alive"].LatencyMs < 0 {
		t.Fatalf("alive: медиана не посчитана: %+v", byID["alive"])
	}
	if byID["blackhole"].Alive || byID["blackhole"].ErrClass != ErrTimeout {
		t.Fatalf("blackhole должен умереть по таймауту: %+v", byID["blackhole"])
	}
	if byID["bad-dns"].Alive || byID["bad-dns"].ErrClass != ErrDNS {
		t.Fatalf("bad-dns должен умереть на DNS: %+v", byID["bad-dns"])
	}
	if byID["bad-dns"].Stages["quic"] != "skip" {
		t.Fatalf("после DNS-фатала QUIC пропускается: %+v", byID["bad-dns"].Stages)
	}
	if byID["bad-auth"].Alive || byID["bad-auth"].ErrClass != ErrAuth {
		t.Fatalf("bad-auth должен дать класс auth: %+v", byID["bad-auth"])
	}

	// стриминг этапов
	close(mu)
	var sawTCP, sawQUIC, sawHTTP bool
	for sr := range mu {
		switch sr.Stage {
		case "tcp":
			sawTCP = true
		case "quic":
			sawQUIC = true
		case "http":
			sawHTTP = true
		}
	}
	if !sawTCP || !sawQUIC || !sawHTTP {
		t.Fatalf("стриминг этапов неполный: tcp=%v quic=%v http=%v", sawTCP, sawQUIC, sawHTTP)
	}

	// Best(): живые первыми по задержке
	sorted := Best(results)
	if sorted[0].ID != "alive" {
		t.Fatalf("Best() должен начинать с живого: %+v", sorted[0])
	}
}

// Регрессия: сервер принимает HY2-auth, но его outbound висит (не отвечает
// на CONNECT). Без жёсткого таймаута tunnel-диала проверка блокировалась
// навсегда (keep-alive не даёт QUIC-соединению умереть).
func TestProbeHTTPHangingOutboundDoesNotBlock(t *testing.T) {
	hyPort, stop := startHangingHY2Server(t, "hang-pass")
	defer stop()

	opts := Options{Mode: "quick", HTTPTimeoutMs: 3000, DialTimeoutMs: 1500}
	opts.Targets = &Targets{GstaticHost: "127.0.0.1", GstaticPort: "9", GstaticPath: "/generate_204"}
	spec := ServerSpec{ID: "hang", Host: "127.0.0.1", Port: hyPort, Auth: "hang-pass"}

	done := make(chan Result, 1)
	go func() { done <- ProbeHTTP(context.Background(), spec, opts, nil) }()
	select {
	case res := <-done:
		if res.Alive {
			t.Fatal("висящий сервер не должен считаться живым")
		}
		if res.ErrClass != ErrHTTP {
			t.Fatalf("ожидали класс http, получили %q (%v)", res.ErrClass, res.Error)
		}
	case <-time.After(12 * time.Second):
		t.Fatal("проба зависла: жёсткий таймаут туннельного dial не сработал")
	}
}

// startHangingHY2Server — HY2-сервер, у которого outbound TCP-запросы «висят».
func startHangingHY2Server(t *testing.T, password string) (port int, stop func()) {
	t.Helper()
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := hyServer.NewServer(&hyServer.Config{
		TLSConfig:     hyServer.TLSConfig{Certificates: []tls.Certificate{selfSignedCert(t)}},
		Conn:          udpConn,
		Authenticator: &staticAuth{password: password},
		Outbound:      &hangOutbound{released: make(chan struct{})},
	})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve()
	return udpConn.LocalAddr().(*net.UDPAddr).Port, func() { srv.Close(); udpConn.Close() }
}

type hangOutbound struct{ released chan struct{} }

func (o *hangOutbound) TCP(addr string) (net.Conn, error) {
	<-o.released // никогда в тесте: имитация зависшего серверного outbound
	return nil, fmt.Errorf("released")
}
func (o *hangOutbound) UDP(addr string) (hyServer.UDPConn, error) {
	return nil, fmt.Errorf("udp не используется")
}
func (o *hangOutbound) CheckUDP(addr string) error { return nil }

func TestMedian(t *testing.T) {
	cases := []struct {
		in   []int
		want int
	}{
		{[]int{}, -1},
		{[]int{42}, 42},
		{[]int{30, 10, 20}, 20},
		{[]int{10, 20, 30, 40}, 25},
		{[]int{5, 5, 5}, 5},
	}
	for _, c := range cases {
		if got := median(c.in); got != c.want {
			t.Errorf("median(%v) = %d, want %d", c.in, got, c.want)
		}
	}
}
