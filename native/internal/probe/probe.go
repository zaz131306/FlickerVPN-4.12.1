// Package probe — многоэтапная проверка живости серверов Hysteria 2.
//
// Pipeline (как у проверенных источников подписок, напр. Au1rxx):
//
//	Этап 1: TCP reachability  — быстрый dial server:port. Отсеивает битый DNS.
//	        ВАЖНО: HY2 — это UDP/QUIC, поэтому TCP-refused/timeout НЕ являются
//	        приговором (сервер может не слушать TCP на этом порту); фатален
//	        только DNS-провал. Реальный фильтр живости — этап 2.
//	Этап 2: QUIC prescan      — настоящий QUIC-handshake (TLS 1.3, ALPN h3)
//	        с таймаутом ~2 c. Salamander-obfs применяется, если задан: при
//	        неверном obfs-пароле сервер не сможет расшифровать пакеты и будет
//	        молчать → таймаут, как будто сервер мёртв.
//	Этап 3: HTTP через туннель — полное HY2-подключение драйвером и запросы:
//	        http://www.gstatic.com/generate_204 (ожидаем 204)
//	        https://www.cloudflare.com/cdn-cgi/trace (ожидаем 200)
//	        Живыми считаются ТОЛЬКО узлы, прошедшие HTTP-over-proxy.
//	Этап 4: задержка          — медиана нескольких HTTP-проб (не TCP RTT).
//	Этап 5: двойной прогон    — оркеструется расширением (повтор через 45 c,
//	        success rate < 50% → мёртв); здесь — вся статистика для него.
//
// Дополнительно: GeoIP по exit IP (ip-api.com через туннель) — страна узла.
package probe

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	hyClient "github.com/apernet/hysteria/core/v2/client"
	hyErrors "github.com/apernet/hysteria/core/v2/errors"
	"github.com/apernet/hysteria/extras/v2/obfs"
	quic "github.com/apernet/quic-go"

	"flicker-vpn/native/internal/config"
	"flicker-vpn/native/internal/tunnel"
)

// ---------------- входные данные ----------------

// ServerSpec — сервер для проверки (приходит из расширения по NM).
type ServerSpec struct {
	ID           string `json:"id"`
	Host         string `json:"host"`
	Port         int    `json:"port"`
	Protocol     string `json:"protocol"` // ""/"hysteria2" (QUIC-путь) | vless | trojan | vmess | shadowsocks
	Auth         string `json:"auth"`
	SNI          string `json:"sni"`
	ObfsType     string `json:"obfsType"` // "salamander" | "none" | ""
	ObfsPassword string `json:"obfsPassword"`
	Insecure     bool   `json:"insecure"`   // не проверять сертификат (skip-verify)
	TLSEnabled   bool   `json:"tlsEnabled"` // vless/vmess: security=tls|reality; trojan: всегда true

	// TCP/443-стек (vless/trojan/vmess/ss)
	UUID           string `json:"uuid,omitempty"`
	Flow           string `json:"flow,omitempty"` // xtls-rprx-vision
	Fingerprint    string `json:"fingerprint,omitempty"`
	RealityPBK     string `json:"realityPublicKey,omitempty"`
	RealitySID     string `json:"realityShortId,omitempty"`
	Cipher         string `json:"cipher,omitempty"`
	TransportType  string `json:"transportType,omitempty"`
	TransportPath  string `json:"transportPath,omitempty"`
	TransportHost  string `json:"transportHost,omitempty"`
	TransportSvcNm string `json:"transportServiceName,omitempty"`
}

// isTCPProtocol — протоколы TCP/443-стека (проверяются без QUIC-prescan).
func (s ServerSpec) isTCPProtocol() bool {
	switch s.Protocol {
	case "vless", "trojan", "vmess", "shadowsocks":
		return true
	}
	return false
}

// Options — параметры прогона.
type Options struct {
	Mode           string `json:"mode"`           // "full" (по умолчанию) | "quick"
	Concurrency    int    `json:"concurrency"`    // предел параллельных проверок
	TCPTimeoutMs   int    `json:"tcpTimeoutMs"`   // этап 1, по умолчанию 1500
	QUICTimeoutMs  int    `json:"quicTimeoutMs"`  // этап 2, по умолчанию 2500
	HTTPTimeoutMs  int    `json:"httpTimeoutMs"`  // этап 3 (на одну пробу), по умолчанию 7000
	DialTimeoutMs  int    `json:"dialTimeoutMs"`  // открытие потока в туннеле, по умолчанию min(http, 5000)
	GeoIPTimeoutMs int    `json:"geoIpTimeoutMs"` // GeoIP-запрос, по умолчанию 4000
	HTTPRetries    int    `json:"httpRetries"`    // проб gstatic для медианы, по умолчанию 3
	GeoIP          *bool  `json:"geoIp"`          // делать ли GeoIP (по умолчанию: full — да)
	SkipTCP        bool   `json:"skipTcp"`
	SkipQUIC       bool   `json:"skipQuic"`
	SkipHTTP       bool   `json:"skipHttp"`

	// Targets — цели HTTP-проверок. По умолчанию рабочие адреса из ТЗ;
	// переопределяются только тестами (не сериализуется в NM).
	Targets *Targets `json:"-"`
}

// Targets — какие цели использовать на этапе 3.
type Targets struct {
	GstaticHost    string
	GstaticPort    string // по умолчанию "80"
	GstaticPath    string
	CloudflareHost string
	CloudflarePort string // по умолчанию "443"
	CloudflarePath string
	GeoIPHost      string
	GeoIPPort      string // по умолчанию "80"
	GeoIPPath      string
	InsecureTLS    bool // не проверять сертификат cloudflare-цели (для тестов)
}

func (o *Options) targets() Targets {
	t := Targets{
		GstaticHost:    gstaticHost,
		GstaticPath:    gstaticPath,
		CloudflareHost: cloudflareHost,
		CloudflarePath: cloudflarePath,
		GeoIPHost:      geoipHost,
		GeoIPPath:      geoipPath,
	}
	if o.Targets != nil {
		if o.Targets.GstaticHost != "" {
			t.GstaticHost = o.Targets.GstaticHost
		}
		if o.Targets.GstaticPort != "" {
			t.GstaticPort = o.Targets.GstaticPort
		}
		if o.Targets.GstaticPath != "" {
			t.GstaticPath = o.Targets.GstaticPath
		}
		if o.Targets.CloudflareHost != "" {
			t.CloudflareHost = o.Targets.CloudflareHost
		}
		if o.Targets.CloudflarePort != "" {
			t.CloudflarePort = o.Targets.CloudflarePort
		}
		if o.Targets.CloudflarePath != "" {
			t.CloudflarePath = o.Targets.CloudflarePath
		}
		if o.Targets.GeoIPHost != "" {
			t.GeoIPHost = o.Targets.GeoIPHost
		}
		if o.Targets.GeoIPPort != "" {
			t.GeoIPPort = o.Targets.GeoIPPort
		}
		if o.Targets.GeoIPPath != "" {
			t.GeoIPPath = o.Targets.GeoIPPath
		}
		t.InsecureTLS = o.Targets.InsecureTLS
	}
	if t.GstaticPort == "" {
		t.GstaticPort = "80"
	}
	if t.CloudflarePort == "" {
		t.CloudflarePort = "443"
	}
	if t.GeoIPPort == "" {
		t.GeoIPPort = "80"
	}
	return t
}

func (o *Options) normalize() {
	if o.Mode == "" {
		o.Mode = "full"
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 8
	}
	if o.Concurrency > 32 {
		o.Concurrency = 32
	}
	if o.TCPTimeoutMs <= 0 {
		o.TCPTimeoutMs = 1500
	}
	if o.QUICTimeoutMs <= 0 {
		o.QUICTimeoutMs = 2500
	}
	if o.HTTPTimeoutMs <= 0 {
		o.HTTPTimeoutMs = 7000
	}
	if o.DialTimeoutMs <= 0 {
		// открытие туннельного потока не должно занимать весь HTTP-бюджет:
		// иначе зависший сервер держит воркер и проверка ползёт минутами
		o.DialTimeoutMs = min(o.HTTPTimeoutMs, 5000)
	}
	if o.GeoIPTimeoutMs <= 0 {
		o.GeoIPTimeoutMs = 4000
	}
	if o.HTTPRetries <= 0 {
		o.HTTPRetries = 3
	}
	if o.Mode == "quick" {
		if o.HTTPRetries > 1 {
			o.HTTPRetries = 1
		}
		if o.Concurrency > 4 {
			o.Concurrency = 4 // фоновый режим: не грузим CPU
		}
	}
}

func (o *Options) geoIPEnabled() bool {
	if o.GeoIP != nil {
		return *o.GeoIP
	}
	return o.Mode != "quick"
}

// ---------------- результаты ----------------

// Классы ошибок — по ним расширение строит человеческие сообщения (задача 7).
const (
	ErrDNS     = "dns"     // имя не разрешается
	ErrRefused = "refused" // connection refused / ICMP unreachable
	ErrTimeout = "timeout" // тишина: мёртв или неверный obfs-пароль
	ErrAuth    = "auth"    // сервер ответил, но пароль не подошёл
	ErrHTTP    = "http"    // QUIC прошёл, HTTP-проверка провалилась
	ErrConfig  = "config"  // некорректные данные сервера
	ErrOther   = "other"
)

// StageResult — результат одного этапа (стримится в расширение).
type StageResult struct {
	ID        string `json:"id"`
	Stage     string `json:"stage"` // tcp | quic | http | geoip
	OK        bool   `json:"ok"`
	Fatal     bool   `json:"fatal"` // продолжать бессмысленно
	LatencyMs int    `json:"latencyMs"`
	ErrClass  string `json:"errClass,omitempty"`
	Error     string `json:"error,omitempty"`
}

// Result — итог по серверу.
type Result struct {
	ID          string            `json:"id"`
	Alive       bool              `json:"alive"`
	LatencyMs   int               `json:"latencyMs"` // медиана HTTP-проб через туннель
	QuicMs      int               `json:"quicMs"`
	TcpMs       int               `json:"tcpMs"`
	ExitIP      string            `json:"exitIp,omitempty"`
	Country     string            `json:"country,omitempty"`
	CountryCode string            `json:"countryCode,omitempty"`
	ErrClass    string            `json:"errClass,omitempty"`
	Error       string            `json:"error,omitempty"`
	Stages      map[string]string `json:"stages"` // ok | fail | skip
}

// ---------------- человеческие сообщения (задача 7) ----------------

func humanError(class, detail string, spec ServerSpec) string {
	hasObfs := strings.EqualFold(spec.ObfsType, "salamander") && spec.ObfsPassword != ""
	switch class {
	case ErrDNS:
		return "Не удалось разрешить имя сервера (битый DNS или хост удалён)"
	case ErrRefused:
		return "Сервер сбросил соединение (порт закрыт)"
	case ErrTimeout:
		if hasObfs {
			return "Сервер не отвечает (проверьте obfs-пароль или сервер мёртв)"
		}
		return "Сервер не отвечает (таймаут соединения; возможно, сервер мёртв)"
	case ErrAuth:
		return "Неверный пароль сервера"
	case ErrHTTP:
		return "Сервер отвечает, но HTTP через туннель не работает" + suffix(detail)
	case ErrConfig:
		return "Некорректные данные сервера" + suffix(detail)
	default:
		return "Ошибка проверки" + suffix(detail)
	}
}

func suffix(s string) string {
	if s == "" {
		return ""
	}
	return ": " + s
}

// ---------------- этап 1: TCP ----------------

// ProbeTCP — быстрый TCP-dial. Семантика для HY2 (UDP-протокол):
//   - успех: хост точно жив (tcpMs — задержка handshake);
//   - DNS-провал: фатально (дальше не проверяем);
//   - refused/timeout: НЕ фатально — многие HY2-серверы не слушают TCP
//     на том же порту; вердикт вынесет QUIC-prescan.
func ProbeTCP(ctx context.Context, host string, port int, timeout time.Duration) (ms int, class string, err error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	d := net.Dialer{Timeout: timeout, Control: DialHook}
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return -1, classifyNetError(err), err
	}
	_ = conn.Close()
	return int(time.Since(start).Milliseconds()), "", nil
}

func classifyNetError(err error) string {
	var de *net.DNSError
	if errors.As(err, &de) {
		return ErrDNS
	}
	var ne *net.OpError
	if errors.As(err, &ne) && ne.Err != nil {
		s := ne.Err.Error()
		if strings.Contains(s, "connection refused") {
			return ErrRefused
		}
		if strings.Contains(s, "unreachable") {
			return ErrRefused
		}
		if strings.Contains(s, "no such host") {
			return ErrDNS
		}
	}
	s := err.Error()
	if strings.Contains(s, "no such host") {
		return ErrDNS
	}
	if strings.Contains(s, "connection refused") {
		return ErrRefused
	}
	if errors.Is(err, context.DeadlineExceeded) || strings.Contains(s, "timeout") || strings.Contains(s, "deadline") {
		return ErrTimeout
	}
	return ErrOther
}

// ---------------- этап 2: QUIC prescan ----------------

// ProbeQUIC — настоящий QUIC-handshake с сервером (TLS 1.3, ALPN h3).
// Salamander-obfs применяется, если задан: при неверном obfs-пароле сервер
// молчит и мы получаем таймаут — ровно та семантика, что описана в ТЗ.
//
// Вердикты:
//   - handshake успешен → жив (ok);
//   - сервер ответил ошибкой TLS/ALPN/версии → тоже жив: он слушает QUIC
//     и реагирует (ok=false, но не таймаут → не фатально для «живости»,
//     полный ответ даст этап 3);
//   - таймаут/тишина → мёртв или неверный obfs-пароль (fatal);
//   - DNS/refused → мёртв (fatal).
func ProbeQUIC(ctx context.Context, spec ServerSpec, timeout time.Duration) (ms int, class string, responded bool, err error) {
	host := spec.Host
	port := spec.Port
	if port <= 0 {
		port = 443
	}
	udpAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return -1, classifyNetError(err), false, err
	}

	pc, err := listenUDPHooked()
	if err != nil {
		return -1, ErrOther, false, err
	}
	var conn net.PacketConn = pc
	if strings.EqualFold(spec.ObfsType, "salamander") && spec.ObfsPassword != "" {
		wrapped, werr := obfs.WrapPacketConnSalamander(pc, []byte(spec.ObfsPassword))
		if werr != nil {
			_ = pc.Close()
			return -1, ErrConfig, false, werr
		}
		conn = wrapped
	}

	sni := spec.SNI
	if sni == "" {
		sni = host
	}
	tr := &quic.Transport{Conn: conn}
	defer tr.Close()

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	tlsConf := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // prescan: сертификат не проверяем, важен факт ответа
		NextProtos:         []string{"h3"},
	}
	quicConf := &quic.Config{
		HandshakeIdleTimeout: timeout + 500*time.Millisecond,
		MaxIdleTimeout:       timeout + 500*time.Millisecond,
	}
	qconn, err := tr.Dial(dialCtx, udpAddr, tlsConf, quicConf)
	ms = int(time.Since(start).Milliseconds())
	if err == nil {
		_ = qconn.CloseWithError(0, "probe done")
		return ms, "", true, nil
	}
	// Сервер ответил осмысленной ошибкой (TLS alert, ALPN, версия) — он жив,
	// просто handshake не сошёлся. Таймаут/сеть — смерть.
	class = classifyQUICError(err)
	responded = class != ErrTimeout && class != ErrDNS && class != ErrRefused
	return -1, class, responded, err
}

func classifyQUICError(err error) string {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return ErrTimeout
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "no recent network activity"),
		strings.Contains(s, "handshake did not complete"),
		strings.Contains(s, "i/o timeout"),
		strings.Contains(s, "timeout"):
		return ErrTimeout
	case strings.Contains(s, "no such host"):
		return ErrDNS
	case strings.Contains(s, "connection refused"), strings.Contains(s, "unreachable"):
		return ErrRefused
	}
	return ErrOther // TLS alert / version / ALPN — сервер ответил
}

// ---------------- этап 3: полный тест через HY2-туннель ----------------

const (
	gstaticHost    = "www.gstatic.com"
	gstaticPath    = "/generate_204"
	cloudflareHost = "www.cloudflare.com"
	cloudflarePath = "/cdn-cgi/trace"
	geoipHost      = "ip-api.com"
	geoipPath      = "/json/?fields=status,country,countryCode,query"
)

// httpClientFromSpec создаёт реальный HY2-клиент по спеке (тот же путь,
// что и рабочий драйвер туннеля).
// dialHY2 поднимает HY2-клиент с жёстким таймаутом: библиотека не принимает
// context, поэтому ждём в горутине и бросаем попытку по deadline.
func dialHY2(spec ServerSpec, timeout time.Duration) (hyClient.Client, error) {
	type dialResult struct {
		cli hyClient.Client
		err error
	}
	ch := make(chan dialResult, 1)
	go func() {
		cli, err := newHY2Client(spec)
		ch <- dialResult{cli, err}
	}()
	select {
	case r := <-ch:
		return r.cli, r.err
	case <-time.After(timeout):
		// соединение может established позже — закрываем, чтобы не текло
		go func() {
			if r := <-ch; r.cli != nil {
				_ = r.cli.Close()
			}
		}()
		return nil, fmt.Errorf("handshake: таймаут %s", timeout.Round(time.Millisecond))
	}
}

func newHY2Client(spec ServerSpec) (hyClient.Client, error) {
	if spec.Auth == "" {
		return nil, fmt.Errorf("%s: пустой пароль (auth)", ErrConfig)
	}
	port := spec.Port
	if port <= 0 {
		port = 443
	}
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(spec.Host, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	sni := spec.SNI
	if sni == "" {
		sni = spec.Host
	}
	cfg := &hyClient.Config{
		ServerAddr: addr,
		Auth:       spec.Auth,
		TLSConfig: hyClient.TLSConfig{
			ServerName:         sni,
			InsecureSkipVerify: true, // бесплатные узлы: self-signed сертификаты
		},
		QUICConfig: hyClient.QUICConfig{
			InitialStreamReceiveWindow:     2 * 1024 * 1024,
			MaxStreamReceiveWindow:         8 * 1024 * 1024,
			InitialConnectionReceiveWindow: 8 * 1024 * 1024,
			MaxConnectionReceiveWindow:     32 * 1024 * 1024,
			MaxIdleTimeout:                 30 * time.Second,
			KeepAlivePeriod:                10 * time.Second,
		},
	}
	if strings.EqualFold(spec.ObfsType, "salamander") && spec.ObfsPassword != "" {
		cfg.ConnFactory = &probeObfsFactory{psk: []byte(spec.ObfsPassword)}
	}
	cli, _, err := hyClient.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return cli, nil
}

type probeObfsFactory struct{ psk []byte }

func (f *probeObfsFactory) New(_ net.Addr) (net.PacketConn, error) {
	conn, err := listenUDPHooked()
	if err != nil {
		return nil, err
	}
	return obfs.WrapPacketConnSalamander(conn, f.psk)
}

// DialHook — необязательный хук создания сокетов (Control-колбэк net.Dialer /
// net.ListenConfig). На Android через него применяется VpnService.protect(fd),
// чтобы проверочные пакеты не зацикливались в собственный туннель.
// На десктопе — nil (сокеты идут напрямую).
var DialHook func(network, address string, c syscall.RawConn) error

// listenUDPHooked — UDP-сокет с применением DialHook.
func listenUDPHooked() (net.PacketConn, error) {
	lc := net.ListenConfig{Control: DialHook}
	return lc.ListenPacket(context.Background(), "udp", "")
}

// httpTarget — одна цель HTTP-проверки через туннель.
type httpTarget struct {
	host    string
	port    string
	path    string
	wantTLS bool
	// insecure разрешает самоподписанный сертификат цели (локальные тесты).
	insecure bool
}

// tunnelDialTCP — cli.TCP с жёстким таймаутом.
// Библиотечный TCP() блокирующе ждёт ответ сервера на CONNECT без дедлайна,
// а keep-alive не даёт QUIC-соединению умереть по idle-timeout: на сервере,
// который принял auth, но не отвечает на outbound-запросы, это вечный вис.
// По таймауту закрываем весь клиент — зависшая горутина разблокируется.
func tunnelDialTCP(cli hyClient.Client, addr string, timeout time.Duration) (net.Conn, error) {
	type dialRes struct {
		conn net.Conn
		err  error
	}
	ch := make(chan dialRes, 1)
	go func() {
		c, err := cli.TCP(addr)
		ch <- dialRes{c, err}
	}()
	select {
	case r := <-ch:
		return r.conn, r.err
	case <-time.After(timeout):
		_ = cli.Close()
		go func() {
			if r := <-ch; r.conn != nil {
				_ = r.conn.Close()
			}
		}()
		return nil, fmt.Errorf("туннельный dial %s: таймаут %s", addr, timeout.Round(time.Millisecond))
	}
}

// DialFunc открывает TCP-соединение к addr через туннель (с таймаутом).
// Единая точка для всех протоколов: HY2-клиент, sing-box-драйвер и т.п.
type DialFunc func(addr string, timeout time.Duration) (net.Conn, error)

// httpStatusThroughTunnel выполняет один HTTP-запрос через TCP-поток туннеля
// и возвращает код ответа. Задержка измеряется от открытия потока до получения
// статусной строки — это и есть «реальная задержка через туннель» (этап 4).
func httpStatusThroughTunnel(dial DialFunc, t httpTarget, timeout, dialTimeout time.Duration) (status int, ms int, err error) {
	deadline := time.Now().Add(timeout)

	start := time.Now()
	conn, err := dial(net.JoinHostPort(t.host, t.port), dialTimeout)
	if err != nil {
		return 0, -1, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)

	var rw io.ReadWriter = conn
	if t.wantTLS {
		tconn := tls.Client(conn, &tls.Config{
			ServerName:         t.host,
			InsecureSkipVerify: t.insecure,
		})
		if herr := tconn.Handshake(); herr != nil {
			return 0, -1, herr
		}
		rw = tconn
	}

	req := "GET " + t.path + " HTTP/1.1\r\nHost: " + t.host +
		"\r\nUser-Agent: Mozilla/5.0 (FlickerVPN probe)\r\nAccept: */*\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(rw, req); err != nil {
		return 0, -1, err
	}
	br := bufio.NewReader(rw)
	line, err := br.ReadString('\n')
	if err != nil {
		return 0, -1, err
	}
	ms = int(time.Since(start).Milliseconds())
	// "HTTP/1.1 204 No Content"
	parts := strings.Fields(line)
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/") {
		return 0, ms, fmt.Errorf("не-HTTP ответ: %.40q", line)
	}
	status, err = strconv.Atoi(parts[1])
	if err != nil {
		return 0, ms, fmt.Errorf("битый статус: %.40q", line)
	}
	return status, ms, nil
}

// geoIPThroughTunnel — страна exit-IP через ip-api.com (http, free tier).
func geoIPThroughTunnel(dial DialFunc, t httpTarget, timeout, dialTimeout time.Duration) (country, code, ip string, err error) {
	deadline := time.Now().Add(timeout)
	conn, err := dial(net.JoinHostPort(t.host, t.port), dialTimeout)
	if err != nil {
		return "", "", "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)
	req := "GET " + t.path + " HTTP/1.1\r\nHost: " + t.host +
		"\r\nUser-Agent: FlickerVPN\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		return "", "", "", err
	}
	resp, err := readHTTPResponse(conn)
	if err != nil {
		return "", "", "", err
	}
	var j struct {
		Status      string `json:"status"`
		Country     string `json:"country"`
		CountryCode string `json:"countryCode"`
		Query       string `json:"query"`
	}
	if err := json.Unmarshal(resp, &j); err != nil {
		return "", "", "", fmt.Errorf("geoip json: %w", err)
	}
	if j.Status != "success" {
		return "", "", "", fmt.Errorf("geoip status: %s", j.Status)
	}
	return j.Country, j.CountryCode, j.Query, nil
}

// readHTTPResponse — читает ответ до конца (Connection: close) и возвращает тело.
// readHTTPResponse читает статусную строку, заголовки и тело, опираясь на
// Content-Length / Transfer-Encoding. Читать «до EOF» нельзя: туннель не всегда
// закрывает поток, и вместо ответа получается deadline exceeded.
func readHTTPResponse(r io.Reader) ([]byte, error) {
	br := bufio.NewReader(r)

	statusLine, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	parts := strings.Fields(statusLine)
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/") {
		return nil, fmt.Errorf("не-HTTP ответ: %.40q", statusLine)
	}
	statusCode, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("битый статус: %.40q", statusLine)
	}

	contentLength := int64(-1)
	chunked := false
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "" {
			break
		}
		name, value, found := strings.Cut(trimmed, ":")
		if !found {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "content-length":
			if n, cerr := strconv.ParseInt(strings.TrimSpace(value), 10, 64); cerr == nil {
				contentLength = n
			}
		case "transfer-encoding":
			if strings.Contains(strings.ToLower(value), "chunked") {
				chunked = true
			}
		}
	}

	// 204/304 и ответы на HEAD тела не имеют.
	if statusCode == http.StatusNoContent || statusCode == http.StatusNotModified {
		return nil, nil
	}

	switch {
	case chunked:
		body, err := io.ReadAll(io.LimitReader(httputil.NewChunkedReader(br), 64*1024))
		if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
			return nil, err
		}
		return body, nil
	case contentLength >= 0:
		return io.ReadAll(io.LimitReader(br, min64(contentLength, 64*1024)))
	default:
		// длина неизвестна: сервер обязан закрыть соединение; EOF — норма
		body, err := io.ReadAll(io.LimitReader(br, 64*1024))
		if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
			return nil, err
		}
		return body, nil
	}
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func median(vals []int) int {
	if len(vals) == 0 {
		return -1
	}
	cp := append([]int(nil), vals...)
	sort.Ints(cp)
	m := len(cp) / 2
	if len(cp)%2 == 1 {
		return cp[m]
	}
	return (cp[m-1] + cp[m]) / 2
}

// ProbeHTTP — этапы 3+4 для HY2: полное подключение HY2-драйвером и HTTP-тесты.
//
// full:  gstatic 204 × retries (медиана = реальная задержка) + cloudflare trace 200 + GeoIP.
// quick: одна проба gstatic 204.
func ProbeHTTP(ctx context.Context, spec ServerSpec, opts Options, onStage func(StageResult)) Result {
	opts.normalize() // защита от вызова вне Run(): таймауты по умолчанию

	cli, err := dialHY2(spec, time.Duration(opts.HTTPTimeoutMs)*time.Millisecond)
	if err != nil {
		res := Result{
			ID:        spec.ID,
			LatencyMs: -1,
			Stages:    map[string]string{"tcp": "skip", "quic": "skip", "http": "fail", "geoip": "skip"},
		}
		class := ErrOther
		var authErr hyErrors.AuthError
		var connErr hyErrors.ConnectError
		switch {
		case errors.As(err, &authErr):
			class = ErrAuth
		case strings.HasPrefix(err.Error(), ErrConfig):
			class = ErrConfig
		default:
			if errors.As(err, &connErr) {
				err = connErr.Unwrap()
			}
			class = classifyQUICError(err)
			if class == ErrOther {
				class = classifyNetError(err)
			}
		}
		res.ErrClass = class
		res.Error = humanError(class, trimErr(err), spec)
		if onStage != nil {
			onStage(StageResult{ID: spec.ID, Stage: "http", OK: false, Fatal: true, ErrClass: class, Error: res.Error})
		}
		return res
	}
	defer cli.Close()

	dial := func(addr string, timeout time.Duration) (net.Conn, error) {
		return tunnelDialTCP(cli, addr, timeout)
	}
	return runHTTPChecks(spec, dial, opts, onStage)
}

// ProbeSing — этапы 3+4 для TCP/443-стека (vless/trojan/vmess/ss):
// временный драйвер на базе sing-box, через него те же HTTP-проверки.
// Живыми считаются ТОЛЬКО узлы, прошедшие HTTP-over-proxy.
func ProbeSing(ctx context.Context, spec ServerSpec, opts Options, onStage func(StageResult)) Result {
	opts.normalize()

	cfg := singConfigFromSpec(spec)
	drv, err := tunnel.New(cfg, tunnel.Events{}, tunnel.NewCounters())
	if err != nil {
		return singFailure(spec, onStage, ErrConfig, err)
	}
	startCtx, cancel := context.WithTimeout(ctx, time.Duration(opts.HTTPTimeoutMs+3000)*time.Millisecond)
	defer cancel()
	if err := drv.Start(startCtx); err != nil {
		class := classifySingStartError(err)
		return singFailure(spec, onStage, class, err)
	}
	defer func() { _ = drv.Close() }()

	dial := func(addr string, timeout time.Duration) (net.Conn, error) {
		dctx, dcancel := context.WithTimeout(context.Background(), timeout+2*time.Second)
		defer dcancel()
		return drv.DialTCP(dctx, addr)
	}
	return runHTTPChecks(spec, dial, opts, onStage)
}

func singFailure(spec ServerSpec, onStage func(StageResult), class string, err error) Result {
	res := Result{
		ID:        spec.ID,
		LatencyMs: -1,
		Stages:    map[string]string{"tcp": "skip", "quic": "skip", "http": "fail", "geoip": "skip"},
		ErrClass:  class,
		Error:     humanError(class, trimErr(err), spec),
	}
	if onStage != nil {
		onStage(StageResult{ID: spec.ID, Stage: "http", OK: false, Fatal: true, ErrClass: class, Error: res.Error})
	}
	return res
}

// classifySingStartError — ошибки старта sing-драйвера → классы из ТЗ.
// VLESS с неверным uuid / Trojan с неверным пароля: сервер рвёт соединение
// (reset/EOF) — трактуем как ошибку авторизации.
func classifySingStartError(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "no such host"):
		return ErrDNS
	case strings.Contains(s, "connection refused"):
		return ErrRefused
	case strings.Contains(s, "timeout"), strings.Contains(s, "deadline"), strings.Contains(s, "canceled"):
		return ErrTimeout
	case strings.Contains(s, "reset by peer"), strings.Contains(s, "EOF"),
		strings.Contains(s, "handshake failure"), strings.Contains(s, "bad record MAC"),
		strings.Contains(s, "unknown certificate"), strings.Contains(s, "access denied"):
		return ErrAuth
	}
	return ErrOther
}

// singConfigFromSpec — конфиг драйвера из пробы-спеки.
func singConfigFromSpec(spec ServerSpec) *config.ServerConfig {
	cfg := &config.ServerConfig{
		Protocol:    spec.Protocol,
		Server:      spec.Host,
		Port:        spec.Port,
		UUID:        spec.UUID,
		Auth:        spec.Auth,
		Cipher:      spec.Cipher,
		Flow:        spec.Flow,
		Fingerprint: spec.Fingerprint,
	}
	// TLS включается ТОЛЬКО если ссылка это предусматривает: security=none
	// у vless/vmess означает голый TCP, и любой «verify по умолчанию» ломает
	// подключение к plain-серверу.
	if spec.TLSEnabled {
		cfg.SNI = spec.SNI
		cfg.TLS = config.TLSConfig{Verify: !spec.Insecure, Insecure: spec.Insecure}
	}
	if spec.RealityPBK != "" {
		cfg.Reality = &config.RealityClientConfig{
			PublicKey: spec.RealityPBK,
			ShortID:   spec.RealitySID,
		}
	}
	if spec.TransportType != "" {
		cfg.Transport = &config.TransportConfig{
			Type:        spec.TransportType,
			Path:        spec.TransportPath,
			Host:        spec.TransportHost,
			ServiceName: spec.TransportSvcNm,
		}
	}
	if cfg.Protocol == "trojan" || cfg.Protocol == "shadowsocks" {
		// у этих протоколов секрет — в auth
		cfg.Auth = spec.Auth
	}
	return cfg
}

// runHTTPChecks — общие HTTP-проверки через туннель (этапы 3+4):
// gstatic 204 × retries (медиана), cloudflare trace 200 (full), GeoIP.
func runHTTPChecks(spec ServerSpec, dial DialFunc, opts Options, onStage func(StageResult)) Result {
	res := Result{
		ID:     spec.ID,
		Stages: map[string]string{"tcp": "skip", "quic": "skip", "http": "skip", "geoip": "skip"},
	}
	res.Stages["http"] = "fail"

	retries := opts.HTTPRetries
	if opts.Mode == "quick" {
		retries = 1
	}
	httpTimeout := time.Duration(opts.HTTPTimeoutMs) * time.Millisecond
	dialTimeout := time.Duration(opts.DialTimeoutMs) * time.Millisecond
	tg := opts.targets()

	gstatic := httpTarget{host: tg.GstaticHost, port: tg.GstaticPort, path: tg.GstaticPath}
	cloudflare := httpTarget{host: tg.CloudflareHost, port: tg.CloudflarePort, path: tg.CloudflarePath, wantTLS: true, insecure: tg.InsecureTLS}
	geoip := httpTarget{host: tg.GeoIPHost, port: tg.GeoIPPort, path: tg.GeoIPPath}

	// --- gstatic 204: несколько проб, медиана ---
	var samples []int
	gstaticOK := false
	var lastErr error
	for i := 0; i < retries; i++ {
		status, ms, err := httpStatusThroughTunnel(dial, gstatic, httpTimeout, dialTimeout)
		if err != nil {
			lastErr = err
			continue
		}
		if status != 204 {
			lastErr = fmt.Errorf("gstatic вернул %d, ожидали 204", status)
			continue
		}
		gstaticOK = true
		samples = append(samples, ms)
	}
	if gstaticOK {
		res.LatencyMs = median(samples)
	}

	// --- cloudflare trace 200 (только full: вторая независимая цель) ---
	cfOK := opts.Mode == "quick"
	var cfErr error
	if opts.Mode != "quick" {
		status, _, err := httpStatusThroughTunnel(dial, cloudflare, httpTimeout, dialTimeout)
		if err != nil {
			cfErr = err
		} else if status != 200 {
			cfErr = fmt.Errorf("cloudflare вернул %d, ожидали 200", status)
		} else {
			cfOK = true
		}
	}

	// --- GeoIP по exit IP ---
	if opts.geoIPEnabled() && gstaticOK && cfOK {
		country, code, ip, err := geoIPThroughTunnel(dial, geoip, time.Duration(opts.GeoIPTimeoutMs)*time.Millisecond, dialTimeout)
		if err == nil {
			res.Country = country
			res.CountryCode = code
			res.ExitIP = ip
			res.Stages["geoip"] = "ok"
			if onStage != nil {
				onStage(StageResult{ID: spec.ID, Stage: "geoip", OK: true})
			}
		} else {
			res.Stages["geoip"] = "fail"
			if onStage != nil {
				onStage(StageResult{ID: spec.ID, Stage: "geoip", OK: false, Error: trimErr(err)})
			}
		}
	}

	alive := gstaticOK && cfOK
	res.Alive = alive
	if alive {
		res.Stages["http"] = "ok"
	} else {
		res.ErrClass = ErrHTTP
		detail := ""
		if !gstaticOK && lastErr != nil {
			detail = trimErr(lastErr)
		} else if !cfOK && cfErr != nil {
			detail = trimErr(cfErr)
		}
		res.Error = humanError(ErrHTTP, detail, spec)
	}
	if onStage != nil {
		onStage(StageResult{
			ID: spec.ID, Stage: "http", OK: alive, Fatal: !alive,
			LatencyMs: res.LatencyMs, ErrClass: res.ErrClass, Error: res.Error,
		})
	}
	return res
}

func trimErr(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return s
}

// ---------------- оркестрация ----------------

// Run прогоняет все спеки через pipeline с ограничением параллелизма.
// onStage вызывается из воркеров для каждого этапа (может быть nil).
func Run(ctx context.Context, specs []ServerSpec, opts Options, onStage func(StageResult)) []Result {
	opts.normalize()
	if onStage == nil {
		onStage = func(StageResult) {}
	}

	results := make([]Result, len(specs))
	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup

	for i, spec := range specs {
		if ctx.Err() != nil {
			break
		}
		if spec.ID == "" {
			spec.ID = fmt.Sprintf("%s:%d#%d", spec.Host, spec.Port, i)
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, spec ServerSpec) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = runOne(ctx, spec, opts, onStage)
		}(i, spec)
	}
	wg.Wait()
	return results
}

func runOne(ctx context.Context, spec ServerSpec, opts Options, onStage func(StageResult)) Result {
	base := Result{
		ID:        spec.ID,
		LatencyMs: -1,
		Stages:    map[string]string{"tcp": "skip", "quic": "skip", "http": "skip", "geoip": "skip"},
	}
	if spec.Host == "" || spec.Port <= 0 || spec.Port > 65535 {
		base.ErrClass = ErrConfig
		base.Error = humanError(ErrConfig, "host/port", spec)
		base.Stages["tcp"], base.Stages["quic"], base.Stages["http"] = "fail", "fail", "fail"
		onStage(StageResult{ID: spec.ID, Stage: "tcp", OK: false, Fatal: true, ErrClass: ErrConfig, Error: base.Error})
		return base
	}

	// --- Этап 1: TCP reachability ---
	if !opts.SkipTCP {
		tctx, cancel := context.WithTimeout(ctx, time.Duration(opts.TCPTimeoutMs)*time.Millisecond+500*time.Millisecond)
		ms, class, err := ProbeTCP(tctx, spec.Host, spec.Port, time.Duration(opts.TCPTimeoutMs)*time.Millisecond)
		cancel()
		// Для HY2 (UDP/QUIC) фатален только DNS-провал: TCP-refused/timeout
		// на этом порту ничего не значит (сервер вправе не слушать TCP).
		// Для TCP-протоколов (vless/trojan/...) TCP-стадия — полноценный
		// фильтр: refused/timeout означают смерть.
		fatal := class == ErrDNS ||
			(spec.isTCPProtocol() && (class == ErrRefused || class == ErrTimeout))
		ok := err == nil
		base.TcpMs = ms
		if ok {
			base.Stages["tcp"] = "ok"
		} else {
			base.Stages["tcp"] = "fail"
		}
		sr := StageResult{ID: spec.ID, Stage: "tcp", OK: ok, Fatal: fatal, LatencyMs: ms, ErrClass: class}
		if !ok {
			sr.Error = humanError(class, trimErr(err), spec)
		}
		onStage(sr)
		if fatal {
			base.ErrClass = class
			base.Error = sr.Error
			base.Stages["quic"], base.Stages["http"] = "skip", "skip"
			return base
		}
	}

	// --- Этап 2: QUIC prescan (только HY2; TCP-протоколы пропускают) ---
	if !opts.SkipQUIC && !spec.isTCPProtocol() {
		qctx, cancel := context.WithTimeout(ctx, time.Duration(opts.QUICTimeoutMs)*time.Millisecond+1500*time.Millisecond)
		ms, class, responded, err := ProbeQUIC(qctx, spec, time.Duration(opts.QUICTimeoutMs)*time.Millisecond)
		cancel()
		// «responded» — сервер ответил на QUIC (пусть и ошибкой TLS/ALPN):
		// значит порт слушает именно QUIC, и презумпция живости переходит к этапу 3.
		alive := err == nil || responded
		base.QuicMs = ms
		if alive {
			base.Stages["quic"] = "ok"
		} else {
			base.Stages["quic"] = "fail"
		}
		sr := StageResult{ID: spec.ID, Stage: "quic", OK: alive, Fatal: !alive, ErrClass: class}
		if !alive {
			sr.Error = humanError(class, trimErr(err), spec)
			base.ErrClass = class
			base.Error = sr.Error
		}
		onStage(sr)
		if !alive {
			return base
		}
	}

	// --- Этапы 3+4: HTTP через туннель + медиана задержки ---
	if opts.SkipHTTP {
		base.Alive = true // дошли сюда без фаталов — считаем условно живым
		base.Stages["http"] = "skip"
		return base
	}
	var res Result
	if spec.isTCPProtocol() {
		res = ProbeSing(ctx, spec, opts, onStage)
	} else {
		res = ProbeHTTP(ctx, spec, opts, onStage)
	}
	res.TcpMs = base.TcpMs
	res.QuicMs = base.QuicMs
	res.Stages["tcp"], res.Stages["quic"] = base.Stages["tcp"], base.Stages["quic"]
	return res
}

// Best — сортировка результатов: живые первыми по возрастанию задержки.
func Best(results []Result) []Result {
	out := append([]Result(nil), results...)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Alive != b.Alive {
			return a.Alive
		}
		la, lb := a.LatencyMs, b.LatencyMs
		if la < 0 {
			la = 1 << 30
		}
		if lb < 0 {
			lb = 1 << 30
		}
		return la < lb
	})
	return out
}
