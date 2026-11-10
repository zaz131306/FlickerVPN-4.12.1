// SPDX-License-Identifier: GPL-3.0-or-later
// (в составе бинарника flicker-host — производное от sing-box, см. LICENSE-NOTES.md и COPYING)
package tunnel

// sing.go — драйвер на базе встроенного sing-box (GPL-3.0).
//
// Покрывает TCP/443-стек маскировки:
//   - VLESS + Reality (+ Vision flow, uTLS-фингерпринты, ws/grpc-транспорты);
//   - Trojan (TLS);
//   - VMess, Shadowsocks;
//   - WireGuard, включая «матрёшку»: WG-пакеты туннелируются через
//     VLESS/Trojan-детур (endpoint wireguard + detour → outbound vless).
//
// Архитектура: на каждый туннель поднимается экземпляр sing-box с
// внутренним SOCKS5-inbound на ephemeral-порту 127.0.0.1. Driver.DialTCP
// выполняет SOCKS5-CONNECT к этому порту, поэтому sing-box встраивается в
// существующую цепочку «расширение → flicker-host SOCKS5 :1080 → драйвер»
// без изменения остального кода.

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"

	"flicker-vpn/native/internal/config"
	"flicker-vpn/native/internal/singcfg"
	"flicker-vpn/native/internal/singreg"
)

type singDriver struct {
	cfg      *config.ServerConfig
	ev       Events
	counters *Counters
	rtt      rttTracker
	dropped  atomic.Uint64

	mu        sync.Mutex
	box       *box.Box
	cancelBox context.CancelFunc
	socksPort uint16
	closed    bool
}

func newSingDriver(cfg *config.ServerConfig, ev Events, counters *Counters) (Driver, error) {
	if err := validateSingConfig(cfg); err != nil {
		return nil, err
	}
	return &singDriver{cfg: cfg, ev: ev, counters: counters}, nil
}

func (d *singDriver) Name() string { return d.cfg.Protocol }

func validateSingConfig(cfg *config.ServerConfig) error {
	switch cfg.Protocol {
	case "vless", "vmess":
		if cfg.UUID == "" {
			return fmt.Errorf("%s: UUID обязателен", cfg.Protocol)
		}
	case "trojan", "shadowsocks":
		if cfg.Auth == "" {
			return fmt.Errorf("%s: пароль обязателен", cfg.Protocol)
		}
	case "wireguard":
		if cfg.WireGuard == nil || cfg.WireGuard.PrivateKey == "" || cfg.WireGuard.PeerPublicKey == "" {
			return errors.New("wireguard: privateKey и peerPublicKey обязательны")
		}
	default:
		return fmt.Errorf("sing: неподдерживаемый протокол %q", cfg.Protocol)
	}
	return nil
}

// ---------- генерация конфига sing-box ----------

func freeLocalPort() (uint16, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := uint16(l.Addr().(*net.TCPAddr).Port)
	_ = l.Close()
	return port, nil
}

func (d *singDriver) buildOptions(socksPort uint16) (*option.Options, error) {
	optsJSON := d.buildConfigJSON(socksPort)
	ctx := singreg.Context(context.Background())
	opts, err := singjson.UnmarshalExtendedContext[option.Options](ctx, []byte(optsJSON))
	if err != nil {
		return nil, fmt.Errorf("sing: разбор сгенерированного конфига: %w", err)
	}
	return &opts, nil
}

func (d *singDriver) buildConfigJSON(socksPort uint16) string {
	cfg := d.cfg

	inbound := map[string]any{
		"type": "socks", "tag": "flicker-in",
		"listen": "127.0.0.1", "listen_port": socksPort,
	}

	built := singcfg.Build(cfg)
	outbounds := append(built.Outbounds, map[string]any{"type": "direct", "tag": "flicker-direct"})

	logOpts := map[string]any{"disabled": true}
	if os.Getenv("FLICKER_SING_LOG") != "" {
		logOpts = map[string]any{
			"level":  "debug",
			"output": os.Getenv("FLICKER_SING_LOG"),
		}
	}
	full := map[string]any{
		"log":       logOpts,
		"inbounds":  []map[string]any{inbound},
		"outbounds": outbounds,
		"route": map[string]any{
			"final":                 built.Final,
			"auto_detect_interface": false,
		},
	}
	if len(built.Endpoints) > 0 {
		full["endpoints"] = built.Endpoints
	}
	b, err := json.Marshal(full)
	if err != nil {
		panic(err) // map[string]any маршализуется всегда
	}
	return string(b)
}

// ---------- жизненный цикл ----------

func (d *singDriver) Start(ctx context.Context) error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return errors.New("sing: драйвер закрыт")
	}
	d.mu.Unlock()

	port := uint16(d.cfg.InternalPort)
	if port == 0 {
		var err error
		if port, err = freeLocalPort(); err != nil {
			return fmt.Errorf("sing: нет свободного локального порта: %w", err)
		}
	}
	opts, err := d.buildOptions(port)
	if err != nil {
		return err
	}

	// box.New получает ctx вызывающей стороны. Если тот отменится (например,
	// context.WithTimeout у startTunnel истечёт), sing-box закроет туннель —
	// поэтому берём производный контекст без дедлайна и управляем закрытием
	// сами через Close().
	bctx, cancelBox := context.WithCancel(singreg.Context(context.WithoutCancel(ctx)))
	b, err := box.New(box.Options{Options: *opts, Context: bctx})
	if err != nil {
		cancelBox()
		return fmt.Errorf("sing: создание экземпляра: %w", err)
	}

	if d.ev.OnStatus != nil {
		d.ev.OnStatus("connecting", "")
	}
	start := time.Now()
	if err := b.Start(); err != nil {
		cancelBox()
		return fmt.Errorf("sing: старт: %w", err)
	}

	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		_ = b.Close()
		cancelBox()
		return errors.New("sing: драйвер закрыт во время старта")
	}
	d.box = b
	d.cancelBox = cancelBox
	d.socksPort = port
	d.mu.Unlock()

	// Контрольное рукопожатие: TCP-доступность сервера (или детура).
	// VLESS/Reality-соединение устанавливается лениво на первый запрос,
	// поэтому проверяем базовую достижимость до включения прокси браузера.
	if err := d.smokeCheck(ctx); err != nil {
		_ = b.Close()
		d.mu.Lock()
		d.box = nil
		cb := d.cancelBox
		d.cancelBox = nil
		d.mu.Unlock()
		if cb != nil {
			cb()
		}
		if d.ev.OnError != nil {
			d.ev.OnError(err)
		}
		return err
	}
	d.rtt.Observe(time.Since(start))

	if d.ev.OnStatus != nil {
		d.ev.OnStatus("connected", "")
	}
	return nil
}

// smokeCheck — быстрый TCP-handshake до сервера (или детура) напрямую:
// отсекает «сервер не отвечает» до того, как браузер начнёт ходить через SOCKS.
// Для прямого WireGuard (без детура) неприменим: endpoint говорит по UDP.
func (d *singDriver) smokeCheck(ctx context.Context) error {
	if d.cfg.Protocol == "wireguard" && d.cfg.Detour == nil {
		return nil
	}
	host := d.cfg.Server
	port := d.cfg.Port
	if d.cfg.Detour != nil {
		host = d.cfg.Detour.Server
		port = d.cfg.Detour.Port
	}
	t := time.Now()
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var lc net.Dialer
	conn, err := lc.DialContext(dialCtx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		d.dropped.Add(1)
		return fmt.Errorf("sing: сервер %s:%d недоступен: %w", host, port, err)
	}
	_ = conn.Close()
	d.rtt.Observe(time.Since(t))
	return nil
}

func (d *singDriver) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	d.mu.Lock()
	b, port := d.box, d.socksPort
	d.mu.Unlock()
	if b == nil {
		return nil, errors.New("sing: туннель не установлен")
	}
	start := time.Now()
	conn, err := socks5DialContext(ctx, "127.0.0.1:"+strconv.Itoa(int(port)), addr)
	if err != nil {
		d.dropped.Add(1)
		return nil, err
	}
	d.rtt.Observe(time.Since(start))
	return &countedConn{Conn: conn, counters: d.counters}, nil
}

func (d *singDriver) NewUDPSession(ctx context.Context) (UDPSession, error) {
	d.mu.Lock()
	b, port := d.box, d.socksPort
	d.mu.Unlock()
	if b == nil {
		return nil, errors.New("sing: туннель не установлен")
	}
	return newSocks5UDPSession(ctx, "127.0.0.1:"+strconv.Itoa(int(port)))
}

func (d *singDriver) RTT() time.Duration { return d.rtt.rtt() }
func (d *singDriver) Dropped() uint64    { return d.dropped.Load() }

func (d *singDriver) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	if d.box != nil {
		err := d.box.Close()
		d.box = nil
		if d.cancelBox != nil {
			d.cancelBox()
			d.cancelBox = nil
		}
		return err
	}
	return nil
}

// countedConn — учитывает байты прикладного уровня в общих счётчиках хоста.
type countedConn struct {
	net.Conn
	counters *Counters
}

func (c *countedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.counters.AddRecv(int64(n))
	}
	return n, err
}

func (c *countedConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.counters.AddSent(int64(n))
	}
	return n, err
}

// ---------- минимальный SOCKS5-клиент к внутреннему порту sing-box ----------

func socks5DialContext(ctx context.Context, proxy, target string) (net.Conn, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", proxy)
	if err != nil {
		return nil, err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(15 * time.Second)
	}
	_ = conn.SetDeadline(deadline)

	// greeting: одна версия — без авторизации
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		_ = conn.Close()
		return nil, err
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5 greeting: %w", err)
	}
	if buf[0] != 0x05 || buf[1] != 0x00 {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5: сервер отказал в методе авторизации (%#x)", buf[1])
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5: цель %q: %w", target, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5: порт цели %q", portStr)
	}

	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, 0x01)
			req = append(req, v4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			_ = conn.Close()
			return nil, errors.New("socks5: слишком длинное имя хоста")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(port))
	req = append(req, pb[:]...)
	if _, err := conn.Write(req); err != nil {
		_ = conn.Close()
		return nil, err
	}

	resp := make([]byte, 4)
	if _, err := io.ReadFull(conn, resp); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5 connect: %w", err)
	}
	if resp[0] != 0x05 {
		_ = conn.Close()
		return nil, errors.New("socks5: битый ответ")
	}
	if resp[1] != 0x00 {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5: connect отклонён (код %#x)", resp[1])
	}
	// пропускаем BND.ADDR + BND.PORT
	switch resp[3] {
	case 0x01:
		_, err = io.CopyN(io.Discard, conn, 4+2)
	case 0x04:
		_, err = io.CopyN(io.Discard, conn, 16+2)
	case 0x03:
		lb := make([]byte, 1)
		if _, err = io.ReadFull(conn, lb); err == nil {
			_, err = io.CopyN(io.Discard, conn, int64(lb[0])+2)
		}
	default:
		err = errors.New("socks5: неизвестный тип адреса")
	}
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// ---------- SOCKS5 UDP ASSOCIATE ----------

type socks5UDPSession struct {
	tcp    net.Conn
	udp    *net.UDPConn
	relay  netip.AddrPort
	closed atomic.Bool
}

func newSocks5UDPSession(ctx context.Context, proxy string) (UDPSession, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", proxy)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		_ = conn.Close()
		return nil, err
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil || buf[1] != 0 {
		_ = conn.Close()
		return nil, errors.New("socks5 udp: greeting")
	}
	// ASSOCIATE: клиентский адрес не важен (loopback)
	req := append([]byte{0x05, 0x03, 0x00, 0x01}, 127, 0, 0, 1, 0, 0)
	if _, err := conn.Write(req); err != nil {
		_ = conn.Close()
		return nil, err
	}
	resp := make([]byte, 10)
	if _, err := io.ReadFull(conn, resp); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if resp[1] != 0 || resp[3] != 1 {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5 udp: associate отклонён (%#x)", resp[1])
	}
	relayAddr := netip.AddrPortFrom(
		netip.AddrFrom4([4]byte{resp[4], resp[5], resp[6], resp[7]}),
		binary.BigEndian.Uint16(resp[8:10]))
	if relayAddr.Addr().IsUnspecified() {
		relayAddr = netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), relayAddr.Port())
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	s := &socks5UDPSession{tcp: conn, udp: udp, relay: relayAddr}
	// держим TCP-контроль живым: если закроется — закроем и UDP
	go func() {
		_, _ = io.Copy(io.Discard, conn)
		if !s.closed.Load() {
			_ = s.Close()
		}
	}()
	return s, nil
}

func (s *socks5UDPSession) WriteTo(p []byte, addr string) (int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, err
	}
	frame := make([]byte, 0, len(p)+10)
	frame = append(frame, 0x00, 0x00, 0x00) // RSV + FRAG
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			frame = append(frame, 0x01)
			frame = append(frame, v4...)
		} else {
			frame = append(frame, 0x04)
			frame = append(frame, ip.To16()...)
		}
	} else {
		frame = append(frame, 0x03, byte(len(host)))
		frame = append(frame, host...)
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(port))
	frame = append(frame, pb[:]...)
	frame = append(frame, p...)
	ra := net.UDPAddrFromAddrPort(s.relay)
	n, err := s.udp.WriteTo(frame, ra)
	if err != nil {
		return 0, err
	}
	return n - (len(frame) - len(p)), nil
}

func (s *socks5UDPSession) ReadFrom() ([]byte, string, error) {
	buf := make([]byte, 64*1024)
	for {
		n, _, err := s.udp.ReadFrom(buf)
		if err != nil {
			return nil, "", err
		}
		if n < 10 || buf[3] != 0x01 {
			continue
		}
		addr := netip.AddrFrom4([4]byte{buf[4], buf[5], buf[6], buf[7]})
		port := binary.BigEndian.Uint16(buf[8:10])
		payload := make([]byte, n-10)
		copy(payload, buf[10:n])
		return payload, netip.AddrPortFrom(addr, port).String(), nil
	}
}

func (s *socks5UDPSession) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	e1 := s.udp.Close()
	e2 := s.tcp.Close()
	if e1 != nil {
		return e1
	}
	return e2
}
