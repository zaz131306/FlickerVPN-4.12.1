// Package tunnel — абстракция транспортного драйвера туннеля.
//
// Архитектура (исправление ТЗ: в ТЗ весь код был в одном main, драйверы
// перемешаны с SOCKS5 и NM-циклом):
//
//	SOCKS5 (internal/socks5)  ->  Driver (этот пакет)  ->  сеть
//
// Драйвер реализует DialTCP / NewUDPSession поверх конкретного протокола.
package tunnel

import (
	"context"
	"net"
	"sync/atomic"
	"time"

	"flicker-vpn/native/internal/config"
)

// UDPSession — сессия дейтаграмм через туннель (аналог net.PacketConn,
// но адресация строками "host:port").
type UDPSession interface {
	// WriteTo отправляет дейтаграмму на удалённый адрес через туннель.
	WriteTo(p []byte, addr string) (int, error)
	// ReadFrom читает входящую дейтаграмму; возвращает данные и адрес источника.
	ReadFrom() (p []byte, addr string, err error)
	Close() error
}

// Events — обратные вызовы драйвера в host-цикл.
type Events struct {
	// OnStatus вызывается при смене состояния туннеля:
	// "connecting" | "connected" | "disconnected".
	OnStatus func(status string, reason string)
	// OnError — фатальные ошибки транспорта.
	OnError func(err error)
}

// Driver — транспортный драйвер протокола.
type Driver interface {
	Name() string
	// Start устанавливает транспорт (может быть асинхронным: статус придёт в Events).
	Start(ctx context.Context) error
	// DialTCP открывает TCP-подобное соединение к addr через туннель.
	DialTCP(ctx context.Context, addr string) (net.Conn, error)
	// NewUDPSession открывает UDP-сессию через туннель.
	NewUDPSession(ctx context.Context) (UDPSession, error)
	// RTT — скользящая средняя задержки установления потока.
	RTT() time.Duration
	// Dropped — счётчик неудачных dial/записей.
	Dropped() uint64
	Close() error
}

// Counters — атомарные счётчики трафика (байты прикладного уровня).
type Counters struct {
	sent atomic.Uint64
	recv atomic.Uint64
}

func NewCounters() *Counters { return &Counters{} }

func (c *Counters) AddSent(n int64) { c.sent.Add(uint64(max(n, 0))) }
func (c *Counters) AddRecv(n int64) { c.recv.Add(uint64(max(n, 0))) }
func (c *Counters) Sent() uint64    { return c.sent.Load() }
func (c *Counters) Recv() uint64    { return c.recv.Load() }
func (c *Counters) Reset()          { c.sent.Store(0); c.recv.Store(0) }

// rttTracker — экспоненциальное скользящее среднее RTT.
type rttTracker struct {
	mu    atomic.Uint64 // хранит time.Duration как uint64 (нс)
	count atomic.Uint64
}

func (t *rttTracker) Observe(d time.Duration) {
	for {
		old := t.rtt().Nanoseconds()
		var next int64
		if old == 0 {
			next = d.Nanoseconds()
		} else {
			// EMA alpha = 0.25
			next = old + (d.Nanoseconds()-old)/4
		}
		if t.mu.CompareAndSwap(uint64(old), uint64(next)) {
			t.count.Add(1)
			return
		}
	}
}

func (t *rttTracker) rtt() time.Duration { return time.Duration(t.mu.Load()) }

// Drivers возвращает список имён доступных в этой сборке драйверов.
func Drivers() []string { return registeredDrivers() }

// New создаёт драйвер по протоколу конфига.
func New(cfg *config.ServerConfig, ev Events, counters *Counters) (Driver, error) {
	switch cfg.Protocol {
	case "direct":
		return newDirectDriver(cfg, ev, counters), nil
	case "hysteria2":
		// запасной UDP/QUIC-протокол (скрыт из дефолтного UI)
		return newHysteria2Driver(cfg, ev, counters)
	case "vless", "trojan", "vmess", "shadowsocks", "wireguard":
		// TCP/443-стек: sing-box (VLESS+Reality+Vision, Trojan, VMess, SS,
		// WireGuard включая «матрёшку» через detour)
		return newSingDriver(cfg, ev, counters)
	default:
		return nil, errUnknownProtocol(cfg.Protocol)
	}
}
