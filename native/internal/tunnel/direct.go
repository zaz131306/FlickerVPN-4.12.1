package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"flicker-vpn/native/internal/config"
)

func errUnknownProtocol(p string) error {
	return fmt.Errorf("неизвестный протокол: %q", p)
}

// ---------------- direct driver (диагностика, stdlib-only) ----------------

type directDriver struct {
	cfg      *config.ServerConfig
	ev       Events
	counters *Counters
	rtt      rttTracker
	dropped  atomic.Uint64
	dialer   *net.Dialer

	mu     sync.Mutex
	closed bool
}

func newDirectDriver(cfg *config.ServerConfig, ev Events, counters *Counters) Driver {
	return &directDriver{
		cfg:      cfg,
		ev:       ev,
		counters: counters,
		dialer: &net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		},
	}
}

func (d *directDriver) Name() string { return "direct" }

func (d *directDriver) Start(ctx context.Context) error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return errors.New("driver закрыт")
	}
	d.mu.Unlock()
	if d.ev.OnStatus != nil {
		d.ev.OnStatus("connected", "")
	}
	return nil
}

func (d *directDriver) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	start := time.Now()
	conn, err := d.dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		d.dropped.Add(1)
		return nil, err
	}
	d.rtt.Observe(time.Since(start))
	return conn, nil
}

func (d *directDriver) NewUDPSession(ctx context.Context) (UDPSession, error) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		d.dropped.Add(1)
		return nil, err
	}
	return &directUDPSession{pc: pc}, nil
}

func (d *directDriver) RTT() time.Duration { return d.rtt.rtt() }
func (d *directDriver) Dropped() uint64    { return d.dropped.Load() }
func (d *directDriver) Close() error {
	d.mu.Lock()
	d.closed = true
	d.mu.Unlock()
	return nil
}

type directUDPSession struct {
	pc net.PacketConn
}

func (s *directUDPSession) WriteTo(p []byte, addr string) (int, error) {
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return 0, err
	}
	return s.pc.WriteTo(p, raddr)
}

func (s *directUDPSession) ReadFrom() ([]byte, string, error) {
	buf := make([]byte, 65535)
	n, raddr, err := s.pc.ReadFrom(buf)
	if err != nil {
		return nil, "", err
	}
	return buf[:n], raddr.String(), nil
}

func (s *directUDPSession) Close() error { return s.pc.Close() }

func registeredDrivers() []string {
	return []string{"direct", "hysteria2", "vless", "trojan", "vmess", "shadowsocks", "wireguard"}
}
