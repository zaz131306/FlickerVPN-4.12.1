package tunnel

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	hyClient "github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/extras/v2/obfs"

	"flicker-vpn/native/internal/config"
)

// ---------------- Hysteria 2 driver (реальный QUIC-транспорт) ----------------

type hy2Driver struct {
	cfg      *config.ServerConfig
	ev       Events
	counters *Counters
	rtt      rttTracker
	dropped  atomic.Uint64

	mu     sync.Mutex
	client hyClient.Client
	closed bool
}

func newHysteria2Driver(cfg *config.ServerConfig, ev Events, counters *Counters) (Driver, error) {
	if cfg.Auth == "" {
		return nil, errors.New("hysteria2: пароль (auth) обязателен")
	}
	return &hy2Driver{cfg: cfg, ev: ev, counters: counters}, nil
}

func (d *hy2Driver) Name() string { return "hysteria2" }

// obfsConnFactory — фабрикует UDP-соединения, обёрнутые в Salamander obfs.
type obfsConnFactory struct {
	psk []byte
}

func (f *obfsConnFactory) New(_ net.Addr) (net.PacketConn, error) {
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	if f.psk == nil {
		return conn, nil
	}
	return obfs.WrapPacketConnSalamander(conn, f.psk)
}

func loadRootCAs(certs []string) (*x509.CertPool, error) {
	if len(certs) == 0 {
		return nil, nil
	}
	pool := x509.NewCertPool()
	for _, c := range certs {
		var pem []byte
		if strings.Contains(c, "-----BEGIN") {
			pem = []byte(c)
		} else {
			b, err := os.ReadFile(c)
			if err != nil {
				return nil, fmt.Errorf("hysteria2: сертификат %q: %w", c, err)
			}
			pem = b
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("hysteria2: некорректный PEM сертификата %q", c)
		}
	}
	return pool, nil
}

func (d *hy2Driver) Start(ctx context.Context) error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return errors.New("hysteria2: драйвер закрыт")
	}
	d.mu.Unlock()

	addr, err := net.ResolveUDPAddr("udp", d.cfg.Addr())
	if err != nil {
		return fmt.Errorf("hysteria2: resolve %s: %w", d.cfg.Addr(), err)
	}

	rootCAs, err := loadRootCAs(d.cfg.TLS.Certificates)
	if err != nil {
		return err
	}

	hyCfg := &hyClient.Config{
		ServerAddr: addr,
		Auth:       d.cfg.Auth,
		TLSConfig: hyClient.TLSConfig{
			ServerName:         d.cfg.SNIToUse(),
			InsecureSkipVerify: d.cfg.TLS.Insecure || !d.cfg.TLS.Verify,
			RootCAs:            rootCAs,
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

	// Конgestion control: bbr / cubic
	switch strings.ToLower(d.cfg.Congestion.Type) {
	case "bbr":
		hyCfg.CongestionConfig = hyClient.CongestionConfig{Type: "bbr"}
	case "cubic":
		hyCfg.CongestionConfig = hyClient.CongestionConfig{Type: "cubic"}
	}

	// Полоса пропускания (Mbps -> bytes/s)
	if d.cfg.Congestion.UpMbps > 0 {
		hyCfg.BandwidthConfig.MaxTx = uint64(d.cfg.Congestion.UpMbps) * 1_000_000 / 8
	}
	if d.cfg.Congestion.DownMbps > 0 {
		hyCfg.BandwidthConfig.MaxRx = uint64(d.cfg.Congestion.DownMbps) * 1_000_000 / 8
	}

	// Salamander obfs
	if strings.EqualFold(d.cfg.Obfs.Type, "salamander") && d.cfg.Obfs.Password != "" {
		hyCfg.ConnFactory = &obfsConnFactory{psk: []byte(d.cfg.Obfs.Password)}
	}

	if d.ev.OnStatus != nil {
		d.ev.OnStatus("connecting", "")
	}

	start := time.Now()
	cli, _, err := hyClient.NewClient(hyCfg)
	if err != nil {
		d.dropped.Add(1)
		if d.ev.OnError != nil {
			d.ev.OnError(fmt.Errorf("hysteria2: handshake с %s не удался: %w", d.cfg.Addr(), err))
		}
		return fmt.Errorf("hysteria2: handshake: %w", err)
	}
	d.rtt.Observe(time.Since(start))

	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		_ = cli.Close()
		return errors.New("hysteria2: драйвер закрыт во время handshake")
	}
	d.client = cli
	d.mu.Unlock()

	if d.ev.OnStatus != nil {
		d.ev.OnStatus("connected", "")
	}
	return nil
}

func (d *hy2Driver) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	d.mu.Lock()
	cli := d.client
	d.mu.Unlock()
	if cli == nil {
		return nil, errors.New("hysteria2: туннель не установлен")
	}
	start := time.Now()
	conn, err := cli.TCP(addr)
	if err != nil {
		d.dropped.Add(1)
		return nil, err
	}
	d.rtt.Observe(time.Since(start))
	return conn, nil
}

func (d *hy2Driver) NewUDPSession(ctx context.Context) (UDPSession, error) {
	d.mu.Lock()
	cli := d.client
	d.mu.Unlock()
	if cli == nil {
		return nil, errors.New("hysteria2: туннель не установлен")
	}
	hy, err := cli.UDP()
	if err != nil {
		d.dropped.Add(1)
		return nil, err
	}
	return &hy2UDPSession{conn: hy}, nil
}

func (d *hy2Driver) RTT() time.Duration { return d.rtt.rtt() }
func (d *hy2Driver) Dropped() uint64    { return d.dropped.Load() }

func (d *hy2Driver) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	if d.client != nil {
		return d.client.Close()
	}
	return nil
}

type hy2UDPSession struct {
	conn hyClient.HyUDPConn
}

func (s *hy2UDPSession) WriteTo(p []byte, addr string) (int, error) {
	if err := s.conn.Send(p, addr); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (s *hy2UDPSession) ReadFrom() ([]byte, string, error) {
	return s.conn.Receive()
}

func (s *hy2UDPSession) Close() error { return s.conn.Close() }
