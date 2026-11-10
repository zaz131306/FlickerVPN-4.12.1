// SPDX-License-Identifier: GPL-3.0-or-later
// (в составе бинарника flicker-host — производное от sing-box, см. LICENSE-NOTES.md и COPYING)
// flicker-host — native messaging host FLICKER VPN Pro.
//
// Цикл: stdin (NM-команды) -> туннель (драйвер) + локальный SOCKS5 -> stdout (NM-статусы).
// Логи пишутся в файл (-logfile) или stderr; stdout зарезервирован под NM-протокол.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"flicker-vpn/native/internal/config"
	"flicker-vpn/native/internal/nm"
	"flicker-vpn/native/internal/probe"
	"flicker-vpn/native/internal/socks5"
	"flicker-vpn/native/internal/tunnel"
)

const version = "4.0.1"

type host struct {
	out      *nm.Writer
	counters *tunnel.Counters
	logger   *log.Logger

	drv       tunnel.Driver
	socks     *socks5.Server
	listen    string
	startedAt time.Time

	dropped uint64

	// probeServers: активный прогон и его отмена (задача 3)
	probeMu      sync.Mutex
	probeCancel  context.CancelFunc
	probeRunning bool
	probeRequest string
}

// probeCancelFn отменяет активный прогон probeServers (если есть).
func (h *host) probeCancelFn() {
	h.probeMu.Lock()
	cancel := h.probeCancel
	h.probeMu.Unlock()
	if cancel != nil {
		cancel()
		h.logger.Printf("probe: отмена запрошена")
	}
}

// probeServers — многоэтапная проверка живости: TCP → QUIC prescan →
// HTTP через туннель → медиана задержки → GeoIP. Результаты стримятся
// в расширение: probeResult по каждому этапу, probeDone в конце.
func (h *host) probeServers(msg *nm.Message) {
	var specs []probe.ServerSpec
	if len(msg.Servers) > 0 {
		if err := json.Unmarshal(msg.Servers, &specs); err != nil {
			h.send(map[string]any{"type": "error", "message": "probeServers: разбор списка: " + err.Error()})
			return
		}
	}
	var opts probe.Options
	if len(msg.Opts) > 0 {
		if err := json.Unmarshal(msg.Opts, &opts); err != nil {
			h.send(map[string]any{"type": "error", "message": "probeServers: разбор opts: " + err.Error()})
			return
		}
	}

	h.probeMu.Lock()
	if h.probeRunning {
		prev := h.probeCancel
		h.probeMu.Unlock()
		if prev != nil {
			prev() // новый прогон вытесняет старый
		}
		h.probeMu.Lock()
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.probeCancel = cancel
	h.probeRunning = true
	h.probeRequest = msg.RequestID
	h.probeMu.Unlock()

	h.logger.Printf("probe: старт %d серверов (mode=%s request=%s)", len(specs), opts.Mode, msg.RequestID)
	startedAt := time.Now()

	results := probe.Run(ctx, specs, opts, func(sr probe.StageResult) {
		h.send(map[string]any{
			"type":      "probeResult",
			"requestId": msg.RequestID,
			"id":        sr.ID,
			"stage":     sr.Stage,
			"ok":        sr.OK,
			"fatal":     sr.Fatal,
			"latencyMs": sr.LatencyMs,
			"errClass":  sr.ErrClass,
			"error":     sr.Error,
		})
	})

	alive := 0
	for _, r := range results {
		if r.Alive {
			alive++
		}
	}
	cancel()
	h.probeMu.Lock()
	h.probeRunning = false
	h.probeCancel = nil
	h.probeMu.Unlock()

	h.send(map[string]any{
		"type":      "probeDone",
		"requestId": msg.RequestID,
		"total":     len(results),
		"alive":     alive,
		"cancelled": ctx.Err() != nil,
		"elapsedMs": int(time.Since(startedAt).Milliseconds()),
		"results":   results,
	})
	h.logger.Printf("probe: готово — %d живых из %d за %s", alive, len(results), time.Since(startedAt).Round(time.Millisecond))
}

func main() {
	logfile := flag.String("logfile", "", "путь к файлу логов (по умолчанию stderr)")
	showVer := flag.Bool("version", false, "показать версию и выйти")
	flag.Parse()

	if *showVer {
		fmt.Println("flicker-host", version)
		return
	}

	var logger *log.Logger
	if *logfile != "" {
		f, err := os.OpenFile(*logfile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			fmt.Fprintln(os.Stderr, "logfile:", err)
			os.Exit(1)
		}
		defer f.Close()
		logger = log.New(f, "[flicker-host] ", log.LstdFlags|log.Lmsgprefix)
	} else {
		// дублируем логи в файл: stderr уходит в браузер и обычно недоступен
		f, err := os.OpenFile(filepath.Join(os.TempDir(), "flicker-host.log"),
			os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err == nil {
			defer f.Close()
			logger = log.New(io.MultiWriter(os.Stderr, f), "[flicker-host] ", log.LstdFlags)
		} else {
			logger = log.New(os.Stderr, "[flicker-host] ", log.LstdFlags)
		}
	}

	h := &host{
		out:      nm.NewWriter(os.Stdout),
		counters: tunnel.NewCounters(),
		logger:   logger,
	}

	h.send(map[string]any{
		"type":    "hello",
		"version": version,
		"drivers": tunnel.Drivers(),
	})
	logger.Printf("flicker-host %s запущен (pid %d), драйверы: %v", version, os.Getpid(), tunnel.Drivers())

	go h.statsLoop()
	go h.ctlWatcher()

	for {
		msg, err := nm.Read(os.Stdin)
		if err != nil {
			// EOF/обрыв потока или нересинхронизируемый заголовок — выход.
			// Битый JSON при целой длине — ошибка в stdout и продолжаем.
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
				errors.Is(err, nm.ErrTooLarge) {
				h.logger.Printf("stdin закрыт: %v", err)
				h.shutdown()
				return
			}
			h.logger.Printf("битое NM-сообщение: %v", err)
			h.send(map[string]any{"type": "error", "message": "битое сообщение: " + err.Error()})
			continue
		}
		switch msg.Command {
		case "start":
			h.start(msg.Config)
		case "stop":
			h.stop("")
		case "ping":
			go h.ping(msg)
		case "probeServers":
			go h.probeServers(msg)
		case "probeCancel":
			h.probeCancelFn()
		case "announce":
			h.announce(msg)
		case "dbg":
			h.logger.Printf("dbg: %s", msg.Text)
		case "diagnose":
			h.diagnose()
		default:
			h.send(map[string]any{"type": "error", "message": "неизвестная команда: " + msg.Command})
		}
	}
}

func (h *host) send(v any) {
	if err := h.out.Write(v); err != nil {
		// браузер закрыл stdout (EPIPE) — штатное завершение
		h.logger.Printf("запись в stdout не удалась: %v", err)
		h.shutdown()
		os.Exit(0)
	}
}

// ---------- start / stop ----------

func (h *host) start(raw json.RawMessage) {
	var cfg config.ServerConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		h.send(map[string]any{"type": "error", "message": "разбор конфига: " + err.Error()})
		return
	}
	if err := cfg.Validate(); err != nil {
		h.send(map[string]any{"type": "error", "message": err.Error()})
		return
	}

	h.stop("restart")

	drv, err := tunnel.New(&cfg, tunnel.Events{
		OnStatus: func(status, reason string) {
			h.send(map[string]any{"type": "status", "status": status, "reason": reason})
			h.logger.Printf("туннель: %s (%s) %s", cfg.Protocol, cfg.Addr(), status)
		},
		OnError: func(err error) {
			h.send(map[string]any{"type": "error", "message": err.Error()})
			h.logger.Printf("ошибка транспорта: %v", err)
		},
	}, h.counters)
	if err != nil {
		h.send(map[string]any{"type": "error", "message": err.Error()})
		return
	}

	h.counters.Reset()
	h.dropped = 0
	h.listen = cfg.ListenAddr()

	srv, err := socks5.New(h.listen, drv, h.counters, h.logger)
	if err != nil {
		h.send(map[string]any{"type": "error", "message": err.Error()})
		_ = drv.Close()
		return
	}
	h.socks = srv
	h.drv = drv
	h.startedAt = time.Now()
	h.logger.Printf("SOCKS5 слушает %s", srv.Addr())

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := drv.Start(ctx); err != nil {
		h.send(map[string]any{"type": "error", "message": err.Error()})
		h.stop("start failed")
		return
	}
}

func (h *host) stop(reason string) {
	if h.socks != nil {
		_ = h.socks.Close()
		h.socks = nil
	}
	if h.drv != nil {
		_ = h.drv.Close()
		h.drv = nil
	}
	if h.startedAt.IsZero() == false {
		h.startedAt = time.Time{}
		h.send(map[string]any{"type": "status", "status": "disconnected", "reason": reason})
	}
}

func (h *host) shutdown() {
	h.stop("shutdown")
}

// ctlWatcher — диагностический контрольный канал: файл-команда в temp
// (flicker-ctl.json) превращается в NM-сообщение расширению. Используется
// live-тестами для открытия UI-вкладки (webdriver не может навигировать
// на moz-extension:// напрямую). В обычной работе файл не создаётся.
func (h *host) ctlWatcher() {
	p := filepath.Join(os.TempDir(), "flicker-ctl.json")
	ticker := time.NewTicker(400 * time.Millisecond)
	defer ticker.Stop()
	for range ticker.C {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		_ = os.Remove(p)
		var cmd struct {
			Command string `json:"command"`
		}
		if json.Unmarshal(b, &cmd) != nil {
			continue
		}
		switch cmd.Command {
		case "openUiTab":
			h.send(map[string]any{"type": "openUiTab"})
			h.logger.Printf("ctl: openUiTab")
		default:
			h.logger.Printf("ctl: неизвестная команда %q", cmd.Command)
		}
	}
}

// ---------- stats ----------

func (h *host) statsLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		payload := map[string]any{
			"type":          "stats",
			"bytesSent":     h.counters.Sent(),
			"bytesReceived": h.counters.Recv(),
		}
		if h.drv != nil {
			payload["rtt"] = int(h.drv.RTT().Milliseconds())
			payload["dropped"] = h.drv.Dropped()
		} else {
			payload["rtt"] = 0
			payload["dropped"] = 0
		}
		h.send(payload)
	}
}

// ---------- ping ----------

// ping — UDP-проба с трёхзначной семантикой latency:
//
//	>= 0 — хост ответил, latency в мс (жив);
//	-1   — тишина по таймауту: статус неизвестен (QUIC-серверы вправе молчать);
//	-2   — хост точно недоступен: DNS-провал, ICMP unreachable/refused (мёртв).
func (h *host) ping(msg *nm.Message) {
	latency := -1
	addr := net.JoinHostPort(msg.Server, fmt.Sprintf("%d", msg.Port))
	conn, err := net.DialTimeout("udp", addr, 2*time.Second)
	if err != nil {
		latency = -2
	} else {
		start := time.Now()
		if _, werr := conn.Write([]byte("flicker-ping")); werr != nil {
			if isConnRefused(werr) || isUnreachable(werr) {
				latency = -2
			}
		} else {
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			buf := make([]byte, 64)
			_, rerr := conn.Read(buf)
			switch {
			case rerr == nil:
				latency = int(time.Since(start).Milliseconds())
			case isConnRefused(rerr) || isUnreachable(rerr):
				latency = -2
			default:
				latency = -1
			}
		}
		_ = conn.Close()
	}
	h.send(map[string]any{
		"type":     "ping",
		"serverId": msg.ServerID,
		"latency":  latency,
	})
}

func isConnRefused(err error) bool {
	var ne *net.OpError
	if errors.As(err, &ne) && ne.Err != nil {
		return strings.Contains(ne.Err.Error(), "connection refused")
	}
	return false
}

func isUnreachable(err error) bool {
	var ne *net.OpError
	if errors.As(err, &ne) && ne.Err != nil {
		s := ne.Err.Error()
		return strings.Contains(s, "unreachable") || strings.Contains(s, "no such host")
	}
	return false
}

// announce — расширение сообщило свой URL: пишем файл-маяк в temp
// (используется диагностикой и live-тестами в реальном Firefox).
func (h *host) announce(msg *nm.Message) {
	payload := map[string]any{
		"url":        msg.URL,
		"extVersion": msg.ExtVersion,
		"hostPid":    os.Getpid(),
		"at":         time.Now().Unix(),
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return
	}
	p := filepath.Join(os.TempDir(), "flicker-announce.json")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		h.logger.Printf("announce: %v", err)
		return
	}
	h.logger.Printf("announce: %s", msg.URL)
}

// ---------- diagnose ----------

func (h *host) diagnose() {
	payload := map[string]any{
		"type":           "diagnose",
		"version":        version,
		"drivers":        tunnel.Drivers(),
		"tunnelActive":   h.drv != nil,
		"socksListening": h.socks != nil,
		"listenAddr":     h.listen,
		"bytesSent":      h.counters.Sent(),
		"bytesReceived":  h.counters.Recv(),
	}
	if h.drv != nil {
		payload["driver"] = h.drv.Name()
		payload["rtt"] = int(h.drv.RTT().Milliseconds())
		payload["uptimeSec"] = int(time.Since(h.startedAt).Seconds())
	}
	h.send(payload)
}
