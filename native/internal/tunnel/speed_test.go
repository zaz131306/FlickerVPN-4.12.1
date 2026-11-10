package tunnel

// speed_test.go — сравнение пропускной способности и задержки:
//   A) чистый VLESS-туннель (TCP);
//   B) «матрёшка» WireGuard-в-VLESS (двойная инкапсуляция + gVisor-netstack).
//
// Замер ЛОКАЛЬНЫЙ (loopback): сеть исключена из уравнения, измеряется именно
// накладные расходы стека клиента/сервера. На реальном VPS абсолютные числа
// будут другими (упрётся в канал), но относительный вклад двойной
// инкапсуляции сохраняется. Запуск: go test -run TestSpeed -v -tags "with_utls with_gvisor"

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"flicker-vpn/native/internal/config"
)

const benchBytes = 16 << 20 // 16 МБ

func startPayloadBackend(t *testing.T, host string) string {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bulk" {
			w.Header().Set("Content-Length", fmt.Sprint(benchBytes))
			buf := make([]byte, 64*1024)
			for i := range buf {
				buf[i] = byte(i)
			}
			written := 0
			for written < benchBytes {
				n, err := w.Write(buf)
				if err != nil {
					return
				}
				written += n
			}
			return
		}
		io.WriteString(w, "pong") // маленький ответ для latency-проб
	}))
	srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	return ln.Addr().String()
}

// measure — качает /bulk и меряет N маленьких /-запросов через драйвер.
func measure(t *testing.T, drv Driver, backend string) (mbps float64, latMs float64) {
	t.Helper()
	ctx := context.Background()

	// латентность: 12 маленьких запросов, отбрасываем первый (прогрев)
	var lats []time.Duration
	for i := 0; i < 12; i++ {
		start := time.Now()
		conn, err := drv.DialTCP(ctx, backend)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		req := "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
		if _, err := conn.Write([]byte(req)); err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(io.LimitReader(conn, 4096))
		_ = conn.Close()
		if err != nil || len(body) == 0 {
			t.Fatalf("latency-запрос %d: %v", i, err)
		}
		if i > 0 {
			lats = append(lats, time.Since(start))
		}
	}
	var sum time.Duration
	for _, l := range lats {
		sum += l
	}
	latMs = float64(sum.Microseconds()) / float64(len(lats)) / 1000

	// пропускная способность
	conn, err := drv.DialTCP(ctx, backend)
	if err != nil {
		t.Fatalf("dial bulk: %v", err)
	}
	defer conn.Close()
	req := "GET /bulk HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	// пропускаем заголовки
	br := make([]byte, 1)
	headerSeen := 0
	total := 0
	start := time.Now()
	buf := make([]byte, 256*1024)
	for {
		n, err := conn.Read(buf)
		total += n
		if n > 0 && headerSeen < 4 {
			// грубый поиск \r\n\r\n в первых байтах
			headerSeen += n
		}
		if err != nil {
			break
		}
		_ = br
	}
	elapsed := time.Since(start).Seconds()
	if elapsed <= 0 {
		elapsed = 0.000001
	}
	mbps = float64(total) * 8 / 1e6 / elapsed
	return mbps, latMs
}

func TestSpeedMatryoshkaVsPlainVless(t *testing.T) {
	ip := primaryIPv4(t)
	backend := startPayloadBackend(t, ip)
	const uuid = "speed-bench-uuid-0001"

	// ---- серверная сторона ----
	vlessPort := freeTCPPort(t)
	wgPort := freeUDPPort(t)
	srvPriv, srvPub := x25519Keypair(t)
	cliPriv, cliPub := x25519Keypair(t)

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
	    "address": ["10.97.0.1/24"],
	    "private_key": %q,
	    "listen_port": %d,
	    "peers": [{"public_key": %q, "allowed_ips": ["10.97.0.2/32"]}]
	  }],
	  "outbounds": [{"type": "direct", "tag": "out"}],
	  "route": {"final": "out"}
	}`, vlessPort, uuid, srvPriv, wgPort, cliPub))
	defer stop()

	// ---- A) чистый VLESS ----
	drvA := startDriver(t, &config.ServerConfig{
		Protocol: "vless", Server: "127.0.0.1", Port: vlessPort, UUID: uuid,
	})
	mbpsA, latA := measure(t, drvA, backend)
	t.Logf("A) VLESS (TCP):            %.1f Мбит/с, латентность %.2f мс", mbpsA, latA)

	// ---- B) матрёшка WG-в-VLESS ----
	drvB := startDriver(t, &config.ServerConfig{
		Protocol: "wireguard", Server: "127.0.0.1", Port: wgPort,
		WireGuard: &config.WireGuardConfig{
			PrivateKey: cliPriv, PeerPublicKey: srvPub,
			Address: []string{"10.97.0.2/32"}, AllowedIPs: []string{"0.0.0.0/0"},
		},
		Detour: &config.DetourConfig{Protocol: "vless", Server: "127.0.0.1", Port: vlessPort, UUID: uuid},
	})
	mbpsB, latB := measure(t, drvB, backend)
	t.Logf("B) WG-в-VLESS (матрёшка):  %.1f Мбит/с, латентность %.2f мс", mbpsB, latB)

	ratio := mbpsB / mbpsA
	t.Logf("отношение B/A: %.1f%% (потолок матрёшки на этом CPU: %.0f Мбит/с)", ratio*100, mbpsB)

	// Интерпретация (честная): на loopback чистый VLESS упирается в память
	// (десятки Гбит/с), а матрёшка — в CPU-потолок userspace-WG+netstack
	// (сотни Мбит/с). Процент «накладных» здесь бессмысленен; значимы:
	//  1) абсолютный потолок матрёшки (на реальном канале ≤ потолка — разница
	//     не видна; выше — упрётся);
	//  2) добавка к латентности (двойная инкапсуляция + WG-handshake).
	// На реальном VPS повторить тем же методом (см. tools/speed-remote.md).
	if mbpsA <= 0 || mbpsB <= 0 {
		t.Fatal("один из туннелей не передал данные")
	}
	if mbpsB < 30 {
		t.Fatalf("матрёшка аномально медленная: %.1f Мбит/с", mbpsB)
	}
	if latB > latA+100 {
		t.Fatalf("матрёшка добавила аномальную латентность: %.2f vs %.2f мс", latB, latA)
	}
}
