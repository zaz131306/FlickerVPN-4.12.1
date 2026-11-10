// SPDX-License-Identifier: GPL-3.0-or-later

package mobile

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"flicker-vpn/native/internal/probe"
	"flicker-vpn/native/internal/shareparse"
)

// ---------- вспомогательные ----------

type collectFetch struct {
	mu       sync.Mutex
	progress []sourceProgress
	done     chan fetchResult
}

func (c *collectFetch) OnSourceProgress(resultJSON string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var p sourceProgress
	_ = json.Unmarshal([]byte(resultJSON), &p)
	c.progress = append(c.progress, p)
}

func (c *collectFetch) OnFetchDone(resultJSON string) {
	var r fetchResult
	_ = json.Unmarshal([]byte(resultJSON), &r)
	if c.done == nil {
		c.done = make(chan fetchResult, 1)
	}
	c.done <- r
}

type collectProbe struct {
	mu     sync.Mutex
	stages []probe.StageResult
	done   chan string
}

func (c *collectProbe) OnProbeStage(resultJSON string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var s probe.StageResult
	_ = json.Unmarshal([]byte(resultJSON), &s)
	c.stages = append(c.stages, s)
}

func (c *collectProbe) OnProbeDone(resultJSON string) {
	if c.done == nil {
		c.done = make(chan string, 1)
	}
	c.done <- resultJSON
}

func (c *collectProbe) stagesCopy() []probe.StageResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]probe.StageResult, len(c.stages))
	copy(out, c.stages)
	return out
}

// validateSingBox — структурная проверка конфига sing-box. Разбор схемы
// sing-box уже покрыт тестами internal/singcfg (те же билдеры), здесь —
// контракт мобилок: секции на месте и согласованы.
func validateSingBox(t *testing.T, configJSON string) {
	t.Helper()
	var bp struct {
		Log       map[string]any   `json:"log"`
		DNS       map[string]any   `json:"dns"`
		Inbounds  []map[string]any `json:"inbounds"`
		Outbounds []map[string]any `json:"outbounds"`
		Endpoints []map[string]any `json:"endpoints"`
		Route     map[string]any   `json:"route"`
	}
	if err := json.Unmarshal([]byte(configJSON), &bp); err != nil {
		t.Fatalf("структура: %v", err)
	}
	if bp.Log["level"] == nil {
		t.Fatal("нет log.level")
	}
	if len(bp.Inbounds) == 0 {
		t.Fatal("нет inbounds")
	}
	if len(bp.Outbounds) == 0 {
		t.Fatal("нет outbounds")
	}
	if bp.DNS["final"] == nil {
		t.Fatal("нет dns.final")
	}
	if bp.Route["final"] == nil {
		t.Fatal("нет route.final")
	}
}

// ---------- BuildTunConfig ----------

func TestBuildTunConfigVlessReality(t *testing.T) {
	link := "vless://00000000-0000-0000-0000-000000000001@1.2.3.4:443?" +
		"security=reality&sni=www.microsoft.com&fp=chrome&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=ab12cd" +
		"&flow=xtls-rprx-vision&type=tcp#NL%20Reality"
	res := ParseSubscription(link, "test", false)
	var parsed shareparse.ParseResult
	if err := json.Unmarshal([]byte(res), &parsed); err != nil {
		t.Fatalf("ParseSubscription: %v (%s)", err, res)
	}
	if len(parsed.Servers) != 1 {
		t.Fatalf("servers=%d failed=%v", len(parsed.Servers), parsed.Failed)
	}
	serverJSON := mustJSON(parsed.Servers[0])

	cfgJSON, err := BuildTunConfig(serverJSON, `{"mtu":1420}`)
	if err != nil {
		t.Fatalf("BuildTunConfig: %v", err)
	}
	if err := CheckTunConfig(cfgJSON); err != nil {
		t.Fatalf("CheckTunConfig: %v", err)
	}
	validateSingBox(t, cfgJSON)

	var cfg map[string]any
	_ = json.Unmarshal([]byte(cfgJSON), &cfg)

	inbounds := cfg["inbounds"].([]any)
	in := inbounds[0].(map[string]any)
	if in["type"] != "tun" {
		t.Fatalf("inbound type=%v, хочу tun", in["type"])
	}
	if int(in["mtu"].(float64)) != 1420 {
		t.Fatalf("mtu=%v", in["mtu"])
	}
	addrs := in["address"].([]any)
	if len(addrs) != 2 {
		t.Fatalf("address=%v (ожидал v4+v6 дефолт)", addrs)
	}
	if !strings.Contains(addrs[1].(string), ":") {
		t.Fatalf("второй адрес должен быть IPv6: %v", addrs)
	}

	outbounds := cfg["outbounds"].([]any)
	out := outbounds[0].(map[string]any)
	if out["type"] != "vless" {
		t.Fatalf("outbound type=%v", out["type"])
	}
	tlsBlk := out["tls"].(map[string]any)
	reality := tlsBlk["reality"].(map[string]any)
	if reality["enabled"] != true || reality["public_key"] == nil {
		t.Fatalf("reality блок: %v", reality)
	}
	if out["flow"] != "xtls-rprx-vision" {
		t.Fatalf("flow=%v", out["flow"])
	}
	utls := tlsBlk["utls"].(map[string]any)
	if utls["fingerprint"] != "chrome" {
		t.Fatalf("utls=%v", utls)
	}
	route := cfg["route"].(map[string]any)
	if route["auto_detect_interface"] != true {
		t.Fatalf("нет auto_detect_interface: %v", route)
	}
	// DNS идёт через туннель
	dns := cfg["dns"].(map[string]any)
	servers := dns["servers"].([]any)
	remote := servers[1].(map[string]any)
	if remote["detour"] != route["final"] {
		t.Fatalf("dns detour=%v route final=%v", remote["detour"], route["final"])
	}
}

func TestBuildTunConfigWGMatryoshka(t *testing.T) {
	kp1, _ := wgKeypairJSON(t)
	kp2, _ := wgKeypairJSON(t)
	server := shareparse.Server{
		ID: "sub-test", Name: "WG", Host: "5.6.7.8", Port: 443, Protocol: "wireguard",
		WireGuard: &shareparse.WireGuardRef{
			PrivateKey: kp1["privateKey"], PeerPublicKey: kp2["publicKey"],
			Address: []string{"172.16.0.2/32"}, AllowedIPs: []string{"0.0.0.0/0"},
		},
		Detour: map[string]any{
			"protocol": "vless", "server": "9.9.9.9", "port": 8443,
			"uuid": "00000000-0000-0000-0000-000000000002",
		},
	}
	cfgJSON, err := BuildTunConfig(mustJSON(server), "")
	if err != nil {
		t.Fatalf("BuildTunConfig: %v", err)
	}
	if err := CheckTunConfig(cfgJSON); err != nil {
		t.Fatalf("CheckTunConfig: %v", err)
	}
	validateSingBox(t, cfgJSON)

	var cfg map[string]any
	_ = json.Unmarshal([]byte(cfgJSON), &cfg)
	endpoints := cfg["endpoints"].([]any)
	if len(endpoints) != 1 {
		t.Fatalf("endpoints=%d", len(endpoints))
	}
	ep := endpoints[0].(map[string]any)
	if ep["type"] != "wireguard" {
		t.Fatalf("endpoint type=%v", ep["type"])
	}
	// детур-outbound присутствует в outbounds
	foundDetour := false
	for _, o := range cfg["outbounds"].([]any) {
		om := o.(map[string]any)
		if om["type"] == "vless" {
			foundDetour = true
		}
	}
	if !foundDetour {
		t.Fatalf("нет vless-детура в outbounds: %v", cfg["outbounds"])
	}
	route := cfg["route"].(map[string]any)
	if !strings.Contains(route["final"].(string), "wg") && route["final"] == "flicker-direct" {
		t.Fatalf("final=%v", route["final"])
	}
}

func wgKeypairJSON(t *testing.T) (map[string]string, string) {
	t.Helper()
	s, err := GenerateWGKeypair()
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m, s
}

func TestGenerateWGKeypair(t *testing.T) {
	s1, raw := wgKeypairJSON(t)
	s2, _ := wgKeypairJSON(t)
	for _, k := range []string{"privateKey", "publicKey"} {
		b, err := base64.StdEncoding.DecodeString(s1[k])
		if err != nil || len(b) != 32 {
			t.Fatalf("%s: base64 err=%v len=%d", k, err, len(b))
		}
		if s1[k] == s2[k] {
			t.Fatalf("%s совпали между вызовами", k)
		}
	}
	if !strings.Contains(raw, "privateKey") {
		t.Fatalf("формат: %s", raw)
	}
}

// ---------- FetchSubscriptions ----------

func TestFetchSubscriptions(t *testing.T) {
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") == "" {
			t.Error("нет User-Agent")
		}
		w.Write([]byte("vless://00000000-0000-0000-0000-000000000003@1.1.1.1:443?security=tls&sni=a.example#S1\n" +
			"vless://00000000-0000-0000-0000-000000000003@1.1.1.1:443?security=tls&sni=a.example#dup-ignored\n" +
			"garbage-line\n"))
	}))
	defer good.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()

	sources := []shareparse.Source{
		{ID: "ok", Name: "Хороший", URL: good.URL, Enabled: true},
		{ID: "bad", Name: "Плохой", URL: bad.URL, Enabled: true},
		{ID: "off", Name: "Выключен", URL: "http://127.0.0.1:1/x", Enabled: false},
	}
	listener := &collectFetch{done: make(chan fetchResult, 1)}
	FetchSubscriptions(mustJSON(sources), true, 10, listener)

	select {
	case r := <-listener.done:
		if len(r.Servers) != 1 {
			t.Fatalf("servers=%d (ожидал 1, дубль и мусор отсеяны): %v", len(r.Servers), r.Servers)
		}
		if r.Servers[0].Source != "ok" {
			t.Fatalf("source=%s", r.Servers[0].Source)
		}
		if len(r.PerSource) != 2 {
			t.Fatalf("perSource=%d (выключенный не должен грузиться)", len(r.PerSource))
		}
		if len(r.Errors) != 1 || !strings.Contains(r.Errors[0], "HTTP 500") {
			t.Fatalf("errors=%v", r.Errors)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("таймаут FetchSubscriptions")
	}
	listener.mu.Lock()
	defer listener.mu.Unlock()
	if len(listener.progress) != 2 {
		t.Fatalf("progress=%d", len(listener.progress))
	}
}

// ---------- ProbeServers ----------

// blackHoleTCP — принимает соединения и молчит: TCP-этап проходит,
// рукопожатие vless зависает (герметичная замена внешнего «висящего» хоста).
func blackHoleTCP(t *testing.T) (string, int, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { time.Sleep(30 * time.Second); c.Close() }(c)
		}
	}()
	return "127.0.0.1", ln.Addr().(*net.TCPAddr).Port, func() { ln.Close() }
}

func TestProbeServersBlackholeAndCancel(t *testing.T) {
	specs := []probe.ServerSpec{
		{ID: "s1", Host: "127.0.0.1", Port: 1, Protocol: "vless", UUID: "00000000-0000-0000-0000-000000000009"},
	}
	opts := probe.Options{Mode: "quick", TCPTimeoutMs: 250, GeoIP: boolPtr(false)}

	// 1) отказ соединения → tcp-этап падает, alive=0
	l1 := &collectProbe{done: make(chan string, 1)}
	ProbeServers(mustJSON(specs), mustJSON(opts), l1)
	select {
	case raw := <-l1.done:
		var done map[string]any
		_ = json.Unmarshal([]byte(raw), &done)
		if int(done["alive"].(float64)) != 0 {
			t.Fatalf("alive=%v", done["alive"])
		}
		if done["cancelled"] != false {
			t.Fatalf("cancelled=%v (raw=%s)", done["cancelled"], raw)
		}
		stages := l1.stagesCopy()
		if len(stages) == 0 || stages[0].Stage != "tcp" || stages[0].OK {
			t.Fatalf("stages=%v", stages)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("таймаут OnProbeDone")
	}

	// 2) «висящий» сервер: второй запуск отклоняется, CancelProbe завершает прогон
	host, port, stop := blackHoleTCP(t)
	defer stop()
	hangSpecs := []probe.ServerSpec{
		{ID: "s2", Host: host, Port: port, Protocol: "vless", UUID: "00000000-0000-0000-0000-000000000009"},
	}
	hangOpts := probe.Options{Mode: "quick", TCPTimeoutMs: 500, DialTimeoutMs: 500, HTTPTimeoutMs: 20000, GeoIP: boolPtr(false)}
	l2 := &collectProbe{done: make(chan string, 1)}
	ProbeServers(mustJSON(hangSpecs), mustJSON(hangOpts), l2)
	if !ProbeActive() {
		t.Fatal("ProbeActive=false во время прогона")
	}
	l3 := &collectProbe{done: make(chan string, 1)}
	ProbeServers(mustJSON(specs), mustJSON(opts), l3)
	select {
	case raw := <-l3.done:
		if !strings.Contains(raw, "уже идёт") {
			t.Fatalf("ожидал отказ, получил: %s", raw)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("параллельный запуск не отклонён")
	}
	CancelProbe()
	select {
	case raw := <-l2.done:
		var done map[string]any
		_ = json.Unmarshal([]byte(raw), &done)
		if done["cancelled"] != true {
			t.Fatalf("cancelled=%v (raw=%s)", done["cancelled"], raw)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("CancelProbe не завершил прогон")
	}
	if ProbeActive() {
		t.Fatal("ProbeActive=true после завершения")
	}
}

func TestProbeSpecsFromServers(t *testing.T) {
	servers := []shareparse.Server{
		{ID: "a", Host: "1.1.1.1", Port: 443, Protocol: "vless", UUID: "00000000-0000-0000-0000-00000000000a", TLSEnabled: true, SNI: "a.example", Fingerprint: "chrome",
			Reality: &shareparse.RealityRef{PublicKey: "AAAA", ShortID: "x"}},
		{ID: "b", Host: "2.2.2.2", Port: 443, Protocol: "hysteria2", Auth: "pw"},
		{ID: "c", Host: "3.3.3.3", Port: 443, Protocol: "vless"}, // без UUID → не проверяем
		{ID: "d", Host: "4.4.4.4", Port: 443, Protocol: "trojan", Auth: "pw", Demo: true},
	}
	specsJSON := ProbeSpecsFromServers(mustJSON(servers), false)
	var specs []probe.ServerSpec
	_ = json.Unmarshal([]byte(specsJSON), &specs)
	if len(specs) != 1 || specs[0].ID != "a" {
		t.Fatalf("allowHY2=false: %+v", specs)
	}
	if specs[0].RealityPBK != "AAAA" || specs[0].Fingerprint == "" || !specs[0].TLSEnabled {
		t.Fatalf("поля спеки: %+v", specs[0])
	}
	specsJSON = ProbeSpecsFromServers(mustJSON(servers), true)
	specs = nil
	_ = json.Unmarshal([]byte(specsJSON), &specs)
	if len(specs) != 2 {
		t.Fatalf("allowHY2=true: %d specs %+v", len(specs), specs)
	}
}

// ---------- прочие функции ----------

func TestParseMergeSortPruneRoundtrip(t *testing.T) {
	res := ParseSubscription("vless://00000000-0000-0000-0000-000000000004@5.5.5.5:443?security=tls&sni=b.example#B1", "src1", true)
	var parsed shareparse.ParseResult
	_ = json.Unmarshal([]byte(res), &parsed)
	if len(parsed.Servers) != 1 {
		t.Fatalf("parse: %s", res)
	}
	merged := MergeServers("[]", mustJSON(parsed.Servers), time.Now().UnixMilli())
	var mr shareparse.MergeResult
	_ = json.Unmarshal([]byte(merged), &mr)
	if len(mr.Merged) != 1 || mr.Added != 1 {
		t.Fatalf("merge: %s", merged)
	}
	sorted := SortServers(mustJSON(mr.Merged))
	var ss []shareparse.Server
	_ = json.Unmarshal([]byte(sorted), &ss)
	if len(ss) != 1 || ss[0].ID != parsed.Servers[0].ID {
		t.Fatalf("sort: %s", sorted)
	}
	// PruneStale: сервер без lastSeenAt свежее maxAge → остаётся
	pruned := PruneStale(sorted, time.Now().UnixMilli(), time.Hour.Milliseconds())
	var ps []shareparse.Server
	_ = json.Unmarshal([]byte(pruned), &ps)
	if len(ps) != 1 {
		t.Fatalf("prune: %s", pruned)
	}
	// sources roundtrip
	srcs := NormalizeSources("")
	var list []shareparse.Source
	if err := json.Unmarshal([]byte(srcs), &list); err != nil || len(list) == 0 {
		t.Fatalf("DefaultSources: %s", srcs)
	}
	if ds := DefaultSources(); !strings.Contains(ds, "enabled") {
		t.Fatalf("DefaultSources формат: %s", ds)
	}
	if f := CountryFlag("NL"); f != "🇳🇱" {
		t.Fatalf("flag=%s", f)
	}
	if v := Version(); v != "4.0.1" {
		t.Fatalf("version=%s", v)
	}
}

func TestCheckTunConfigErrors(t *testing.T) {
	if err := CheckTunConfig("{"); err == nil {
		t.Fatal("ожидана ошибка на не-JSON")
	}
	if err := CheckTunConfig(`{"outbounds":[]}`); err == nil {
		t.Fatal("ожидана ошибка: нет inbounds")
	}
}

// fakeProtector — имитация VpnService.protect(fd) из Kotlin.
type fakeProtector struct {
	mu    sync.Mutex
	calls int
}

func (f *fakeProtector) ProtectFd(fd int32) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return true
}

func (f *fakeProtector) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func TestSetSocketProtector(t *testing.T) {
	fp := &fakeProtector{}
	SetSocketProtector(fp)
	defer SetSocketProtector(nil)

	specs := []probe.ServerSpec{
		{ID: "p1", Host: "127.0.0.1", Port: 1, Protocol: "vless", UUID: "00000000-0000-0000-0000-000000000009"},
	}
	opts := probe.Options{Mode: "quick", TCPTimeoutMs: 250, GeoIP: boolPtr(false)}
	l := &collectProbe{done: make(chan string, 1)}
	ProbeServers(mustJSON(specs), mustJSON(opts), l)
	select {
	case <-l.done:
	case <-time.After(10 * time.Second):
		t.Fatal("таймаут")
	}
	if fp.count() == 0 {
		t.Fatal("protect(fd) не вызывался для TCP-сокета пробы")
	}

	// после отключения хук снимается
	SetSocketProtector(nil)
	before := fp.count()
	l2 := &collectProbe{done: make(chan string, 1)}
	ProbeServers(mustJSON(specs), mustJSON(opts), l2)
	select {
	case <-l2.done:
	case <-time.After(10 * time.Second):
		t.Fatal("таймаут")
	}
	if fp.count() != before {
		t.Fatal("после SetSocketProtector(nil) protector продолжает вызываться")
	}
}

// ---------- ApplyProbeResults ----------

func TestApplyProbeResults(t *testing.T) {
	servers := []shareparse.Server{
		{ID: "a", Sub: true, Protocol: "vless"},
		{ID: "b", Sub: true, Protocol: "vless"},
		{ID: "c", Sub: false, Protocol: "trojan"},
	}
	results := []probe.Result{
		{ID: "a", Alive: true, LatencyMs: 120, CountryCode: "NL", Country: "Нидерланды", ExitIP: "1.2.3.4"},
		{ID: "b", Alive: false, ErrClass: "timeout", Error: "Сервер не отвечает (таймаут)"},
		{ID: "c", Alive: true, LatencyMs: 90},
	}
	out := ApplyProbeResults(mustJSON(servers), mustJSON(results), 1000)
	var res struct {
		Servers []shareparse.Server `json:"servers"`
		Alive   int                 `json:"alive"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if res.Alive != 2 {
		t.Fatalf("alive=%d", res.Alive)
	}
	a, b, c := res.Servers[0], res.Servers[1], res.Servers[2]
	if a.Ping == nil || *a.Ping != 120 || a.Flag != "🇳🇱" || a.ExitIP != "1.2.3.4" || a.ChecksOk != 1 {
		t.Fatalf("a: %+v", a)
	}
	if b.Ping == nil || *b.Ping != -2 || b.ErrClass != "timeout" || b.LastError == "" {
		t.Fatalf("b: %+v", b)
	}
	if c.Ping == nil || *c.Ping != 90 {
		t.Fatalf("c: %+v", c)
	}

	// двойной прогон: recent [0,1,0,0] (sub, >=2 проверок, rate<50%) → unstable
	servers2 := []shareparse.Server{{ID: "d", Sub: true, Protocol: "vless", Recent: []int{0, 1, 0}}}
	results2 := []probe.Result{{ID: "d", Alive: false, ErrClass: "refused", Error: "отказ"}}
	out2 := ApplyProbeResults(mustJSON(servers2), mustJSON(results2), 2000)
	var res2 struct {
		Servers []shareparse.Server `json:"servers"`
	}
	_ = json.Unmarshal([]byte(out2), &res2)
	d := res2.Servers[0]
	if d.ErrClass != "unstable" || !strings.Contains(d.LastError, "Нестабильный узел") {
		t.Fatalf("двойной прогон: %+v", d)
	}
	if len(d.Recent) != 4 {
		t.Fatalf("recent=%v", d.Recent)
	}
}

// ---------- ApplyProbeResults → окно ----------

func TestApplyProbeResultsWindow(t *testing.T) {
	servers := []shareparse.Server{{ID: "w", Sub: false, Protocol: "vless"}}
	cur := mustJSON(servers)
	for i := 0; i < 6; i++ {
		out := ApplyProbeResults(cur, mustJSON([]probe.Result{{ID: "w", Alive: true, LatencyMs: 50}}), int64(1000+i))
		var res struct {
			Servers []shareparse.Server `json:"servers"`
		}
		_ = json.Unmarshal([]byte(out), &res)
		cur = mustJSON(res.Servers)
		if len(res.Servers[0].Recent) > 4 {
			t.Fatalf("окно выросло: %v", res.Servers[0].Recent)
		}
	}
	var final []shareparse.Server
	if err := json.Unmarshal([]byte(cur), &final); err != nil {
		t.Fatalf("final unmarshal: %v (%s)", err, cur)
	}
	w := final[0]
	if w.ChecksTotal != 6 || w.ChecksOk != 6 || len(w.Recent) != 4 {
		t.Fatalf("статистика: %+v", w)
	}
}

// ---------- ApplyProbeResults → прочее ----------

func boolPtr(b bool) *bool { return &b }
