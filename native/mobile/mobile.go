// SPDX-License-Identifier: GPL-3.0-or-later
// (в составе AAR с libbox — производное от sing-box; см. native/COPYING)

// Package mobile — gomobile-фасад ядра FLICKER VPN для Android-приложения.
//
// Все функции работают с JSON-строками (стабильный контракт между Go и
// Kotlin, не зависит от особенностей кодогенерации gomobile):
//
//	ParseSubscription / MergeServers / SortServers / PruneStale — подписки;
//	FetchSubscriptions — асинхронная загрузка источников (колбэки);
//	ProbeServers / CancelProbe — многоэтапная проверка живости (колбэки);
//	BuildTunConfig — конфиг sing-box (TUN-inbound) для libbox/VpnService;
//	CheckTunConfig — валидация конфига без запуска;
//	GenerateWGKeypair — ключи WireGuard (wg(8)-формат).
//
// Тот же набор используется desktop-расширением через background.js (логика
// идентична: общий internal/shareparse и internal/probe), поэтому id узлов и
// статистика живости совместимы между платформами.
package mobile

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"flicker-vpn/native/internal/config"
	"flicker-vpn/native/internal/probe"
	"flicker-vpn/native/internal/shareparse"
	"flicker-vpn/native/internal/singcfg"
)

// Version — версия ядра. Держать синхронно с android/app/build.gradle.kts
// (versionName) и manifest.json расширения; проверяется в mobile_test.go.
func Version() string { return "4.0.1" }

// ---------- подписки (синхронные преобразования) ----------

// DefaultSources — встроенные источники (JSON []shareparse.Source).
func DefaultSources() string { return mustJSON(shareparse.DefaultSources()) }

// NormalizeSources — слияние сохранённых источников с дефолтами.
func NormalizeSources(savedJSON string) string {
	var saved []shareparse.Source
	if savedJSON != "" {
		_ = json.Unmarshal([]byte(savedJSON), &saved)
	}
	return mustJSON(shareparse.NormalizeSources(saved))
}

// ParseSubscription — разбор текста подписки одного источника.
// Возвращает JSON shareparse.ParseResult {servers, failed, linkCount}.
func ParseSubscription(text, sourceID string, allowHY2 bool) string {
	res := shareparse.ParseSubscription(text, sourceID, allowHY2)
	return mustJSON(res)
}

// MergeServers — слияние свежих серверов с сохранёнными (статистика не теряется).
// Возвращает JSON {merged, added, updated}.
func MergeServers(existingJSON, incomingJSON string, nowMs int64) string {
	var existing, incoming []shareparse.Server
	_ = json.Unmarshal([]byte(existingJSON), &existing)
	_ = json.Unmarshal([]byte(incomingJSON), &incoming)
	if nowMs <= 0 {
		nowMs = time.Now().UnixMilli()
	}
	return mustJSON(shareparse.MergeServers(existing, incoming, nowMs))
}

// SortServers — сортировка для UI (direct, живые по задержке, неизвестные, мёртвые).
func SortServers(serversJSON string) string {
	var servers []shareparse.Server
	_ = json.Unmarshal([]byte(serversJSON), &servers)
	return mustJSON(shareparse.SortServers(servers))
}

// PruneStale — GC подписочных серверов, пропавших из источников.
func PruneStale(serversJSON string, nowMs, maxAgeMs int64) string {
	var servers []shareparse.Server
	_ = json.Unmarshal([]byte(serversJSON), &servers)
	return mustJSON(shareparse.PruneStale(servers, nowMs, maxAgeMs))
}

// CountryFlag — ISO-код страны → emoji-флаг.
func CountryFlag(code string) string { return shareparse.CountryFlag(code) }

// ---------- загрузка подписок (асинхронно) ----------

// FetchListener — колбэки загрузки подписок (реализуется в Kotlin).
type FetchListener interface {
	// OnSourceProgress — по каждому источнику:
	// {id,name,count,failed,error,elapsedMs}
	OnSourceProgress(resultJSON string)
	// OnFetchDone — итог: {servers:[...], perSource:[...], errors:[...]}
	OnFetchDone(resultJSON string)
}

type sourceProgress struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Count     int    `json:"count"`
	Failed    int    `json:"failed"`
	Error     string `json:"error,omitempty"`
	ElapsedMs int64  `json:"elapsedMs"`
}

type fetchResult struct {
	Servers   []shareparse.Server `json:"servers"`
	PerSource []sourceProgress    `json:"perSource"`
	Errors    []string            `json:"errors"`
}

// FetchSubscriptions — скачать и разобрать все включённые источники.
// Асинхронно: результаты приходят в listener. allowHY2 — глобальный тумблер
// «экспериментальные UDP» (источник дополнительно должен иметь allowHY2).
func FetchSubscriptions(sourcesJSON string, allowHY2 bool, timeoutSeconds int, listener FetchListener) {
	var sources []shareparse.Source
	if err := json.Unmarshal([]byte(sourcesJSON), &sources); err != nil {
		listener.OnFetchDone(mustJSON(fetchResult{
			Servers: []shareparse.Server{}, PerSource: []sourceProgress{},
			Errors: []string{"битый JSON источников: " + err.Error()},
		}))
		return
	}
	if timeoutSeconds <= 0 {
		timeoutSeconds = 25
	}
	go func() {
		res := fetchResult{Servers: []shareparse.Server{}, PerSource: []sourceProgress{}, Errors: []string{}}
		seen := map[string]bool{}
		client := &http.Client{Timeout: time.Duration(timeoutSeconds) * time.Second}
		for _, src := range sources {
			if !src.Enabled {
				continue
			}
			start := time.Now()
			text, err := fetchText(client, src.URL)
			if err != nil {
				p := sourceProgress{ID: src.ID, Name: src.Name, Error: err.Error(), ElapsedMs: ms(time.Since(start))}
				res.PerSource = append(res.PerSource, p)
				res.Errors = append(res.Errors, src.Name+": "+err.Error())
				listener.OnSourceProgress(mustJSON(p))
				continue
			}
			parsed := shareparse.ParseSubscription(text, src.ID, src.AllowHY2 && allowHY2)
			added := 0
			for _, s := range parsed.Servers {
				if seen[s.ID] {
					continue
				}
				seen[s.ID] = true
				res.Servers = append(res.Servers, s)
				added++
			}
			p := sourceProgress{ID: src.ID, Name: src.Name, Count: added, Failed: len(parsed.Failed), ElapsedMs: ms(time.Since(start))}
			res.PerSource = append(res.PerSource, p)
			if len(parsed.Servers) == 0 {
				res.Errors = append(res.Errors, src.Name+": HY2/VLESS-ссылок не найдено (формат изменился?)")
			}
			listener.OnSourceProgress(mustJSON(p))
		}
		listener.OnFetchDone(mustJSON(res))
	}()
}

func fetchText(client *http.Client, url string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "FlickerVPN/4.0 (Android)")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024*1024))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// ---------- проверка живости (асинхронно) ----------

// ProbeListener — колбэки многоэтапной проверки (реализуется в Kotlin).
type ProbeListener interface {
	// OnProbeStage — по этапам: {id,stage,ok,fatal,latencyMs,errClass,error}
	OnProbeStage(resultJSON string)
	// OnProbeDone — итог: {total,alive,elapsedMs,results:[...]}
	OnProbeDone(resultJSON string)
}

var (
	probeMu     sync.Mutex
	probeCancel context.CancelFunc
	probeActive bool
)

// ProbeActive — идёт ли сейчас проверка.
func ProbeActive() bool {
	probeMu.Lock()
	defer probeMu.Unlock()
	return probeActive
}

// CancelProbe — отменить активную проверку.
func CancelProbe() {
	probeMu.Lock()
	cancel := probeCancel
	probeMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// ProbeServers — TCP → (QUIC для hy2) → HTTP через туннель → медиана → GeoIP.
// specsJSON: []probe.ServerSpec; optsJSON: probe.Options (mode full/quick, …).
// Асинхронно; прогресс — в listener.
func ProbeServers(specsJSON, optsJSON string, listener ProbeListener) {
	var specs []probe.ServerSpec
	if err := json.Unmarshal([]byte(specsJSON), &specs); err != nil {
		listener.OnProbeDone(`{"error":"specs: ` + escapeJSON(err.Error()) + `"}`)
		return
	}
	var opts probe.Options
	if optsJSON != "" {
		if err := json.Unmarshal([]byte(optsJSON), &opts); err != nil {
			listener.OnProbeDone(`{"error":"opts: ` + escapeJSON(err.Error()) + `"}`)
			return
		}
	}

	probeMu.Lock()
	if probeActive {
		probeMu.Unlock()
		listener.OnProbeDone(`{"error":"проверка уже идёт"}`)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	probeCancel = cancel
	probeActive = true
	probeMu.Unlock()

	go func() {
		started := time.Now()
		results := probe.Run(ctx, specs, opts, func(sr probe.StageResult) {
			listener.OnProbeStage(mustJSON(sr))
		})
		cancelled := ctx.Err() != nil // фиксируем ДО внутреннего cancel()
		cancel()
		probeMu.Lock()
		probeActive = false
		probeCancel = nil
		probeMu.Unlock()

		alive := 0
		for _, r := range results {
			if r.Alive {
				alive++
			}
		}
		listener.OnProbeDone(mustJSON(map[string]any{
			"total":     len(results),
			"alive":     alive,
			"cancelled": cancelled,
			"elapsedMs": ms(time.Since(started)),
			"results":   results,
		}))
	}()
}

// ProbeSpecsFromServers — конвертация сохранённых серверов (shareparse.Server)
// в probe-спеки. serversJSON: []shareparse.Server; возвращает JSON []probe.ServerSpec.
func ProbeSpecsFromServers(serversJSON string, allowHY2 bool) string {
	var servers []shareparse.Server
	_ = json.Unmarshal([]byte(serversJSON), &servers)
	specs := []probe.ServerSpec{}
	for _, s := range servers {
		if s.Demo || !probableProtocol(s.Protocol, allowHY2) || !hasCredentials(s) {
			continue
		}
		specs = append(specs, serverToProbeSpec(s))
	}
	return mustJSON(specs)
}

func probableProtocol(p string, allowHY2 bool) bool {
	switch p {
	case "vless", "trojan", "vmess", "shadowsocks":
		return true
	case "hysteria2":
		return allowHY2
	}
	return false
}

func hasCredentials(s shareparse.Server) bool {
	switch s.Protocol {
	case "vless", "vmess":
		return s.UUID != ""
	case "trojan", "shadowsocks", "hysteria2":
		return s.Auth != ""
	case "wireguard":
		return s.WireGuard != nil && s.WireGuard.PrivateKey != "" && s.WireGuard.PeerPublicKey != ""
	}
	return true
}

// serverToProbeSpec — одна серверная запись → проба-спека (не экспортируется:
// gomobile-API фасада держим на строках/примитивах, без структур internal-пакетов).
func serverToProbeSpec(s shareparse.Server) probe.ServerSpec {
	spec := probe.ServerSpec{
		ID: s.ID, Host: s.Host, Port: s.Port, Protocol: s.Protocol,
		Auth: s.Auth, SNI: s.SNI,
		TLSEnabled: s.TLSEnabled,
	}
	if s.TLS != nil {
		spec.Insecure = s.TLS.Insecure
	}
	if s.Protocol == "hysteria2" {
		spec.TLSEnabled = true
		if s.Obfs != nil {
			spec.ObfsType, spec.ObfsPassword = s.Obfs.Type, s.Obfs.Password
		}
	}
	if s.Protocol == "vless" || s.Protocol == "vmess" {
		spec.UUID = s.UUID
		spec.Flow = s.Flow
		spec.Fingerprint = s.Fingerprint
		if s.Reality != nil {
			spec.RealityPBK = s.Reality.PublicKey
			spec.RealitySID = s.Reality.ShortID
		}
	}
	spec.Cipher = s.Cipher
	if s.Transport != nil {
		spec.TransportType = s.Transport.Type
		spec.TransportPath = s.Transport.Path
		spec.TransportHost = s.Transport.Host
		spec.TransportSvcNm = s.Transport.ServiceName
	}
	return spec
}

// ---------- конфиг туннеля для libbox ----------

// TunParams — параметры TUN-входа (JSON из Kotlin).
type TunParams struct {
	MTU         int      `json:"mtu"`
	Address     []string `json:"address"`     // пусто → 172.19.0.1/30 + fdfe:dcba:9876::1/126
	DNSServer   string   `json:"dnsServer"`   // DNS через туннель; пусто → 1.1.1.1
	LogLevel    string   `json:"logLevel"`    // пусто → warning
	DisableIPv6 bool     `json:"disableIpv6"` // убрать IPv6-адреса TUN
}

// serverToConfig — shareparse.Server → config.ServerConfig (общая схема NM/libbox;
// не экспортируется — см. serverToProbeSpec).
func serverToConfig(s shareparse.Server) *config.ServerConfig {
	cfg := &config.ServerConfig{
		Protocol:    s.Protocol,
		Server:      s.Host,
		Port:        s.Port,
		Auth:        s.Auth,
		UUID:        s.UUID,
		Cipher:      s.Cipher,
		Flow:        s.Flow,
		Fingerprint: s.Fingerprint,
		PacketEnc:   s.PacketEncoding,
	}
	if s.TLSEnabled {
		cfg.SNI = s.SNI
		cfg.TLS = config.TLSConfig{Verify: true}
		if s.TLS != nil {
			cfg.TLS = config.TLSConfig{Verify: s.TLS.Verify, Insecure: s.TLS.Insecure}
		}
	}
	if s.Reality != nil && s.Reality.PublicKey != "" {
		cfg.Reality = &config.RealityClientConfig{PublicKey: s.Reality.PublicKey, ShortID: s.Reality.ShortID}
	}
	if s.Transport != nil && s.Transport.Type != "" {
		cfg.Transport = &config.TransportConfig{
			Type: s.Transport.Type, Path: s.Transport.Path,
			Host: s.Transport.Host, ServiceName: s.Transport.ServiceName,
		}
	}
	if s.Obfs != nil && s.Protocol == "hysteria2" {
		cfg.Obfs = config.ObfsConfig{Type: s.Obfs.Type, Password: s.Obfs.Password}
	}
	if s.WireGuard != nil {
		cfg.WireGuard = &config.WireGuardConfig{
			PrivateKey: s.WireGuard.PrivateKey, PeerPublicKey: s.WireGuard.PeerPublicKey,
			PreSharedKey: s.WireGuard.PreSharedKey, Address: s.WireGuard.Address,
			AllowedIPs: s.WireGuard.AllowedIPs, MTU: s.WireGuard.MTU,
			Reserved: s.WireGuard.Reserved, Keepalive: s.WireGuard.Keepalive,
		}
		if d, ok := s.Detour.(map[string]any); ok {
			cfg.Detour = detourFromMap(d)
		}
	}
	return cfg
}

func detourFromMap(d map[string]any) *config.DetourConfig {
	dt := &config.DetourConfig{}
	str := func(k string) string { v, _ := d[k].(string); return v }
	num := func(k string) int { v, _ := d[k].(float64); return int(v) }
	dt.Protocol = str("protocol")
	dt.Server = str("server")
	dt.Port = num("port")
	dt.UUID = str("uuid")
	dt.Password = str("password")
	dt.Flow = str("flow")
	dt.SNI = str("sni")
	dt.Fingerprint = str("fingerprint")
	if r, ok := d["reality"].(map[string]any); ok {
		pk, _ := r["publicKey"].(string)
		sid, _ := r["shortId"].(string)
		if pk != "" {
			dt.Reality = &config.RealityClientConfig{PublicKey: pk, ShortID: sid}
		}
	}
	return dt
}

// BuildTunConfig — полный конфиг sing-box для libbox: TUN-inbound (VpnService),
// outbound по протоколу сервера, DNS через туннель, auto_detect_interface.
// serverJSON: shareparse.Server; tunJSON: TunParams.
func BuildTunConfig(serverJSON, tunJSON string) (string, error) {
	var s shareparse.Server
	if err := json.Unmarshal([]byte(serverJSON), &s); err != nil {
		return "", fmt.Errorf("serverJSON: %w", err)
	}
	var tun TunParams
	if tunJSON != "" {
		if err := json.Unmarshal([]byte(tunJSON), &tun); err != nil {
			return "", fmt.Errorf("tunJSON: %w", err)
		}
	}
	if tun.MTU <= 0 {
		tun.MTU = 9000
	}
	if len(tun.Address) == 0 {
		// дефолт как в SFA: приватный v4 + ULA v6
		tun.Address = []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"}
	}
	if tun.DisableIPv6 {
		filtered := tun.Address[:0]
		for _, a := range tun.Address {
			if !strings.Contains(a, ":") {
				filtered = append(filtered, a)
			}
		}
		tun.Address = filtered
	}
	if tun.DNSServer == "" {
		tun.DNSServer = "1.1.1.1"
	}
	if tun.LogLevel == "" {
		tun.LogLevel = "warning"
	}

	cfg := serverToConfig(s)
	if err := cfg.Validate(); err != nil {
		return "", err
	}
	built := singcfg.Build(cfg)
	outbounds := append(built.Outbounds, map[string]any{"type": "direct", "tag": "flicker-direct"})

	// ВАЖНО: здесь НЕ ДОЛЖНО быть "sniff" (и sniff_override_destination,
	// sniff_timeout, domain_strategy, udp_disable_domain_unmapping).
	//
	// В sing-box v1.14.2 option/inbound.go при разборе ЛЮБОГО inbound проверяет:
	//
	//	if listenWrapper.TakeListenOptions().InboundOptions != (InboundOptions{}) {
	//		return E.New("legacy inbound fields are deprecated in sing-box 1.11.0
	//		              and removed in sing-box 1.13.0, checkout migration: ...")
	//	}
	//
	// Это E.New, то есть ФАТАЛЬНАЯ ошибка разбора конфига, а не предупреждение.
	// Сравнение идёт со СТАНДАРТНЫМ значением структуры, поэтому достаточно
	// любого одного непустого поля — и весь конфиг отвергается.
	//
	// Поля по-прежнему объявлены в InboundOptions с тегом json:"sniff,omitempty"
	// и помечены schema:"omit". schema:"omit" убирает их только из JSON-схемы
	// для документации; парсер их принимает, а потом падает на этой проверке.
	// Поэтому «поле есть в структуре» НЕ означает «поле можно передавать».
	//
	// Сниффинг переехал в route-правила (см. ниже).
	tunInbound := map[string]any{
		"type": "tun", "tag": "tun-in",
		"address": tun.Address,
		"mtu":     tun.MTU,
	}

	// ВАЖНО: поле "server", а НЕ "address".
	//
	// В sing-box v1.14.2 схема DNS-транспортов переписана:
	//   type DNSServerAddressOptions struct {
	//       Server     string `json:"server"`
	//       ServerPort uint16 `json:"server_port,omitempty"`
	//   }
	// Старое поле "address" удалено, и парсер конфига собран с
	// DisallowUnknownFields, поэтому на "address" он отвечает:
	//   decode config: dns.servers(1).address: json: unknown field "address"
	//
	// "detour" при этом остаётся валидным: RemoteDNSServerOptions встраивает
	// RawLocalDNSServerOptions -> DialerOptions, где
	//   Detour string `json:"detour,omitempty"`
	//
	// Адрес с портом ("1.1.1.1:5353") нужно разделять: server + server_port.
	srvHost, srvPort := splitHostPort(tun.DNSServer)
	remoteDNS := map[string]any{
		"type": "udp", "tag": "remote",
		"server": srvHost, "detour": built.Final,
	}
	if srvPort > 0 {
		remoteDNS["server_port"] = srvPort
	}

	dns := map[string]any{
		"servers": []map[string]any{
			{"type": "hosts", "tag": "hosts"},
			remoteDNS,
		},
		"final": "remote",
	}

	full := map[string]any{
		"log":       map[string]any{"level": tun.LogLevel},
		"dns":       dns,
		"inbounds":  []map[string]any{tunInbound},
		"outbounds": outbounds,
		"route": map[string]any{
			"final":                 built.Final,
			"auto_detect_interface": true,
			// Сниффинг и перехват DNS — теперь route-действия, а не поля inbound.
			// Миграция: sing-box.sagernet.org/migration/#migrate-legacy-inbound-fields-to-rule-actions
			//
			//	{"action":"sniff"}                     заменяет inbound.sniff
			//	{"protocol":"dns","action":"hijack-dns"} заменяет перехват DNS в tun
			//
			// Оба значения валидны: option/rule_action.go
			//	Action string `json:"action,omitempty"
			//	  enum:"route,route-options,direct,bypass,reject,hijack-dns,sniff,resolve"`
			// "protocol" — поле сопоставления из RawDefaultRule.
			//
			// Порядок важен: правила обходятся сверху вниз, поэтому sniff должен
			// стоять ДО hijack-dns — иначе DNS-пакеты уйдут на перехват
			// не сниффингованными.
			"rules": []map[string]any{
				{"action": "sniff"},
				{"protocol": "dns", "action": "hijack-dns"},
			},
		},
	}
	if len(built.Endpoints) > 0 {
		full["endpoints"] = built.Endpoints
	}
	b, err := json.Marshal(full)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// CheckTunConfig — базовая структурная проверка конфига. Полную проверку схемы
// sing-box делает libbox (Libbox.checkConfig в Kotlin) — мобильный фасад её
// не дублирует, чтобы не тянуть libbox в свои тесты.
func CheckTunConfig(configJSON string) error {
	var probe map[string]any
	if err := json.Unmarshal([]byte(configJSON), &probe); err != nil {
		return fmt.Errorf("не JSON: %w", err)
	}
	if _, ok := probe["outbounds"]; !ok {
		return fmt.Errorf("нет секции outbounds")
	}
	if _, ok := probe["inbounds"]; !ok {
		return fmt.Errorf("нет секции inbounds")
	}
	if _, ok := probe["route"]; !ok {
		return fmt.Errorf("нет секции route")
	}
	return nil
}

// ---------- WireGuard-ключи ----------

// GenerateWGKeypair — новая пара X25519 в wg(8)-формате (base64 с padding).
// Возвращает JSON {"privateKey": "...", "publicKey": "..."}.
func GenerateWGKeypair() (string, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	return mustJSON(map[string]string{
		"privateKey": base64.StdEncoding.EncodeToString(key.Bytes()),
		"publicKey":  base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()),
	}), nil
}

// ---------- применение результатов проб ----------

// recentWindow — окно success rate (как RECENT_WINDOW в background.js).
const recentWindow = 4

// ApplyProbeResults — применить итоги проверки к списку серверов
// (семантика 1:1 с background.js: stats-поля, флаг/страна/exitIp,
// человеческие ошибки + «двойной прогон»: success rate < 50% по окну
// последних проверок → узел считается мёртвым/нестабильным).
// resultsJSON: []probe.Result. Возвращает JSON {servers:[...], alive:N}.
func ApplyProbeResults(serversJSON, resultsJSON string, nowMs int64) string {
	var servers []shareparse.Server
	_ = json.Unmarshal([]byte(serversJSON), &servers)
	var results []probe.Result
	_ = json.Unmarshal([]byte(resultsJSON), &results)
	if nowMs <= 0 {
		nowMs = time.Now().UnixMilli()
	}
	byID := map[string]*shareparse.Server{}
	for i := range servers {
		byID[servers[i].ID] = &servers[i]
	}
	alive := 0
	for _, r := range results {
		s := byID[r.ID]
		if s == nil {
			continue
		}
		s.ChecksTotal++
		if r.Alive {
			s.Recent = append(s.Recent, 1)
		} else {
			s.Recent = append(s.Recent, 0)
		}
		if len(s.Recent) > recentWindow {
			s.Recent = s.Recent[len(s.Recent)-recentWindow:]
		}
		when := nowMs
		s.LastCheckAt = &when
		if r.Alive {
			alive++
			s.ChecksOk++
			p := r.LatencyMs
			if p < 0 {
				if s.Ping != nil && *s.Ping >= 0 {
					p = *s.Ping
				} else {
					p = 0
				}
			}
			s.Ping = &p
			s.ErrClass, s.LastError = "", ""
			if r.CountryCode != "" {
				s.CountryCode, s.Country = r.CountryCode, r.Country
				s.Flag = shareparse.CountryFlag(r.CountryCode)
			}
			if r.ExitIP != "" {
				s.ExitIP = r.ExitIP
			}
		} else {
			neg2 := -2
			s.Ping = &neg2
			s.ErrClass = r.ErrClass
			s.LastError = r.Error
		}
	}
	// двойной прогон: нестабильные узлы (<50% успеха) помечаем мёртвыми
	for i := range servers {
		s := &servers[i]
		if !s.Sub || len(s.Recent) < 2 {
			continue
		}
		sum := 0
		for _, v := range s.Recent {
			sum += v
		}
		rate := float64(sum) / float64(len(s.Recent))
		if rate < 0.5 {
			neg2 := -2
			s.Ping = &neg2
			s.ErrClass = "unstable"
			s.LastError = fmt.Sprintf("Нестабильный узел: успех %.0f%% за последние %d проверок", rate*100, len(s.Recent))
		}
	}
	return mustJSON(map[string]any{"servers": servers, "alive": alive})
}

// ---------- Android: защита сокетов от зацикливания в собственный туннель ----------

// SocketProtector — реализация VpnService.protect(fd) на стороне Kotlin.
// Вызывается для каждого сокета, который создаёт проверка живости;
// возвращает false, если сокет защитить не удалось.
type SocketProtector interface {
	ProtectFd(fd int32) bool
}

var (
	protectorMu sync.RWMutex
	protector   SocketProtector
)

// SetSocketProtector — подключить/отключить защитник сокетов (nil — отключить).
// Когда защитник установлен, все TCP/UDP-сокеты проверок помечаются
// VpnService.protect(fd) и ходят напрямую, минуя активный туннель.
func SetSocketProtector(p SocketProtector) {
	protectorMu.Lock()
	protector = p
	protectorMu.Unlock()
	if p == nil {
		probe.DialHook = nil
		return
	}
	probe.DialHook = func(network, address string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			protectorMu.RLock()
			pr := protector
			protectorMu.RUnlock()
			if pr != nil {
				pr.ProtectFd(int32(fd))
			}
		})
	}
}

// ---------- утилиты ----------

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return `{"error":"` + escapeJSON(err.Error()) + `"}`
	}
	return string(b)
}

func escapeJSON(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`)
	return r.Replace(s)
}

func ms(d time.Duration) int64 { return d.Milliseconds() }

// splitHostPort разрезает "1.1.1.1:5353" на хост и порт.
//
// Нужно потому, что в sing-box v1.14.2 DNS-сервер задаётся ДВУМЯ полями
// (server + server_port), а не одной строкой "host:port". IPv6-адреса в
// квадратных скобках ("[2001:4860:4860::8888]:53") обрабатываются отдельно:
// наивный поиск последнего ":" порезал бы такой адрес пополам.
//
// Порт 0 означает «не задан» — вызывающий код тогда не пишет server_port,
// и sing-box берёт дефолт для транспорта (53 для udp/tcp, 853 для tls, 443 для https).
func splitHostPort(addr string) (string, uint16) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", 0
	}
	// IPv6 в квадратных скобках: [::1]:5353
	if strings.HasPrefix(addr, "[") {
		if end := strings.Index(addr, "]"); end >= 0 {
			host := addr[1:end]
			rest := addr[end+1:]
			if strings.HasPrefix(rest, ":") {
				if p, err := strconv.Atoi(rest[1:]); err == nil && p > 0 && p <= 65535 {
					return host, uint16(p)
				}
			}
			return host, 0
		}
	}
	// "host:port" — но только если двоеточие ровно одно (иначе это голый IPv6)
	if i := strings.LastIndex(addr, ":"); i > 0 && strings.Count(addr, ":") == 1 {
		host := addr[:i]
		if p, err := strconv.Atoi(addr[i+1:]); err == nil && p > 0 && p <= 65535 {
			return host, uint16(p)
		}
		// Порт неразборчив или вне диапазона. Отбрасываем его и возвращаем хост
		// с нулевым портом — sing-box возьмёт дефолт транспорта. Одна опечатка
		// в поле DNS не должна лишать пользователя подключения.
		return host, 0
	}
	return addr, 0
}
