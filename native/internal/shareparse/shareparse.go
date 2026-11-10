// Package shareparse — Go-порт парсеров подписочных ссылок (lib/hy2-parser.js,
// lib/share-parser.js, lib/subscriptions.js). Единое ядро для Android-приложения
// (gomobile), CLI-инструментов и тестов паритета с JS-версией расширения.
//
// Семантика и генерируемые id ОБЯЗАНЫ совпадать с JS: один и тот же узел из
// одной подписки получает одинаковый id ("sub-"+fnv1a) на всех платформах —
// это позволяет переиспользовать накопленную статистику живости.
package shareparse

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// ---------- общая модель сервера (JSON-теги = поля JS-объектов) ----------

type RealityRef struct {
	PublicKey string `json:"publicKey"`
	ShortID   string `json:"shortId,omitempty"`
}

type TransportRef struct {
	Type        string `json:"type"`
	Path        string `json:"path,omitempty"`
	Host        string `json:"host,omitempty"`
	ServiceName string `json:"serviceName,omitempty"`
}

type ObfsRef struct {
	Type     string `json:"type"`
	Password string `json:"password"`
}

type TLSRef struct {
	Verify   bool `json:"verify"`
	Insecure bool `json:"insecure"`
}

type WireGuardRef struct {
	PrivateKey    string   `json:"privateKey"`
	PeerPublicKey string   `json:"peerPublicKey"`
	PreSharedKey  string   `json:"preSharedKey,omitempty"`
	Address       []string `json:"address,omitempty"`
	AllowedIPs    []string `json:"allowedIPs,omitempty"`
	MTU           int      `json:"mtu,omitempty"`
	Reserved      []int    `json:"reserved,omitempty"`
	Keepalive     int      `json:"keepalive,omitempty"`
}

type Server struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`

	Auth   string `json:"auth,omitempty"`
	UUID   string `json:"uuid,omitempty"`
	Cipher string `json:"cipher,omitempty"`
	SNI    string `json:"sni,omitempty"`

	Flow        string        `json:"flow,omitempty"`
	Fingerprint string        `json:"fingerprint,omitempty"`
	SpiderX     string        `json:"spiderX,omitempty"`
	Reality     *RealityRef   `json:"reality,omitempty"`
	Transport   *TransportRef `json:"transport,omitempty"`
	Obfs        *ObfsRef      `json:"obfs,omitempty"`
	WireGuard   *WireGuardRef `json:"wireguard,omitempty"`
	Detour      any           `json:"detour,omitempty"`

	TLSEnabled bool    `json:"tlsEnabled"`
	TLS        *TLSRef `json:"tls,omitempty"`

	PacketEncoding string `json:"packetEncoding,omitempty"`
	AlterID        int    `json:"alterId,omitempty"`

	Source string `json:"source,omitempty"`
	Sub    bool   `json:"sub,omitempty"`
	Demo   bool   `json:"demo,omitempty"`
	Flag   string `json:"flag,omitempty"`
	Ping   *int   `json:"ping"`

	// статистика проверок (заполняется при слиянии/пробах)
	AddedAt     int64  `json:"addedAt,omitempty"`
	LastSeenAt  int64  `json:"lastSeenAt,omitempty"`
	LastCheckAt *int64 `json:"lastCheckAt,omitempty"`
	ChecksOk    int    `json:"checksOk,omitempty"`
	ChecksTotal int    `json:"checksTotal,omitempty"`
	Recent      []int  `json:"recent,omitempty"`
	Country     string `json:"country,omitempty"`
	CountryCode string `json:"countryCode,omitempty"`
	ExitIP      string `json:"exitIp,omitempty"`
	ErrClass    string `json:"errClass,omitempty"`
	LastError   string `json:"lastError,omitempty"`
}

// ---------- утилиты (семантика 1:1 с JS) ----------

// FNV1aHex — идентичен fnv1aHex из JS (Math.imul ≡ uint32-умножение в Go).
func FNV1aHex(s string) string {
	h := uint32(0x811c9dc5)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 0x01000193
	}
	return fmt.Sprintf("%08x", h)
}

// tryDecode — аналог JS tryDecode(decodeURIComponent): '+' НЕ заменяется,
// битые последовательности возвращаются как есть.
func tryDecode(v string) string {
	if !strings.Contains(v, "%") {
		return v
	}
	if dec, err := url.PathUnescape(v); err == nil {
		return dec
	}
	return v
}

var hostnameRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9\-_.]*[A-Za-z0-9])?$`)

func isValidHostname(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	if isIPv4(h) {
		return true
	}
	if strings.Contains(h, "://") || strings.Contains(h, "/") || strings.Contains(h, " ") {
		return false
	}
	return hostnameRe.MatchString(h)
}

func isIPv4(h string) bool {
	parts := strings.Split(h, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if n, err := strconv.Atoi(p); err != nil || n < 0 || n > 255 || (len(p) > 1 && p[0] == '0') {
			return false
		}
	}
	return true
}

func parseBoolParam(v string) bool {
	switch strings.ToLower(v) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// splitHostPort — поддержка IPv6-литералов [::1]:443; defaultPort при отсутствии.
func splitHostPortDef(hp string, defaultPort int) (string, int) {
	if hp == "" {
		return "", defaultPort
	}
	if strings.HasPrefix(hp, "[") {
		end := strings.Index(hp, "]")
		if end < 0 {
			return "", defaultPort
		}
		host := hp[1:end]
		rest := hp[end+1:]
		if strings.HasPrefix(rest, ":") {
			if p, err := strconv.Atoi(rest[1:]); err == nil {
				return host, p
			}
		}
		return host, defaultPort
	}
	idx := strings.LastIndex(hp, ":")
	if idx < 0 {
		return hp, defaultPort
	}
	p, err := strconv.Atoi(hp[idx+1:])
	if err != nil {
		return hp, defaultPort
	}
	return hp[:idx], p
}

func parseQueryMap(query string) map[string]string {
	params := map[string]string{}
	for _, kv := range strings.Split(query, "&") {
		if kv == "" {
			continue
		}
		eq := strings.Index(kv, "=")
		var k, v string
		if eq < 0 {
			k = kv
		} else {
			k, v = kv[:eq], tryDecode(kv[eq+1:])
		}
		k = strings.ToLower(k)
		if k != "" {
			params[k] = v
		}
	}
	return params
}

var emojiNameRe = regexp.MustCompile(`^[\s\p{So}\p{Sk}\p{Cn}]+$`)

func cleanName(fragment, fallback string) string {
	name := strings.TrimSpace(tryDecode(fragment))
	if i := strings.Index(name, "|"); i >= 0 {
		name = strings.TrimSpace(name[:i])
	}
	if name == "" || emojiNameRe.MatchString(name) {
		name = fallback
	}
	if r := []rune(name); len(r) > 64 {
		name = string(r[:64])
	}
	return name
}

func intPtr(v int) *int       { return &v }
func nilInt() *int            { return nil }
func int64Ptr(v int64) *int64 { return &v }

// ---------- Hysteria 2 (запасной UDP-стек) ----------

var hy2SchemeRe = regexp.MustCompile(`(?i)^(hysteria2|hy2)://`)

func ParseHY2Link(link, source string) (Server, error) {
	raw := strings.TrimRight(strings.TrimSpace(link), "\r")
	if raw == "" {
		return Server{}, fmt.Errorf("пустая ссылка")
	}
	if !hy2SchemeRe.MatchString(raw) {
		return Server{}, fmt.Errorf("не HY2-ссылка (ожидался hysteria2:// или hy2://)")
	}
	rest := hy2SchemeRe.ReplaceAllString(raw, "")

	fragment := ""
	if i := strings.Index(rest, "#"); i >= 0 {
		fragment, rest = rest[i+1:], rest[:i]
	}
	query := ""
	if i := strings.Index(rest, "?"); i >= 0 {
		query, rest = rest[i+1:], rest[:i]
	}
	rest = strings.TrimRight(rest, "/")

	userinfo, hostport := "", rest
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		userinfo, hostport = rest[:i], rest[i+1:]
	}
	auth := tryDecode(userinfo)
	host, port := splitHostPortDef(tryDecode(hostport), 443)

	if host == "" {
		return Server{}, fmt.Errorf("не указан сервер")
	}
	if port < 1 || port > 65535 {
		return Server{}, fmt.Errorf("некорректный порт: %s", hostport)
	}
	if auth == "" {
		return Server{}, fmt.Errorf("не указан пароль (auth пуст)")
	}

	p := parseQueryMap(query)
	sni := p["sni"]
	if sni == "" {
		sni = p["peer"]
	}
	if !isValidHostname(sni) {
		sni = ""
	}

	obfsType := strings.ToLower(p["obfs"])
	obfsPassword := firstSet(p["obfs-password"], p["obfspassword"], p["obfs-pass"])
	var obfs *ObfsRef
	switch {
	case obfsType == "salamander" && obfsPassword != "":
		obfs = &ObfsRef{Type: "salamander", Password: obfsPassword}
	case obfsType == "" || obfsType == "none":
		obfs = &ObfsRef{Type: "none", Password: ""}
	case obfsType == "salamander":
		return Server{}, fmt.Errorf("obfs=salamander без obfs-password")
	default:
		return Server{}, fmt.Errorf("неподдерживаемый obfs: %s", obfsType)
	}

	// insecure отсутствует → true (бесплатные узлы почти всегда self-signed)
	insecure := true
	if v, ok := firstSetOK(p["insecure"], p["skip-cert-verify"], p["allowinsecure"]); ok {
		insecure = parseBoolParam(v)
	}

	id := "sub-" + FNV1aHex(fmt.Sprintf("%s:%d:%s:%s", strings.ToLower(host), port, auth, obfs.Password))
	s := Server{
		ID: id, Name: cleanName(fragment, host), Host: host, Port: port,
		Protocol: "hysteria2", Auth: auth, SNI: sni, Obfs: obfs,
		TLSEnabled: true,
		TLS:        &TLSRef{Verify: !insecure, Insecure: insecure},
		Source:     sourceOrCustom(source), Sub: true, Flag: "🌍", Ping: nilInt(),
	}
	if up, err := strconv.Atoi(p["up"]); err == nil && up > 0 {
		_ = up // пропускная способность hy2 на Android не конфигурируется (BBR внутри)
	}
	return s, nil
}

func firstSet(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func firstSetOK(vals ...string) (string, bool) {
	for _, v := range vals {
		if v != "" {
			return v, true
		}
	}
	return "", false
}

func sourceOrCustom(source string) string {
	if source == "" {
		return "custom"
	}
	return source
}

// ---------- VLESS ----------

var fpValid = map[string]bool{
	"chrome": true, "firefox": true, "safari": true, "ios": true, "android": true,
	"edge": true, "360": true, "qq": true, "random": true, "randomized": true,
	"chrome_psk": true, "chrome_psk_shuffle": true, "chrome_padding_psk_shuffle": true,
	"chrome_pq": true, "chrome_pq_psk": true,
}

func ParseVLESSLink(link, source string) (Server, error) {
	raw := strings.TrimSpace(link)
	body, fragment, ok := splitScheme(raw, "vless")
	if !ok {
		return Server{}, fmt.Errorf("не vless-ссылка")
	}
	query := ""
	if i := strings.Index(body, "?"); i >= 0 {
		query, body = body[i+1:], body[:i]
	}
	at := strings.LastIndex(body, "@")
	if at < 0 {
		return Server{}, fmt.Errorf("vless: нет uuid@host")
	}
	uuid := tryDecode(body[:at])
	host, port := splitHostPortDef(tryDecode(body[at+1:]), 443)
	if uuid == "" {
		return Server{}, fmt.Errorf("vless: пустой uuid")
	}
	if host == "" {
		return Server{}, fmt.Errorf("vless: не указан сервер")
	}
	if port < 1 || port > 65535 {
		return Server{}, fmt.Errorf("vless: некорректный порт")
	}

	p := parseQueryMap(query)
	security := strings.ToLower(p["security"])
	switch security {
	case "", "none", "tls", "reality":
	default:
		return Server{}, fmt.Errorf("vless: неизвестный security=%s", security)
	}
	reality := security == "reality" || p["pbk"] != ""
	sni := firstSet(p["sni"], p["peer"])
	if !isValidHostname(sni) {
		sni = ""
	}
	if sni == "" && (security == "tls" || reality) {
		sni = host
	}
	fp := strings.ToLower(p["fp"])
	if !fpValid[fp] {
		fp = ""
	}
	if fp == "" && reality {
		fp = "chrome"
	}
	flow := ""
	if strings.ToLower(p["flow"]) == "xtls-rprx-vision" {
		flow = "xtls-rprx-vision"
	}

	id := "sub-" + FNV1aHex(fmt.Sprintf("vless|%s:%d:%s:%s:%s", strings.ToLower(host), port, uuid, p["pbk"], flow))
	s := Server{
		ID: id, Name: cleanName(fragment, host), Host: host, Port: port,
		Protocol: "vless", UUID: uuid, Flow: flow, Fingerprint: fp, SNI: sni,
		TLSEnabled: security == "tls" || reality,
		Transport:  parseTransport(p),
		Source:     sourceOrCustom(source), Sub: true, Flag: "🌍", Ping: nilInt(),
	}
	insecure := parseBoolParam(firstSet(p["allowinsecure"], p["insecure"]))
	s.TLS = &TLSRef{Verify: !insecure, Insecure: insecure}
	if pe := p["packetencoding"]; pe != "" {
		s.PacketEncoding = pe
	}
	if reality {
		if p["pbk"] == "" {
			return Server{}, fmt.Errorf("vless+reality: нет pbk")
		}
		s.Reality = &RealityRef{PublicKey: p["pbk"], ShortID: p["sid"]}
		if p["spx"] != "" {
			s.SpiderX = p["spx"]
		}
	}
	return s, nil
}

// ---------- Trojan ----------

func ParseTrojanLink(link, source string) (Server, error) {
	raw := strings.TrimSpace(link)
	body, fragment, ok := splitScheme(raw, "trojan")
	if !ok {
		return Server{}, fmt.Errorf("не trojan-ссылка")
	}
	query := ""
	if i := strings.Index(body, "?"); i >= 0 {
		query, body = body[i+1:], body[:i]
	}
	at := strings.LastIndex(body, "@")
	if at < 0 {
		return Server{}, fmt.Errorf("trojan: нет password@host")
	}
	password := tryDecode(body[:at])
	host, port := splitHostPortDef(tryDecode(body[at+1:]), 443)
	if password == "" {
		return Server{}, fmt.Errorf("trojan: пустой пароль")
	}
	if host == "" {
		return Server{}, fmt.Errorf("trojan: не указан сервер")
	}
	if port < 1 || port > 65535 {
		return Server{}, fmt.Errorf("trojan: некорректный порт")
	}
	p := parseQueryMap(query)
	sni := firstSet(p["sni"], p["peer"])
	if !isValidHostname(sni) {
		sni = ""
	}
	if sni == "" {
		sni = host
	}
	insecure := parseBoolParam(firstSet(p["allowinsecure"], p["insecure"]))
	id := "sub-" + FNV1aHex(fmt.Sprintf("trojan|%s:%d:%s", strings.ToLower(host), port, password))
	return Server{
		ID: id, Name: cleanName(fragment, host), Host: host, Port: port,
		Protocol: "trojan", Auth: password, SNI: sni,
		TLSEnabled: true,
		TLS:        &TLSRef{Verify: !insecure, Insecure: insecure},
		Transport:  parseTransport(p),
		Source:     sourceOrCustom(source), Sub: true, Flag: "🌍", Ping: nilInt(),
	}, nil
}

// ---------- VMess ----------

type vmessJSON struct {
	Add  string `json:"add"`
	Aid  int    `json:"aid"`
	Host string `json:"host"`
	ID   string `json:"id"`
	Net  string `json:"net"`
	Path string `json:"path"`
	Port string `json:"port"`
	Ps   string `json:"ps"`
	Sni  string `json:"sni"`
	TLS  string `json:"tls"`
	Type string `json:"type"`
	Scy  string `json:"scy"`
	V    string `json:"v"`
}

var vmessRe = regexp.MustCompile(`^vmess://([A-Za-z0-9+/=]+)\s*(?:#(.*))?$`)

func ParseVmessLink(link, source string) (Server, error) {
	m := vmessRe.FindStringSubmatch(strings.TrimSpace(link))
	if m == nil {
		return Server{}, fmt.Errorf("vmess: не ссылка или не base64")
	}
	raw, err := base64.StdEncoding.DecodeString(m[1])
	if err != nil {
		if raw, err = base64.RawStdEncoding.DecodeString(m[1]); err != nil {
			return Server{}, fmt.Errorf("vmess: битый base64")
		}
	}
	var j vmessJSON
	if err := json.Unmarshal(raw, &j); err != nil {
		return Server{}, fmt.Errorf("vmess: битый JSON")
	}
	host := firstSet(j.Add)
	port, _ := strconv.Atoi(j.Port)
	if host == "" || j.ID == "" || port < 1 || port > 65535 {
		return Server{}, fmt.Errorf("vmess: неполные данные")
	}
	net := strings.ToLower(j.Net)
	if net == "" {
		net = "tcp"
	}
	tlsOn := strings.EqualFold(j.TLS, "tls")
	sni := j.Sni
	if sni == "" && tlsOn {
		sni = host
	}
	p := map[string]string{"type": net, "host": j.Host, "path": j.Path}
	if net == "grpc" {
		p["servicename"] = j.Path
	}
	name := cleanName(m[2], "")
	if name == "" {
		name = cleanName(j.Ps, host)
	}
	id := "sub-" + FNV1aHex(fmt.Sprintf("vmess|%s:%d:%s", strings.ToLower(host), port, j.ID))
	s := Server{
		ID: id, Name: name, Host: host, Port: port,
		Protocol: "vmess", UUID: j.ID, Cipher: firstSet2(j.Scy, "auto"), AlterID: j.Aid,
		TLSEnabled: tlsOn, Transport: parseTransport(p),
		Source: sourceOrCustom(source), Sub: true, Flag: "🌍", Ping: nilInt(),
	}
	if tlsOn {
		s.SNI = sni
		s.TLS = &TLSRef{Verify: true}
	}
	return s, nil
}

func firstSet2(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// ---------- Shadowsocks (SIP002) ----------

func ParseSSLink(link, source string) (Server, error) {
	raw := strings.TrimSpace(link)
	body, fragment, ok := splitScheme(raw, "ss")
	if !ok {
		return Server{}, fmt.Errorf("не ss-ссылка")
	}
	if i := strings.Index(body, "?"); i >= 0 {
		body = body[:i] // ss-плагины игнорируем
	}
	at := strings.LastIndex(body, "@")
	if at < 0 {
		return Server{}, fmt.Errorf("ss: нет userinfo@host")
	}
	userinfo := body[:at]
	host, port := splitHostPortDef(body[at+1:], 8388)
	if host == "" {
		return Server{}, fmt.Errorf("ss: не указан сервер")
	}
	method, password := "", ""
	if !strings.Contains(userinfo, ":") {
		dec := tryDecode(userinfo)
		dec = strings.ReplaceAll(dec, "-", "+")
		dec = strings.ReplaceAll(dec, "_", "/")
		if b, err := base64.StdEncoding.DecodeString(padB64(dec)); err == nil {
			if s := string(b); strings.Contains(s, ":") {
				i := strings.Index(s, ":")
				method, password = s[:i], s[i+1:]
			}
		}
	}
	if method == "" && strings.Contains(userinfo, ":") {
		i := strings.Index(userinfo, ":")
		method, password = userinfo[:i], tryDecode(userinfo[i+1:])
	}
	if method == "" || password == "" {
		return Server{}, fmt.Errorf("ss: не разобран method:password")
	}
	id := "sub-" + FNV1aHex(fmt.Sprintf("ss|%s:%d:%s:%s", strings.ToLower(host), port, method, password))
	return Server{
		ID: id, Name: cleanName(fragment, host), Host: host, Port: port,
		Protocol: "shadowsocks", Auth: password, Cipher: method,
		Source: sourceOrCustom(source), Sub: true, Flag: "🌍", Ping: nilInt(),
	}, nil
}

func padB64(s string) string {
	switch len(s) % 4 {
	case 2:
		return s + "=="
	case 3:
		return s + "="
	}
	return s
}

// ---------- WireGuard ----------

func ParseWireGuardLink(link, source string) (Server, error) {
	raw := strings.TrimSpace(link)
	body, fragment, ok := splitScheme(raw, "wireguard")
	if !ok {
		return Server{}, fmt.Errorf("не wireguard-ссылка")
	}
	query := ""
	if i := strings.Index(body, "?"); i >= 0 {
		query, body = body[i+1:], body[:i]
	}
	at := strings.LastIndex(body, "@")
	if at < 0 {
		return Server{}, fmt.Errorf("wireguard: нет key@endpoint")
	}
	priv := tryDecode(body[:at])
	host, port := splitHostPortDef(tryDecode(body[at+1:]), 51820)
	if priv == "" {
		return Server{}, fmt.Errorf("wireguard: пустой приватный ключ")
	}
	if host == "" {
		return Server{}, fmt.Errorf("wireguard: не указан endpoint")
	}
	p := parseQueryMap(query)
	pub := firstSet(p["publickey"], p["pubkey"], p["peer_public_key"])
	if pub == "" {
		return Server{}, fmt.Errorf("wireguard: нет publickey пира")
	}
	wg := &WireGuardRef{
		PrivateKey:    priv,
		PeerPublicKey: pub,
		PreSharedKey:  firstSet(p["psk"], p["presharedkey"]),
		Address:       splitCSV(firstSet(p["address"], p["local_address"])),
		AllowedIPs:    splitCSV(firstSet(p["allowedips"], p["allowed_ips"])),
		Keepalive:     25,
	}
	if len(wg.AllowedIPs) == 0 {
		wg.AllowedIPs = []string{"0.0.0.0/0", "::/0"}
	}
	if mtu, err := strconv.Atoi(p["mtu"]); err == nil && mtu > 0 {
		wg.MTU = mtu
	} else {
		wg.MTU = 1280
	}
	if r := splitCSV(p["reserved"]); len(r) == 3 {
		wg.Reserved = []int{}
		okAll := true
		for _, x := range r {
			n, err := strconv.Atoi(x)
			if err != nil {
				okAll = false
				break
			}
			wg.Reserved = append(wg.Reserved, n)
		}
		if !okAll {
			wg.Reserved = nil
		}
	}
	if k, err := strconv.Atoi(p["keepalive"]); err == nil && k > 0 {
		wg.Keepalive = k
	}
	id := "sub-" + FNV1aHex(fmt.Sprintf("wg|%s:%d:%s:%s", strings.ToLower(host), port, priv, pub))
	return Server{
		ID: id, Name: cleanName(fragment, host), Host: host, Port: port,
		Protocol: "wireguard", WireGuard: wg, Detour: nil,
		Source: sourceOrCustom(source), Sub: true, Flag: "🌍", Ping: nilInt(),
	}, nil
}

func splitCSV(v string) []string {
	if v == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(v, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ---------- общие хелперы схем/транспортов ----------

// splitScheme отделяет body и fragment; проверяет схему (регистронезависимо).
func splitScheme(raw, scheme string) (body, fragment string, ok bool) {
	prefix := scheme + "://"
	if len(raw) <= len(prefix) || !strings.EqualFold(raw[:len(prefix)], prefix) {
		return "", "", false
	}
	rest := raw[len(prefix):]
	if i := strings.Index(rest, "#"); i >= 0 {
		return rest[:i], rest[i+1:], true
	}
	return rest, "", true
}

func parseTransport(p map[string]string) *TransportRef {
	net := strings.ToLower(firstSet(p["type"], p["net"]))
	switch net {
	case "ws":
		path := p["path"]
		if path == "" {
			path = "/"
		}
		return &TransportRef{Type: "ws", Path: path, Host: p["host"]}
	case "grpc":
		return &TransportRef{Type: "grpc", ServiceName: firstSet(p["servicename"], p["path"])}
	case "http", "h2":
		path := p["path"]
		if path == "" {
			path = "/"
		}
		return &TransportRef{Type: "http", Path: path, Host: p["host"]}
	case "httpupgrade":
		path := p["path"]
		if path == "" {
			path = "/"
		}
		return &TransportRef{Type: "httpupgrade", Path: path, Host: p["host"]}
	case "tcp":
		if strings.EqualFold(firstSet(p["headertype"], p["type2"]), "http") {
			path := p["path"]
			if path == "" {
				path = "/"
			}
			return &TransportRef{Type: "http", Path: path, Host: p["host"]}
		}
		return nil
	}
	return nil
}

// ---------- пакетный разбор ----------

type FailedLink struct {
	Link  string `json:"link"`
	Error string `json:"error"`
}

type ParseResult struct {
	Servers   []Server     `json:"servers"`
	Failed    []FailedLink `json:"failed"`
	LinkCount int          `json:"linkCount"`
}

type parserEntry struct {
	prefixes []string
	parse    func(link, source string) (Server, error)
}

var parsers = []parserEntry{
	{[]string{"vless://"}, ParseVLESSLink},
	{[]string{"trojan://"}, ParseTrojanLink},
	{[]string{"vmess://"}, ParseVmessLink},
	{[]string{"ss://"}, ParseSSLink},
	{[]string{"wireguard://"}, ParseWireGuardLink},
}

var hy2Parsers = []parserEntry{
	{[]string{"hysteria2://", "hy2://"}, ParseHY2Link},
}

// ParseShareLinks разбирает массив ссылок; hy2 — только при allowHY2.
func ParseShareLinks(links []string, source string, allowHY2 bool) ParseResult {
	res := ParseResult{Servers: []Server{}, Failed: []FailedLink{}}
	seen := map[string]bool{}
	all := parsers
	if allowHY2 {
		all = append(all, hy2Parsers...)
	}
	for _, link := range links {
		var found *parserEntry
		for i := range all {
			for _, pre := range all[i].prefixes {
				if strings.HasPrefix(strings.ToLower(link), pre) {
					found = &all[i]
					break
				}
			}
			if found != nil {
				break
			}
		}
		if found == nil {
			res.Failed = append(res.Failed, FailedLink{Link: trunc(link, 120), Error: "неподдерживаемая схема"})
			continue
		}
		s, err := found.parse(link, source)
		if err != nil {
			res.Failed = append(res.Failed, FailedLink{Link: trunc(link, 120), Error: err.Error()})
			continue
		}
		if seen[s.ID] {
			continue
		}
		seen[s.ID] = true
		res.Servers = append(res.Servers, s)
	}
	return res
}

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

// ---------- подписки: decode / extract / parse ----------

var b64CharsetRe = regexp.MustCompile(`^[A-Za-z0-9+/=\s]+$`)

// DecodeSubscriptionText — plain или base64-блоб (эвристика как в JS).
func DecodeSubscriptionText(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	if strings.Contains(trimmed, "://") {
		return trimmed
	}
	if len(trimmed) >= 16 && b64CharsetRe.MatchString(trimmed) {
		clean := strings.Join(strings.Fields(trimmed), "")
		if b, err := base64.StdEncoding.DecodeString(padB64(clean)); err == nil {
			if t := string(b); strings.Contains(t, "://") {
				return t
			}
		}
	}
	return trimmed
}

var (
	shareRe = regexp.MustCompile(`(?i)(?:vless|trojan|vmess|ss)://[^\s"'<>]+`)
	wgRe    = regexp.MustCompile(`(?i)wireguard://[^\s"'<>]+`)
	hy2Re   = regexp.MustCompile(`(?i)(?:hysteria2|hy2)://[^\s"'<>]+`)
	tailPun = `),;.'"<>`
)

// ExtractShareLinks — все ссылки TCP/443-стека (+wg); hy2 — по флагу.
func ExtractShareLinks(text string, allowHY2 bool) []string {
	if text == "" {
		return nil
	}
	var out []string
	collect := func(re *regexp.Regexp) {
		for _, m := range re.FindAllString(text, -1) {
			m = strings.TrimRight(m, tailPun)
			if len(m) > 8 {
				out = append(out, m)
			}
		}
	}
	collect(shareRe)
	collect(wgRe)
	if allowHY2 {
		collect(hy2Re)
	}
	return out
}

var hy2LinkRe = regexp.MustCompile(`(?i)^(hysteria2|hy2)://`)
var schemeRe = regexp.MustCompile(`^https?://`)

// ParseSubscription — полный разбор текста подписки одного источника.
func ParseSubscription(rawText, sourceID string, allowHY2 bool) ParseResult {
	text := DecodeSubscriptionText(rawText)
	links := ExtractShareLinks(text, allowHY2)
	var share, hy2 []string
	for _, l := range links {
		if hy2LinkRe.MatchString(l) {
			hy2 = append(hy2, l)
		} else {
			share = append(share, l)
		}
	}
	r1 := ParseShareLinks(share, sourceID, false)
	var r2 ParseResult
	if len(hy2) > 0 {
		r2 = ParseShareLinks(hy2, sourceID, true)
	}
	return ParseResult{
		Servers:   append(r1.Servers, r2.Servers...),
		Failed:    append(r1.Failed, r2.Failed...),
		LinkCount: len(links),
	}
}

// ---------- источники (зеркало DEFAULT_SOURCES из lib/subscriptions.js) ----------

type Source struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	URL            string `json:"url"`
	RefreshMinutes int    `json:"refreshMinutes"`
	Builtin        bool   `json:"builtin"`
	Enabled        bool   `json:"enabled"`
	AllowHY2       bool   `json:"allowHY2,omitempty"`
	Note           string `json:"note,omitempty"`
	LastFetchAt    int64  `json:"lastFetchAt,omitempty"`
	LastCount      int    `json:"lastCount,omitempty"`
	LastError      string `json:"lastError,omitempty"`
}

func DefaultSources() []Source {
	return []Source{
		{ID: "au1rxx", Name: "Au1rxx · free-vpn-subscriptions (verified)",
			URL:            "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/v2ray-base64.txt",
			RefreshMinutes: 1440, Builtin: true, Enabled: true,
			Note: "Узлы проверены HTTP-трафиком перед публикацией; vless/trojan/vmess/ss"},
		{ID: "matin-vless", Name: "MatinGhanbari · v2ray-configs (VLESS)",
			URL:            "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vless.txt",
			RefreshMinutes: 60, Builtin: true, Enabled: true,
			Note: "Только VLESS (включая Reality/Vision), частые обновления"},
		{ID: "matin-trojan", Name: "MatinGhanbari · v2ray-configs (Trojan)",
			URL:            "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/trojan.txt",
			RefreshMinutes: 60, Builtin: true, Enabled: true,
			Note: "Только Trojan (TCP/443)"},
		{ID: "peasoft", Name: "peasoft · NoMoreWalls",
			URL:            "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list_raw.txt",
			RefreshMinutes: 360, Builtin: true, Enabled: true,
			Note: "Смешанный список (vless/trojan/ss/vmess)"},
		{ID: "matin-hy2", Name: "MatinGhanbari · Hysteria 2 (экспериментальный UDP)",
			URL:            "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/hysteria2.txt",
			RefreshMinutes: 60, Builtin: true, Enabled: false, AllowHY2: true,
			Note: "UDP/QUIC; включите, только если нужен запасной протокол"},
		{ID: "jichang", Name: "hysteria350 · free-jichang (экспериментальный UDP)",
			URL:            "https://ndxy.fn0821.xyz/nodes/9d002b4c7aae73013aa9d4004ba80e17",
			RefreshMinutes: 1440, Builtin: true, Enabled: false, AllowHY2: true,
			Note: "Ежедневные HY2-подписки, менее надёжный источник"},
	}
}

// NormalizeSources — слияние сохранённых источников с дефолтами (как в JS).
func NormalizeSources(saved []Source) []Source {
	out := []Source{}
	byID := map[string]Source{}
	for _, s := range saved {
		byID[s.ID] = s
	}
	for _, def := range DefaultSources() {
		s := def
		if prev, ok := byID[s.ID]; ok {
			s.Enabled = prev.Enabled
			if prev.RefreshMinutes > 0 {
				s.RefreshMinutes = prev.RefreshMinutes
			}
			s.LastFetchAt, s.LastCount, s.LastError = prev.LastFetchAt, prev.LastCount, prev.LastError
			delete(byID, s.ID)
		}
		out = append(out, s)
	}
	for _, s := range saved {
		if _, dup := byID[s.ID]; !dup {
			continue
		}
		if !strings.HasPrefix(strings.ToLower(s.URL), "http://") && !strings.HasPrefix(strings.ToLower(s.URL), "https://") {
			continue
		}
		if s.RefreshMinutes <= 0 {
			s.RefreshMinutes = 720
		}
		s.Builtin = false
		if s.Name == "" {
			s.Name = trunc(schemeRe.ReplaceAllString(s.URL, ""), 48)
		}
		if s.Note == "" {
			s.Note = "Пользовательский источник"
		}
		out = append(out, s)
	}
	return out
}

// ---------- слияние / GC / сортировка / флаги ----------

func credsKey(s Server) string {
	b, _ := json.Marshal([]any{s.Auth, s.UUID, obfsPass(s), realityPK(s), wgPriv(s), s.Host, s.Port})
	return string(b)
}
func obfsPass(s Server) string {
	if s.Obfs != nil {
		return s.Obfs.Password
	}
	return ""
}
func realityPK(s Server) string {
	if s.Reality != nil {
		return s.Reality.PublicKey
	}
	return ""
}
func wgPriv(s Server) string {
	if s.WireGuard != nil {
		return s.WireGuard.PrivateKey
	}
	return ""
}

type MergeResult struct {
	Merged  []Server `json:"merged"`
	Added   int      `json:"added"`
	Updated int      `json:"updated"`
}

// MergeServers — семантика 1:1 с lib/subscriptions.js mergeServers.
func MergeServers(existing, incoming []Server, now int64) MergeResult {
	byID := map[string]Server{}
	order := []string{}
	for _, s := range existing {
		if _, ok := byID[s.ID]; !ok {
			order = append(order, s.ID)
		}
		byID[s.ID] = s
	}
	res := MergeResult{}
	for _, inc := range incoming {
		prev, exists := byID[inc.ID]
		if !exists {
			inc.AddedAt, inc.LastSeenAt = now, now
			inc.ChecksOk, inc.ChecksTotal, inc.Recent = 0, 0, []int{}
			byID[inc.ID] = inc
			order = append(order, inc.ID)
			res.Added++
			continue
		}
		linkChanged := credsKey(prev) != credsKey(inc)
		merged := inc
		// имя: прежнее важнее сгенерированного
		if prev.Name != "" && prev.Name != "deleted" {
			merged.Name = prev.Name
		}
		if linkChanged {
			merged.Ping = nilInt()
			merged.LastCheckAt = nil
			merged.ChecksOk, merged.ChecksTotal, merged.Recent = 0, 0, []int{}
			merged.Flag = "🌍"
		} else {
			merged.Ping = prev.Ping
			merged.LastCheckAt = prev.LastCheckAt
			merged.ChecksOk, merged.ChecksTotal, merged.Recent = prev.ChecksOk, prev.ChecksTotal, prev.Recent
			merged.Country, merged.CountryCode, merged.ExitIP = prev.Country, prev.CountryCode, prev.ExitIP
			merged.Flag, merged.ErrClass, merged.LastError = prev.Flag, prev.ErrClass, prev.LastError
		}
		merged.Source = firstSet2(prev.Source, inc.Source)
		merged.AddedAt = prev.AddedAt
		if merged.AddedAt == 0 {
			merged.AddedAt = now
		}
		merged.LastSeenAt = now
		byID[inc.ID] = merged
		res.Updated++
	}
	for _, id := range order {
		res.Merged = append(res.Merged, byID[id])
	}
	return res
}

// PruneStale — GC подписочных серверов, не встречавшихся maxAge.
func PruneStale(servers []Server, now, maxAgeMs int64) []Server {
	if maxAgeMs <= 0 {
		maxAgeMs = 14 * 24 * 3600 * 1000
	}
	out := []Server{}
	for _, s := range servers {
		if s.Sub && s.LastSeenAt > 0 && now-s.LastSeenAt > maxAgeMs {
			continue
		}
		out = append(out, s)
	}
	return out
}

func rank(s Server) int {
	if s.Demo {
		return 4
	}
	if s.Ping != nil && *s.Ping >= 0 {
		return 0
	}
	if s.Ping == nil || *s.Ping == -1 {
		return 2
	}
	if *s.Ping == -2 {
		return 3
	}
	return 2
}

// SortServers — direct сверху, живые по задержке, неизвестные, мёртвые, демо.
func SortServers(servers []Server) []Server {
	out := append([]Server(nil), servers...)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if (a.Protocol == "direct") != (b.Protocol == "direct") {
			return a.Protocol == "direct"
		}
		ra, rb := rank(a), rank(b)
		if ra != rb {
			return ra < rb
		}
		const far = int(^uint(0) >> 1)
		pa, pb := far, far
		if a.Ping != nil && *a.Ping >= 0 {
			pa = *a.Ping
		}
		if b.Ping != nil && *b.Ping >= 0 {
			pb = *b.Ping
		}
		if pa != pb {
			return pa < pb
		}
		return a.Name < b.Name
	})
	return out
}

// CountryFlag — ISO-код → emoji-флаг (как countryFlag в JS).
func CountryFlag(code string) string {
	if len(code) != 2 {
		return "🌍"
	}
	up := strings.ToUpper(code)
	for _, r := range up {
		if r < 'A' || r > 'Z' {
			return "🌍"
		}
	}
	out := []rune{}
	for _, r := range up {
		out = append(out, rune(0x1F1E6)+r-'A')
	}
	return string(out)
}

// SourceIsDue — пора ли перечитывать источник.
func SourceIsDue(src Source, now time.Time) bool {
	if !src.Enabled {
		return false
	}
	if src.LastFetchAt == 0 {
		return true
	}
	refresh := src.RefreshMinutes
	if refresh <= 0 {
		refresh = 720
	}
	return now.UnixMilli()-src.LastFetchAt >= int64(refresh)*60_000
}

// проверка, что net-пакет используется (splitHostPortDef для IPv6)
var _ = net.ParseIP
var _ = unicode.IsLetter
