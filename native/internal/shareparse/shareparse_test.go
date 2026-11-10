package shareparse

// shareparse_test.go — паритет с JS-парсерами (lib/hy2-parser.js,
// lib/share-parser.js, lib/subscriptions.js). Эталонные id сгенерированы
// JS-версией (node) на тех же ссылках — совпадение id гарантирует, что
// Android и расширение Firefox говорят об одних и тех же узлах.

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// ---------- паритет id (эталон из JS-прогона 2026-10-07) ----------

func TestIDParityWithJS(t *testing.T) {
	cases := []struct {
		name   string
		link   string
		wantID string
		parse  func(string, string) (Server, error)
	}{
		{"hy2", `hysteria2://46gfRN8Pcy@91.99.225.11:443?insecure=1&sni=refersion.com&obfs=salamander&obfs-password=Jsbdksj@V2RayyNGvpn$Miracle#n`, "sub-ec67ee0a", ParseHY2Link},
		{"vless-reality", `vless://b4caaf57-ad77-4948-a6f5-51b3513799bf@46.250.250.149:2053?fp=firefox&pbk=hieuCHb3HYdDYHmTDyWw2SGqyfo36AVuA-wSiZMdU1M&security=reality&sid=9922313fffed1c63&sni=www.apple.com&type=tcp#vless-1262373571`, "sub-1f1cbb80", ParseVLESSLink},
		{"vless-vision", `vless://814bd064-544d-4255-a070-5705c03f6da9@3.114.220.22:10583?flow=xtls-rprx-vision&fp=chrome&pbk=k2hPp0tTW0Da-HK94wYpSCLbuK44LfGqC2MSJIM1Ti0&security=reality&sid=48050fab&sni=www.apple.com&type=tcp#v`, "sub-e78f0daf", ParseVLESSLink},
		{"trojan", `trojan://UX82473651@winning-marten.rooster465.autos:443?allowInsecure=1&sni=winning-marten.rooster465.autos&type=tcp#trojan-1648313005`, "sub-92fbb83a", ParseTrojanLink},
		{"vmess", `vmess://eyJhZGQiOiJ3dzExLmxldmlrb2dqZmRkLmlyIiwiYWlkIjowLCJob3N0Ijoid3cxMS5sZXZpa29namZkZC5pciIsImlkIjoiZjhjOGRjM2QtMGQzNy00NmIwLThiMzQtYTcyMzI4ODJmY2ZlIiwibmV0IjoicmF3IiwicGF0aCI6Ii8iLCJwb3J0IjoiMTgwMDAiLCJwcyI6InZtZXNzLTEwNjA5MDQ0OTciLCJzbmkiOiJ3dzExLmxldmlrb2dqZmRkLmlyIiwidGxzIjoiIiwidHlwZSI6Im5vbmUiLCJ2IjoiMiJ9`, "sub-e0f74325", ParseVmessLink},
		{"ss", `ss://YWVzLTEyOC1nY206c2hhZG93c29ja3M@149.22.87.240:443#shadowsocks-213`, "sub-310ef193", ParseSSLink},
		{"wg", `wireguard://aPUw1YAfQ8YEUZT7q0yCG3zo1rLHf0XGY18YVrRfYFE@1.2.3.4:51820?publickey=SPnovmLAlUeU6jxQ0zBdQ6a6FbbG9dDPA5h5y+svXXM=&allowedips=0.0.0.0/0,::/0&address=172.16.0.2/24&mtu=1280&reserved=111,73,244#WG-test`, "sub-44d77f0b", ParseWireGuardLink},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, err := c.parse(c.link, "parity")
			if err != nil {
				t.Fatalf("ошибка разбора: %v", err)
			}
			if s.ID != c.wantID {
				t.Fatalf("id расходится с JS: got %s, want %s", s.ID, c.wantID)
			}
			if s.Source != "parity" || !s.Sub {
				t.Fatalf("метаданные источника: %+v", s)
			}
		})
	}
}

// ---------- семантика vless ----------

func TestVLESSSemantics(t *testing.T) {
	s, err := ParseVLESSLink(`vless://814bd064-544d-4255-a070-5705c03f6da9@3.114.220.22:10583?flow=xtls-rprx-vision&fp=chrome&pbk=k2hPp0tTW0Da-HK94wYpSCLbuK44LfGqC2MSJIM1Ti0&security=reality&sid=48050fab&sni=www.apple.com&type=tcp#v`, "x")
	if err != nil {
		t.Fatal(err)
	}
	if s.Flow != "xtls-rprx-vision" || s.Fingerprint != "chrome" {
		t.Fatalf("flow/fp: %+v", s)
	}
	if s.Reality == nil || s.Reality.ShortID != "48050fab" {
		t.Fatalf("reality: %+v", s.Reality)
	}
	if !s.TLSEnabled || s.TLS.Insecure {
		t.Fatalf("tls: %+v %+v", s.TLSEnabled, s.TLS)
	}

	// security=none → TLS выключен
	s2, err := ParseVLESSLink(`vless://u@plain.example.com:80?security=none&type=tcp#p`, "x")
	if err != nil {
		t.Fatal(err)
	}
	if s2.TLSEnabled || s2.SNI != "" {
		t.Fatalf("plain vless: tls=%v sni=%q", s2.TLSEnabled, s2.SNI)
	}

	// неизвестный security → отказ
	if _, err := ParseVLESSLink(`vless://u@h.example:443?security=xtls#x`, "x"); err == nil {
		t.Fatal("ожидали отказ на security=xtls")
	}
	// reality без pbk → отказ
	if _, err := ParseVLESSLink(`vless://u@h.example:443?security=reality#x`, "x"); err == nil {
		t.Fatal("ожидали отказ: reality без pbk")
	}

	// ws-транспорт
	s3, err := ParseVLESSLink(`vless://u@104.20.36.205:443?host=argo.example&path=%2Fabc&security=tls&sni=argo.example&type=ws#w`, "x")
	if err != nil {
		t.Fatal(err)
	}
	if s3.Transport == nil || s3.Transport.Type != "ws" || s3.Transport.Path != "/abc" || s3.Transport.Host != "argo.example" {
		t.Fatalf("ws transport: %+v", s3.Transport)
	}
}

// ---------- семантика hy2 ----------

func TestHY2Semantics(t *testing.T) {
	// obfs + percent-encoded + мусорный sni
	s, err := ParseHY2Link(`hy2://H7mP2xY9kJ4nQ8wR5tF6vB3z@103.115.109.49:443?insecure=1&sni=https%3A%2F%2Ft.me%2Fx#hysteria2-16610`, "x")
	if err != nil {
		t.Fatal(err)
	}
	if s.SNI != "" {
		t.Fatalf("мусорный sni должен отбрасываться: %q", s.SNI)
	}
	s2, err := ParseHY2Link(`hysteria2://p%40ss%3Aw0rd@srv.example.org:443?insecure=1#enc`, "x")
	if err != nil {
		t.Fatal(err)
	}
	if s2.Auth != "p@ss:w0rd" {
		t.Fatalf("percent-decode auth: %q", s2.Auth)
	}
	if _, err := ParseHY2Link(`hysteria2://abc@x.example.com:443?obfs=salamander#n`, "x"); err == nil {
		t.Fatal("salamander без пароля → ошибка")
	}
	if _, err := ParseHY2Link(`hysteria2://abc@x.example.com:99999#x`, "x"); err == nil {
		t.Fatal("порт 99999 → ошибка")
	}
	// insecure отсутствует → insecure=true (как в JS)
	s3, _ := ParseHY2Link(`hysteria2://abc@plain.example.com:443#n`, "x")
	if !s3.TLS.Insecure || s3.TLS.Verify {
		t.Fatalf("дефолт insecure: %+v", s3.TLS)
	}
	// userpass
	s4, _ := ParseHY2Link(`hysteria2://user1:secretpass@1.2.3.4:443?insecure=1#u`, "x")
	if s4.Auth != "user1:secretpass" {
		t.Fatalf("userpass: %q", s4.Auth)
	}
}

// ---------- trojan / ss / wg ----------

func TestTrojanSSWG(t *testing.T) {
	s, err := ParseTrojanLink(`trojan://p%40ss%23w0rd@t.example.com:443?sni=t.example.com#x`, "x")
	if err != nil {
		t.Fatal(err)
	}
	if s.Auth != "p@ss#w0rd" || !s.TLSEnabled || s.TLS.Insecure {
		t.Fatalf("trojan: %+v", s)
	}

	ss, err := ParseSSLink(`ss://YWVzLTEyOC1nY206c2hhZG93c29ja3M@149.22.87.240:443#s`, "x")
	if err != nil {
		t.Fatal(err)
	}
	if ss.Cipher != "aes-128-gcm" || ss.Auth != "shadowsocks" {
		t.Fatalf("ss: %+v", ss)
	}

	wg, err := ParseWireGuardLink(`wireguard://priv@5.6.7.8:51820?publickey=pub&address=172.16.0.2/24#WG`, "x")
	if err != nil {
		t.Fatal(err)
	}
	if wg.WireGuard == nil || wg.WireGuard.PeerPublicKey != "pub" || wg.WireGuard.MTU != 1280 {
		t.Fatalf("wg: %+v", wg.WireGuard)
	}
	if len(wg.WireGuard.AllowedIPs) != 2 {
		t.Fatalf("allowedIPs дефолт: %+v", wg.WireGuard.AllowedIPs)
	}
	if _, err := ParseWireGuardLink(`wireguard://priv@5.6.7.8:51820#x`, "x"); err == nil {
		t.Fatal("wg без publickey → ошибка")
	}
}

// ---------- decode / extract / parseSubscription ----------

func TestDecodeAndExtract(t *testing.T) {
	plain := strings.Join([]string{
		"vless://u@one.example:443?security=none#one",
		"trojan://pw@two.example:443#two",
		"hy2://b@seven.example:443#seven-hy2",
		"https://not-a-node.example/page",
	}, "\n")
	b64 := base64.StdEncoding.EncodeToString([]byte(plain))
	if got := DecodeSubscriptionText(b64); got != plain {
		t.Fatalf("base64 decode: %q", got)
	}
	if got := DecodeSubscriptionText(plain); got != plain {
		t.Fatal("plain без изменений")
	}

	links := ExtractShareLinks(plain, false)
	if len(links) != 2 {
		t.Fatalf("без allowHY2: %v", links)
	}
	links = ExtractShareLinks(plain, true)
	if len(links) != 3 {
		t.Fatalf("с allowHY2: %v", links)
	}

	res := ParseSubscription(b64, "src", false)
	if len(res.Servers) != 2 || res.LinkCount != 2 {
		t.Fatalf("parseSubscription: %+v", res)
	}
	res2 := ParseSubscription(b64, "src", true)
	if len(res2.Servers) != 3 {
		t.Fatalf("parseSubscription allowHY2: %d", len(res2.Servers))
	}
}

// ---------- merge / prune / sort / flag ----------

func TestMergePruneSort(t *testing.T) {
	ping50 := 50
	now := time.Now().UnixMilli()
	existing := []Server{{
		ID: "sub-a", Name: "A", Host: "1.1.1.1", Port: 443, Protocol: "vless", UUID: "u",
		Ping: &ping50, ChecksOk: 3, ChecksTotal: 4, Recent: []int{1, 1, 0, 1},
		Country: "DE", CountryCode: "DE", Flag: "🇩🇪", ExitIP: "1.1.1.1",
		Sub: true, Source: "au1rxx", AddedAt: now - 1000, LastSeenAt: now - 1000,
	}}
	incoming := []Server{{
		ID: "sub-a", Name: "A-new", Host: "1.1.1.1", Port: 443, Protocol: "vless", UUID: "u",
		SNI: "new.sni", Sub: true, Source: "peasoft", Ping: nilInt(),
	}}
	m := MergeServers(existing, incoming, now)
	if m.Added != 0 || m.Updated != 1 || len(m.Merged) != 1 {
		t.Fatalf("merge counts: %+v", m)
	}
	got := m.Merged[0]
	if got.SNI != "new.sni" {
		t.Fatal("поле ссылки не обновлено")
	}
	if got.Ping == nil || *got.Ping != 50 || got.Country != "DE" || got.Source != "au1rxx" {
		t.Fatalf("статистика/источник потеряны: %+v", got)
	}

	// смена uuid → сброс проб
	incoming[0].UUID = "u2"
	m2 := MergeServers(existing, incoming, now)
	if m2.Merged[0].Ping != nil || m2.Merged[0].ChecksOk != 0 || len(m2.Merged[0].Recent) != 0 {
		t.Fatalf("смена credentials должна сбрасывать пробы: %+v", m2.Merged[0])
	}

	// prune
	day := int64(24 * 3600 * 1000)
	pruned := PruneStale([]Server{
		{ID: "old", Sub: true, LastSeenAt: now - 15*day},
		{ID: "fresh", Sub: true, LastSeenAt: now - day},
		{ID: "user", Sub: false, LastSeenAt: now - 100*day},
	}, now, 0)
	if len(pruned) != 2 || pruned[0].ID != "fresh" || pruned[1].ID != "user" {
		t.Fatalf("prune: %+v", pruned)
	}

	// sort
	dead, unknown := -2, 0
	sorted := SortServers([]Server{
		{ID: "dead", Protocol: "vless", Ping: &dead, Name: "d"},
		{ID: "fast", Protocol: "vless", Ping: &unknown, Name: "f"},
		{ID: "diag", Protocol: "direct", Name: "Диагностика"},
		{ID: "demo", Protocol: "vless", Demo: true, Name: "demo"},
	})
	if sorted[0].ID != "diag" || sorted[1].ID != "fast" || sorted[2].ID != "dead" || sorted[3].ID != "demo" {
		t.Fatalf("sort: %v", idsOf(sorted))
	}

	// flag
	if CountryFlag("DE") != "🇩🇪" || CountryFlag("us") != "🇺🇸" || CountryFlag("") != "🌍" || CountryFlag("DEU") != "🌍" {
		t.Fatal("countryFlag")
	}
}

func idsOf(ss []Server) []string {
	out := []string{}
	for _, s := range ss {
		out = append(out, s.ID)
	}
	return out
}

// ---------- источники ----------

func TestSources(t *testing.T) {
	defs := DefaultSources()
	enabled := 0
	for _, s := range defs {
		if s.Enabled {
			enabled++
		}
		if (s.ID == "matin-hy2" || s.ID == "jichang") && (s.Enabled || !s.AllowHY2) {
			t.Fatalf("HY2-источник должен быть выключен и allowHY2: %+v", s)
		}
	}
	if enabled != 4 {
		t.Fatalf("включённых источников: %d (ожидали 4)", enabled)
	}
	norm := NormalizeSources([]Source{{ID: "matin-vless", Enabled: false, RefreshMinutes: 30}})
	mv := norm[1]
	if mv.Enabled || mv.RefreshMinutes != 30 {
		t.Fatalf("normalize: %+v", mv)
	}
	if SourceIsDue(mv, time.Now()) {
		t.Fatal("выключенный источник не должен быть due")
	}
}
