package config

import "testing"

func TestValidate(t *testing.T) {
	cases := []struct {
		name    string
		cfg     ServerConfig
		wantErr bool
	}{
		{"hy2 ok", ServerConfig{Protocol: "hysteria2", Server: "h", Port: 443, Auth: "p"}, false},
		{"hy2 no auth", ServerConfig{Protocol: "hysteria2", Server: "h", Port: 443}, true},
		{"vless ok", ServerConfig{Protocol: "vless", Server: "h", Port: 443, UUID: "u"}, false},
		{"vless no uuid", ServerConfig{Protocol: "vless", Server: "h", Port: 443}, true},
		{"vless reality без pbk", ServerConfig{Protocol: "vless", Server: "h", Port: 443, UUID: "u",
			Reality: &RealityClientConfig{}}, true},
		{"vless reality ok", ServerConfig{Protocol: "vless", Server: "h", Port: 443, UUID: "u",
			Reality: &RealityClientConfig{PublicKey: "pbk"}}, false},
		{"trojan ok", ServerConfig{Protocol: "trojan", Server: "h", Port: 443, Auth: "p"}, false},
		{"trojan no password", ServerConfig{Protocol: "trojan", Server: "h", Port: 443}, true},
		{"vmess no uuid", ServerConfig{Protocol: "vmess", Server: "h", Port: 443}, true},
		{"ss ok", ServerConfig{Protocol: "shadowsocks", Server: "h", Port: 443, Auth: "p", Cipher: "aes-256-gcm"}, false},
		{"wg прямой ok", ServerConfig{Protocol: "wireguard", Server: "h", Port: 51820,
			WireGuard: &WireGuardConfig{PrivateKey: "pk", PeerPublicKey: "pub"}}, false},
		{"wg без ключей", ServerConfig{Protocol: "wireguard", Server: "h", Port: 51820,
			WireGuard: &WireGuardConfig{}}, true},
		{"wg матрёшка vless ok", ServerConfig{Protocol: "wireguard", Server: "10.99.0.1", Port: 51820,
			WireGuard: &WireGuardConfig{PrivateKey: "pk", PeerPublicKey: "pub"},
			Detour:    &DetourConfig{Protocol: "vless", Server: "vps", Port: 443, UUID: "u"}}, false},
		{"wg матрёшка без uuid детура", ServerConfig{Protocol: "wireguard", Server: "10.99.0.1", Port: 51820,
			WireGuard: &WireGuardConfig{PrivateKey: "pk", PeerPublicKey: "pub"},
			Detour:    &DetourConfig{Protocol: "vless", Server: "vps", Port: 443}}, true},
		{"wg матрёжка неизвестный протокол", ServerConfig{Protocol: "wireguard", Server: "10.99.0.1", Port: 51820,
			WireGuard: &WireGuardConfig{PrivateKey: "pk", PeerPublicKey: "pub"},
			Detour:    &DetourConfig{Protocol: "hy2", Server: "vps", Port: 443}}, true},
		{"tuic больше нет", ServerConfig{Protocol: "tuic", Server: "h", Port: 443, UUID: "u"}, true},
		{"direct ok", ServerConfig{Protocol: "direct", Server: "127.0.0.1", Port: 8080}, false},
		{"unknown proto", ServerConfig{Protocol: "openvpn", Server: "h", Port: 443}, true},
		{"no host", ServerConfig{Protocol: "direct", Port: 443}, true},
		{"bad port", ServerConfig{Protocol: "direct", Server: "h", Port: 70000}, true},
		{"zero port", ServerConfig{Protocol: "direct", Server: "h"}, true},
	}
	for _, tc := range cases {
		err := tc.cfg.Validate()
		if (err != nil) != tc.wantErr {
			t.Fatalf("%s: err=%v wantErr=%v", tc.name, err, tc.wantErr)
		}
	}
}

func TestAddrAndListen(t *testing.T) {
	c := ServerConfig{Server: "example.com", Port: 8443}
	if got := c.Addr(); got != "example.com:8443" {
		t.Fatalf("Addr=%q", got)
	}
	if got := c.ListenAddr(); got != "127.0.0.1:1080" {
		t.Fatalf("default ListenAddr=%q", got)
	}
	c.Listen = "127.0.0.1:2080"
	if got := c.ListenAddr(); got != "127.0.0.1:2080" {
		t.Fatalf("ListenAddr=%q", got)
	}
}

func TestSNIPriority(t *testing.T) {
	// Fake-SNI удалён: приоритет effectiveSni > sni > host
	c := ServerConfig{Server: "real.host", SNI: "sni.host"}
	if got := c.SNIToUse(); got != "sni.host" {
		t.Fatalf("sni должен побеждать host: %q", got)
	}
	c.SNI = ""
	if got := c.SNIToUse(); got != "real.host" {
		t.Fatalf("fallback на host: %q", got)
	}
	c.EffectiveSNI = "eff.host"
	if got := c.SNIToUse(); got != "eff.host" {
		t.Fatalf("effectiveSni имеет высший приоритет: %q", got)
	}
}
