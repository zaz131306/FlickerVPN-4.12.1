// Package singcfg — генерация outbound/endpoint-секций конфига sing-box по
// ServerConfig. Общий код для desktop-драйвера (tunnel/sing.go, SOCKS-вход)
// и Android-приложения (mobile.BuildTunConfig, TUN-вход через libbox).
package singcfg

import (
	"flicker-vpn/native/internal/config"
)

// Built — результат: исходящие, endpoint'ы и финальный маршрут.
type Built struct {
	Outbounds []map[string]any
	Endpoints []map[string]any
	Final     string
}

// Build собирает outbounds/endpoints/final для серверного конфига.
func Build(cfg *config.ServerConfig) Built {
	var outbounds []map[string]any
	var endpoints []map[string]any
	final := "flicker-out"

	// Транспорт v2ray (ws/grpc/httpupgrade) — общий для vless/vmess/trojan
	transport := func() map[string]any {
		if cfg.Transport == nil {
			return nil
		}
		switch cfg.Transport.Type {
		case "", "tcp", "raw":
			return nil
		}
		t := map[string]any{"type": cfg.Transport.Type}
		switch cfg.Transport.Type {
		case "ws":
			if cfg.Transport.Path != "" {
				t["path"] = cfg.Transport.Path
			}
			if cfg.Transport.Host != "" {
				t["headers"] = map[string]any{"Host": cfg.Transport.Host}
			}
		case "grpc":
			if cfg.Transport.ServiceName != "" {
				t["service_name"] = cfg.Transport.ServiceName
			}
		case "http", "httpupgrade":
			if cfg.Transport.Path != "" {
				t["path"] = cfg.Transport.Path
			}
			if cfg.Transport.Host != "" {
				t["host"] = cfg.Transport.Host
			}
		}
		return t
	}

	// TLS-блок (Reality/uTLS) — для vless/vmess/trojan.
	// Включён, когда: trojan (TLS обязателен), reality, либо ссылка явно
	// содержала security=tls (TLS.Verify/Insecure) или SNI.
	tlsBlock := func() map[string]any {
		if cfg.Protocol == "shadowsocks" {
			return nil
		}
		realityOn := cfg.Reality != nil && cfg.Reality.PublicKey != ""
		enabled := cfg.Protocol == "trojan" || realityOn ||
			cfg.TLS.Verify || cfg.TLS.Insecure || cfg.SNI != ""
		if !enabled {
			return nil
		}
		t := map[string]any{"enabled": true}
		if sni := cfg.SNIToUse(); sni != "" {
			t["server_name"] = sni
		}
		if len(cfg.ALPN) > 0 {
			t["alpn"] = cfg.ALPN
		}
		if cfg.TLS.Insecure {
			t["insecure"] = true
		}
		if len(cfg.TLS.Certificates) > 0 {
			t["certificate"] = cfg.TLS.Certificates // CA PEM для проверки
		}
		if realityOn {
			t["reality"] = map[string]any{
				"enabled":    true,
				"public_key": cfg.Reality.PublicKey,
				"short_id":   cfg.Reality.ShortID,
			}
		}
		fp := cfg.Fingerprint
		if fp == "" && (realityOn || cfg.Flow != "") {
			fp = "chrome"
		}
		if fp != "" {
			t["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
		}
		return t
	}

	switch cfg.Protocol {
	case "vless":
		ob := map[string]any{
			"type": "vless", "tag": "flicker-out",
			"server": cfg.Server, "server_port": cfg.Port,
			"uuid": cfg.UUID,
		}
		if cfg.Flow != "" {
			ob["flow"] = cfg.Flow
		}
		if t := transport(); t != nil {
			ob["transport"] = t
		}
		if t := tlsBlock(); t != nil {
			ob["tls"] = t
		}
		if cfg.PacketEnc != "" {
			ob["packet_encoding"] = cfg.PacketEnc
		}
		outbounds = append(outbounds, ob)

	case "vmess":
		ob := map[string]any{
			"type": "vmess", "tag": "flicker-out",
			"server": cfg.Server, "server_port": cfg.Port,
			"uuid": cfg.UUID,
		}
		if cfg.Cipher != "" {
			ob["security"] = cfg.Cipher // "aes-128-gcm" и т.п. из ссылки
		}
		if t := transport(); t != nil {
			ob["transport"] = t
		}
		if t := tlsBlock(); t != nil {
			ob["tls"] = t
		}
		outbounds = append(outbounds, ob)

	case "trojan":
		ob := map[string]any{
			"type": "trojan", "tag": "flicker-out",
			"server": cfg.Server, "server_port": cfg.Port,
			"password": cfg.Auth,
		}
		if t := transport(); t != nil {
			ob["transport"] = t
		}
		if t := tlsBlock(); t != nil {
			ob["tls"] = t
		}
		outbounds = append(outbounds, ob)

	case "shadowsocks":
		ob := map[string]any{
			"type": "shadowsocks", "tag": "flicker-out",
			"server": cfg.Server, "server_port": cfg.Port,
			"method":   firstNonEmpty(cfg.Cipher, "2022-blake3-aes-128-gcm"),
			"password": cfg.Auth,
		}
		outbounds = append(outbounds, ob)

	case "wireguard":
		wg := cfg.WireGuard
		address := wg.Address
		if len(address) == 0 {
			address = []string{"10.221.0.2/32"} // адрес по умолчанию, если подписка не дала
		}
		allowed := wg.AllowedIPs
		if len(allowed) == 0 {
			allowed = []string{"0.0.0.0/0", "::/0"}
		}
		peer := map[string]any{
			"address": cfg.Server, "port": cfg.Port,
			"public_key":  wg.PeerPublicKey,
			"allowed_ips": allowed,
		}
		if wg.PreSharedKey != "" {
			peer["pre_shared_key"] = wg.PreSharedKey
		}
		if len(wg.Reserved) == 3 {
			peer["reserved"] = wg.Reserved
		}
		keep := wg.Keepalive
		if keep <= 0 {
			keep = 25
		}
		peer["persistent_keepalive_interval"] = keep
		ep := map[string]any{
			"type": "wireguard", "tag": "flicker-wg",
			"system":      false,
			"mtu":         ite(wg.MTU > 0, wg.MTU, 1280),
			"address":     address,
			"private_key": wg.PrivateKey,
			"peers":       []map[string]any{peer},
			"udp_timeout": "30s",
		}
		final = "flicker-wg"
		if cfg.Detour != nil {
			// «Матрёшка»: WG-пакеты туннелируются через VLESS/Trojan-детур.
			// На сервере детур-инбаунд принимает их и доставляет до
			// WG-endpoint (пример серверного конфига — в README).
			ep["detour"] = "flicker-out"
			dt := cfg.Detour
			detour := map[string]any{
				"type": dt.Protocol, "tag": "flicker-out",
				"server": dt.Server, "server_port": dt.Port,
			}
			switch dt.Protocol {
			case "vless":
				detour["uuid"] = dt.UUID
				if dt.Flow != "" {
					detour["flow"] = dt.Flow
				}
			case "trojan":
				detour["password"] = dt.Password
			}
			if dtls := detourTLS(dt); dtls != nil {
				detour["tls"] = dtls
			}
			outbounds = append(outbounds, detour)
		}
		endpoints = append(endpoints, ep)
	}

	return Built{Outbounds: outbounds, Endpoints: endpoints, Final: final}
}

// detourTLS — TLS/Reality/uTLS-блок детура (по его собственным полям).
// Для trojan TLS обязателен; для vless — только если заданы SNI/reality.
func detourTLS(dt *config.DetourConfig) map[string]any {
	realityOn := dt.Reality != nil && dt.Reality.PublicKey != ""
	if !realityOn && dt.SNI == "" && dt.Protocol != "trojan" {
		return nil
	}
	t := map[string]any{"enabled": true}
	if dt.SNI != "" {
		t["server_name"] = dt.SNI
	} else {
		t["server_name"] = dt.Server
	}
	if realityOn {
		t["reality"] = map[string]any{
			"enabled":    true,
			"public_key": dt.Reality.PublicKey,
			"short_id":   dt.Reality.ShortID,
		}
	}
	fp := dt.Fingerprint
	if fp == "" && realityOn {
		fp = "chrome"
	}
	if fp != "" {
		t["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
	}
	return t
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func ite[T any](cond bool, a, b T) T {
	if cond {
		return a
	}
	return b
}
