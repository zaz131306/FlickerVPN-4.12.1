// Package config — конфигурация туннеля, приходящая из расширения по NM.
package config

import (
	"errors"
	"fmt"
	"net"
	"strconv"
)

type ObfsConfig struct {
	Type     string `json:"type"`
	Password string `json:"password"`
	Enabled  bool   `json:"enabled"`
}

type CongestionConfig struct {
	Type     string `json:"type"`
	UpMbps   int    `json:"upMbps,omitempty"`
	DownMbps int    `json:"downMbps,omitempty"`
}

type TLSConfig struct {
	Verify       bool     `json:"verify"`
	Insecure     bool     `json:"insecure"`
	Certificates []string `json:"certificates,omitempty"`
}

// TransportConfig — транспорт v2ray-семейства (ws/grpc/httpupgrade) для
// VLESS/VMess/Trojan. Пустой Type = raw TCP.
type TransportConfig struct {
	Type        string `json:"type,omitempty"` // ""|ws|grpc|http|httpupgrade
	Path        string `json:"path,omitempty"`
	Host        string `json:"host,omitempty"`
	ServiceName string `json:"serviceName,omitempty"`
}

// RealityClientConfig — НАСТОЯЩИЙ VLESS-Reality (публичный ключ сервера,
// short id, uTLS-фингерпринт). Не путать с удалённой симуляцией «REALITY».
type RealityClientConfig struct {
	PublicKey string `json:"publicKey,omitempty"` // pbk из ссылки
	ShortID   string `json:"shortId,omitempty"`   // sid
}

// WireGuardConfig — параметры WG-туннеля (клиентская сторона «матрёшки»).
type WireGuardConfig struct {
	PrivateKey    string   `json:"privateKey,omitempty"`
	PeerPublicKey string   `json:"peerPublicKey,omitempty"`
	PreSharedKey  string   `json:"preSharedKey,omitempty"`
	Address       []string `json:"address,omitempty"`    // виртуальные IP клиента (CIDR)
	AllowedIPs    []string `json:"allowedIPs,omitempty"` // у пира
	MTU           int      `json:"mtu,omitempty"`
	Reserved      []int    `json:"reserved,omitempty"`
	Keepalive     int      `json:"keepalive,omitempty"` // persistent keepalive, сек
}

// DetourConfig — транспорт-детур для «матрёшки» WireGuard-в-VLESS/Trojan.
// Если задан в ServerConfig.Detour — WG-пакеты туннелируются через него.
type DetourConfig struct {
	Protocol    string               `json:"protocol"` // vless | trojan
	Server      string               `json:"server"`
	Port        int                  `json:"port"`
	UUID        string               `json:"uuid,omitempty"`
	Password    string               `json:"password,omitempty"`
	Flow        string               `json:"flow,omitempty"`
	SNI         string               `json:"sni,omitempty"`
	Fingerprint string               `json:"fingerprint,omitempty"`
	Reality     *RealityClientConfig `json:"reality,omitempty"`
}

// ServerConfig — нормализованный конфиг сервера (совпадает с полем config
// команды "start" из background.js).
type ServerConfig struct {
	Protocol     string               `json:"protocol"`
	Server       string               `json:"server"`
	Port         int                  `json:"port"`
	Auth         string               `json:"auth,omitempty"`
	UUID         string               `json:"uuid,omitempty"`
	SNI          string               `json:"sni,omitempty"`
	EffectiveSNI string               `json:"effectiveSni,omitempty"`
	ALPN         []string             `json:"alpn,omitempty"`
	Obfs         ObfsConfig           `json:"obfs,omitempty"`
	Congestion   CongestionConfig     `json:"congestion,omitempty"`
	TLS          TLSConfig            `json:"tls,omitempty"`
	Listen       string               `json:"listen,omitempty"`
	Flow         string               `json:"flow,omitempty"`        // xtls-rprx-vision
	Fingerprint  string               `json:"fingerprint,omitempty"` // uTLS: chrome/firefox/...
	SpiderX      string               `json:"spiderX,omitempty"`     // reality spider path
	PacketEnc    string               `json:"packetEncoding,omitempty"`
	Transport    *TransportConfig     `json:"transport,omitempty"`
	Reality      *RealityClientConfig `json:"reality,omitempty"`
	WireGuard    *WireGuardConfig     `json:"wireguard,omitempty"`
	Detour       *DetourConfig        `json:"detour,omitempty"`       // «матрёшка»: WG через VLESS/Trojan
	Cipher       string               `json:"cipher,omitempty"`       // shadowsocks: метод шифрования
	InternalPort int                  `json:"internalPort,omitempty"` // внутренний SOCKS sing-box (0 = авто)
}

// Validate проверяет минимальную корректность конфига.
func (c *ServerConfig) Validate() error {
	switch c.Protocol {
	case "hysteria2":
		// запасной UDP-протокол (скрыт из дефолтного UI)
		if c.Auth == "" {
			return errors.New("hysteria2: пароль (auth) обязателен")
		}
	case "vless":
		if c.UUID == "" {
			return errors.New("vless: UUID обязателен")
		}
		if c.Reality != nil && c.Reality.PublicKey == "" {
			return errors.New("vless+reality: публичный ключ (pbk) обязателен")
		}
	case "vmess":
		if c.UUID == "" {
			return errors.New("vmess: UUID обязателен")
		}
	case "trojan":
		if c.Auth == "" {
			return errors.New("trojan: пароль обязателен")
		}
	case "shadowsocks":
		if c.Auth == "" {
			return errors.New("shadowsocks: пароль обязателен")
		}
	case "wireguard":
		wg := c.WireGuard
		if wg == nil {
			return errors.New("wireguard: не заполнен блок wireguard")
		}
		if wg.PrivateKey == "" {
			return errors.New("wireguard: приватный ключ клиента обязателен")
		}
		if wg.PeerPublicKey == "" {
			return errors.New("wireguard: публичный ключ пира обязателен")
		}
		if c.Server == "" {
			return errors.New("wireguard: не указан endpoint (server)")
		}
		if c.Detour != nil {
			switch c.Detour.Protocol {
			case "vless":
				if c.Detour.Server == "" || c.Detour.UUID == "" {
					return errors.New("wireguard+detour(vless): server и uuid детура обязательны")
				}
				if c.Detour.Reality != nil && c.Detour.Reality.PublicKey == "" {
					return errors.New("wireguard+detour(vless): reality public_key обязателен")
				}
			case "trojan":
				if c.Detour.Server == "" || c.Detour.Password == "" {
					return errors.New("wireguard+detour(trojan): server и password детура обязательны")
				}
			default:
				return fmt.Errorf("wireguard+detour: неизвестный протокол детура %q", c.Detour.Protocol)
			}
		}
	case "direct":
		// без авторизации
	default:
		return fmt.Errorf("неизвестный протокол: %q", c.Protocol)
	}
	if c.Server == "" {
		return errors.New("host обязателен")
	}
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("некорректный порт: %d", c.Port)
	}
	return nil
}

// Addr — "host:port" удалённого сервера.
func (c *ServerConfig) Addr() string {
	return net.JoinHostPort(c.Server, strconv.Itoa(c.Port))
}

// ListenAddr — адрес локального SOCKS5-слушателя (по умолчанию 127.0.0.1:1080).
func (c *ServerConfig) ListenAddr() string {
	if c.Listen == "" {
		return "127.0.0.1:1080"
	}
	return c.Listen
}

// SNIToUse — итоговый SNI для TLS-handshake: effectiveSni > sni > host.
func (c *ServerConfig) SNIToUse() string {
	if c.EffectiveSNI != "" {
		return c.EffectiveSNI
	}
	if c.SNI != "" {
		return c.SNI
	}
	return c.Server
}
