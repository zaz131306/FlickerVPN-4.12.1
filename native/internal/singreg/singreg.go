// SPDX-License-Identifier: GPL-3.0-or-later
// (в составе бинарника flicker-host — производное от sing-box, см. LICENSE-NOTES.md и COPYING)
// Package singreg — усечённый реестр компонентов sing-box для flicker-host.
//
// Регистрируем только то, что реально используется:
//   - inbound:  socks (внутренний порт драйвера);
//   - outbound: direct, block, vless (Reality/Vision/uTLS), trojan, vmess,
//     shadowsocks;
//   - endpoint: wireguard (включая «матрёшку» через detour);
//   - DNS:      local, hosts, tcp, udp.
//
// НАМЕРЕННО не регистрируем: tun (gvisor-тяжесть и root-права), QUIC-протоколы
// (hysteria/hysteria2/tuic — у нас свой hy2-драйвер), clash-api, tailscale,
// tor, ssh, openvpn и пр. Это уменьшает бинарник и поверхность отказа.
//
// sing-box распространяется под GPL-3.0; flicker-host линкуется с ним и,
// как производное произведение при распространении, наследует GPL-3.0
// (см. LICENSE-примечание в README).
package singreg

import (
	"context"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	dnstransport "github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/dns/transport/hosts"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/protocol/block"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing-box/protocol/vmess"
	"github.com/sagernet/sing-box/protocol/wireguard"
)

// Context возвращает context с нашими (усечёнными) реестрами.
func Context(ctx context.Context) context.Context {
	return box.Context(ctx,
		InboundRegistry(),
		OutboundRegistry(),
		EndpointRegistry(),
		DNSTransportRegistry(),
		ServiceRegistry(),
		CertificateProviderRegistry(),
	)
}

func InboundRegistry() *inbound.Registry {
	registry := inbound.NewRegistry()
	socks.RegisterInbound(registry)
	// серверные inbound'ы: нужны для локальных E2E-стендов (и для запуска
	// flicker-host в серверном режиме «матрёшки» на своём VPS)
	vless.RegisterInbound(registry)
	trojan.RegisterInbound(registry)
	return registry
}

func OutboundRegistry() *outbound.Registry {
	registry := outbound.NewRegistry()
	direct.RegisterOutbound(registry)
	block.RegisterOutbound(registry)
	vless.RegisterOutbound(registry)
	trojan.RegisterOutbound(registry)
	vmess.RegisterOutbound(registry)
	shadowsocks.RegisterOutbound(registry)
	return registry
}

func EndpointRegistry() *endpoint.Registry {
	registry := endpoint.NewRegistry()
	wireguard.RegisterEndpoint(registry)
	return registry
}

func DNSTransportRegistry() *dns.TransportRegistry {
	registry := dns.NewTransportRegistry()
	dnstransport.RegisterTCP(registry)
	dnstransport.RegisterUDP(registry)
	hosts.RegisterTransport(registry)
	local.RegisterTransport(registry)
	return registry
}

func ServiceRegistry() *service.Registry {
	return service.NewRegistry()
}

func CertificateProviderRegistry() *certificate.Registry {
	return certificate.NewRegistry()
}
