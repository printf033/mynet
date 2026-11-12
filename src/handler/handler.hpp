#pragma once

/**
 * @file handler/handler.hpp
 * @brief mynet 处理器总头文件，汇聚全部主流协议处理器与应用层实现：
 *
 * 处理器清单：
 * 1. Inbound & Outbound 基类 (HandlerInboundConnection / HandlerInboundDatagram / HandlerOutboundConnection / HandlerOutboundDatagram)
 * 2. HTTP (HTTP/1.x / HTTP/2 / HTTP/3 QUIC)
 * 3. DNS (RFC 1035 / RFC 3596 TCP/UDP 编解码与 HandlerInboundConnectionDns / HandlerInboundDatagramDns / HandlerOutboundConnectionDns / HandlerOutboundDatagramDns)
 * 4. HTTP Proxy (RFC 7231 CONNECT 隧道 / 明文透明转发代理 / Basic 认证 HandlerInboundHttpProxy)
 * 5. SOCKS (RFC 1928 SOCKS5 / RFC 1929 用户名密码认证 / RFC SOCKS4 / SOCKS4a / 统一嗅探自适应 HandlerInboundSocks / HandlerInboundSocks4 / HandlerInboundSocks5 / HandlerOutboundSocks5)
 * 6. Mixed (SOCKS4 / SOCKS5 / HTTP 自动嗅探共端口混合入站 HandlerInboundMixed)
 * 7. Trojan (RFC Trojan 协议 HandlerInboundTrojan / HandlerOutboundTrojan)
 * 8. VLESS (v0 规范 HandlerInboundVless / HandlerOutboundVless)
 * 9. VMess (16字节 HMAC-MD5 AuthID 头部鉴权 HandlerInboundVmess)
 * 10. Shadowsocks (SIP002 AEAD HandlerInboundShadowsocks)
 * 11. ShadowTLS (v1 / v2 / v3 TLS ClientHello SNI 嗅探 HandlerInboundShadowTls)
 * 12. Snell (v1 / v2 / v3 / v4 协议 HandlerInboundSnell)
 * 13. Hysteria 2 (认证握手与目标转发 HandlerInboundHysteria2 / HandlerOutboundHysteria2)
 * 14. TUIC (v5 协议 HandlerInboundTuic)
 * 15. Transparent (Linux Netfilter Redirect / TProxy 原始目的地址提取 HandlerInboundRedirect / HandlerInboundTProxy)
 * 16. Direct & Block (直连路由与黑洞阻断 HandlerInboundDirect / HandlerOutboundDirect / HandlerInboundBlock / HandlerOutboundBlock)
 */

#include "address.hpp"
#include "inbound.hpp"
#include "outbound.hpp"
#include "block.hpp"
#include "crypto.hpp"
#include "direct.hpp"
#include "dns/cache.hpp"
#include "dns/dns.hpp"
#include "dns/handler.hpp"
#include "sniffing.hpp"
#include "sockmap.hpp"
#include "http/http.hpp"
#include "http/v1/handler.hpp"
#include "http/v2/handler.hpp"
#include "http/v3/handler.hpp"
#include "hysteria2/hysteria2.hpp"
#include "mixed/mixed.hpp"
#include "outbound.hpp"
#include "shadowsocks/shadowsocks.hpp"
#include "shadowtls/shadowtls.hpp"
#include "snell/snell.hpp"
#include "socks/socks.hpp"
#include "socks/socks4.hpp"
#include "socks/socks5.hpp"
#include "transparent/transparent.hpp"
#include "trojan/trojan.hpp"
#include "tuic/tuic.hpp"
#include "vless/vless.hpp"
#include "vmess/vmess.hpp"

