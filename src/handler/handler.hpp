#pragma once

/**
 * @file handler/handler.hpp
 * @brief mynet 处理器总头文件，汇聚全部主流协议处理器与应用层实现：
 *
 * 处理器清单：
 * 1. HTTP (HTTP/1.x / HTTP/2 / HTTP/3 QUIC)
 * 2. DNS (RFC 1035 / RFC 3596 TCP/UDP 编解码与 HandlerDns / HandlerDatagramDns / HandlerOutboundDns)
 * 3. HTTP Proxy (RFC 7231 CONNECT 隧道 / 明文透明转发代理 / Basic 认证)
 * 4. SOCKS (RFC 1928 SOCKS5 / RFC 1929 用户名密码认证 / RFC SOCKS4 / SOCKS4a / 统一嗅探自适应)
 * 5. Mixed (SOCKS4 / SOCKS5 / HTTP 自动嗅探共端口混合入站)
 * 6. Trojan (RFC Trojan 协议 / SHA-224 鉴权 / 内核零拷贝透传)
 * 7. VLESS (v0 规范 / 16字节 UUID 鉴权 / 2字节精简握手响应 / 零拷贝透传)
 * 8. VMess (16字节 HMAC-MD5 AuthID 头部鉴权 / 指令解析)
 * 9. Shadowsocks (SIP002 AEAD: aes-128-gcm / aes-256-gcm / chacha20-ietf-poly1305 / none)
 * 10. ShadowTLS (v1 / v2 / v3 TLS ClientHello SNI 嗅探与 HMAC 挑战鉴权分流)
 * 11. Snell (v1 / v2 / v3 / v4 协议)
 * 12. Hysteria 2 (认证握手与目标转发)
 * 13. TUIC (v5 协议)
 * 14. Transparent (Linux Netfilter Redirect / TProxy 原始目的地址提取)
 * 15. Direct & Block (直连路由与黑洞阻断)
 * 16. Outbound (HandlerOutboundDirect / Trojan / Vless / Socks5 / Block)
 */

#include "address.hpp"
#include "block.hpp"
#include "crypto.hpp"
#include "direct.hpp"
#include "dns/dns.hpp"
#include "dns/handler.hpp"
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

namespace mynet::handler
{
    template <http::v1::HTTP_MODE Mode = http::v1::HTTP_MODE::REQUEST>
    using HandlerHttp = http::v1::HandlerHttp<Mode>;
    using HandlerHttp1 = http::v1::HandlerHttp<http::v1::HTTP_MODE::REQUEST>;

    template <typename StreamHandler = HandlerConnection>
    using HandlerHttp2 = http::v2::HandlerHttp2<StreamHandler>;

    template <typename StreamHandler = HandlerConnection>
    using HandlerHttp3 = http::v3::HandlerHttp3<StreamHandler>;
} // namespace mynet::handler

namespace mynet
{
    using namespace handler;
} // namespace mynet

