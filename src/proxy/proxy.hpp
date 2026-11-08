#pragma once

/**
 * @file proxy/proxy.hpp
 * @brief mynet 代理协议总头文件，汇聚全部主流代理协议实现（对标 sing-box 全协议生态）：
 *
 * 协议清单：
 * 1. SOCKS (RFC 1928 SOCKS5 / RFC 1929 用户名密码认证 / RFC SOCKS4 / SOCKS4a / 统一嗅探自适应)
 * 2. HTTP Proxy (RFC 7231 CONNECT 隧道 / 明文透明转发代理 / Basic 认证)
 * 3. Mixed (SOCKS4 / SOCKS5 / HTTP 自动嗅探共端口混合入站)
 * 4. Trojan (RFC Trojan 协议 / SHA-224 鉴权 / 内核零拷贝透传)
 * 5. VLESS (v0 规范 / 16字节 UUID 鉴权 / 2字节精简握手响应 / 零拷贝透传)
 * 6. VMess (16字节 HMAC-MD5 AuthID 头部鉴权 / 指令解析)
 * 7. Shadowsocks (SIP002 AEAD: aes-128-gcm / aes-256-gcm / chacha20-ietf-poly1305 / none)
 * 8. ShadowTLS (v1 / v2 / v3 TLS ClientHello SNI 嗅探与 HMAC 挑战鉴权分流)
 * 9. Snell (v1 / v2 / v3 / v4 协议)
 * 10. Hysteria 2 (认证握手与目标转发)
 * 11. TUIC (v5 协议)
 * 12. Transparent (Linux Netfilter Redirect / TProxy 原始目的地址提取)
 * 13. Direct & Block (直连路由与黑洞阻断)
 */

#include "address.hpp"
#include "block.hpp"
#include "crypto.hpp"
#include "direct.hpp"
#include "http/http.hpp"
#include "hysteria2/hysteria2.hpp"
#include "mixed/mixed.hpp"
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
