#pragma once

/**
 * @file handler/sniffing.hpp
 * @brief 现代化 C++26 零拷贝应用层协议与域名深度嗅探引擎总入口
 *
 * 借鉴 dae 与 sing-box 设计哲学，将各协议嗅探器拆解为模块化实现：
 * - sniffing/tls.hpp: TLS 1.2 / 1.3 ClientHello (SNI)
 * - sniffing/http.hpp: HTTP 1.0 / 1.1 (Host 首部与端口)
 * - sniffing/quic.hpp: QUIC v1 / v2 / draft-29 Initial (RFC 9000 EVP 解密与 SNI 提取)
 * - sniffing/dns.hpp: DNS 查询 (QNAME)
 * - sniffing/bittorrent.hpp: BitTorrent 握手报文识别
 * - sniffing/ssh.hpp: SSH 协议识别
 * - sniffing/dtls.hpp: DTLS 记录层协议识别
 * - sniffing/stun.hpp: STUN NAT 穿透报文识别 (RFC 5389 / 8489)
 * - sniffing/ntp.hpp: NTP 客户端时间请求识别 (RFC 5905)
 * - sniffing/rdp.hpp: RDP 远程桌面连接识别 (TPKT + COTP)
 */

#include "sniffing/common.hpp"
#include "sniffing/sniffer.hpp"
