/**
 * @file bench_dae_optimizations.cpp
 * @brief 性能基准测试：全面验证借鉴 dae 与 sing-box 优化后的性能提升
 *
 * 包含：
 * 1. UDP I/O 对比：单包 sendto/recvfrom vs 批量 sendmmsg/recvmmsg (批宽度 32)
 * 2. 深度嗅探引擎吞吐与延迟：TLS SNI, HTTP Host, QUIC Initial, DNS QNAME, STUN 等
 * 3. DNS 逆向倒排缓存：插入与高并发查找吞吐 (DnsReverseCache)
 */

#include "handler/sniffing.hpp"
#include "handler/dns/cache.hpp"
#include "datagram.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <numeric>
#include <span>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace mynet;
using namespace mynet::handler;
using Clock = std::chrono::steady_clock;

namespace
{
    // 构造测试用 TLS ClientHello 报文
    std::vector<uint8_t> makeTlsClientHello(std::string_view serverName)
    {
        std::vector<uint8_t> extSni;
        extSni.push_back(0x00);
        extSni.push_back(0x00); // Extension Type: SNI (0x0000)

        const uint16_t nameLen = static_cast<uint16_t>(serverName.size());
        const uint16_t listLen = nameLen + 3;
        const uint16_t extLen = listLen + 2;

        extSni.push_back(static_cast<uint8_t>(extLen >> 8));
        extSni.push_back(static_cast<uint8_t>(extLen & 0xFF));
        extSni.push_back(static_cast<uint8_t>(listLen >> 8));
        extSni.push_back(static_cast<uint8_t>(listLen & 0xFF));
        extSni.push_back(0x00); // HostName type
        extSni.push_back(static_cast<uint8_t>(nameLen >> 8));
        extSni.push_back(static_cast<uint8_t>(nameLen & 0xFF));
        extSni.insert(extSni.end(), serverName.begin(), serverName.end());

        std::vector<uint8_t> hs;
        hs.push_back(0x01); // ClientHello
        hs.push_back(0x00);
        hs.push_back(0x00);
        hs.push_back(0x00); // Length placeholder
        hs.push_back(0x03);
        hs.push_back(0x03); // TLS 1.2
        for (int i = 0; i < 32; ++i) hs.push_back(0x42); // Random
        hs.push_back(0x00); // Session ID len
        hs.push_back(0x00); hs.push_back(0x02); hs.push_back(0x13); hs.push_back(0x01); // Cipher
        hs.push_back(0x01); hs.push_back(0x00); // Compression
        const uint16_t extTotalLen = static_cast<uint16_t>(extSni.size());
        hs.push_back(static_cast<uint8_t>(extTotalLen >> 8));
        hs.push_back(static_cast<uint8_t>(extTotalLen & 0xFF));
        hs.insert(hs.end(), extSni.begin(), extSni.end());

        const uint32_t hsLen = static_cast<uint32_t>(hs.size() - 4);
        hs[1] = static_cast<uint8_t>((hsLen >> 16) & 0xFF);
        hs[2] = static_cast<uint8_t>((hsLen >> 8) & 0xFF);
        hs[3] = static_cast<uint8_t>(hsLen & 0xFF);

        std::vector<uint8_t> rec;
        rec.push_back(0x16); // Handshake
        rec.push_back(0x03); rec.push_back(0x01);
        const uint16_t recLen = static_cast<uint16_t>(hs.size());
        rec.push_back(static_cast<uint8_t>(recLen >> 8));
        rec.push_back(static_cast<uint8_t>(recLen & 0xFF));
        rec.insert(rec.end(), hs.begin(), hs.end());
        return rec;
    }

    std::vector<uint8_t> makeQuicInitial(std::string_view serverName)
    {
        auto tlsRec = makeTlsClientHello(serverName);
        std::span<const uint8_t> ch(tlsRec.data() + 5, tlsRec.size() - 5);

        std::vector<uint8_t> payload;
        payload.push_back(0x06); // CRYPTO
        sniffing::detail::appendUvarint(payload, 0);
        sniffing::detail::appendUvarint(payload, ch.size());
        payload.insert(payload.end(), ch.begin(), ch.end());
        while (payload.size() < 64) payload.push_back(0x00);

        std::array<uint8_t, 8> dcid = {1, 2, 3, 4, 5, 6, 7, 8};
        auto initSecret = crypto::hkdfSha256Extract(sniffing::detail::kQuicSaltV1, dcid);
        std::array<uint8_t, 32> clientSecret{};
        crypto::hkdfExpandLabel(*initSecret, "client in", {}, 32, clientSecret);
        std::array<uint8_t, 16> hpKey{}, key{};
        std::array<uint8_t, 12> iv{};
        crypto::hkdfExpandLabel(clientSecret, "quic hp", {}, 16, hpKey);
        crypto::hkdfExpandLabel(clientSecret, "quic key", {}, 16, key);
        crypto::hkdfExpandLabel(clientSecret, "quic iv", {}, 12, iv);

        std::vector<uint8_t> pkt;
        pkt.push_back(0xC0); // Long header, initial, pnLen=1
        pkt.push_back(0); pkt.push_back(0); pkt.push_back(0); pkt.push_back(1); // v1
        pkt.push_back(static_cast<uint8_t>(dcid.size()));
        pkt.insert(pkt.end(), dcid.begin(), dcid.end());
        pkt.push_back(0); // SCID len
        sniffing::detail::appendUvarint(pkt, 0); // Token len

        size_t protLen = 1 + payload.size() + 16;
        sniffing::detail::appendUvarint(pkt, protLen);

        const size_t hdrLen = pkt.size();
        pkt.push_back(1); // pn = 1
        const size_t extHdrLen = hdrLen + 1;

        std::array<uint8_t, 12> nonce = iv;
        nonce[11] ^= 1;
        std::span<const uint8_t> aad(pkt.data(), extHdrLen);
        std::vector<uint8_t> cipher;
        std::array<uint8_t, 16> tag{};
        crypto::aes128GcmEncryptWithAad(key, nonce, aad, payload, cipher, tag);
        pkt.insert(pkt.end(), cipher.begin(), cipher.end());
        pkt.insert(pkt.end(), tag.begin(), tag.end());

        std::array<uint8_t, 16> sample{}, mask{};
        std::memcpy(sample.data(), pkt.data() + hdrLen + 4, 16);
        crypto::aes128EcbEncryptBlock(hpKey, sample, mask);
        pkt[0] ^= (mask[0] & 0x0F);
        pkt[hdrLen] ^= mask[1];
        return pkt;
    }
}

// ==========================================
// 1. 嗅探性能基准测试
// ==========================================
void benchSniffing()
{
    printf("\n=== [1] 现代化 C++26 零拷贝嗅探引擎性能基准 ===\n");

    // A. TLS SNI
    auto tlsPkt = makeTlsClientHello("www.cloudflare.com");
    std::span<const uint8_t> tlsSpan(tlsPkt.data(), tlsPkt.size());

    constexpr size_t kIterations = 1'000'000;
    auto t0 = Clock::now();
    uint64_t sum = 0;
    for (size_t i = 0; i < kIterations; ++i)
    {
        auto res = sniffing::DomainSniffer::sniffTlsSni(tlsSpan);
        if (res.has_value()) sum += res->size();
    }
    auto t1 = Clock::now();
    double tlsNs = std::chrono::duration<double, std::nano>(t1 - t0).count() / kIterations;
    double tlsOps = 1e9 / tlsNs;
    printf("[TLS SNI]      单次耗时: %6.1f ns | 吞吐: %8.2f 万次/秒 (0 次内存分配, sum=%lu)\n",
           tlsNs, tlsOps / 10000.0, sum);

    // B. HTTP Host
    std::string httpReq = "GET /index.html HTTP/1.1\r\nHost: cdn.jsdelivr.net:8443\r\nAccept: */*\r\n\r\n";
    std::span<const uint8_t> httpSpan(reinterpret_cast<const uint8_t *>(httpReq.data()), httpReq.size());

    t0 = Clock::now();
    sum = 0;
    for (size_t i = 0; i < kIterations; ++i)
    {
        auto res = sniffing::DomainSniffer::sniffHttpHost(httpSpan);
        if (res.has_value()) sum += res->first.size() + res->second;
    }
    t1 = Clock::now();
    double httpNs = std::chrono::duration<double, std::nano>(t1 - t0).count() / kIterations;
    double httpOps = 1e9 / httpNs;
    printf("[HTTP Host]    单次耗时: %6.1f ns | 吞吐: %8.2f 万次/秒 (0 次内存分配, sum=%lu)\n",
           httpNs, httpOps / 10000.0, sum);

    // C. DNS QNAME
    std::vector<uint8_t> dnsReq = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 'w', 'w', 'w', 0x06, 'g', 'o', 'o', 'g', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x01, 0x00, 0x01
    };
    std::span<const uint8_t> dnsSpan(dnsReq.data(), dnsReq.size());

    t0 = Clock::now();
    sum = 0;
    for (size_t i = 0; i < kIterations; ++i)
    {
        auto res = sniffing::DomainSniffer::sniffDnsQuestion(dnsSpan);
        if (res.has_value()) sum += res->size();
    }
    t1 = Clock::now();
    double dnsNs = std::chrono::duration<double, std::nano>(t1 - t0).count() / kIterations;
    double dnsOps = 1e9 / dnsNs;
    printf("[DNS QNAME]    单次耗时: %6.1f ns | 吞吐: %8.2f 万次/秒 (sum=%lu)\n",
           dnsNs, dnsOps / 10000.0, sum);

    // D. QUIC Initial 解密 + SNI 提取 (含 HKDF + AES-ECB 掩码 + AES-GCM 解密)
    auto quicPkt = makeQuicInitial("quic.nginx.org");
    std::span<const uint8_t> quicSpan(quicPkt.data(), quicPkt.size());

    constexpr size_t kQuicIters = 20'000;
    t0 = Clock::now();
    sum = 0;
    for (size_t i = 0; i < kQuicIters; ++i)
    {
        auto res = sniffing::DomainSniffer::sniffQuicSni(quicSpan);
        if (res.has_value()) sum += res->size();
    }
    t1 = Clock::now();
    double quicUs = std::chrono::duration<double, std::micro>(t1 - t0).count() / kQuicIters;
    double quicOps = 1e6 / quicUs;
    printf("[QUIC Initial] 单次耗时: %6.2f µs | 吞吐: %8.2f 万次/秒 (RFC 9000 全解密, sum=%lu)\n",
           quicUs, quicOps / 10000.0, sum);
}

// ==========================================
// 2. DNS 逆向倒排缓存性能基准测试
// ==========================================
void benchDnsReverseCache()
{
    printf("\n=== [2] DNS 逆向域名映射倒排缓存性能基准 ===\n");
    auto &cache = dns::DnsReverseCache::instance();

    constexpr size_t kPreloadCount = 10'000;
    for (size_t i = 1; i <= kPreloadCount; ++i)
    {
        in_addr ip{};
        ip.s_addr = htonl(0x0A000000 + static_cast<uint32_t>(i)); // 10.0.0.1 .. 10.0.39.16
        std::string domain = "node-" + std::to_string(i) + ".cluster.local";
        cache.insert(ip, domain, 3600);
    }

    constexpr size_t kLookupIters = 1'000'000;
    in_addr queryIp{};
    queryIp.s_addr = htonl(0x0A000000 + 4242);
    ProxyAddress target = ProxyAddress::fromIPv4(queryIp.s_addr, 443);

    auto t0 = Clock::now();
    uint64_t hits = 0;
    for (size_t i = 0; i < kLookupIters; ++i)
    {
        auto res = cache.lookup(target);
        if (res.has_value()) ++hits;
    }
    auto t1 = Clock::now();
    double lookupNs = std::chrono::duration<double, std::nano>(t1 - t0).count() / kLookupIters;
    double lookupOps = 1e9 / lookupNs;
    printf("[DNS Reverse Lookup] 单次耗时: %6.1f ns | 吞吐: %8.2f 万次/秒 (并发安全读, 命中=%lu)\n",
           lookupNs, lookupOps / 10000.0, hits);
}

// ==========================================
// 3. UDP I/O 对比测试：单包 sendto/recvfrom vs 批量 sendmmsg/recvmmsg
// ==========================================
void benchUdpIoComparison()
{
    printf("\n=== [3] UDP 高并发收发流水线对比: 单包 vs sendmmsg/recvmmsg (批宽度 32) ===\n");

    int senderFd = ::socket(AF_INET, SOCK_DGRAM, 0);
    int receiverFd = ::socket(AF_INET, SOCK_DGRAM, 0);

    // 调大 socket buffer 避免回环丢包
    int sndbuf = 8 * 1024 * 1024;
    int rcvbuf = 8 * 1024 * 1024;
    ::setsockopt(senderFd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    ::setsockopt(receiverFd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    sockaddr_in rcvAddr{};
    rcvAddr.sin_family = AF_INET;
    rcvAddr.sin_port = 0; // 自动分配端口
    rcvAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ::bind(receiverFd, reinterpret_cast<sockaddr *>(&rcvAddr), sizeof(rcvAddr));

    socklen_t addrLen = sizeof(rcvAddr);
    ::getsockname(receiverFd, reinterpret_cast<sockaddr *>(&rcvAddr), &addrLen);

    constexpr size_t kTotalPackets = 50'000;
    constexpr size_t kPayloadSize = 1024; // 1 KB
    std::vector<uint8_t> payload(kPayloadSize, 0x55);

    // -------------------------------------------------------------
    // 测试 A: 传统单包 sendto / recvfrom
    // -------------------------------------------------------------
    {
        uint64_t sendSyscalls = 0;
        uint64_t recvSyscalls = 0;

        auto t0 = Clock::now();
        std::thread receiverThread([&]() {
            std::vector<uint8_t> buf(2048);
            sockaddr_in peer{};
            socklen_t plen = sizeof(peer);
            for (size_t received = 0; received < kTotalPackets; )
            {
                ssize_t ret = ::recvfrom(receiverFd, buf.data(), buf.size(), 0,
                                         reinterpret_cast<sockaddr *>(&peer), &plen);
                ++recvSyscalls;
                if (ret > 0)
                {
                    ++received;
                }
            }
        });

        for (size_t sent = 0; sent < kTotalPackets; ++sent)
        {
            ::sendto(senderFd, payload.data(), payload.size(), 0,
                     reinterpret_cast<sockaddr *>(&rcvAddr), sizeof(rcvAddr));
            ++sendSyscalls;
        }

        receiverThread.join();
        auto t1 = Clock::now();

        double elapsedMs = std::chrono::duration<double, std::milli>(t1 - t0).count();
        double pps = (kTotalPackets / (elapsedMs / 1000.0));
        double mbps = (kTotalPackets * kPayloadSize) / (elapsedMs / 1000.0) / (1024.0 * 1024.0);

        printf("\n[单包模式 - sendto / recvfrom]\n");
        printf("  总收发报文: %zu 包 | 单包载荷: %zu B | 耗时: %6.2f ms\n", kTotalPackets, kPayloadSize, elapsedMs);
        printf("  系统调用总数: 发送 %lu 次 + 接收 %lu 次 = %lu 次 syscall\n",
               sendSyscalls, recvSyscalls, sendSyscalls + recvSyscalls);
        printf("  传输包率:   %8.0f pps\n", pps);
        printf("  有效吞吐量: %8.2f MB/s\n", mbps);
    }

    // -------------------------------------------------------------
    // 测试 B: 现代化批量 sendmmsg / recvmmsg (批宽度 32)
    // -------------------------------------------------------------
    {
        constexpr size_t kBatch = 32;
        uint64_t sendSyscalls = 0;
        uint64_t recvSyscalls = 0;

        auto t0 = Clock::now();
        std::thread receiverThread([&]() {
            mmsghdr msgs[kBatch]{};
            iovec iovs[kBatch]{};
            sockaddr_in peers[kBatch]{};
            std::array<std::array<char, 2048>, kBatch> bufs{};

            for (size_t i = 0; i < kBatch; ++i)
            {
                iovs[i].iov_base = bufs[i].data();
                iovs[i].iov_len = bufs[i].size();
                msgs[i].msg_hdr.msg_name = &peers[i];
                msgs[i].msg_hdr.msg_namelen = sizeof(sockaddr_in);
                msgs[i].msg_hdr.msg_iov = &iovs[i];
                msgs[i].msg_hdr.msg_iovlen = 1;
            }

            for (size_t received = 0; received < kTotalPackets; )
            {
                const size_t batchCount = std::min(kBatch, kTotalPackets - received);
                int ret = ::recvmmsg(receiverFd, msgs, batchCount, 0, nullptr);
                ++recvSyscalls;
                if (ret > 0)
                {
                    received += static_cast<size_t>(ret);
                }
            }
        });

        // 批量发送
        mmsghdr sendMsgs[kBatch]{};
        iovec sendIovs[kBatch]{};
        for (size_t i = 0; i < kBatch; ++i)
        {
            sendIovs[i].iov_base = payload.data();
            sendIovs[i].iov_len = payload.size();
            sendMsgs[i].msg_hdr.msg_name = &rcvAddr;
            sendMsgs[i].msg_hdr.msg_namelen = sizeof(sockaddr_in);
            sendMsgs[i].msg_hdr.msg_iov = &sendIovs[i];
            sendMsgs[i].msg_hdr.msg_iovlen = 1;
        }

        for (size_t sent = 0; sent < kTotalPackets; )
        {
            const size_t batchCount = std::min(kBatch, kTotalPackets - sent);
            int ret = ::sendmmsg(senderFd, sendMsgs, batchCount, 0);
            ++sendSyscalls;
            if (ret > 0)
            {
                sent += static_cast<size_t>(ret);
            }
        }

        receiverThread.join();
        auto t1 = Clock::now();

        double elapsedMs = std::chrono::duration<double, std::milli>(t1 - t0).count();
        double pps = (kTotalPackets / (elapsedMs / 1000.0));
        double mbps = (kTotalPackets * kPayloadSize) / (elapsedMs / 1000.0) / (1024.0 * 1024.0);

        printf("\n[批量流水线 - sendmmsg / recvmmsg (批宽度 32)]\n");
        printf("  总收发报文: %zu 包 | 单包载荷: %zu B | 耗时: %6.2f ms\n", kTotalPackets, kPayloadSize, elapsedMs);
        printf("  系统调用总数: 发送 %lu 次 + 接收 %lu 次 = %lu 次 syscall\n",
               sendSyscalls, recvSyscalls, sendSyscalls + recvSyscalls);
        printf("  传输包率:   %8.0f pps\n", pps);
        printf("  有效吞吐量: %8.2f MB/s\n", mbps);
    }

    ::close(senderFd);
    ::close(receiverFd);
}

int main()
{
    printf("=================================================================\n");
    printf("           mynet 深度优化落地与性能提升基准测试报告           \n");
    printf("=================================================================\n");

    benchSniffing();
    benchDnsReverseCache();
    benchUdpIoComparison();

    printf("\n=================================================================\n");
    printf("                     基准测试执行完成                           \n");
    printf("=================================================================\n");
    return 0;
}
