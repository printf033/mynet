#pragma once

/**
 * @file datagram.hpp
 * @brief 无状态 UDP 数据报通道基础抽象 (Datagram / DatagramView)
 *
 * 与 Connection 位于同一基础设施层级（无 Acceptor / Dialer / Handler 上层循环依赖），
 * 供 Listener、Dialer、Acceptor、Reactor、Proactor 与 Forwarder 直接统一复用。
 */

#include "address.hpp"
#include "config/log.hpp"
#include "error.hpp"
#include "responseQueue.hpp"

#include <arpa/inet.h>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <expected>
#include <fcntl.h>
#include <functional>
#include <memory>
#include <mutex>
#include <netinet/in.h>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>

#ifndef IP_RECVORIGDSTADDR
#define IP_RECVORIGDSTADDR 20
#endif
#ifndef IP_ORIGDSTADDR
#define IP_ORIGDSTADDR 20
#endif
#ifndef IP_TRANSPARENT
#define IP_TRANSPARENT 19
#endif
#ifndef SO_MARK
#define SO_MARK 36
#endif

namespace mynet
{

    /**
     * @brief 零拷贝只读数据报视图 (DatagramView)
     */
    struct DatagramView
    {
        sockaddr_in peer{};
        sockaddr_in origDst{};
        std::span<const uint8_t> payload{};

        [[nodiscard]] inline std::string_view stringView() const noexcept
        {
            return {reinterpret_cast<const char *>(payload.data()), payload.size()};
        }
        [[nodiscard]] inline const uint8_t *data() const noexcept { return payload.data(); }
        [[nodiscard]] inline size_t size() const noexcept { return payload.size(); }
        [[nodiscard]] inline bool empty() const noexcept { return payload.empty(); }
        [[nodiscard]] inline bool hasOrigDst() const noexcept { return origDst.sin_port != 0; }

        [[nodiscard]] inline Address peerAddress() const noexcept
        {
            return Address::fromIPv4(peer.sin_addr.s_addr, ntohs(peer.sin_port));
        }

        [[nodiscard]] inline Address origDstAddress() const noexcept
        {
            return Address::fromIPv4(origDst.sin_addr.s_addr, ntohs(origDst.sin_port));
        }
    };

    /**
     * @brief 无状态 UDP 数据报通道与端点抽象 (Datagram / DatagramEndpoint)
     */
    class Datagram
    {
    private:
        int fd_{-1};
        bool ownsFd_{true};
        sockaddr_in localAddr_{};

    public:
        Datagram() noexcept = default;

        explicit Datagram(int fd, bool ownsFd = true) noexcept
            : fd_(fd), ownsFd_(ownsFd)
        {
            if (fd_ >= 0)
            {
                socklen_t len = sizeof(localAddr_);
                ::getsockname(fd_, reinterpret_cast<sockaddr *>(&localAddr_), &len);
            }
        }

        ~Datagram() noexcept { close(); }

        Datagram(const Datagram &) = delete;
        Datagram &operator=(const Datagram &) = delete;

        Datagram(Datagram &&other) noexcept
            : fd_(std::exchange(other.fd_, -1)),
              ownsFd_(std::exchange(other.ownsFd_, true)),
              localAddr_(other.localAddr_)
        {
        }

        Datagram &operator=(Datagram &&other) noexcept
        {
            if (this != &other)
            {
                close();
                fd_ = std::exchange(other.fd_, -1);
                ownsFd_ = std::exchange(other.ownsFd_, true);
                localAddr_ = other.localAddr_;
                other.localAddr_ = {};
            }
            return *this;
        }

        [[nodiscard]] inline int fd() const noexcept { return fd_; }
        [[nodiscard]] inline bool valid() const noexcept { return fd_ >= 0; }
        [[nodiscard]] inline bool ownsFd() const noexcept { return ownsFd_; }
        [[nodiscard]] inline const sockaddr_in &localAddr() const noexcept { return localAddr_; }
        [[nodiscard]] inline uint16_t localPort() const noexcept { return ntohs(localAddr_.sin_port); }

        inline void setFd(int fd, bool ownsFd = true) noexcept
        {
            if (fd == fd_)
            {
                ownsFd_ = ownsFd;
                return;
            }
            close();
            fd_ = fd;
            ownsFd_ = ownsFd;
            localAddr_ = {};
            if (fd_ >= 0)
            {
                socklen_t len = sizeof(localAddr_);
                ::getsockname(fd_, reinterpret_cast<sockaddr *>(&localAddr_), &len);
            }
        }

        inline int release() noexcept
        {
            ownsFd_ = false;
            return std::exchange(fd_, -1);
        }

        inline void close() noexcept
        {
            if (ownsFd_ && fd_ >= 0)
            {
                ::close(fd_);
            }
            fd_ = -1;
            localAddr_ = {};
        }

        // =====================================================================
        // 工厂创建与绑定
        // =====================================================================

        [[nodiscard]] static Result<Datagram> create(bool nonBlocking = true) noexcept
        {
            int flags = SOCK_DGRAM | SOCK_CLOEXEC;
            if (nonBlocking)
            {
                flags |= SOCK_NONBLOCK;
            }
            int sockFd = ::socket(AF_INET, flags, 0);
            if (sockFd < 0) [[unlikely]]
            {
                return std::unexpected(ERR::SOCKET_FAILED);
            }
            return Datagram(sockFd, true);
        }

        [[nodiscard]] static Result<Datagram> bind(const sockaddr_in &addr, bool reuseAddr = true,
                                                   bool reusePort = true) noexcept
        {
            auto dgramRes = create(true);
            if (!dgramRes)
            {
                return std::unexpected(dgramRes.error());
            }
            auto &dgram = *dgramRes;
            if (reuseAddr)
                (void)dgram.setReuseAddr(true);
            if (reusePort)
                (void)dgram.setReusePort(true);

            if (::bind(dgram.fd(), reinterpret_cast<const sockaddr *>(&addr), sizeof(addr)) < 0) [[unlikely]]
            {
                return std::unexpected(ERR::BIND_FAILED);
            }

            socklen_t len = sizeof(dgram.localAddr_);
            ::getsockname(dgram.fd(), reinterpret_cast<sockaddr *>(&dgram.localAddr_), &len);
            return dgramRes;
        }

        [[nodiscard]] static Result<Datagram> bind(const char *ip, uint16_t port, bool reuseAddr = true,
                                                   bool reusePort = true) noexcept
        {
            sockaddr_in sa{};
            sa.sin_family = AF_INET;
            sa.sin_port = htons(port);
            if (ip == nullptr || ip[0] == '\0' || ::strcmp(ip, "0.0.0.0") == 0)
            {
                sa.sin_addr.s_addr = INADDR_ANY;
            }
            else
            {
                if (::inet_pton(AF_INET, ip, &sa.sin_addr) <= 0) [[unlikely]]
                {
                    return std::unexpected(ERR::ADDR_INVALID);
                }
            }
            return bind(sa, reuseAddr, reusePort);
        }

        inline Result<> connect(const sockaddr_in &peer) noexcept
        {
            if (fd_ < 0) [[unlikely]]
                return std::unexpected(ERR::SOCKET_FAILED);
            if (::connect(fd_, reinterpret_cast<const sockaddr *>(&peer), sizeof(peer)) < 0) [[unlikely]]
            {
                return std::unexpected(ERR::CONNECT_FAILED);
            }
            return {};
        }

        // =====================================================================
        // 套接字配置选项
        // =====================================================================

        inline Result<> setNonBlocking(bool enable = true) noexcept
        {
            if (fd_ < 0)
                return std::unexpected(ERR::SOCKET_FAILED);
            int flags = ::fcntl(fd_, F_GETFL, 0);
            if (flags < 0)
                return std::unexpected(ERR::SOCKET_FAILED);
            flags = enable ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
            if (::fcntl(fd_, F_SETFL, flags) < 0)
                return std::unexpected(ERR::SOCKET_FAILED);
            return {};
        }

        inline Result<> setReuseAddr(bool enable = true) noexcept
        {
            if (fd_ < 0)
                return std::unexpected(ERR::SOCKET_FAILED);
            int opt = enable ? 1 : 0;
            if (::setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
                return std::unexpected(ERR::SETSOCKOPT_FAILED);
            return {};
        }

        inline Result<> setReusePort(bool enable = true) noexcept
        {
            if (fd_ < 0)
                return std::unexpected(ERR::SOCKET_FAILED);
            int opt = enable ? 1 : 0;
            if (::setsockopt(fd_, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0)
                return std::unexpected(ERR::SETSOCKOPT_FAILED);
            return {};
        }

        inline Result<> setTransparent(bool enable = true) noexcept
        {
            if (fd_ < 0)
                return std::unexpected(ERR::SOCKET_FAILED);
            int opt = enable ? 1 : 0;
            if (::setsockopt(fd_, SOL_IP, IP_TRANSPARENT, &opt, sizeof(opt)) < 0)
                return std::unexpected(ERR::SETSOCKOPT_FAILED);
            return {};
        }

        inline Result<> setRecvOrigDst(bool enable = true) noexcept
        {
            if (fd_ < 0)
                return std::unexpected(ERR::SOCKET_FAILED);
            int opt = enable ? 1 : 0;
            if (::setsockopt(fd_, SOL_IP, IP_RECVORIGDSTADDR, &opt, sizeof(opt)) < 0)
                return std::unexpected(ERR::SETSOCKOPT_FAILED);
            return {};
        }

        inline Result<> setPacketInfo(bool enable = true) noexcept
        {
            if (fd_ < 0)
                return std::unexpected(ERR::SOCKET_FAILED);
            int opt = enable ? 1 : 0;
            if (::setsockopt(fd_, SOL_IP, IP_PKTINFO, &opt, sizeof(opt)) < 0)
                return std::unexpected(ERR::SETSOCKOPT_FAILED);
            return {};
        }

        inline Result<> setMark(uint32_t fwmark) noexcept
        {
            if (fd_ < 0)
                return std::unexpected(ERR::SOCKET_FAILED);
            if (::setsockopt(fd_, SOL_SOCKET, SO_MARK, &fwmark, sizeof(fwmark)) < 0)
                return std::unexpected(ERR::SETSOCKOPT_FAILED);
            return {};
        }

        inline Result<> setDscp(uint8_t dscp) noexcept
        {
            if (fd_ < 0)
                return std::unexpected(ERR::SOCKET_FAILED);
            int tos = static_cast<int>(dscp) << 2;
            if (::setsockopt(fd_, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)) < 0)
                return std::unexpected(ERR::SETSOCKOPT_FAILED);
            return {};
        }

        inline Result<> setInterface(std::string_view ifname) noexcept
        {
            if (fd_ < 0)
                return std::unexpected(ERR::SOCKET_FAILED);
            std::string name(ifname);
            if (::setsockopt(fd_, SOL_SOCKET, SO_BINDTODEVICE, name.c_str(), name.size()) < 0)
                return std::unexpected(ERR::SETSOCKOPT_FAILED);
            return {};
        }

        inline Result<> setBroadcast(bool enable = true) noexcept
        {
            if (fd_ < 0)
                return std::unexpected(ERR::SOCKET_FAILED);
            int opt = enable ? 1 : 0;
            if (::setsockopt(fd_, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt)) < 0)
                return std::unexpected(ERR::SETSOCKOPT_FAILED);
            return {};
        }

        inline Result<> setSendBufferSize(int size) noexcept
        {
            if (fd_ < 0)
                return std::unexpected(ERR::SOCKET_FAILED);
            if (::setsockopt(fd_, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) < 0)
                return std::unexpected(ERR::SETSOCKOPT_FAILED);
            return {};
        }

        inline Result<> setRecvBufferSize(int size) noexcept
        {
            if (fd_ < 0)
                return std::unexpected(ERR::SOCKET_FAILED);
            if (::setsockopt(fd_, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) < 0)
                return std::unexpected(ERR::SETSOCKOPT_FAILED);
            return {};
        }

        // =====================================================================
        // 数据报发送与接收接口
        // =====================================================================

        [[nodiscard]] inline Result<size_t> sendTo(const sockaddr_in &peer, const void *data, size_t len) noexcept
        {
            if (fd_ < 0)
                return std::unexpected(ERR::SOCKET_FAILED);
            if (data == nullptr || len == 0)
                return 0;
            const ssize_t sent = ::sendto(fd_, data, len, MSG_NOSIGNAL,
                                          reinterpret_cast<const sockaddr *>(&peer), sizeof(peer));
            if (sent < 0)
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    return 0;
                return std::unexpected(ERR::SOCKET_FAILED);
            }
            return static_cast<size_t>(sent);
        }

        [[nodiscard]] inline Result<size_t> sendTo(const sockaddr_in &peer, std::string_view payload) noexcept
        {
            return sendTo(peer, payload.data(), payload.size());
        }

        [[nodiscard]] inline Result<size_t> sendTo(const Address &target,
                                                   std::string_view payload) noexcept
        {
            if (auto sin = target.toSockAddrIn(); sin.has_value())
            {
                return sendTo(*sin, payload);
            }
            return std::unexpected(ERR::ADDR_INVALID);
        }

        [[nodiscard]] inline Result<size_t> sendTo(const Packet &packet) noexcept
        {
            return sendTo(packet.peer, packet.bytes.data(), packet.bytes.size());
        }

        [[nodiscard]] Result<size_t> sendToWithSrc(const sockaddr_in &peer, const sockaddr_in &srcAddr,
                                                   const void *data, size_t len) noexcept
        {
            if (fd_ < 0)
                return std::unexpected(ERR::SOCKET_FAILED);
            if (data == nullptr || len == 0)
                return 0;

            if (srcAddr.sin_port != 0)
            {
                int tmpFd = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
                if (tmpFd >= 0)
                {
                    int opt = 1;
                    (void)::setsockopt(tmpFd, SOL_IP, IP_TRANSPARENT, &opt, sizeof(opt));
                    (void)::setsockopt(tmpFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
                    (void)::setsockopt(tmpFd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
                    if (::bind(tmpFd, reinterpret_cast<const sockaddr *>(&srcAddr), sizeof(srcAddr)) == 0)
                    {
                        const ssize_t sent = ::sendto(tmpFd, data, len, MSG_NOSIGNAL,
                                                      reinterpret_cast<const sockaddr *>(&peer), sizeof(peer));
                        ::close(tmpFd);
                        if (sent >= 0)
                            return static_cast<size_t>(sent);
                    }
                    ::close(tmpFd);
                }
            }

            struct msghdr msg{};
            struct iovec iov;
            iov.iov_base = const_cast<void *>(data);
            iov.iov_len = len;
            msg.msg_name = const_cast<sockaddr_in *>(&peer);
            msg.msg_namelen = sizeof(peer);
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;

            alignas(struct cmsghdr) char cbuf[CMSG_SPACE(sizeof(struct in_pktinfo))] = {0};
            msg.msg_control = cbuf;
            msg.msg_controllen = sizeof(cbuf);

            struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
            cmsg->cmsg_level = SOL_IP;
            cmsg->cmsg_type = IP_PKTINFO;
            cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
            auto *pktinfo = reinterpret_cast<struct in_pktinfo *>(CMSG_DATA(cmsg));
            pktinfo->ipi_spec_dst = srcAddr.sin_addr;

            const ssize_t sent = ::sendmsg(fd_, &msg, MSG_NOSIGNAL);
            if (sent < 0)
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    return 0;
                return std::unexpected(ERR::SOCKET_FAILED);
            }
            return static_cast<size_t>(sent);
        }

        [[nodiscard]] inline Result<size_t> recvFrom(void *buf, size_t maxLen, sockaddr_in &outPeer) noexcept
        {
            if (fd_ < 0)
                return std::unexpected(ERR::SOCKET_FAILED);
            if (buf == nullptr || maxLen == 0)
                return 0;
            socklen_t len = sizeof(outPeer);
            const ssize_t n = ::recvfrom(fd_, buf, maxLen, 0, reinterpret_cast<sockaddr *>(&outPeer), &len);
            if (n < 0)
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    return 0;
                return std::unexpected(ERR::SOCKET_FAILED);
            }
            return static_cast<size_t>(n);
        }

        [[nodiscard]] Result<size_t> recvWithDst(void *buf, size_t maxLen, sockaddr_in &outPeer,
                                                 sockaddr_in &outOrigDst) noexcept
        {
            if (fd_ < 0)
                return std::unexpected(ERR::SOCKET_FAILED);
            if (buf == nullptr || maxLen == 0)
                return 0;

            struct msghdr msg{};
            struct iovec iov;
            iov.iov_base = buf;
            iov.iov_len = maxLen;
            msg.msg_name = &outPeer;
            msg.msg_namelen = sizeof(outPeer);
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;

            alignas(struct cmsghdr) char cbuf[256];
            msg.msg_control = cbuf;
            msg.msg_controllen = sizeof(cbuf);

            const ssize_t n = ::recvmsg(fd_, &msg, 0);
            if (n < 0)
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    return 0;
                return std::unexpected(ERR::SOCKET_FAILED);
            }

            outOrigDst = {};
            for (auto *cmsg = CMSG_FIRSTHDR(&msg); cmsg != nullptr;
                 cmsg = CMSG_NXTHDR(const_cast<msghdr *>(&msg), cmsg))
            {
                if (cmsg->cmsg_level == SOL_IP)
                {
                    if (cmsg->cmsg_type == IP_ORIGDSTADDR || cmsg->cmsg_type == IP_RECVORIGDSTADDR)
                    {
                        outOrigDst = *reinterpret_cast<const sockaddr_in *>(CMSG_DATA(cmsg));
                        break;
                    }
                    else if (cmsg->cmsg_type == IP_PKTINFO)
                    {
                        const auto *pktinfo = reinterpret_cast<const struct in_pktinfo *>(CMSG_DATA(cmsg));
                        outOrigDst.sin_family = AF_INET;
                        outOrigDst.sin_addr = pktinfo->ipi_addr;
                        outOrigDst.sin_port = localAddr_.sin_port;
                    }
                }
            }
            return static_cast<size_t>(n);
        }

        [[nodiscard]] Result<size_t> sendBatch(std::span<const Packet> packets) noexcept
        {
            if (fd_ < 0)
                return std::unexpected(ERR::SOCKET_FAILED);
            if (packets.empty())
                return 0;

            constexpr size_t kMaxBatch = 64;
            const size_t batchSize = std::min(packets.size(), kMaxBatch);

            struct mmsghdr msgvec[kMaxBatch];
            struct iovec iovs[kMaxBatch];
            std::memset(msgvec, 0, sizeof(msgvec));

            for (size_t i = 0; i < batchSize; ++i)
            {
                iovs[i].iov_base = const_cast<char *>(packets[i].bytes.data());
                iovs[i].iov_len = packets[i].bytes.size();

                msgvec[i].msg_hdr.msg_name = const_cast<sockaddr_in *>(&packets[i].peer);
                msgvec[i].msg_hdr.msg_namelen = sizeof(sockaddr_in);
                msgvec[i].msg_hdr.msg_iov = &iovs[i];
                msgvec[i].msg_hdr.msg_iovlen = 1;
            }

            const int sent = ::sendmmsg(fd_, msgvec, batchSize, MSG_NOSIGNAL);
            if (sent < 0)
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    return 0;
                return std::unexpected(ERR::SOCKET_FAILED);
            }
            return static_cast<size_t>(sent);
        }

        [[nodiscard]] Result<size_t> recvBatch(std::span<Packet> outPackets) noexcept
        {
            if (fd_ < 0)
                return std::unexpected(ERR::SOCKET_FAILED);
            if (outPackets.empty())
                return 0;

            constexpr size_t kMaxBatch = 64;
            const size_t batchSize = std::min(outPackets.size(), kMaxBatch);

            struct mmsghdr msgvec[kMaxBatch];
            struct iovec iovs[kMaxBatch];
            std::array<std::array<char, 2048>, kMaxBatch> buffers;
            std::memset(msgvec, 0, sizeof(msgvec));

            for (size_t i = 0; i < batchSize; ++i)
            {
                iovs[i].iov_base = buffers[i].data();
                iovs[i].iov_len = buffers[i].size();

                msgvec[i].msg_hdr.msg_name = &outPackets[i].peer;
                msgvec[i].msg_hdr.msg_namelen = sizeof(sockaddr_in);
                msgvec[i].msg_hdr.msg_iov = &iovs[i];
                msgvec[i].msg_hdr.msg_iovlen = 1;
            }

            const int received = ::recvmmsg(fd_, msgvec, batchSize, MSG_DONTWAIT, nullptr);
            if (received < 0)
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    return 0;
                return std::unexpected(ERR::SOCKET_FAILED);
            }

            for (int i = 0; i < received; ++i)
            {
                outPackets[i].bytes.assign(buffers[i].data(), msgvec[i].msg_len);
            }
            return static_cast<size_t>(received);
        }

        /**
         * @brief 批量发送待发数据包（单包走 sendTo，多包分批走 sendBatch；空地址自动补全 fallbackPeer）
         */
        inline void sendPackets(std::span<Packet> packets, const sockaddr_in &fallbackPeer) noexcept
        {
            if (fd_ < 0 || packets.empty())
            {
                return;
            }
            if (packets.size() == 1)
            {
                const auto &pkt = packets[0];
                if (!pkt.bytes.empty())
                {
                    const sockaddr_in &dst =
                        (pkt.peer.sin_port != 0 || pkt.peer.sin_addr.s_addr != 0) ? pkt.peer : fallbackPeer;
                    [[maybe_unused]] auto _ = sendTo(dst, pkt.bytes);
                }
                return;
            }

            std::vector<Packet> batch;
            batch.reserve(std::min<size_t>(packets.size(), 64));
            for (auto &pkt : packets)
            {
                if (pkt.bytes.empty())
                {
                    continue;
                }
                if (pkt.peer.sin_port == 0 && pkt.peer.sin_addr.s_addr == 0)
                {
                    pkt.peer = fallbackPeer;
                }
                batch.push_back(std::move(pkt));
                if (batch.size() >= 64)
                {
                    [[maybe_unused]] auto _ = sendBatch(batch);
                    batch.clear();
                }
            }
            if (!batch.empty())
            {
                [[maybe_unused]] auto _ = sendBatch(batch);
            }
        }

        template <typename Callback>
        size_t drain(Callback &&cb) noexcept
        {
            if (fd_ < 0)
                return 0;
            uint8_t buf[65536];
            size_t count = 0;
            while (true)
            {
                sockaddr_in peer{};
                socklen_t len = sizeof(peer);
                const ssize_t n = ::recvfrom(fd_, buf, sizeof(buf), 0,
                                             reinterpret_cast<sockaddr *>(&peer), &len);
                if (n < 0)
                {
                    if (errno == EAGAIN || errno == EWOULDBLOCK)
                        break;
                    if (errno == EINTR)
                        continue;
                    break;
                }

                DatagramView view{
                    .peer = peer,
                    .origDst = {},
                    .payload = std::span<const uint8_t>(buf, static_cast<size_t>(n))};

                if constexpr (std::is_invocable_v<Callback, const DatagramView &>)
                {
                    cb(view);
                }
                else
                {
                    cb(peer, std::span<const uint8_t>(buf, static_cast<size_t>(n)));
                }
                ++count;
            }
            return count;
        }

        template <typename Callback>
        size_t drainWithDst(Callback &&cb) noexcept
        {
            if (fd_ < 0)
                return 0;
            uint8_t buf[65536];
            size_t count = 0;
            while (true)
            {
                sockaddr_in peer{};
                sockaddr_in origDst{};
                auto res = recvWithDst(buf, sizeof(buf), peer, origDst);
                if (!res.has_value() || *res == 0)
                {
                    break;
                }

                DatagramView view{
                    .peer = peer,
                    .origDst = origDst,
                    .payload = std::span<const uint8_t>(buf, *res)};

                if constexpr (std::is_invocable_v<Callback, const DatagramView &>)
                {
                    cb(view);
                }
                else
                {
                    cb(peer, origDst, std::span<const uint8_t>(buf, *res));
                }
                ++count;
            }
            return count;
        }
    };

} // namespace mynet
