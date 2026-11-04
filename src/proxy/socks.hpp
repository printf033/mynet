#pragma once

/**
 * @file proxy/socks.hpp
 * @brief 统一 SOCKS 代理协议服务端状态机处理器（同时支持 SOCKS4/SOCKS4a 与 SOCKS5）。
 */

#include "socks4.hpp"
#include "socks5.hpp"

namespace mynet::proxy
{

    enum class SocksProtocolVersion : uint8_t
    {
        UNKNOWN,
        SOCKS4,
        SOCKS5
    };

    /**
     * @brief 统一 SOCKS 服务端处理器
     *
     * 自动嗅探客户端发起的首字节协议版本号：
     * - 0x04: 路由至 SOCKS4 / SOCKS4a 处理逻辑
     * - 0x05: 路由至 SOCKS5 (RFC 1928 / RFC 1929) 处理逻辑
     */
    class HandlerSocks : public HandlerConnection
    {
    public:
        using AuthCallback = std::function<bool(std::string_view user, std::string_view pass)>;
        using RequestCallback = std::function<void(uint8_t cmd, const ProxyAddress &target)>;

        static constexpr bool kEnableSplice = true;

        inline void enableSpliceForward(int targetFd) noexcept { setSpliceTarget(targetFd); }
        inline void enableSpliceForward(SPLICE_CONTROL ctrl) noexcept { setSpliceTarget(ctrl); }
        inline void disableSpliceForward() noexcept { disableSplice(); }
        [[nodiscard]] inline bool isSpliceForwardActive() const noexcept { return isSpliceActive(); }

    private:
        SocksProtocolVersion version_{SocksProtocolVersion::UNKNOWN};
        HandlerSocks4 s4_{};
        HandlerSocks5 s5_{};
        AuthCallback authCallback_{nullptr};
        RequestCallback requestCallback_{nullptr};

    public:
        HandlerSocks() noexcept = default;
        explicit HandlerSocks(const ProxyConfig &cfg) noexcept
            : s4_(cfg),
              s5_(cfg)
        {
        }
        ~HandlerSocks() noexcept override = default;

        HandlerSocks(const HandlerSocks &) = delete;
        HandlerSocks &operator=(const HandlerSocks &) = delete;
        HandlerSocks(HandlerSocks &&) = delete;
        HandlerSocks &operator=(HandlerSocks &&) = delete;

        void setAuthenticator(AuthCallback cb) noexcept
        {
            authCallback_ = cb;
            s5_.setAuthenticator(cb);
            s4_.setAuthenticator([cb](std::string_view uid) { return cb(uid, ""); });
        }

        void setOnRequest(RequestCallback cb) noexcept
        {
            requestCallback_ = cb;
            s4_.setOnRequest(cb);
            s5_.setOnRequest(cb);
        }

        [[nodiscard]] SocksProtocolVersion version() const noexcept { return version_; }
        [[nodiscard]] bool isEstablished() const noexcept
        {
            return (version_ == SocksProtocolVersion::SOCKS4 && s4_.isEstablished()) ||
                   (version_ == SocksProtocolVersion::SOCKS5 && s5_.isEstablished());
        }

        [[nodiscard]] std::optional<ProxyAddress> targetAddress() const noexcept
        {
            if (version_ == SocksProtocolVersion::SOCKS4)
            {
                return s4_.targetAddress();
            }
            if (version_ == SocksProtocolVersion::SOCKS5)
            {
                return s5_.targetAddress();
            }
            return std::nullopt;
        }

        void configure(const ProxyConfig &cfg) noexcept
        {
            s4_.configure(cfg);
            s5_.configure(cfg);
        }

        void reset() noexcept override
        {
            HandlerConnection::reset();
            version_ = SocksProtocolVersion::UNKNOWN;
            s4_.reset();
            s5_.reset();
            disableSpliceForward();
        }

        void onMessageComplete() noexcept {}
        void onParseError(const char *reason) noexcept { (void)reason; }

        void process()
        {
            if (version_ == SocksProtocolVersion::UNKNOWN)
            {
                if (requestBytes() == 0)
                {
                    return;
                }
                const uint8_t firstByte = static_cast<uint8_t>(*requestBegin());
                if (firstByte == socks4::kVersion)
                {
                    version_ = SocksProtocolVersion::SOCKS4;
                }
                else if (firstByte == socks5::kVersion)
                {
                    version_ = SocksProtocolVersion::SOCKS5;
                }
                else
                {
                    onParseError("SOCKS: Unknown protocol version");
                    setCloseAfterResponse(true);
                    return;
                }
            }

            if (version_ == SocksProtocolVersion::SOCKS4)
            {
                // 将本连接的请求数据同步给 s4_
                syncToChild(s4_);
                s4_.process();
                syncFromChild(s4_);
            }
            else if (version_ == SocksProtocolVersion::SOCKS5)
            {
                syncToChild(s5_);
                s5_.process();
                syncFromChild(s5_);
            }
        }

    private:
        void syncToChild(HandlerConnection &child)
        {
            const size_t avail = requestBytes();
            if (avail > child.requestBytes())
            {
                const size_t diff = avail - child.requestBytes();
                const char *p = requestBegin() + child.requestBytes();
                [[maybe_unused]] auto _ = child.appendRequest(p, static_cast<ssize_t>(diff));
            }
        }

        void syncFromChild(HandlerConnection &child)
        {
            // 同步消耗的请求字节
            const size_t childAvail = child.requestBytes();
            if (requestBytes() > childAvail)
            {
                requestConsume(requestBytes() - childAvail);
            }

            // 同步子状态机的响应报文
            while (child.hasResponse())
            {
                std::string resp = child.takeResponse();
                [[maybe_unused]] auto _ = pushResponse(resp);
            }

            if (child.closeAfterResponse())
            {
                setCloseAfterResponse(true);
            }

            if (child.isSpliceActive())
            {
                setSpliceTarget(child.spliceTarget());
            }
        }
    };

} // namespace mynet::proxy
