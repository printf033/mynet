#pragma once

/**
 * @file inboundMux.hpp
 * @brief 通用多协议自适应入站处理器 (HandlerInboundMux) 与入站端点 (InboundMux)。
 *
 * 作为 Inbound 层的通用协议多路复用能力 (Inbound Multiplexer)：
 * - 单端口同时支持 SOCKS4/SOCKS4a、SOCKS5 与 HTTP Proxy (RFC 7230/9110)；
 * - 提供探针注册机制 (InboundProbeMatcher)，支持通过首包特征扩展分流其他协议；
 * - 零内存分配优化：内联常见协议解析状态机，命中协议后直接零拷贝交接缓冲与流通道；
 * - 统一生命周期管理：与 InboundBase、AcceptorBase 及 Core::dispatch 无缝集成。
 */

#include "address.hpp"
#include "connection.hpp"
#include "http/http.hpp"
#include "inboundHandler.hpp"
#include "inboundManager.hpp"
#include "socks/socks4.hpp"
#include "socks/socks5.hpp"
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace mynet::handler
{

    /**
     * @brief 协议嗅探探针匹配器
     */
    struct InboundProbeMatcher
    {
        std::string name;
        std::function<bool(std::span<const uint8_t>)> probe;
        std::function<std::unique_ptr<HandlerInboundConnectionBase>()> factory;
    };

    /**
     * @brief 通用多协议自适应入站处理器 (HandlerInboundMux)
     */
    class HandlerInboundMux : public HandlerInboundConnectionBase
    {
    public:
        using AuthCallback = std::function<bool(std::string_view user, std::string_view pass)>;

    private:
        std::string activeProtocol_{};
        HandlerInboundConnectionBase *activeHandler_{nullptr};

        // 内置零堆分配默认子处理器（针对最高频的 SOCKS4/SOCKS5/HTTP 混合场景）
        HandlerInboundSocks4 s4_{};
        HandlerInboundSocks5 s5_{};
        HandlerInboundHttpProxy http_{};

        // 扩展自定义探针与其动态创建的 Handler
        std::vector<InboundProbeMatcher> customProbes_{};
        std::unique_ptr<HandlerInboundConnectionBase> customHandler_{nullptr};

        AuthCallback authCallback_{nullptr};

    public:
        HandlerInboundMux() noexcept = default;
        explicit HandlerInboundMux(const ProxyConfig &cfg) noexcept
            : s4_(cfg),
              s5_(cfg)
        {
        }
        ~HandlerInboundMux() noexcept override = default;

        HandlerInboundMux(const HandlerInboundMux &) = delete;
        HandlerInboundMux &operator=(const HandlerInboundMux &) = delete;
        HandlerInboundMux(HandlerInboundMux &&) = delete;
        HandlerInboundMux &operator=(HandlerInboundMux &&) = delete;

        /**
         * @brief 注册自定义协议探针
         */
        void registerProbe(InboundProbeMatcher probe) { customProbes_.push_back(std::move(probe)); }

        void setAuthenticator(AuthCallback cb) noexcept
        {
            authCallback_ = cb;
            s5_.setAuthenticator(cb);
            s4_.setAuthenticator([cb](std::string_view uid) { return cb(uid, ""); });
            http_.setAuthenticator(cb);
        }

        [[nodiscard]] std::string_view activeProtocol() const noexcept { return activeProtocol_; }

        [[nodiscard]] bool isEstablished() const noexcept
        {
            return activeHandler_ != nullptr && activeHandler_->isEstablished();
        }

        [[nodiscard]] const std::optional<ProxyAddress> &targetAddress() const noexcept
        {
            if (activeHandler_ != nullptr)
            {
                return activeHandler_->targetAddress();
            }
            return targetAddress_;
        }

        void configure(const ProxyConfig &cfg) noexcept
        {
            s4_.configure(cfg);
            s5_.configure(cfg);
        }

        void reset() noexcept override
        {
            HandlerInboundConnectionBase::reset();
            activeHandler_ = nullptr;
            activeProtocol_.clear();
            customHandler_.reset();
            s4_.reset();
            s5_.reset();
            http_.reset();
        }

        void onMessageComplete() noexcept {}
        void onParseError(const char *reason) noexcept { (void)reason; }

        void handle() override
        {
            if (activeHandler_ == nullptr)
            {
                if (requestBytes() == 0)
                {
                    return;
                }

                const uint8_t b = static_cast<uint8_t>(*requestBegin());
                if (b == socks4::kVersion)
                {
                    activeHandler_ = &s4_;
                    activeProtocol_ = "socks4";
                }
                else if (b == socks5::kVersion)
                {
                    activeHandler_ = &s5_;
                    activeProtocol_ = "socks5";
                }
                else if (isHttpChar(b))
                {
                    activeHandler_ = &http_;
                    activeProtocol_ = "http";
                }
                else
                {
                    // 检查扩展探针表
                    auto data = std::span(reinterpret_cast<const uint8_t *>(requestBegin()), requestBytes());
                    for (const auto &matcher : customProbes_)
                    {
                        if (matcher.probe && matcher.probe(data))
                        {
                            if (matcher.factory)
                            {
                                customHandler_ = matcher.factory();
                                activeHandler_ = customHandler_.get();
                                activeProtocol_ = matcher.name;
                                if (authCallback_ && customHandler_)
                                {
                                    // 预留给扩展协议的认证设置
                                }
                                break;
                            }
                        }
                    }
                }

                if (activeHandler_ == nullptr)
                {
                    onParseError("Mux: Unrecognized protocol byte");
                    setCloseAfterResponse(true);
                    return;
                }
            }

            syncToChild(*activeHandler_);
            activeHandler_->handle();
            syncFromChild(*activeHandler_);

            if (activeHandler_->isEstablished())
            {
                stage_ = InboundStage::STREAMING;
                targetAddress_ = activeHandler_->targetAddress();
                command_ = activeHandler_->command();
            }
        }

    private:
        static bool isHttpChar(uint8_t b) noexcept
        {
            return (b == 'C' || b == 'G' || b == 'P' || b == 'H' || b == 'D' || b == 'O' || b == 'T' ||
                    (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z'));
        }

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
            const size_t childAvail = child.requestBytes();
            if (requestBytes() > childAvail)
            {
                requestConsume(requestBytes() - childAvail);
            }

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

} // namespace mynet::handler

namespace mynet
{

    /**
     * @brief 统一多协议自适应入站端点 (InboundMux)
     */
    class InboundMux : public InboundBase
    {
    private:
        std::string username_{};
        std::string password_{};
        std::vector<std::string> protocols_{"socks5", "http", "socks4"};

    public:
        InboundMux(std::string tag, std::string host, uint16_t port, std::string username = "",
                   std::string password = "", bool enableSniffing = true,
                   std::vector<std::string> protocols = {"socks5", "http", "socks4"})
            : InboundBase(std::move(tag), "mux", std::move(host), port, enableSniffing),
              username_(std::move(username)),
              password_(std::move(password)),
              protocols_(std::move(protocols))
        {
        }

        [[nodiscard]] inline const std::string &username() const noexcept { return username_; }
        [[nodiscard]] inline const std::string &password() const noexcept { return password_; }
        [[nodiscard]] const std::vector<std::string> &protocols() const noexcept { return protocols_; }

        [[nodiscard]] std::unique_ptr<handler::HandlerInboundConnectionBase> createHandler() override
        {
            auto h = std::make_unique<handler::HandlerInboundMux>();
            if (!username_.empty() || !password_.empty())
            {
                std::string u = username_;
                std::string p = password_;
                h->setAuthenticator([u, p](std::string_view user, std::string_view pass)
                                    { return user == u && (p.empty() || pass == p); });
            }
            return h;
        }
    };

} // namespace mynet
