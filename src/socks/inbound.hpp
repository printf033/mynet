#pragma once

#include "../http/http.hpp"
#include "../inboundManager.hpp"
#include "socks.hpp"
#include "socks5.hpp"
#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace mynet
{

    /**
     * @brief SOCKS5 协议接收器 (AcceptorSocks5 / InboundSocks5)
     */
    class AcceptorSocks5 : public Acceptor
    {
    private:
        std::string username_{};
        std::string password_{};

    public:
        AcceptorSocks5(std::string tag = "socks5", std::string host = "0.0.0.0", uint16_t port = 1080,
                       std::string username = "", std::string password = "", bool enableSniffing = true)
            : Acceptor(std::move(tag), "socks5", std::move(host), port, enableSniffing),
              username_(std::move(username)),
              password_(std::move(password))
        {
        }

        [[nodiscard]] bool match(std::span<const uint8_t> initialBytes) const noexcept override
        {
            if (initialBytes.empty())
                return false;
            return initialBytes[0] == 0x05 || initialBytes[0] == 0x04;
        }

        [[nodiscard]] inline const std::string &username() const noexcept { return username_; }
        [[nodiscard]] inline const std::string &password() const noexcept { return password_; }

        [[nodiscard]] std::unique_ptr<Handler> createHandler() override
        {
            auto h = std::make_unique<handler::HandlerInboundSocks5>();
            if (!username_.empty() || !password_.empty())
            {
                std::string u = username_;
                std::string p = password_;
                h->setAuthenticator([u, p](std::string_view user, std::string_view pass)
                                    { return user == u && pass == p; });
            }
            return h;
        }
    };

    using InboundSocks5 = AcceptorSocks5;

    namespace handler
    {
        /**
         * @brief 混合代理入站状态机 (自动自适应 SOCKS4 / SOCKS5 与 HTTP Proxy)
         */
        class HandlerInboundMixed : public MuxInboundHandler<HandlerInboundSocks, HandlerInboundHttpProxy>
        {
        public:
            using AuthCallback = std::function<bool(std::string_view user, std::string_view pass)>;

        private:
            enum class Mode
            {
                UNKNOWN,
                SOCKS,
                HTTP
            };
            Mode mode_{Mode::UNKNOWN};
            AuthCallback authCallback_{nullptr};

        public:
            HandlerInboundMixed() noexcept = default;

            void setAuthenticator(AuthCallback cb) noexcept
            {
                authCallback_ = std::move(cb);
                if (auto *s = std::get_if<HandlerInboundSocks>(&activeVariant_); s != nullptr)
                {
                    s->setAuthenticator(authCallback_);
                }
                else if (auto *h = std::get_if<HandlerInboundHttpProxy>(&activeVariant_); h != nullptr)
                {
                    h->setAuthenticator(authCallback_);
                }
            }

            void reset() noexcept override
            {
                MuxInboundHandler::reset();
                mode_ = Mode::UNKNOWN;
            }

            void handle() override
            {
                if (mode_ == Mode::UNKNOWN)
                {
                    if (requestBytes() == 0)
                        return;
                    const uint8_t b = static_cast<uint8_t>(*requestBegin());
                    if (b == 0x04 || b == 0x05)
                    {
                        mode_ = Mode::SOCKS;
                        auto &s = emplaceChild<HandlerInboundSocks>();
                        if (authCallback_)
                            s.setAuthenticator(authCallback_);
                    }
                    else
                    {
                        mode_ = Mode::HTTP;
                        auto &h = emplaceChild<HandlerInboundHttpProxy>();
                        if (authCallback_)
                            h.setAuthenticator(authCallback_);
                    }
                }

                if (Handler *child = activeChild(); child != nullptr)
                {
                    driveChild(*child);
                }
            }
        };
    } // namespace handler

    /**
     * @brief 混合代理接收器 (AcceptorMixed / InboundMixed)
     */
    class AcceptorMixed : public Acceptor
    {
    private:
        std::string username_{};
        std::string password_{};

    public:
        AcceptorMixed(std::string tag = "mixed", std::string host = "0.0.0.0", uint16_t port = 1080,
                      std::string username = "", std::string password = "", bool enableSniffing = true)
            : Acceptor(std::move(tag), "mixed", std::move(host), port, enableSniffing),
              username_(std::move(username)),
              password_(std::move(password))
        {
        }

        [[nodiscard]] bool match(std::span<const uint8_t> initialBytes) const noexcept override
        {
            if (initialBytes.empty())
                return false;
            const uint8_t b = initialBytes[0];
            return b == 0x05 || b == 0x04 || b == 'C' || b == 'G' || b == 'P' || b == 'H' || b == 'D' || b == 'O';
        }

        [[nodiscard]] inline const std::string &username() const noexcept { return username_; }
        [[nodiscard]] inline const std::string &password() const noexcept { return password_; }

        [[nodiscard]] std::unique_ptr<Handler> createHandler() override
        {
            auto h = std::make_unique<handler::HandlerInboundMixed>();
            if (!username_.empty() || !password_.empty())
            {
                std::string u = username_;
                std::string p = password_;
                h->setAuthenticator([u, p](std::string_view user, std::string_view pass)
                                    { return user == u && pass == p; });
            }
            return h;
        }
    };

    using InboundMixed = AcceptorMixed;

} // namespace mynet
