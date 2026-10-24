#include "concepts.hpp"
#include "event.hpp"
#include "handler.hpp"
#include <gtest/gtest.h>

using namespace mynet;

namespace
{
    struct ValidResettable
    {
        void reset() noexcept {}
    };

    struct NonNoexceptReset
    {
        void reset() {}
    };

    struct NonVoidReset
    {
        int reset() noexcept { return 0; }
    };

    struct NoReset
    {
    };

    struct FakeHandler : public HandlerBase
    {
        [[nodiscard]] Result<> appendRequest(const char *, ssize_t) noexcept { return {}; }
        bool hasResponse() noexcept { return false; }
        std::string takeResponse() { return ""; }
        bool requestOverLimit() noexcept { return false; }
        void process() {}
        void reset() noexcept {}
    };

    struct ThrowingAppendHandler : public HandlerBase
    {
        // 历史语义：appendRequest 曾允许抛出 bad_alloc，现被 ProtocolHandler
        // 约束拒绝——非 noexcept、非 Result<> 返回的摄入路径不再是合法协议头。
        void appendRequest(const char *, ssize_t) {}
        bool hasResponse() noexcept { return false; }
        std::string takeResponse() { return ""; }
        bool requestOverLimit() noexcept { return false; }
        void process() {}
        void reset() noexcept {}
    };

    struct DeletedProcessHandler : public HandlerBase
    {
        void process() = delete;
    };

    struct DeletedTakeResponseHandler : public HandlerBase
    {
        std::string takeResponse() = delete;
    };

    struct NonDerivedHandler
    {
        [[nodiscard]] Result<> appendRequest(const char *, ssize_t) noexcept { return {}; }
        bool hasResponse() noexcept { return false; }
        std::string takeResponse() { return ""; }
        bool requestOverLimit() noexcept { return false; }
        void process() {}
        void reset() noexcept {}
    };
} // namespace

TEST(Concepts, ResettableStrictlyRequiresNoexceptVoidReset)
{
    static_assert(Resettable<ValidResettable>);
    static_assert(Resettable<HandlerBase>);
    static_assert(Resettable<EventBase<HandlerBase>>);
    static_assert(Resettable<EventSocket<HandlerBase>>);
    static_assert(Resettable<EventSsl<HandlerBase>>);

    static_assert(!Resettable<NonNoexceptReset>);
    static_assert(!Resettable<NonVoidReset>);
    static_assert(!Resettable<NoReset>);

    EXPECT_TRUE(Resettable<ValidResettable>);
    EXPECT_FALSE(Resettable<NonNoexceptReset>);
    EXPECT_FALSE(Resettable<NonVoidReset>);
    EXPECT_FALSE(Resettable<NoReset>);
}

TEST(Concepts, DerivedFromHandlerBaseConstraints)
{
    static_assert(DerivedFromHandlerBase<HandlerBase>);
    static_assert(DerivedFromHandlerBase<FakeHandler>);
    static_assert(DerivedFromHandlerBase<HandlerHttp<HTTP_MODE::REQUEST>>);
    static_assert(!DerivedFromHandlerBase<NonDerivedHandler>);
    static_assert(!DerivedFromHandlerBase<int>);

    EXPECT_TRUE(DerivedFromHandlerBase<HandlerBase>);
    EXPECT_TRUE(DerivedFromHandlerBase<HandlerHttp<HTTP_MODE::REQUEST>>);
    EXPECT_FALSE(DerivedFromHandlerBase<NonDerivedHandler>);
}

TEST(Concepts, ProtocolHandlerContractEnforcement)
{
    static_assert(ProtocolHandler<HandlerBase>);
    static_assert(ProtocolHandler<FakeHandler>);
    static_assert(ProtocolHandler<HandlerHttp<HTTP_MODE::REQUEST>>);
    static_assert(!ProtocolHandler<ThrowingAppendHandler>); // 旧语义：允许抛出的摄入路径现被约束拒绝

    static_assert(!ProtocolHandler<DeletedProcessHandler>);
    static_assert(!ProtocolHandler<DeletedTakeResponseHandler>);
    static_assert(!ProtocolHandler<NonDerivedHandler>);
    static_assert(!ProtocolHandler<NoReset>);

    EXPECT_TRUE(ProtocolHandler<HandlerBase>);
    EXPECT_FALSE(ProtocolHandler<ThrowingAppendHandler>);
    EXPECT_FALSE(ProtocolHandler<DeletedProcessHandler>);
    EXPECT_FALSE(ProtocolHandler<DeletedTakeResponseHandler>);
    EXPECT_FALSE(ProtocolHandler<NonDerivedHandler>);
}

TEST(Concepts, DerivedFromDatagramHandlerConstraints)
{
    static_assert(DerivedFromDatagramHandler<DatagramHandler>);
    static_assert(!DerivedFromDatagramHandler<HandlerBase>);
    static_assert(!DerivedFromDatagramHandler<NonDerivedHandler>);

    EXPECT_TRUE(DerivedFromDatagramHandler<DatagramHandler>);
    EXPECT_FALSE(DerivedFromDatagramHandler<HandlerBase>);
}

TEST(Concepts, EventConceptsEvaluationOnCompleteTypes)
{
    using BaseEv = EventBase<HandlerBase>;
    using SockEv = EventSocket<HandlerBase>;
    using SslEv = EventSsl<HandlerBase>;

    // DerivedFromEventBase
    static_assert(DerivedFromEventBase<BaseEv>);
    static_assert(DerivedFromEventBase<SockEv>);
    static_assert(DerivedFromEventBase<SslEv>);
    static_assert(!DerivedFromEventBase<HandlerBase>);

    // SocketEvent
    static_assert(SocketEvent<SockEv>);
    static_assert(!SocketEvent<BaseEv>);
    static_assert(!SocketEvent<SslEv>);

    // SslEvent
    static_assert(SslEvent<SslEv>);
    static_assert(!SslEvent<BaseEv>);
    static_assert(!SslEvent<SockEv>);

    EXPECT_TRUE(DerivedFromEventBase<BaseEv>);
    EXPECT_TRUE(SocketEvent<SockEv>);
    EXPECT_TRUE(SslEvent<SslEv>);
    EXPECT_FALSE(SocketEvent<SslEv>);
    EXPECT_FALSE(SslEvent<SockEv>);
}
