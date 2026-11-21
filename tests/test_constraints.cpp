#include "acceptor.hpp"
#include "block/block.hpp"
#include "configHolder.hpp"
#include "connection.hpp"
#include "constraints.hpp"
#include "dialer.hpp"
#include "direct/direct.hpp"
#include "dns/handler.hpp"
#include "http/v1/handler.hpp"
#include "http/v3/handler.hpp"
#include "hysteria2/hysteria2.hpp"
#include "proactor.hpp"
#include "reactor.hpp"
#include "socks/socks5.hpp"
#include "trojan/trojan.hpp"
#include "vless/vless.hpp"
#include <gtest/gtest.h>
#include <type_traits>
#include <version>

using namespace mynet;
using namespace mynet::handler;
using namespace mynet::http::v1;
using namespace mynet::http::v3;

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

    /// 正例：派生自 HandlerConnection，只重写 handle() 表达业务定制。
    struct FakeHandler : public HandlerConnection
    {
        void handle() {}
    };

    /// 反例：手写齐全部流式成员与生命周期钩子——结构上无懈可击，
    /// 仅因未继承 HandlerConnection 而被拒。这条用例隔离出"必须派生"本身。
    struct FullContractWithoutDerivation
    {
        [[nodiscard]] Result<> appendRequest(const char *, ssize_t) noexcept { return {}; }
        [[nodiscard]] Result<> appendRequest(std::string_view) noexcept { return {}; }
        bool hasResponse() noexcept { return false; }
        size_t responseCount() noexcept { return 0; }
        std::string takeResponse() { return ""; }
        void recycleSpare(std::string &&) noexcept {}
        Result<> pushResponse(std::string &&) noexcept { return {}; }
        Result<> pushResponse(const std::string &) noexcept { return {}; }
        Result<> pushResponse(std::string_view) noexcept { return {}; }
        Result<> pushResponse(const char *) noexcept { return {}; }
        Result<> reserveResponses(size_t) noexcept { return {}; }
        bool requestOverLimit() noexcept { return false; }
        size_t requestBytes() noexcept { return 0; }
        const char *requestBegin() noexcept { return ""; }
        void requestConsume(size_t) noexcept {}
        void requestClear() noexcept {}
        void handle() {}
        void reset() noexcept {}
        void onConnect(int) noexcept {}
        void onUpgrade() noexcept {}
        void onMessageComplete() noexcept {}
        void onParseError(const char *) noexcept {}
        [[nodiscard]] std::expected<char *, ERR> prepareRequestWritable(size_t = 4 << 10) noexcept { return nullptr; }
        char *requestWritableBegin() noexcept { return nullptr; }
        size_t requestWritableBytes() noexcept { return 0; }
        void commitRequest(size_t) noexcept {}
        size_t readCredit() noexcept { return 0; }
        void setMaxRequestBytes(size_t) noexcept {}
        bool closeAfterResponse() noexcept { return false; }
        void setCloseAfterResponse(bool) noexcept {}
        void setSpliceTarget(int) noexcept {}
        void setSpliceTarget(SPLICE_CONTROL) noexcept {}
        void setSpliceControl(SPLICE_CONTROL) noexcept {}
        SPLICE_CONTROL spliceControl() noexcept { return SPLICE_CONTROL::DISABLED; }
        int spliceTarget() noexcept { return -1; }
        bool isSpliceActive() noexcept { return false; }
        void pauseSplice() noexcept {}
        void resumeSplice() noexcept {}
        void drainSplice() noexcept {}
        void disableSplice() noexcept {}
        bool spliceEnabled() noexcept { return false; }
        int fd() noexcept { return -1; }
    };

    /// 反例：只有六个方法。同时不满足派生与结构两层要求。
    struct LegacySixMemberHandler
    {
        [[nodiscard]] Result<> appendRequest(const char *, ssize_t) noexcept { return {}; }
        bool hasResponse() noexcept { return false; }
        std::string takeResponse() { return ""; }
        bool requestOverLimit() noexcept { return false; }
        void handle() {}
        void reset() noexcept {}
    };

    struct ThrowingAppendHandler : public HandlerConnection
    {
        // 历史语义：appendRequest 曾允许抛出 bad_alloc，现被 MandatoryMethodConnection
        // 约束拒绝——非 noexcept、非 Result<> 返回的摄入路径不再是合法协议头。
        void appendRequest(const char *, ssize_t) {}
    };

    struct DeletedHandleHandler
    {
        void handle() = delete;
    };

    struct DeletedTakeResponseHandler : public HandlerConnection
    {
        std::string takeResponse() = delete;
    };

    struct DeletedPushResponseHandler : public HandlerConnection
    {
        Result<> pushResponse(std::string &&) = delete;
    };

    struct DeletedPrepareRequestWritableHandler : public HandlerConnection
    {
        std::expected<char *, ERR> prepareRequestWritable(size_t) = delete;
    };

    struct DeletedSpliceControlHandler : public HandlerConnection
    {
        void setSpliceControl(SPLICE_CONTROL) = delete;
    };

    struct DeletedPauseSpliceHandler : public HandlerConnection
    {
        void pauseSplice() = delete;
    };

    /// 双特化组合：两个并列的独立基类，成员访问均为直接偏移，不经过虚基类。
    struct CombinedHandler : HandlerConnection, HandlerDatagram
    {
        using HandlerConnection::fd;
        using HandlerConnection::handle;

        void reset() noexcept override
        {
            HandlerConnection::reset();
            HandlerDatagram::reset();
        }
        void onMessageComplete() noexcept override
        {
            HandlerConnection::onMessageComplete();
            HandlerDatagram::onMessageComplete();
        }
        void onParseError(const char *reason) noexcept override
        {
            HandlerConnection::onParseError(reason);
            HandlerDatagram::onParseError(reason);
        }
        void onDatagram(const sockaddr_in &, const char *, size_t) noexcept override {}
    };

    /// 纯报文处理器：只派生报文特化，不具备任何流式设施。
    struct PureDatagramHandler : HandlerDatagram
    {
        void onDatagram(const sockaddr_in &, const char *, size_t) noexcept override {}
    };

    /// 反例：已派生报文特化，但引擎经处理器类型直接读取的接收上界缺失。
    struct MissingMaxDatagramBytesHandler : HandlerDatagram
    {
        void onDatagram(const sockaddr_in &, const char *, size_t) noexcept override {}
        size_t maxDatagramBytes() = delete;
    };

    struct DeletedSendToHandler : HandlerDatagram
    {
        void sendTo(const sockaddr_in &, const char *, size_t) = delete;
    };

    struct DeletedTakeOutgoingHandler : HandlerDatagram
    {
        Protocol<HandlerDatagram> takeOutgoing() = delete;
    };

    /// 反例：方法全齐、可重置，但未派生 HandlerDatagram。
    /// 隔离出「必须派生」这一层：数据报侧的回复队列必须来自真实基类子对象。
    struct DatagramContractWithoutDerivation
    {
        void onDatagram(const sockaddr_in &, const char *, size_t) noexcept {}
        void onMessageComplete() noexcept {}
        void onParseError(const char *) noexcept {}

        void sendTo(const sockaddr_in &, const char *, size_t) {}
        void sendTo(const sockaddr_in &, std::string) {}
        void forwardTo(const sockaddr_in &, const char *, size_t) {}
        void broadcastTo(const std::vector<sockaddr_in> &, const char *, size_t) {}

        bool hasOutgoing() noexcept { return false; }
        size_t outgoingCount() noexcept { return 0; }
        const Protocol<HandlerDatagram> &peekOutgoing() noexcept
        {
            static Protocol<HandlerDatagram> p;
            return p;
        }
        Protocol<HandlerDatagram> takeOutgoing() { return {}; }
        size_t droppedOutgoing() noexcept { return 0; }

        void setMaxDatagramBytes(size_t) noexcept {}
        size_t maxDatagramBytes() noexcept { return 0; }
        void setMaxPendingOutgoing(size_t) noexcept {}
        size_t maxPendingOutgoing() noexcept { return 0; }
        void reset() noexcept {}
    };

    /// 流式入口可用性探测。
    ///
    /// 必须把被测类型作为模板参数传进来：非依赖表达式里的约束失败在 GCC 下是硬错误，
    /// 不是替换失败；依赖形式才能让 requires 表达式求值为 false。
    template <typename E>
    concept CanRunTcp = requires(E &e) { e.runTcp("0.0.0.0", 0); };

    template <typename E, typename H>
    concept CanRunUdp = requires(E &e, H &h) { e.runUdp("0.0.0.0", 0, h); };

    struct NonDerivedHandler
    {
        [[nodiscard]] Result<> appendRequest(const char *, ssize_t) noexcept { return {}; }
        bool hasResponse() noexcept { return false; }
        std::string takeResponse() { return ""; }
        bool requestOverLimit() noexcept { return false; }
        void echo() {}
        void reset() noexcept {}
    };
} // namespace

TEST(Constraints, ResettableStrictlyRequiresNoexceptVoidReset)
{
    static_assert(Resettable<ValidResettable>);
    static_assert(Resettable<RequestBuffer>);
    static_assert(Resettable<ResponseQueue>);
    static_assert(Resettable<DatagramQueue>);
    static_assert(Resettable<HandlerConnection>);
    static_assert(Resettable<HandlerDatagram>);
    static_assert(Resettable<Acceptor<HandlerConnection>>);
    static_assert(Resettable<AcceptorBase<HandlerConnection>>);
    static_assert(Resettable<Dialer<HandlerConnection>>);
    static_assert(Resettable<DialerBase<HandlerConnection>>);
    static_assert(Resettable<HandlerInboundConnectionBase>);
    static_assert(Resettable<HandlerInboundDatagramBase>);
    static_assert(Resettable<HandlerOutboundConnectionBase>);
    static_assert(Resettable<HandlerOutboundDatagramBase>);
    static_assert(Resettable<HandlerOutboundDirect>);
    static_assert(Resettable<HandlerOutboundTrojan>);
    static_assert(Resettable<HandlerOutboundVless>);
    static_assert(Resettable<HandlerOutboundSocks5>);
    static_assert(Resettable<HandlerOutboundBlock>);
    static_assert(Resettable<HandlerOutboundHysteria2>);

    static_assert(!Resettable<NonNoexceptReset>);
    static_assert(!Resettable<NonVoidReset>);
    static_assert(!Resettable<NoReset>);

    EXPECT_TRUE(Resettable<ValidResettable>);
    EXPECT_FALSE(Resettable<NonNoexceptReset>);
    EXPECT_FALSE(Resettable<NonVoidReset>);
    EXPECT_FALSE(Resettable<NoReset>);
}

TEST(Constraints, HandlerConstraintEnforcement)
{
    // 原 HandlerBase 的接口契约在此以概念形式保留：两个处理器基类并列独立，
    // 事件层只依赖这份最小约束，不再依赖任何共同祖先。
    static_assert(HandlerConstraint<HandlerConnection>);
    static_assert(HandlerConstraint<HandlerDatagram>);
    static_assert(HandlerConstraint<FakeHandler>);
    static_assert(HandlerConstraint<HandlerHttp<HTTP_MODE::REQUEST>>);
    static_assert(HandlerConstraint<HandlerHttp3<>>);

    // 反例：缺 onMessageComplete / onParseError 钩子，或不可重置
    static_assert(!HandlerConstraint<ValidResettable>); // 只有 reset()
    static_assert(!HandlerConstraint<NonDerivedHandler>);
    static_assert(!HandlerConstraint<NoReset>);
    static_assert(!HandlerConstraint<int>);

    EXPECT_TRUE(HandlerConstraint<HandlerConnection>);
    EXPECT_TRUE(HandlerConstraint<HandlerDatagram>);
    EXPECT_TRUE(HandlerConstraint<HandlerHttp3<>>);
    EXPECT_FALSE(HandlerConstraint<ValidResettable>);
    EXPECT_FALSE(HandlerConstraint<NonDerivedHandler>);
}

TEST(Constraints, MandatoryMethodConnectionContractEnforcement)
{
    // 报文基类不承诺字节流契约；流式契约只由 HandlerConnection 提供
    static_assert(!MandatoryMethodConnection<HandlerDatagram>);
    static_assert(MandatoryMethodConnection<HandlerConnection>);
    static_assert(MandatoryMethodConnection<FakeHandler>);
    // 两层要求各自可独立生效：结构齐全但不派生 → 仍被拒
    static_assert(!MandatoryMethodConnection<FullContractWithoutDerivation>);
    static_assert(!MandatoryMethodConnection<LegacySixMemberHandler>); // 既未派生又缺方法
    static_assert(MandatoryMethodConnection<CombinedHandler>);         // 双特化组合（流式 + 数据报）仍然成立
    static_assert(MandatoryMethodConnection<HandlerHttp<HTTP_MODE::REQUEST>>);
    static_assert(!MandatoryMethodConnection<ThrowingAppendHandler>); // 旧语义：允许抛出的摄入路径现被约束拒绝

    static_assert(!MandatoryMethodConnection<DeletedHandleHandler>);
    static_assert(!MandatoryMethodConnection<DeletedTakeResponseHandler>);
    static_assert(!MandatoryMethodConnection<DeletedPushResponseHandler>);
    static_assert(!MandatoryMethodConnection<DeletedPrepareRequestWritableHandler>);
    static_assert(!MandatoryMethodConnection<DeletedSpliceControlHandler>);
    static_assert(!MandatoryMethodConnection<DeletedPauseSpliceHandler>);
    static_assert(!MandatoryMethodConnection<NonDerivedHandler>);
    static_assert(!MandatoryMethodConnection<NoReset>);

    EXPECT_FALSE(MandatoryMethodConnection<HandlerDatagram>);
    EXPECT_TRUE(MandatoryMethodConnection<HandlerConnection>);
    EXPECT_FALSE(MandatoryMethodConnection<FullContractWithoutDerivation>);
    EXPECT_FALSE(MandatoryMethodConnection<LegacySixMemberHandler>);
    EXPECT_FALSE(MandatoryMethodConnection<ThrowingAppendHandler>);
    EXPECT_FALSE(MandatoryMethodConnection<DeletedHandleHandler>);
    EXPECT_FALSE(MandatoryMethodConnection<DeletedTakeResponseHandler>);
    EXPECT_FALSE(MandatoryMethodConnection<DeletedPushResponseHandler>);
    EXPECT_FALSE(MandatoryMethodConnection<DeletedPrepareRequestWritableHandler>);
    EXPECT_FALSE(MandatoryMethodConnection<DeletedSpliceControlHandler>);
    EXPECT_FALSE(MandatoryMethodConnection<DeletedPauseSpliceHandler>);
    EXPECT_FALSE(MandatoryMethodConnection<NonDerivedHandler>);
}

TEST(Constraints, DerivedFromHandlerConnectionConstraints)
{
    static_assert(DerivedFromHandlerConnection<HandlerConnection>);
    static_assert(DerivedFromHandlerConnection<HandlerHttp<HTTP_MODE::REQUEST>>);
    static_assert(DerivedFromHandlerConnection<CombinedHandler>);
    static_assert(!DerivedFromHandlerConnection<HandlerHttp3<>>); // HTTP/3 纯报文处理器不继承 HandlerConnection
    static_assert(DerivedFromHandlerDatagram<HandlerHttp3<>>);
    // 两个处理器基类并列独立，各自都满足通用生命周期契约
    static_assert(HandlerConstraint<HandlerConnection>);
    static_assert(HandlerConstraint<HandlerHttp3<>>);

    // 报文基类不是流式处理器
    static_assert(!DerivedFromHandlerConnection<HandlerDatagram>);
    static_assert(!DerivedFromHandlerConnection<NonDerivedHandler>);

    EXPECT_TRUE(DerivedFromHandlerConnection<HandlerHttp<HTTP_MODE::REQUEST>>);
    EXPECT_FALSE(DerivedFromHandlerConnection<HandlerHttp3<>>);
    EXPECT_TRUE(DerivedFromHandlerDatagram<HandlerHttp3<>>);
    EXPECT_FALSE(DerivedFromHandlerConnection<HandlerDatagram>);
}

TEST(Constraints, HandlerBasesArePeersWithoutVirtualInheritance)
{
    // 双传输处理器同时继承两个并列的处理器基类。两者都不是虚基类：成员访问是
    // 编译期确定的直接偏移，不经过 vbase offset 表，也不产生虚基类共享子对象的
    // 构造/销毁记账。断言在此作为回归护栏：一旦有人把某个处理器基类改回
    // `virtual` 继承（共享根），布局与访问开销会静默回退，这里会立刻失败。
#if defined(__cpp_lib_is_virtual_base_of)
    static_assert(!std::is_virtual_base_of_v<HandlerConnection, CombinedHandler>);
    static_assert(!std::is_virtual_base_of_v<HandlerDatagram, CombinedHandler>);
#endif

    // 两个基类各自贡献完整的子对象（虚继承下它们会共享/折叠布局）。
    static_assert(sizeof(CombinedHandler) >= sizeof(HandlerConnection) + sizeof(HandlerDatagram));

    // 两个基类互不派生：流式与报文是并列层次，没有共同祖先
    static_assert(!std::derived_from<HandlerConnection, HandlerDatagram>);
    static_assert(!std::derived_from<HandlerDatagram, HandlerConnection>);

#if defined(__cpp_lib_is_virtual_base_of)
    EXPECT_FALSE((std::is_virtual_base_of_v<HandlerConnection, CombinedHandler>));
    EXPECT_FALSE((std::is_virtual_base_of_v<HandlerDatagram, CombinedHandler>));
#endif
}

TEST(Constraints, DerivedFromHandlerDatagramConstraints)
{
    static_assert(DerivedFromHandlerDatagram<HandlerDatagram>);
    static_assert(DerivedFromHandlerDatagram<CombinedHandler>);
    static_assert(HandlerConstraint<HandlerDatagram>);
    static_assert(HandlerConstraint<CombinedHandler>);
    static_assert(std::derived_from<CombinedHandler, HandlerConnection>);
    static_assert(MandatoryMethodConnection<CombinedHandler>);
    static_assert(Resettable<CombinedHandler>);
    static_assert(!DerivedFromHandlerDatagram<HandlerConnection>);
    static_assert(!DerivedFromHandlerDatagram<NonDerivedHandler>);

    EXPECT_TRUE(DerivedFromHandlerDatagram<HandlerDatagram>);
    EXPECT_TRUE(DerivedFromHandlerDatagram<CombinedHandler>);
    EXPECT_TRUE(HandlerConstraint<CombinedHandler>);
    EXPECT_TRUE(MandatoryMethodConnection<CombinedHandler>);
    EXPECT_FALSE(DerivedFromHandlerDatagram<HandlerConnection>);
}

TEST(Constraints, MandatoryMethodDatagramContractEnforcement)
{
    // 数据报侧的必需方法契约：与 MandatoryMethodConnection 对称的两层保证。
    static_assert(MandatoryMethodDatagram<HandlerDatagram>); // 概念只校验接口，不要求可实例化
    static_assert(MandatoryMethodDatagram<PureDatagramHandler>);
    static_assert(MandatoryMethodDatagram<CombinedHandler>);
    static_assert(MandatoryMethodDatagram<HandlerHttp3<>>);

    // 数据报路径不要求任何流式设施
    static_assert(!MandatoryMethodConnection<PureDatagramHandler>);
    static_assert(!MandatoryMethodConnection<HandlerDatagram>);

    // 派生但缺必需方法 → 被拒
    static_assert(!MandatoryMethodDatagram<MissingMaxDatagramBytesHandler>);
    static_assert(!MandatoryMethodDatagram<DeletedSendToHandler>);
    static_assert(!MandatoryMethodDatagram<DeletedTakeOutgoingHandler>);

    // 方法齐、可重置，但未派生 → 仍被拒（回复队列必须来自真实基类子对象）
    static_assert(!MandatoryMethodDatagram<DatagramContractWithoutDerivation>);

    // 流式处理器不是数据报处理器，反之亦然
    static_assert(!MandatoryMethodDatagram<HandlerConnection>);
    static_assert(!MandatoryMethodDatagram<NonDerivedHandler>);

    EXPECT_TRUE(MandatoryMethodDatagram<PureDatagramHandler>);
    EXPECT_TRUE(MandatoryMethodDatagram<CombinedHandler>);
    EXPECT_FALSE(MandatoryMethodDatagram<MissingMaxDatagramBytesHandler>);
    EXPECT_FALSE(MandatoryMethodDatagram<DeletedSendToHandler>);
    EXPECT_FALSE(MandatoryMethodDatagram<DeletedTakeOutgoingHandler>);
    EXPECT_FALSE(MandatoryMethodDatagram<DatagramContractWithoutDerivation>);
}

TEST(Constraints, AcceptorConceptsEvaluationOnCompleteTypes)
{
    using Acc = Acceptor<HandlerConnection>;
    using BaseAcc = AcceptorBase<HandlerConnection>;

    // 概念约束测试：DerivedFromAcceptor & DerivedFromAcceptorBase
    static_assert(DerivedFromAcceptor<Acc>);
    static_assert(DerivedFromAcceptorBase<BaseAcc>);
    static_assert(!DerivedFromAcceptor<HandlerConnection>);

    // 概念约束测试：BaseAcceptor
    static_assert(BaseAcceptor<Acc>);
    static_assert(BaseAcceptor<BaseAcc>);

    EXPECT_TRUE(DerivedFromAcceptor<Acc>);
    EXPECT_TRUE(BaseAcceptor<Acc>);
}

TEST(Constraints, DialerAndOutboundConceptsEvaluation)
{
    using Dial = Dialer<HandlerConnection>;
    using BaseDial = DialerBase<HandlerConnection>;

    // 概念约束测试：DerivedFromDialer & DerivedFromDialerBase
    static_assert(DerivedFromDialer<Dial>);
    static_assert(DerivedFromDialerBase<BaseDial>);
    static_assert(!DerivedFromDialer<HandlerConnection>);

    static_assert(BaseDialer<Dial>);
    static_assert(BaseDialer<BaseDial>);

    EXPECT_TRUE(DerivedFromDialer<Dial>);
    EXPECT_TRUE(BaseDialer<Dial>);

    // 出站协议处理器约束测试：全部满足 HandlerConstraint 与 MandatoryMethodConnection
    static_assert(HandlerConstraint<HandlerOutboundConnectionBase>);
    static_assert(MandatoryMethodConnection<HandlerOutboundConnectionBase>);

    static_assert(HandlerConstraint<HandlerOutboundDatagramBase>);
    static_assert(MandatoryMethodDatagram<HandlerOutboundDatagramBase>);

    static_assert(HandlerConstraint<HandlerInboundConnectionBase>);
    static_assert(MandatoryMethodConnection<HandlerInboundConnectionBase>);

    static_assert(HandlerConstraint<HandlerInboundDatagramBase>);
    static_assert(MandatoryMethodDatagram<HandlerInboundDatagramBase>);

    static_assert(HandlerConstraint<HandlerOutboundDirect>);
    static_assert(MandatoryMethodConnection<HandlerOutboundDirect>);

    static_assert(HandlerConstraint<HandlerOutboundTrojan>);
    static_assert(MandatoryMethodConnection<HandlerOutboundTrojan>);

    static_assert(HandlerConstraint<HandlerOutboundVless>);
    static_assert(MandatoryMethodConnection<HandlerOutboundVless>);

    static_assert(HandlerConstraint<HandlerOutboundSocks5>);
    static_assert(MandatoryMethodConnection<HandlerOutboundSocks5>);

    static_assert(HandlerConstraint<HandlerOutboundBlock>);
    static_assert(MandatoryMethodConnection<HandlerOutboundBlock>);

    static_assert(HandlerConstraint<HandlerOutboundHysteria2>);
    static_assert(MandatoryMethodConnection<HandlerOutboundHysteria2>);

    // DNS 协议处理器族约束测试
    static_assert(HandlerConstraint<HandlerInboundConnectionDns>);
    static_assert(MandatoryMethodConnection<HandlerInboundConnectionDns>);
    static_assert(HandlerConstraint<HandlerInboundDatagramDns>);
    static_assert(MandatoryMethodDatagram<HandlerInboundDatagramDns>);
    static_assert(HandlerConstraint<HandlerOutboundConnectionDns>);
    static_assert(MandatoryMethodConnection<HandlerOutboundConnectionDns>);
    static_assert(HandlerConstraint<HandlerOutboundDatagramDns>);
}

TEST(Constraints, AcceptorAndDialerPlaceholderZeroOverhead)
{
    // 测试 Acceptor 与 Dialer 的占位符在没有上下文时占 0 额外字节 (Zero Overhead)
    struct CustomAcceptor : Acceptor<EmptyInbound>
    {
    };
    struct CustomDialer : Dialer<EmptyOutbound>
    {
    };
    static_assert(DerivedFromAcceptor<CustomAcceptor>);
    static_assert(DerivedFromDialer<CustomDialer>);

    // Reactor 模板实例化与单/多 Acceptor 编译期调度
    Reactor<CustomAcceptor> singleReactor;
    Reactor<CustomAcceptor, Acceptor<EmptyInbound>> multiReactor;

    EXPECT_EQ(singleReactor.connections(), 0u);
    EXPECT_EQ(multiReactor.connections(), 0u);
}

TEST(Constraints, EveryRunOverloadIsInstantiable)
{
    const mynet::MynetConfig saved = mynet::getMynetConfig();
    mynet::MynetConfig poison = saved;
    poison.server.host = "256.256.256.256";
    poison.server.port = 1;
    mynet::publishMynetConfig(poison);

    mynet::Reactor<mynet::Acceptor<mynet::EmptyInbound>> reactor;

#if defined(MYNET_ENABLE_URING)
    mynet::Proactor<mynet::Acceptor<mynet::EmptyInbound>> proactor;
#endif

    [[maybe_unused]] auto r1 = reactor.runTcp("1.2.3.4", 0);
    [[maybe_unused]] auto r2 = reactor.runTcp();
    [[maybe_unused]] auto r3 = reactor.runUdp("1.2.3.4", 0);
    [[maybe_unused]] auto r4 = reactor.runUdp();

#if defined(MYNET_ENABLE_URING)
    [[maybe_unused]] auto r5 = proactor.runTcp("1.2.3.4", 0);
    [[maybe_unused]] auto r6 = proactor.runTcp();
    [[maybe_unused]] auto r7 = proactor.runUdp("1.2.3.4", 0);
    [[maybe_unused]] auto r8 = proactor.runUdp();
#endif

    mynet::publishMynetConfig(saved);
    SUCCEED();
}
