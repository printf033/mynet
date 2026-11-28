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

    struct SniffProtoA
    {
        static constexpr TransportType transport = TransportType::TCP;
        static constexpr uint16_t default_port = 443;
    };

    struct SniffProtoB
    {
        static constexpr TransportType transport = TransportType::TCP;
        static constexpr uint16_t default_port = 443;
    };

    struct ProtoHttp
    {
        static constexpr TransportType transport = TransportType::TCP;
        static constexpr uint16_t default_port = 80;
    };

    struct ProtoHttps
    {
        static constexpr TransportType transport = TransportType::TCP;
        static constexpr uint16_t default_port = 443;
    };

    struct ProtoDns
    {
        static constexpr TransportType transport = TransportType::UDP;
        static constexpr uint16_t default_port = 53;
    };

    /// 正例：派生自 HandlerConnection，只重写 handle() 表达业务定制。
    struct FakeHandler : public Handler
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

    struct ThrowingAppendHandler : public Handler
    {
        // 历史语义：appendRequest 曾允许抛出 bad_alloc，现被 MandatoryMethodConnection
        // 约束拒绝——非 noexcept、非 Result<> 返回的摄入路径不再是合法协议头。
        void appendRequest(const char *, ssize_t) {}
    };

    struct DeletedHandleHandler
    {
        void handle() = delete;
    };

    struct DeletedTakeResponseHandler : public Handler
    {
        std::string takeResponse() = delete;
    };

    struct DeletedPushResponseHandler : public Handler
    {
        Result<> pushResponse(std::string &&) = delete;
    };

    struct DeletedPrepareRequestWritableHandler : public Handler
    {
        std::expected<char *, ERR> prepareRequestWritable(size_t) = delete;
    };

    /// 双特化组合：统一 HandlerBase 兼具流式与数据报双模能力
    struct CombinedHandler : Handler
    {
        void reset() noexcept override { Handler::reset(); }
        void onMessageComplete() noexcept override { Handler::onMessageComplete(); }
        void onParseError(const char *reason) noexcept override { Handler::onParseError(reason); }
        void onDatagram(const sockaddr_in &, const char *, size_t) noexcept override {}
    };

    /// 纯报文处理器：只派生报文特化，不具备任何流式设施。
    struct PureDatagramHandler : Handler
    {
        void onDatagram(const sockaddr_in &, const char *, size_t) noexcept override {}
    };

    /// 反例：已派生报文特化，但引擎经处理器类型直接读取的接收上界缺失。
    struct MissingMaxDatagramBytesHandler : Handler
    {
        void onDatagram(const sockaddr_in &, const char *, size_t) noexcept override {}
        size_t maxDatagramBytes() = delete;
    };

    struct DeletedSendToHandler : Handler
    {
        void sendTo(const sockaddr_in &, const char *, size_t) = delete;
    };

    struct DeletedTakeOutgoingHandler : Handler
    {
        Packet takeOutgoing() = delete;
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
        const Packet &peekOutgoing() noexcept
        {
            static Packet p;
            return p;
        }
        Packet takeOutgoing() { return {}; }
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

    template <typename E>
    concept HasLoopParity =
        requires(E &e, int fd, uint32_t ev, std::function<void(uint32_t)> watchCb, std::function<void()> task,
                 std::chrono::milliseconds ms) {
            { e.loop().addWatch(fd, ev, watchCb) } -> std::same_as<bool>;
            { e.loop().modWatch(fd, ev) } -> std::same_as<bool>;
            e.loop().delWatch(fd);
            e.loop().runInLoop(task);
            e.loop().queueInLoop(task);
            e.loop().runAfter(ms, task);
            e.loop().runEvery(ms, task);
            e.loop().cancelTimer(uint64_t{1});
            e.stop();
        };

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
    static_assert(Resettable<Handler>);
    static_assert(Resettable<Handler>);
    static_assert(Resettable<AcceptorBase<Handler>>);
    static_assert(Resettable<DialerBase<Handler>>);
    static_assert(Resettable<HandlerInbound>);
    static_assert(Resettable<HandlerInbound>);
    static_assert(Resettable<HandlerOutbound>);
    static_assert(Resettable<HandlerOutbound>);
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
    static_assert(HandlerConstraint<Handler>);
    static_assert(HandlerConstraint<Handler>);
    static_assert(HandlerConstraint<FakeHandler>);
    static_assert(HandlerConstraint<HandlerHttp<HTTP_MODE::REQUEST>>);
    static_assert(HandlerConstraint<HandlerHttp3<>>);

    // 反例：缺 onMessageComplete / onParseError 钩子，或不可重置
    static_assert(!HandlerConstraint<ValidResettable>); // 只有 reset()
    static_assert(!HandlerConstraint<NonDerivedHandler>);
    static_assert(!HandlerConstraint<NoReset>);
    static_assert(!HandlerConstraint<int>);

    EXPECT_TRUE(HandlerConstraint<Handler>);
    EXPECT_TRUE(HandlerConstraint<Handler>);
    EXPECT_TRUE(HandlerConstraint<HandlerHttp3<>>);
    EXPECT_FALSE(HandlerConstraint<ValidResettable>);
    EXPECT_FALSE(HandlerConstraint<NonDerivedHandler>);
}

TEST(Constraints, MandatoryMethodConnectionContractEnforcement)
{
    // 报文基类不承诺字节流契约；流式契约只由 HandlerConnection 提供
    static_assert(MandatoryMethodConnection<Handler>);
    static_assert(MandatoryMethodConnection<Handler>);
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
    static_assert(!MandatoryMethodConnection<NonDerivedHandler>);
    static_assert(!MandatoryMethodConnection<NoReset>);

    EXPECT_TRUE(MandatoryMethodConnection<Handler>);
    EXPECT_TRUE(MandatoryMethodConnection<Handler>);
    EXPECT_FALSE(MandatoryMethodConnection<FullContractWithoutDerivation>);
    EXPECT_FALSE(MandatoryMethodConnection<LegacySixMemberHandler>);
    EXPECT_FALSE(MandatoryMethodConnection<ThrowingAppendHandler>);
    EXPECT_FALSE(MandatoryMethodConnection<DeletedHandleHandler>);
    EXPECT_FALSE(MandatoryMethodConnection<DeletedTakeResponseHandler>);
    EXPECT_FALSE(MandatoryMethodConnection<DeletedPushResponseHandler>);
    EXPECT_FALSE(MandatoryMethodConnection<DeletedPrepareRequestWritableHandler>);
    EXPECT_FALSE(MandatoryMethodConnection<NonDerivedHandler>);
}

TEST(Constraints, DerivedFromHandlerConnectionConstraints)
{
    static_assert(DerivedFromHandlerConnection<Handler>);
    static_assert(DerivedFromHandlerConnection<HandlerHttp<HTTP_MODE::REQUEST>>);
    static_assert(DerivedFromHandlerConnection<CombinedHandler>);
    static_assert(DerivedFromHandlerConnection<HandlerHttp3<>>);
    static_assert(DerivedFromHandlerDatagram<HandlerHttp3<>>);
    static_assert(HandlerConstraint<Handler>);
    static_assert(HandlerConstraint<HandlerHttp3<>>);

    static_assert(!DerivedFromHandlerConnection<NonDerivedHandler>);

    EXPECT_TRUE(DerivedFromHandlerConnection<HandlerHttp<HTTP_MODE::REQUEST>>);
    EXPECT_TRUE(DerivedFromHandlerConnection<HandlerHttp3<>>);
    EXPECT_TRUE(DerivedFromHandlerDatagram<HandlerHttp3<>>);
    EXPECT_FALSE(DerivedFromHandlerConnection<NonDerivedHandler>);
}

TEST(Constraints, HandlerBaseIsUnifiedWithoutVirtualInheritance)
{
#if defined(__cpp_lib_is_virtual_base_of)
    static_assert(!std::is_virtual_base_of_v<Handler, CombinedHandler>);
#endif

    static_assert(std::same_as<Handler, Handler>);
    static_assert(std::same_as<Handler, Handler>);
    static_assert(HandlerConstraint<Handler>);
    static_assert(MandatoryMethodConnection<Handler>);
    static_assert(MandatoryMethodDatagram<Handler>);
}

TEST(Constraints, DerivedFromHandlerDatagramConstraints)
{
    static_assert(DerivedFromHandlerDatagram<Handler>);
    static_assert(DerivedFromHandlerDatagram<CombinedHandler>);
    static_assert(HandlerConstraint<Handler>);
    static_assert(HandlerConstraint<CombinedHandler>);
    static_assert(std::derived_from<CombinedHandler, Handler>);
    static_assert(MandatoryMethodConnection<CombinedHandler>);
    static_assert(Resettable<CombinedHandler>);
    static_assert(!DerivedFromHandlerDatagram<NonDerivedHandler>);

    EXPECT_TRUE(DerivedFromHandlerDatagram<Handler>);
    EXPECT_TRUE(DerivedFromHandlerDatagram<CombinedHandler>);
    EXPECT_TRUE(HandlerConstraint<CombinedHandler>);
    EXPECT_TRUE(MandatoryMethodConnection<CombinedHandler>);
}

TEST(Constraints, MandatoryMethodDatagramContractEnforcement)
{
    // 数据报侧的必需方法契约：与 MandatoryMethodConnection 对称的两层保证。
    static_assert(MandatoryMethodDatagram<Handler>); // 概念只校验接口，不要求可实例化
    static_assert(MandatoryMethodDatagram<PureDatagramHandler>);
    static_assert(MandatoryMethodDatagram<CombinedHandler>);
    static_assert(MandatoryMethodDatagram<HandlerHttp3<>>);

    // 统一 HandlerBase 兼具流式与数据报双模能力
    static_assert(MandatoryMethodConnection<PureDatagramHandler>);
    static_assert(MandatoryMethodConnection<Handler>);

    // 派生但缺必需方法 → 被拒
    static_assert(!MandatoryMethodDatagram<MissingMaxDatagramBytesHandler>);
    static_assert(!MandatoryMethodDatagram<DeletedSendToHandler>);
    static_assert(!MandatoryMethodDatagram<DeletedTakeOutgoingHandler>);

    // 方法齐、可重置，但未派生 → 仍被拒（回复队列必须来自真实基类子对象）
    static_assert(!MandatoryMethodDatagram<DatagramContractWithoutDerivation>);

    // 流式处理器不是数据报处理器，反之亦然
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
    using Acc = AcceptorBase<Handler>;
    using BaseAcc = Acceptor;

    static_assert(DerivedFromAcceptor<Acc>);
    static_assert(DerivedFromAcceptor<BaseAcc>);
    static_assert(!DerivedFromAcceptor<Handler>);

    EXPECT_TRUE(DerivedFromAcceptor<Acc>);
}

TEST(Constraints, DialerAndOutboundConceptsEvaluation)
{
    using Dial = DialerBase<Handler>;
    using BaseDial = Dialer;

    // 概念约束测试：DerivedFromDialer & DerivedFromDialerBase
    static_assert(DerivedFromDialer<Dial>);
    static_assert(DerivedFromDialer<BaseDial>);
    static_assert(DerivedFromDialerBase<BaseDial>);
    static_assert(!DerivedFromDialer<Handler>);

    static_assert(BaseDialer<Dial>);
    static_assert(BaseDialer<BaseDial>);

    EXPECT_TRUE(DerivedFromDialer<Dial>);
    EXPECT_TRUE(BaseDialer<Dial>);

    // 出站协议处理器约束测试：全部满足 HandlerConstraint 与 MandatoryMethodConnection
    static_assert(HandlerConstraint<HandlerOutbound>);
    static_assert(MandatoryMethodConnection<HandlerOutbound>);

    static_assert(HandlerConstraint<HandlerOutbound>);
    static_assert(MandatoryMethodDatagram<HandlerOutbound>);

    static_assert(HandlerConstraint<HandlerInbound>);
    static_assert(MandatoryMethodConnection<HandlerInbound>);

    static_assert(HandlerConstraint<HandlerInbound>);
    static_assert(MandatoryMethodDatagram<HandlerInbound>);

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
    struct CustomAcceptor : AcceptorBase<EmptyInbound>
    {
    };
    struct CustomDialer : DialerBase<EmptyOutbound>
    {
    };
    static_assert(DerivedFromAcceptor<CustomAcceptor>);
    static_assert(DerivedFromDialer<CustomDialer>);

    // 纯 TCP 反应器：自动推导推算出 1 个 TCP 监听器
    using PureTcpReactor = Reactor<AcceptorBase<ProtoHttp>>;
    static_assert(PureTcpReactor::kListenerCount == 1);
    static_assert(PureTcpReactor::kHasTcp);
    static_assert(!PureTcpReactor::kHasUdp);

    using BaseReactor = Reactor<AcceptorBase<Handler>>;
    static_assert(BaseReactor::kListenerCount == 1);
    static_assert(BaseReactor::kHasTcp);
    static_assert(!BaseReactor::kHasUdp);

    // 纯 UDP 反应器：自动推导推算出 1 个 UDP 监听器
    using PureUdpReactor = Reactor<AcceptorBase<ProtoDns>>;
    static_assert(PureUdpReactor::kListenerCount == 1);
    static_assert(!PureUdpReactor::kHasTcp);
    static_assert(PureUdpReactor::kHasUdp);

    // 双传输反应器：自动推导推算出 2 个监听器 (1 个 TCP + 1 个 UDP)
    using DualReactor = Reactor<AcceptorBase<ProtoHttp>, AcceptorBase<ProtoDns>>;
    static_assert(DualReactor::kListenerCount == 2);
    static_assert(DualReactor::kHasTcp);
    static_assert(DualReactor::kHasUdp);

    // 多协议共享端口嗅探场景：2 个 Acceptor 共享 443 端口 -> 自动推导合并为 1 个 Listener (<= Acceptor 数量)
    using SniffReactor = Reactor<AcceptorBase<SniffProtoA>, AcceptorBase<SniffProtoB>>;
    static_assert(SniffReactor::kProtocolCount == 2);
    static_assert(SniffReactor::kListenerCount == 1); // 2 Acceptors -> 1 Listener!

    // 多协议不同端口场景：HTTP(80) + HTTPS(443) + DNS(53) -> 自动推导分配 3 个 Listener
    using MultiPortReactor = Reactor<AcceptorBase<ProtoHttp>, AcceptorBase<ProtoHttps>, AcceptorBase<ProtoDns>>;
    static_assert(MultiPortReactor::kProtocolCount == 3);
    static_assert(MultiPortReactor::kListenerCount == 3);
    static_assert(MultiPortReactor::kListenerConfigs[0].defaultPort == 80);
    static_assert(MultiPortReactor::kListenerConfigs[1].defaultPort == 443);
    static_assert(MultiPortReactor::kListenerConfigs[2].defaultPort == 53);

    // 实例运行与容量检查
    Reactor<CustomAcceptor> singleReactor;
    Reactor<CustomAcceptor, AcceptorBase<EmptyInbound>> multiReactor;

    EXPECT_EQ(singleReactor.connections(), 0u);
    EXPECT_EQ(multiReactor.connections(), 0u);
    EXPECT_GE(singleReactor.listenerCapacity(), 1u);
    EXPECT_EQ(singleReactor.listenerCount(), 0u);
}

TEST(Constraints, EveryRunOverloadIsInstantiable)
{
    const mynet::MynetConfig saved = mynet::getMynetConfig();
    mynet::MynetConfig poison = saved;
    poison.server.host = "256.256.256.256";
    poison.server.port = 1;
    mynet::publishMynetConfig(poison);

    mynet::Reactor<mynet::AcceptorBase<mynet::EmptyInbound>> reactor;

#if defined(MYNET_ENABLE_URING)
    mynet::Proactor<mynet::AcceptorBase<mynet::EmptyInbound>> proactor;
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

TEST(Constraints, ReactorAndProactorLoopParity)
{
    static_assert(CanRunTcp<Reactor<AcceptorBase<EmptyInbound>>>);
    static_assert(HasLoopParity<Reactor<AcceptorBase<EmptyInbound>>>);
    EXPECT_TRUE((HasLoopParity<Reactor<AcceptorBase<EmptyInbound>>>));

#if defined(MYNET_ENABLE_URING)
    static_assert(CanRunTcp<Proactor<AcceptorBase<EmptyInbound>>>);
    static_assert(HasLoopParity<Proactor<AcceptorBase<EmptyInbound>>>);
    static_assert(requires(Proactor<AcceptorBase<EmptyInbound>> &p, ForwarderLoopHooks &h, const sockaddr_in &sin,
                           std::function<void(int)> cb) {
        p.loop().attachForwarderHooks(h);
        p.asyncConnect(1, sin, cb);
    });
    EXPECT_TRUE((HasLoopParity<Proactor<AcceptorBase<EmptyInbound>>>));
#endif
}
