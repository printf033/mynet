#pragma once

#include <concepts>

namespace mynet
{

    /**
     * @brief 可重置对象约束概念
     *
     * 约束对象必须提供 noexcept 的 reset() 方法，以支持对象池的高性能回收重用。
     */
    template <typename O>
    concept Resettable = requires(O obj) {
        { obj.reset() } noexcept -> std::same_as<void>;
    };

    /**
     * @brief 处理器基础约束（传输无关）
     *
     * 只收拢所有处理器共有、且不牵涉协议语义的那几项：可重置、可析构，以及一条
     * 消息处理完成与一次解析失败两个钩子。原 HandlerBase 的接口契约在此以概念形式
     * 保留——删除公共根类之后，HandlerConnection（流式）与 HandlerDatagram（报文）
     * 是两个并列的独立基类，事件层只依赖这份最小约束，不必为了一个共同根引入额外
     * 继承层级。
     *
     * 引擎真正需要的强约束（必须派生自真实基类子对象）由各自的
     * MandatoryMethodConnection / MandatoryMethodDatagram 给出。
     */
    template <typename H>
    concept HandlerConstraint = Resettable<H> && std::destructible<H> &&
                                requires(H &h, const char *reason) {
                                    { h.onMessageComplete() } noexcept;
                                    { h.onParseError(reason) } noexcept;
                                };

    // 基类与其派生约束分散在各自头文件：HandlerConnection / HandlerDatagram 及
    // 其概念在 connection.hpp、datagram.hpp，EventBase 及其概念在 event.hpp。
    // 传输无关的通用契约集中在本文件，避免事件层反向依赖具体传输。

} // namespace mynet
