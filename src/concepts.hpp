#pragma once

#include "error.hpp"
#include <concepts>
#include <cstdint>
#include <string>
#include <sys/types.h>

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

    // 前向声明
    class HandlerBase;
    class DatagramHandler;

    /**
     * @brief 协议处理器基类派生约束
     */
    template <typename H>
    concept DerivedFromHandlerBase = std::derived_from<H, HandlerBase>;

    /**
     * @brief 协议处理器契约概念
     *
     * 规定连接所持有的协议处理器必须具备：摄入字节流、生成响应、支持背压上限检测，
     * 以及支持重置以便对象池安全复用。
     */
    template <typename H>
    concept ProtocolHandler =
        DerivedFromHandlerBase<H> && Resettable<H> && requires(H &h, const char *buf, ssize_t rn) {
            // 零异常纪律：摄入路径 noexcept，扩容失败经错误码交付
            { h.appendRequest(buf, rn) } noexcept -> std::same_as<Result<>>;
            { h.hasResponse() } noexcept -> std::same_as<bool>;
            { h.takeResponse() } -> std::same_as<std::string>;
            { h.requestOverLimit() } noexcept -> std::same_as<bool>;
            h.process();
        };

    /**
     * @brief UDP 数据报处理器派生约束
     */
    template <typename D>
    concept DerivedFromDatagramHandler = std::derived_from<D, DatagramHandler>;

} // namespace mynet
