#pragma once

/**
 * @file http/v2/handler.hpp
 * @brief HTTP/2 协议处理器入口，包含分帧、流表与基于信用的流多路复用器。
 */

#include "frame.hpp"
#include "multiplexer.hpp"
#include "streamTable.hpp"

namespace mynet
{
    namespace http::v2
    {
        using ::mynet::Frame;
        using ::mynet::FRAME_ERROR;
        using ::mynet::FRAME_TYPE;
        using ::mynet::FrameDecoder;
        using ::mynet::STREAM_ERROR;
        namespace FrameFlags = ::mynet::FrameFlags;

        template <typename StreamHandler = HandlerBase>
        using HandlerHttp2 = ::mynet::Multiplexer<StreamHandler>;

        template <typename StreamHandler = HandlerBase>
        using Multiplexer = ::mynet::Multiplexer<StreamHandler>;
    } // namespace http::v2

    template <typename StreamHandler = HandlerBase>
    using HandlerHttp2 = http::v2::HandlerHttp2<StreamHandler>;

} // namespace mynet
