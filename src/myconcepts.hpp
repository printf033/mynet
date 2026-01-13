#pragma once

#include <concepts>
#include <vector>
#include <sys/types.h>
#include "transporter.hpp"

template <typename O>
concept mustResettable = requires(O obj) {{ obj.reset() } noexcept -> std::same_as<void>; };

template <typename T>
concept mustDerivedFromTransporter = std::derived_from<T, Transporter_base>;

template <typename T>
concept mustTransporter = std::same_as<T, Transporter_base>;

template <typename P>
struct ProtocolMember
{
};

template <typename T>
concept mustTransporterSSL = std::same_as<T, Transporter_ssl>;

template <>
struct ProtocolMember<Transporter_ssl>
{
    SSL_CTX *ctx = nullptr;
};

class Handler_base;

template <typename H>
concept mustDerivedFromHandler = std::derived_from<H, Handler_base>;

template <typename H>
concept mustHandler = std::same_as<H, Handler_base>;

enum class Mode_http
{
    REQUEST,
    RESPONSE
};

template <Mode_http M>
class Handler_llhttp;

template <typename H, Mode_http M>
concept mustHandlerHTTP = std::same_as<H, Handler_llhttp<M>>;
