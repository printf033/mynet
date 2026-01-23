#pragma once

#include <concepts>

template <typename O>
concept mustResettable = requires(O obj) {{ obj.reset() } noexcept -> std::same_as<void>; };

// Handler

class Handler_base;

template <typename H>
concept mustDerivedFromHandlerBase = std::derived_from<H, Handler_base>;

template <typename H>
concept mustHandlerBase = std::same_as<H, Handler_base>;

enum class MODE_http
{
    REQUEST,
    RESPONSE
};

template <MODE_http M>
class Handler_http;

template <typename H, MODE_http M>
concept mustHandlerHTTP = std::same_as<H, Handler_http<M>>;

// Event

template <typename HandlerType>
    requires mustDerivedFromHandlerBase<HandlerType> && mustResettable<HandlerType>
struct Event_base;

template <typename E>
concept mustDerivedFromEventBase = requires { typename E::Handler; } && std::derived_from<E, Event_base<typename E::Handler>>;

template <typename E>
concept mustEventBase = requires { typename E::Handler; } && std::same_as<E, Event_base<typename E::Handler>>;

template <typename Handler>
    requires mustDerivedFromHandlerBase<Handler> && mustResettable<Handler>
struct Event_socket;

template <typename E>
concept mustEventSocket = requires { typename E::Handler; } && std::same_as<E, Event_socket<typename E::Handler>>;

template <typename>
struct Protocol
{
};

template <typename Handler>
    requires mustDerivedFromHandlerBase<Handler> && mustResettable<Handler>
struct Event_ssl;

template <typename E>
concept mustEventSSL = requires { typename E::Handler; } && std::same_as<E, Event_ssl<typename E::Handler>>;

#include <openssl/types.h>

template <typename H>
struct Protocol<Event_ssl<H>>
{
    SSL_CTX *ctx = nullptr;
};

