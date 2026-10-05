#pragma once

#include <concepts>
#include <cstdint>
#include <openssl/types.h>
#include <string>
#include <sys/types.h>

template <typename O>
concept mustResettable = requires(O obj) {{ obj.reset() } noexcept -> std::same_as<void>; };

// Buffer

class Buffer;

template <typename B>
concept mustBuffer = requires(B b, const char *p) {
    { b.readableBytes() } noexcept -> std::same_as<size_t>;
    { b.retrieveAll() } noexcept -> std::same_as<void>;
    { b.readableBegin() } noexcept -> std::same_as<const char *>;
    b.append(p, static_cast<ssize_t>(0));
};

// Handler

class HandlerBase;

template <typename H>
concept mustDerivedFromHandlerBase = std::derived_from<H, HandlerBase>;

template <typename H>
concept mustHandlerBase = std::same_as<H, HandlerBase>;

// The contract a protocol processor offers the event loop: take bytes in,
// hand finished responses out, and be resettable so a connection object can
// be recycled by the pool.
template <typename H>
concept mustHandleProtocol = mustDerivedFromHandlerBase<H> && mustResettable<H> && requires(H &h, const char *buf, ssize_t rn) {
    { h.appendRequest(buf, rn) } noexcept;
    { h.hasResponse() } noexcept -> std::same_as<bool>;
    { h.takeResponse() } -> std::same_as<std::string>;
    { h.requestOverLimit() } noexcept -> std::same_as<bool>;
    h.process();
};

enum class HttpMode : uint8_t
{
    request,
    response
};

template <HttpMode M>
class HandlerHttp;

template <typename H, HttpMode M>
concept mustHandlerHTTP = std::same_as<H, HandlerHttp<M>>;

// Datagram

class DatagramHandler;

template <typename D>
concept mustDerivedFromDatagramHandler = std::derived_from<D, DatagramHandler>;

// Event

template <typename HandlerType>
    requires mustDerivedFromHandlerBase<HandlerType> && mustResettable<HandlerType>
struct EventBase;

template <typename E>
concept mustDerivedFromEventBase = requires { typename E::Handler; } && std::derived_from<E, EventBase<typename E::Handler>>;

template <typename E>
concept mustEventBase = requires { typename E::Handler; } && std::same_as<E, EventBase<typename E::Handler>>;

template <typename Handler>
    requires mustDerivedFromHandlerBase<Handler> && mustResettable<Handler>
struct EventSocket;

template <typename E>
concept mustEventSocket = requires { typename E::Handler; } && std::same_as<E, EventSocket<typename E::Handler>>;

template <typename>
struct Protocol
{
};

template <typename Handler>
    requires mustDerivedFromHandlerBase<Handler> && mustResettable<Handler>
struct EventSsl;

template <typename E>
concept mustEventSSL = requires { typename E::Handler; } && std::same_as<E, EventSsl<typename E::Handler>>;

template <typename H>
struct Protocol<EventSsl<H>>
{
    SSL_CTX *ctx = nullptr;
};

// Connection

template <typename HandlerType>
    requires mustHandleProtocol<HandlerType>
class Connection;

template <typename C>
concept mustConnection = requires { typename C::Handler; } && std::same_as<C, Connection<typename C::Handler>>;
