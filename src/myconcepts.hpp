#pragma once

#include <concepts>
#include <utility>
#include <sys/types.h>

template <typename P, typename... A, typename... B, typename... C>
concept mustPeer = requires(P peer, A &&...a, B &&...b, C &&...c) {
    { peer.listen(std::forward<A>(a)...) } -> std::same_as<int>;
    { peer.recv(std::forward<B>(b)...) } -> std::same_as<ssize_t>;
    { peer.send(std::forward<C>(c)...) } -> std::same_as<ssize_t>;
};

class Peer_tcp;
template <typename P>
concept mustPeerTcp = std::same_as<P, Peer_tcp>;

class Peer_tls;
template <typename P>
concept mustPeerTls = std::same_as<P, Peer_tls>;

template <typename P>
concept mustTrustedPeer = mustPeerTcp<P> || mustPeerTls<P>;

template <typename O>
concept mustResettable = requires(O obj) {
    { obj.reset() } noexcept -> std::same_as<void>;
};

class Handler_base;
template <typename H>
concept mustHandler = std::derived_from<H, Handler_base>;

enum class Mode_http
{
    REQUEST,
    RESPONSE
};
template <Mode_http M>
concept validModeHttp = (M == Mode_http::REQUEST || M == Mode_http::RESPONSE);
