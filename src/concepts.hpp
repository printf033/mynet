#pragma once

#include <concepts>
#include "peer.hpp"

template <typename Peer>
concept is_tcp = std::is_same_v<Peer, Peer_tcp>;
template <typename Peer>
concept is_tls = std::is_same_v<Peer, Peer_tls>;
template <typename Obj>
concept Resettable = requires(Obj obj) {{ obj.reset() } noexcept -> std::same_as<void>; };