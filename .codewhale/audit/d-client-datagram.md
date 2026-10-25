# 审查报告：src/client.hpp 与 src/datagram.hpp（第二轮 D 组）

- 审查人：C++26 焛络库资深审查员（子代理 d）
- 日期：2026-10-22
- 范围：仅 `src/client.hpp`（789 行）、`src/datagram.hpp`（140 行），只读
- 基线：错误语义 `Result<T> = std::expected<T, ERR>`；参数校验走 `contract_assert`；`= delete("reason")` 带原因；noexcept 纪律；中文 Doxygen
- 编译实证：`g++ (GCC) 16.2.1 20260810`，`g++ -std=c++26 -freflection -I src -I thirdparty/mylog/src -fsyntax-only src/client.hpp src/datagram.hpp` 均通过（EXIT=0，仅 pragma-once 主文件警告）。注：仓库标准命令 `-I src` 缺 `reflection.hpp`/`logger.hpp` 路径（需 `-I thirdparty/mylog/src`）与 `-freflection`。
- 探针：`/tmp/audit-d.*`（tmpfs 沙箱会话隔离，已随会话销毁；源码与结论摘录如下）

---

## 发现

### [HIGH] src/client.hpp:657-659 — UDP 单向发送场景客户端永久挂起

**缺陷**：`updateInterest()` 退出条件 `udpAnswered = type_ == SOCK_DGRAM && stdinEof_ && backlog() == 0 && recvTotal_ > 0 && toOutOffset_ == toOut_.size()` 要求 `recvTotal_ > 0`。UDP 无连接、无 FIN：当调用方发送请求但对端不回包（服务器宕机、丢包、fire-and-forget）时，`recvTotal_` 永远为 0，`udpAnswered` 永假，而 `peerEof_`（依赖 EPOLLHUP/EOF）对 UDP 同样永假——循环无任何退出路径，`runUdp()` 永不返回。

**调用方证据**：`runUdp` 是公共 API（samples/client_udp.cpp:40 `Client<EventSocket<HandlerBase>>().runUdp(ip, port)`）。探针实证：绑定 127.0.0.1 的 UDP sink（只收不回）+ `printf 'one-way' | client`，stdin EOF、backlog=0、sent>0、received=0，客户端在 `timeout 6` 下退出码 **124（挂起）**。对照探针：同一 client 对 echo 服务器（received=4, sent=4）`elapsed=0ms` 正常退出，证明缺陷仅在 `recvTotal_==0` 路径。TCP 对照（sink accept 后不关）同样挂起，但那是正确 TCP 语义（等待对端 FIN/响应）；UDP 无此信号，挂起是纯缺陷。

**建议修法**：UDP 分支去掉 `recvTotal_ > 0` 约束——`type_ == SOCK_DGRAM && stdinEof_ && backlog() == 0 && toOutOffset_ == toOut_.size()` 即退出；或区分"已发完即完成"（UDP 请求-响应语义由调用方 `stop()` 决定）并在 Doxygen 明确 UDP 退出语义（中文）。

### [MEDIUM] src/client.hpp:683-692, 560-563 — connected-UDP 的异步错误被吞，返回成功

**缺陷**：UDP 套接字已 `connect()`（client.hpp:107），对端端口未监听时内核回 ICMP 不可达，后续 `recv` 报 `ECONNREFUSED`。`readSome()` 中 `ECONNREFUSED` 不匹配 `EINTR/EAGAIN/EWOULDBLOCK`，落入 `FATAL`；`drainPeer()` 把 `FATAL` 折叠为 `peerEof_ = true`（client.hpp:502-505），`failReason_` 不设置，`updateInterest()` 满足退出条件后 `runLoop()` 因 `reason` 为空而**返回 `{}`（成功）**。同理 `writeSome()` 中 UDP 的 `ECONNREFUSED` 不匹配 `ECONNRESET/EPIPE` 判定（client.hpp:727-729）也归为 `FATAL` → 静默成功。

**调用方证据**：samples/client_udp.cpp:40-43 以 `!res` 判断失败并 `toExitCode(res.error())`——发送到不可达端口的失败对调用方完全不可见。代码路径推演基于 client.hpp:492-508（drainPeer）、703-724（readSome）、345-352（runLoop 返回逻辑）。

**建议修法**：`readSome`/`writeSome` 为 UDP（`type_ == SOCK_DGRAM`）增加 `ECONNREFUSED` → `IO_END::FATAL` 显式分支，并在 `drainPeer`/`flushToPeer` 的 FATAL 路径设置 `failReason_ = ERR::CONNECT_FAILED`（或新增 `ERR::UDP_UNREACHABLE`，符合"每个失败场景唯一命名"的 error.hpp 基线），使 `runUdp` 返回 `std::unexpected`。

### [MEDIUM] src/client.hpp:252-259 — peerText() 使用线程不安全的 inet_ntoa，且与 datagramPeerText 重复实现

**缺陷**：`peerText()` 用 `::inet_ntoa(addr_.sin_addr)`——返回线程级静态缓冲，非线程安全（man inet_ntoa: "The string is returned in a statically allocated buffer, which subsequent calls will overwrite"）。本库支持跨线程 `stop()`（client.hpp:186），虽 `peerText` 目前仅在 loop 线程日志路径调用（:457, :478），但这是埋雷；同时与 `datagramPeerText()`（datagram.hpp:30-51，`inet_ntop` 实现）形成两份平行的地址格式化实现，违背复用一致性。

**调用方证据**：仅内部日志使用（client.hpp:457、478）；`datagramPeerText` 被 samples/udp_echo.hpp:31 与 proactor.hpp:453,459,489 广泛使用，证明库已有标准实现。

**建议修法**：删除 `peerText()`，内部直接复用 `datagramPeerText(addr_)`（`datagram.hpp` 已是 header-only 公共设施），或改写为 `inet_ntop` 实现并标 `[[nodiscard]]`。

### [MEDIUM] src/client.hpp:551-566 — SSL 半关闭在 SSL_shutdown()==0 时提前放弃，close_notify 可能未发完

**缺陷**：`halfClosePeer()` 只处理 `SSL_shutdown() < 0`（WANT_READ/WANT_WRITE 时保持 `pendingShutdown_` 重试）。按 OpenSSL 语义，返回 0 表示 shutdown 流程"未完成"（close_notify 已发送/发送中但未收到对端 close_notify），此时代码直接 `pendingShutdown_ = false; return;`——若 close_notify 尚在 TLS 记录层缓冲未 flush，后续不再有重试机会（`updateInterest` 的 `pendingShutdown_` 条件消失），TLS 终止序列不完整，部分对端会记录截断告警。

**调用方证据**：`runSsl` 公共 API（samples/client_ssl.cpp:52）；`pendingShutdown_` 状态机仅此一处驱动（client.hpp:541-543, 561, 568）。

**建议修法**：`e == 0` 时同样保留 `pendingShutdown_ = true` 依赖 EPOLLOUT 继续驱动 `SSL_shutdown`，或明确文档化（中文）"客户端只做单向半关闭、不等待对端 close_notify"的设计取舍。

### [MEDIUM] src/datagram.hpp:86-92 — pushReply(const char*, size_t) 对 buf==nullptr && n>0 静默降级为空报文，缺 contract_assert

**缺陷**：`replies_.push_back(DatagramReply{peer, (buf != nullptr && n > 0) ? std::string(buf, n) : std::string()})`——`buf == nullptr` 且 `n > 0` 时不校验而是静默入队空载荷，把调用方编程错误变成难查的"对端收到空包"。error.hpp:20 明确"参数校验（如空指针……）通过 C++26 contract_assert 契约处理"。

**调用方证据**：proactor.hpp:475-489 为消费侧；生产侧公共 API（samples/udp_echo.hpp:32 `pushReply(peer, data, n)` 传入 recvfrom 缓冲）。当前仓库无 nullptr 传入点，但 API 可达且静默降级违背基线。

**建议修法**：`contract_assert(buf != nullptr || n == 0);`（或对 `buf == nullptr && n > 0` 直接契约终止），与 `Client::runTcp` 的 `contract_assert(ip != nullptr)` 风格对齐。

### [MEDIUM] src/datagram.hpp:126-133 — setMaxPendingReplies(0)/setMaxDatagramBytes(0) 无契约校验，语义为"永久丢弃一切"

**缺陷**：两个 setter 均无下限校验。探针实证：`p.setMaxPendingReplies(0); p.pushReply(a, "hi", 2);` 输出 `count=0 dropped=1 hasReply=0`（日志 `reply queue full (0 pending), dropping a 2 byte reply`）——上限 0 等于永久丢弃所有回复，且 `setMaxDatagramBytes(0)` 会被 proactor.hpp:448 `datagram_->maxDatagramBytes()` 用于接收缓冲决策。参数校验按基线应走 `contract_assert`。

**调用方证据**：proactor.hpp:448-459 直接消费 `maxDatagramBytes()`；setter 为公共 API，当前 samples 未调用但类型层面可达。

**建议修法**：`contract_assert(n > 0)`（与 `runTcp` 的 `contract_assert(bufSize > 0)` 对齐）；如需"禁用回复"语义应显式设计而非借 0 值。

### [LOW] src/client.hpp:475-484 — TLS 握手失败复用 ERR::CONNECT_FAILED，错误粒度损失

**缺陷**：`SSL_connect` 失败映射 `ERR::CONNECT_FAILED`，与 TCP connect 失败（:456-459）无法区分；error.hpp 枚举有 `SSL_CTX_FAILED/SSL_NEW_FAILED/...` 但缺握手失败专用项，与"每个可能导致 OpenSSL 失败的场景在此具有唯一命名"的自述（error.hpp:14）不符。

**调用方证据**：samples/client_ssl.cpp:52 统一打印 `toString(res.error())`，用户将看到 "connect() failed" 而实为握手失败。

**建议修法**：新增 `ERR::SSL_HANDSHAKE_FAILED` 枚举与描述表项（注意同步 `kErrCount`/`kErrDescriptions` static_assert），失败路径改用之。

### [LOW] src/client.hpp:1-789 — Doxygen 全英文，违背"中文 Doxygen"架构基线

**缺陷**：文件头（:3-4）、类注释（:32-34）、`runTcp`（:62-67）、`stop`（:184）、`reset`（:192）等全部英文注释；对照 `datagram.hpp`（全中文）与 error.hpp/event.hpp（中文）不一致。

**调用方证据**：纯一致性发现；与第一轮 buffer.hpp 基线核对标准冲突。

**建议修法**：统一翻译为中文 Doxygen（@brief/@param/@return），技术名词保留英文。

### [LOW] src/client.hpp:64-66 — runTcp Doxygen "@return nullopt on success" 已过时

**缺陷**：文档描述旧式 `std::optional<ERR>` 语义，实际返回 `Result<>`（`std::expected<void, ERR>`）——恰是 error.hpp:100-103 注释中声明要"消除"的历史模型，文档与实现脱节。

**调用方证据**：samples/client_tcp.cpp:40 以 `!res` + `res.error()` 消费。

**建议修法**：改为 "@return Result<> 成功返回 {}，失败返回 std::unexpected(ERR::...)"，与 runUdp/runSsl 保持一致。

### [LOW] src/datagram.hpp:110 — takeReply() 缺 [[nodiscard]]，静默丢头部报文

**缺陷**：`takeReply()` 弹出并返回队列头部报文，但未标 `[[nodiscard]]`（同组 `hasReply/peekReply/replyCount/droppedReplies` 均有标注）。`datagram_->takeReply();`（丢弃返回值即丢弃一条待发报文）无编译警告。

**调用方证据**：proactor.hpp:477 `DatagramReply reply = datagram_->takeReply();` 正常消费；探针中 `p.takeReply();` 编译零警告（-Wall -Wextra）确认缺口。

**建议修法**：补 `[[nodiscard]]`；无参版本可另考虑 `popReply()` 显式丢弃语义。

### [LOW] src/datagram.hpp:86-101 — pushReply 可抛 bad_alloc，异常逃逸出 void 接口，与 Result 错误语义不完全一致

**缺陷**：`std::string(buf, n)` / `replies_.push_back` 可能抛 `bad_alloc`，经 `onDatagram` 实现方传播至 loop 回调链，未被转为 `Result`；error.hpp 专门设有 `POOL_ALLOC_FAILED`（:48）表明库对分配失败有转换惯例。

**调用方证据**：samples/udp_echo.hpp:32 在 `onDatagram`（noexcept 虚函数）内调用 `pushReply`——noexcept 回调内抛异常将直接 `std::terminate`，这是真实可达路径。

**建议修法**：文档化 OOM 行为；或 pushReply 内捕获 `bad_alloc` 转为 `++droppedReplies_` 计数（与溢出丢包同一防线的自然延伸）。

---

## 编译器与探针证据汇总

| 项 | 命令/方法 | 结果 |
|---|---|---|
| 语法验证 | `g++ -std=c++26 -freflection -I src -I thirdparty/mylog/src -fsyntax-only src/client.hpp`（及 datagram.hpp） | EXIT=0 |
| datagram 行为 | 探针：`setMaxPendingReplies(0)` 后 push | `count=0 dropped=1 hasReply=0`（0=全丢） |
| Client 删除语义 | `static_assert(!is_copy/move_constructible_v<Client<EventSocket<HandlerBase>>>)` 等 4 项 + `is_empty_v<Protocol<EventSocket<HandlerBase>>>` | 全部通过 |
| UDP echo 回环 | 真 socket echo server + 真实 `Client::runUdp` | `received=4 sent=4 elapsed=0ms` 正常退出 |
| **UDP 单向挂起** | sink（只收不回）+ `timeout 6` | **退出码 124（挂起）** |
| TCP 对照 | sink accept 后不关 | 挂起（TCP 等待对端为正确语义，仅对照） |
| 契约校验 | `runUdp("127.0.0.1", 65536)` | contract violation → SIGABRT（134），基线符合 |
| stop() 跨线程 | 500ms 后 `stop()`，sink 不回包 | `elapsed=500ms` 正常退出 |
| TCP 拒连 | `runTcp("127.0.0.1", 1)` | 0ms 返回 CONNECT_FAILED |

## 结论

- **HIGH 缺陷：1 项**（UDP 单向永久挂起，已运行时实证）。
- **MEDIUM 缺陷：5 项**（UDP 异步错误吞没、inet_ntoa 线程安全、SSL 半关闭提前放弃、两处 contract_assert 缺失）。
- LOW：5 项（注释语言/过时文档/nodiscard/错误粒度/异常逃逸）。
- datagram.hpp 总体质量良好：`= delete("reason")` 带原因、中文 Doxygen、溢出丢包计数防线均符合基线；主要缺口在参数契约。
- client.hpp 的 epoll 状态机（level-triggered、背压高/低水位 kHighWater/kLowWater、SIGPIPE 遮蔽与恢复 restoreSigpipeMask）经代码走查与运行时探针验证工作正常；`runLoop` 的 mask 恢复路径在 `loop_.init()`/`addFd` 失败分支均正确回滚。

### SUMMARY
完成 client.hpp 与 datagram.hpp 只读深审：1 HIGH（UDP 单向挂起，运行时实证）+ 5 MEDIUM + 5 LOW，已写入 .codewhale/audit/d-client-datagram.md。
### EVIDENCE
g++ 16.2.1 -std=c++26 -freflection syntax-only 两文件 EXIT=0；7 组运行时探针（含 UDP echo 正常、UDP 单向 timeout 124 挂起、契约 abort、stop 跨线程 500ms 退出）。
### CHANGES
仅新增 .codewhale/audit/d-client-datagram.md（本次审查报告）；探针均为一次性 tmpfs 会话文件，未触碰任何源码。
### RISKS
UDP ECONNREFUSED 吞错为代码路径推演（需真实不可达网络环境复现）；SSL_shutdown==0 判定基于 OpenSSL 文档语义而非运行时复现。
### BLOCKERS
None.
