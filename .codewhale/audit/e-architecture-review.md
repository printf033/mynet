# mynet 架构级设计缺陷评审（no-exception 改造后终版）

日期：2026-10-22 ｜ 范围：src/ 全部 16 头文件 + CMake + README 声明
方法：全文件精读 + 调用方交叉核对 + 编译器/运行时实证。每项缺陷附代码证据与严重程度。

## 零、本轮已修复（与去异常工作同步落地）

- **P1（重构残留，中）** `src/objectPool.hpp` `reset()` 遗留 `available_.clear()`——旧 vector 成员已删除但 reset 漏改。
  仅在全新构建目录 + `-fno-exceptions` 探针下暴露（`-Wtemplate-body` error）；
  运行期表现为 `freeCount_` 未初始化导致 acquire() 恒返 nullptr（11 个测试失败）。
  教训：探针输出 `head -N` 截断掩盖过 error 行；已改用 error 计数法全量验证。

## 一、缺陷清单（按严重程度）

### D1（中）Proactor TLS 会话失去 multishot/buffer-ring 红利，双 syscall 就绪路径

- 证据：`src/proactor.hpp:634-643` `postRecv()` 对 SSL 会话直接转 `postPoll()` →
  `io_uring_prep_poll_add`（单次就绪通知），就绪后再单独提交 recv；
  明文会话走 `io_uring_prep_recv_multishot` + kernel buffer ring（`sqe->buf_group`）。
- 影响：每个 TLS 会话每轮可读事件多一次 CQE 消耗与一次 recv 提交（poll→wakeup→recv 三步 vs 明文 multishot 一步）。
  TLS 高并发短连接场景下 Proactor 相对 Reactor 的性能优势被显著吃掉。
- 缓解现状：README 如实声明 "poll-driven TLS"（非隐瞒）；OpenSSL 无 io_uring kTLS 接管时的合理取舍。
- 建议方向：评估 kernel TLS（`setsockopt TCP_ULP`/kTLS send/recv）让 TLS 流量回到 multishot 路径；或文档化 TLS 会话容量规划按 poll CQE 预算。

### D2（中）STL 可抛容器与 no-exception/零分配哲学的结构性张力

- 证据：`Buffer::data_` 为 `std::string`（buffer.hpp:213）、`HandlerBase::responseQueue_` 为
  `std::deque<std::string>`（handler.hpp:165）、`Multiplexer::outScratch_` 为 `std::string`（multiplexer.hpp:843）、
  `Reactor::index_`/`Multiplexer::streams_` 为 `std::unordered_map`（reactor.hpp:596、multiplexer.hpp:841）、
  `Proactor::sessions_` 为 `std::vector`（proactor.hpp:1059）。
- `-fno-exceptions` 下这些扩容/节点分配 OOM 直接 abort（显式可预测，但不是 Result 错误面）。
- 缓解现状（实证）：热路径增长已有三层背压——请求 4MiB 上限（handler.hpp:166 `maxRequestBytes_`）、
  写高水位→暂停读（connection.hpp:283-286 `readPaused_`）、会话/流/连接全部固定容量池
  （proactor.hpp:586-591 池耗尽 WARN+close fd；reactor connPool 同构）。
  剩余 abort 面仅全局内存耗尽——进程级本就无解，abort 是可辩护策略。
- 本轮落地：CMakeLists.txt GCC 分支 `-fno-exceptions` 机制化（编译器强制，遗漏路径不再静默）；
  objectPool.hpp 已先表率改 nothrow 分配。
- 建议方向：Buffer 底层换自管 nothrow 存储（见 D5），deque/vector 逐步 ObjectPool 化。

### D3（低）`Reactor::updateInterest` 名实不符：更新兴趣掩码函数内嵌读排空副作用

- 证据：`src/reactor.hpp:395-409`——`rearmRead` 时在 modFd 之后同步调用 `conn->handleRead()`。
- 行为正确（EPOLLET rearm 后强制排空是 ET 语义的标准做法，第一轮已审），但函数名只说"更新兴趣"，
  控制流却包含一次完整读处理（可能触发 closeConn/槽位回收）。维护者极易误用。
- 建议：拆分 `rearmAndDrain()` 显式命名，或注释前置警示。

### D4（低）单线程纪律仅靠文档，无机制断言

- 证据：ObjectPool 注释声明"非线程安全"（objectPool.hpp 类注释第 4 条）；
  全库唯一的线程检查是 `EventLoop::inLoopThread()`（loop.hpp:126）；
  Connection/ObjectPool/TimerQueue 的跨线程误用是静默 UB，contract_assert 不覆盖线程归属。
- 取舍：零原子/零同步开销是 README 卖点，逐访问加 thread_id 比较会伤及热路径。
- 建议：Debug 构建下给 ObjectPool::acquire/release 加 `contract_assert(inLoopThread())` 类检查（Release 零开销），CMake 变量控制。

### D5（低）`Buffer::writableBytes()` 语义误导——名字承诺可直接写，实际不可写

- 证据：`src/buffer.hpp:152-157`——注释自认"std::string 不承诺连续性与 SSO 行为，
  writableBytes() > 0 并不表示可以直接向内部存储写入"。
- 接口名与可用性矛盾是 std::string 选型的固有别扭；若底层换自管 nothrow 块（与 D2 建议同根），
  此接口可变为真正的可写窗口 + `appendInPlace()`，一并消掉 string 扩容异常面。
- 现状诚实：注释已如实警告，无静默误用面。

### D6（低）Multiplexer 流表 unordered_map 与 ObjectPool 哲学不一致

- 证据：`src/multiplexer.hpp:841` `std::unordered_map<uint32_t, StreamSlot> streams_`，
  每帧处理一次 `find`（multiplexer.hpp:620 等）；而 handler 槽位已走固定容量 `streamPool_`。
- 节点级堆分配 + rehash 在 no-exception 下为 abort 面（并入 D2 计），且与"零分配热路径"卖点不符。
- 建议：流 ID → 槽位用开放寻址定容数组（池容量 = maxStreams_ 已有上界），查找 O(1) 最坏有界。

## 二、已排除疑点（实证为非缺陷）

- **contract_assert 真实强制**：探针实证 GCC `-fcontracts` 默认 `semantic: enforce, terminating: yes`
  （违反即 abort，exit=134）——安全防线非摆设。
- **Reactor/Proactor 接纳背压完整**：连接/会话池固定容量，acquire 耗尽 → WARN + close fd
  （proactor.hpp:586-591），无无界接纳路径。
- **读侧背压完整**：请求上限（4MiB）+ 写高水位暂停读（connection.hpp:283-286），
  慢读对端无法造成响应侧无界堆积。
- **timer O(1) 取消**：哈希集合 + lazy heap（第二轮已审已修）。
- **objectPool 指针稳定性**：槽位定容定址，release 五段校验（边界/对齐/双重归还）完整（本轮加固）。

## 三、总评

架构主线（双引擎统一 Connection/Handler、Result<T> 错误面、固定容量池、contract 实证 enforce）是自洽的。
最深的结构性张力是 **D2：STL 可抛容器与"零分配 + no-exception"卖点的矛盾**——本轮已用
`-fno-exceptions` 把矛盾变成显式契约（abort 语义），下一步的真解是核心热路径容器 ObjectPool 化。
D1 是 Proactor 引擎诚实的性能短板，值得列入路线图而非文档粉饰。
