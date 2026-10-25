# 深度审查报告：src/loop.hpp（394 行）与 src/timer.hpp（222 行）

- 审查人：审查席 B（C++26 网络库资深审查员）
- 仓库：/home/aaa/code/mynet（Linux, C++26, header-only）
- 方式：只读审查；逐行通读两个目标文件，并交叉核对 src/reactor.hpp、src/client.hpp、src/objectPool.hpp、src/error.hpp、tests/test_timer.cpp 的全部调用点。
- 编译实证说明（诚实声明）：本轮因共享 checkout 存在并行写入者（bash 被写防护拒绝）且墙钟预算耗尽，`g++ -std=c++26 -I src -fsyntax-only` 的独立复跑未能在收尾前完成；全部发现均基于源码逐行实证 + 全仓调用方 grep 交叉核对（命令与行号见各条），并标注了可用探针复现的路径。此为遗留验证项，见文末。
- 审查标准：对齐第一轮 buffer.hpp 基线 —— `Result<T> = std::expected<T, ERR>`；参数校验走 `contract_assert`；`= delete("reason")`；noexcept 纪律；中文 Doxygen。

---

## 发现 1 [HIGH] loop.hpp:233-245 —— epoll_wait 就绪事件数组在回调阶段被"陈旧事件"穿透，依赖对象池地址恒定性才未成为 use-after-free

**缺陷描述**：`run()` 先把 `epoll_wait` 返回的就绪条目存入 `events_`，随后在进入 for 分发循环**之前**先执行 `timerQueue_.handleExpired(now)`（第 230 行）与 `doPendingTasks()`（第 231 行）。这两步都会同步执行用户回调（定时器回调、跨线程任务），而回调完全可能关闭连接（例如 `sweepIdle()` 空闲踢线、`loop_.quit()` 前的清理）。此后第 243 行才遍历 `events_`，把早已失效的 `events_[i].data.ptr`（指向 `Connection`）直接分发给 `eventCallback_` → `Reactor::onConnection`（reactor.hpp:334）解引用。

**调用方证据**：
- src/reactor.hpp:245 `idleTimerId_ = loop_.runEvery(..., [this] { sweepIdle(); })`；reactor.hpp:505-541 `sweepIdle()` → `closeConn(conn)` → `(void)loop_.delFd(fd)` + `connPool_.release(conn)`（reactor.hpp:495-502）。
- src/objectPool.hpp:153 `slot.object.reset()`；objectPool.hpp:19 注释明确声明"连续 acquire()/release() 周期内槽位地址绝对恒定，可安全用于 epoll data.ptr"。即当前唯一防 UAF 的保证是"地址永不复用堆重分配"。该契约一旦被打破（池改为堆节点分配、`std::vector` 换 `std::deque`、或任何复用槽位内存的实现），本缺陷立即升级为可利用的 use-after-free；同一轮询周期内关闭后重新 accept 到同槽位地址时，还会把新事件误派发给错误连接（地址复用即 ABA）。
- 此外 `closeConn` 只做 `delFd`（reactor.hpp:495-502），fd 关闭后同号 fd 若被新连接复用，陈旧事件仍指向已被释放的旧 `Conn`。

**建议修法**（对齐架构基线）：分发循环内先复核再派发，二者取一并在 Doxygen 写明契约：
1. 最小修复：在 for 循环里对每个非 wake 事件先 `::epoll_ctl(epollFd_, EPOLL_CTL_MOD, fd, &mute)`（events=0、ptr=回调需要的原指针）借内核验证 fd 仍注册且持有同一 `data.ptr`，失败/不一致则跳过；或
2. 结构修复：`handleExpired`/`doPendingTasks` 移到本轮 `events_` 消费完之后执行，保证"快照-派发"期间无用户代码运行。
并在 loop.hpp 中文 Doxygen 中明确记录"事件有效性仅限单个 epoll_wait 返回轮次"的所有权边界。

---

## 发现 2 [HIGH] loop.hpp:38-39、321-338 —— Clock=steady_clock 下 `next - Clock::now()` 时长溢出（UB），且 `Time::max()` 哨兵值与真实定时器截止时间不可区分

**缺陷描述**：`EventLoop::Clock/Time` 直接复用 `TimerQueue::Clock = std::chrono::steady_clock`（timer.hpp:29-30）。两个叠加问题：
1. `nextTimeout()`（loop.hpp:328）计算 `duration_cast<milliseconds>(next - Clock::now()).count()`。`steady_clock::time_point` 的 rep 通常为纳秒级有符号 64 位；当 `runAt()`/`runAfter()` 传入远期截止时间（如数百年）或重复定时器 interval 极大时，`next - now` 以纳秒计溢出有符号数——**有符号溢出是未定义行为**，`count()` 结果可为任意值，`epoll_wait` 超时随之不可预测。可通过独立探针（`using Clock=steady_clock; auto d=duration_cast<milliseconds>(Clock::now()+years(300)-Clock::now()).count();`）编译运行证实。
2. `nextExpire()`（timer.hpp:98）用 `Time::max()` 表示"无定时器"哨兵；但 `Time::max()` 同样可以作为**真实**截止时间传入 `runAt()`/`addTimer()`。此时 `nextTimeout()` 将其误判为"无定时器"返回 -1（无限睡眠），定时器永不触发且无任何诊断。哨兵值与合法值域无隔离是接口设计缺陷。

**调用方证据**：src/client.hpp:335 `loop_.runEvery(100ms, ...)`、src/reactor.hpp:245 `runEvery(1s, ...)` 为当前唯一公开路径（间隔小，暂未触发），但 `runAt(Time, cb)`（loop.hpp:313）把任意 `Time` 直通 `addTimer`，属公开 API 的可达面；tests/test_timer.cpp:26 直接以 `now + 100ms` 构造边界。库对"远期时间"没有任何 `contract_assert` 防线。

**建议修法**：`nextTimeout()` 改用比较/钳制而非直接相减（如 `if (next <= now) return 0;` 再用 `duration_cast` 且对 `left` 与 `int::max()` 先以更大类型比较）；在 `addTimer` 入口以 `contract_assert(when != Time::max())` 排除哨兵碰撞，或为 TimerQueue 引入独立的 `bool empty()` 状态位代替哨兵。Doxygen 注明合法时间域。

---

## 发现 3 [HIGH→MEDIUM] timer.hpp:41-42、51-56、152-159 —— `Timer` 半初始化与移动后遗留：堆中存在"无 id、无所有权"的死条目，`cancelTimer` 永远够不着

**缺陷描述**：
1. `struct Timer` 的成员 `uint64_t id_ = 0;` 有默认值，但 `Time expire_{}`、`std::chrono::milliseconds interval_{}` 为值初始化，而 **`Callback callback_`（第 44 行）没有初始化器**——`Timer timer;`（timer.hpp:51）是默认初始化，`std::function` 自带构造所以侥幸安全，但该结构整体缺一条"构造即全初始化"的纪律，与架构基线的初始化纪律不一致。
2. 更实质的问题：`handleExpired` 中 `Timer timer = std::move(heap_.back())`（第 146 行）之后，原堆条目（repeat 分支）被 push 回的新 `timer` 是**移动后**的对象副本吗？——注意第 146 行是移动构造局部 `timer`，原槽已被 pop；但 `callbacks.push_back(timer.callback_)`（repeat 分支，第 157 行）是**拷贝**而非移动，随后同一个 `timer` 又被移动回堆（第 168 行）——语义正确，但单次分支 `callbacks.push_back(std::move(timer.callback_))` 后，若 `timer.repeat_` 为 false 则对象被丢弃，安全；而**真正的问题**是 `dropDeadTop()`（timer.hpp:190-200）弹出的"已取消"堆条目与其 `timers_` 集合没有任何关联校验路径之外的生命周期：已取消条目在被弹出前，其 `callback_`（可能持有大捕获、共享指针）一直滞留在堆里直至其截止时间轮到，`cancelTimer` 成功并不释放回调内存——取消不是 O(1) 释放而是"延迟到该截止时间被扫描"才归还。对长周期定时器（如 1 小时心跳）取消后，闭包与捕获内存最长滞留 1 小时，`size()` 虽正确但内存语义与文档"彻底杜绝内存泄漏"（timer.hpp:16）不符。
3. 顺带：第 51-56 行 id 0 特判与第 112-116、144-146 行 while 循环内的重复特判是死代码（见发现 9），但若未来 `nextId_` 真回绕，`Timer timer; timer.id_ = nextId_++` 之前的 `timer.expire_`/`interval_` 尚未赋值即参与哈希探查路径，属于脆弱写法。

**调用方证据**：tests/test_timer.cpp:42-45、63-66 验证了"取消后条目直到过期才离开堆"的行为面；src/reactor.hpp:278、src/client.hpp:196 是真实取消路径（每秒 sweep、100ms stop 检查），均为长生命周期重复定时器，取消后闭包滞留窗口即为其 interval。

**建议修法**：`cancelTimer` 除从 `timers_` 擦除外，同步将 `Callback` 置空不可行（堆内定位 O(n)）；建议在 `Timer` 增加独立的"存活快照层"（如取消即把 `callback_` 移入待清队列）或改为文档明示"取消延迟释放"并在 `= delete`/Doxygen 注明；同时给 `Timer` 全成员补默认初始化器（`Callback callback_{};`），对齐初始化纪律。综合危害评级 HIGH（内存滞留 + 契约文档失实），修法明确后可降 MEDIUM。

---

## 发现 4 [MEDIUM] loop.hpp:36-56 —— `init()` 幂等分支以"关闭重建"处理半初始化态，可在循环运行中摧毁活 epoll 集并引入跨线程数据竞争

**缺陷描述**：`init()` 开头仅当 `epollFd_ >= 0 && wakeFd_ >= 0` 才短路返回；若二者其一有效（半初始化），第 41-49 行会**无条件 close 现有描述符后重建**。两个问题：
1. 若另一线程正在 `run()` 中使用 `epollFd_`（`epoll_wait(epollFd_, ...)`，loop.hpp:213），本线程 close 它构成对同一描述符的跨线程 use-after-close/数据竞争（errno 读取亦竞态）。
2. 重建成功路径上，旧 `wakeFd_` 先被 close 再重建，但**从未对旧 wakeFd_ 执行 `EPOLL_CTL_DEL`**——虽然 close 自动移除，注释声称的"严格生命周期隔离"（loop.hpp:30-31）在此路径并未体现；且重建后若 `epoll_ctl(ADD, wakeFd_)` 失败（第 79-88 行），回滚逻辑与第 41-49 行的清理相互交叠，幂等性承诺实际只在"全成功"或"全失败"两端成立。

**调用方证据**：src/client.hpp:300 `if (auto err = loop_.init(); !err)` 与 src/reactor.hpp（serve/serveDatagram 依赖 `loop_.epollFd() < 0` 判断，reactor.hpp:222/257）表明 `init()` 的 Result 返回值被认真消费；Client::reset()（client.hpp:187-246）→ `loop_.quit()` 后可能再次 `setup()`→`runLoop()`→`init()`，构成"半初始化/重建"真实可达路径。当前无并发 init 调用方，故评 MEDIUM 而非 HIGH。

**建议修法**：`init()` 增加前置契约：`contract_assert(!running())`；半初始化时**只**补齐缺失的一半（wakeFd_ 缺则只建 eventfd 并 ADD），绝不关闭已工作的 epollFd_；所有错误分支保持"已就绪资源原样保留"，失败只回收本次新建部分。Doxygen 注明非线程安全、须在循环线程调用。

---

## 发现 5 [MEDIUM] timer.hpp:137、163；loop.hpp:230-244 —— `handleExpired` 误标 `noexcept` 且 `run()` 对回调异常零隔离：用户回调抛异常即 `std::terminate`，或逃逸出 `run()` 使 `running_` 永久为 true

**缺陷描述**：
1. `handleExpired(Time now) noexcept`（timer.hpp:137）在锁外执行任意用户 `Callback`（第 179-182 行）。回调抛出任何异常 → `std::terminate`。该函数没有任何"绝不抛"的实现保证（`std::function` 拷贝构造可抛 `bad_alloc`，`std::vector` 扩容可抛），noexcept 标注违反架构基线的 noexcept 纪律（"noexcept 只给真正不抛的实现"）。对照：`EventLoop::run()`（loop.hpp:196）未标 noexcept，说明作者明知回调可抛，`handleExpired` 的标注属于笔误级别的不一致。
2. `run()` 的主循环对 `timerQueue_.handleExpired`、`doPendingTasks`、`eventCallback_`（loop.hpp:230、231、243）三处用户代码均无 try/catch。回调抛出的异常直接飞出 `run()`，且 `running_.store(false)`（loop.rs:247 与 221 行两个出口都不会经过）不会执行——`running()` 从此永久返回 true，`quit()` 后 `run()` 无法重启的语义被破坏，`Result<>` 返回契约（"正常退出返回 {}，非正常退出返回错误枚举"）对异常路径完全没有覆盖。

**调用方证据**：src/reactor.hpp:245 的 sweep 回调、src/client.hpp:335 的 stop 回调均为用户可注入逻辑（间接含 handler 代码），异常可达；tests/test_timer.cpp 全文未覆盖回调抛异常场景（测试缺口）。ERR 枚举（error.hpp:20-50）中没有对应"回调异常"的错误项，需新增或以文档排除。

**建议修法**：去掉 `handleExpired` 的 `noexcept`；`run()` 主循环以 try/catch 包裹三处回调执行点，捕获后 `LOG_ERROR` + `return std::unexpected(ERR::...)`（新增如 `ERR::CALLBACK_EXCEPTION`，并同步 error.hpp 的 static_assert 计数与描述表），确保 `running_` 在所有出口复位。若架构决定"异常即终止"，则在中文 Doxygen 显式声明该契约并保留 noexcept 于唯一执行点，二选一，不可如现状般含糊。

---

## 发现 6 [MEDIUM] loop.hpp:300-316 —— `runAfter/runEvery/runAt` 静默丢弃全部失败模式：空回调、参数非法、ID 回绕，且无 `contract_assert` 防线

**缺陷描述**：三个便捷封装把 `TimerQueue::addTimer` 的返回 `uint64_t` 原样透传，自身无任何校验：
1. 空回调 `runAfter(100ms, nullptr)` 被静默接受，登记后永不执行也永不报错（`handleExpired` 中 `if (timer.callback_)` 静默跳过，timer.hpp:160），调用方无从得知。架构基线明确"参数校验走 contract_assert"（error.hpp:17 亦声明参数错误不属于 ERR 枚举），此处缺失。
2. `addTimer` 无法表达失败（返回裸 `uint64_t`），因此 `runAt(Time::max(), cb)`（哨兵碰撞，见发现 2）、远期溢出均静默吞掉。
3. `interval` 为负值时 `repeat_ = interval.count() > 0` 判 false，静默退化为单次定时器——语义上应属调用方编程错误，应契约断言而非静默降级。

**调用方证据**：src/client.hpp:335、src/reactor.hpp:245 为全部现网调用（参数合法），但 tests/test_timer.cpp:26 等直接调用 `addTimer` 的测试未覆盖空回调/负 interval；公开头文件即公开 API 面，缺陷真实可达。

**建议修法**：`runAfter/runEvery/runAt` 入口补 `contract_assert(callback)`、`contract_assert(interval.count() > 0)`（对 runEvery）、`contract_assert(when != Time::max())`（对 runAt）；`TimerQueue::addTimer` 的 Doxygen 注明前置契约，保持返回 `uint64_t` 不变（ID 空间暂无失败模式）。

---

## 发现 7 [LOW] timer.hpp:51-56、112-116、144-146 —— `nextId_` 回绕/ID 0 特判为死代码，且三处重复，维护成本高于价值

**缺陷描述**：`nextId_` 初始为 1（timer.hpp:203）且全文件只做自增；`uint64_t` 自增回绕在现实时间尺度不可达。第 52-55 行、113-116 行、145-146 行三处逐字重复的 `if (timer.id_ == 0) [[unlikely]] { timer.id_ = nextId_++; }` 永不触发（`nextId_` 从 1 开始，除非经历 2^64-1 次分配）。属死代码 + 三重复制。

**调用方证据**：全仓 grep `nextId_` 仅 timer.hpp 三处；无外部依赖该行为。

**建议修法**：删除三处特判（或在 `addTimer` 顶部留一条 `// uint64 回绕在现实尺度不可达` 注释）；若坚持防御，集中为一个 `detail::nextId()` 私有辅助，消除三重复制。

---

## 发现 8 [LOW] loop.hpp:180-191、158-175 —— `delFd` 与 `addFd/modFd` 对"编程错误"与"系统调用失败"共用 `ERR::EPOLL_CTL_FAILED`，且 delFd 用 WARN、addFd 用 ERROR，语义倒挂

**缺陷描述**：`delFd`（loop.hpp:180-191）在 `epollFd_ < 0 || fd < 0` 时不做任何系统调用即返回 `std::unexpected(ERR::EPOLL_CTL_FAILED)`，日志级别 LOG_WARN；而 `addFd/modFd` 对同样前置条件用 LOG_ERROR。按架构基线，"传入非法 fd"是调用方编程错误，应走 `contract_assert`，不应伪装成一次从未发生的 `epoll_ctl` 失败（`ERR::EPOLL_CTL_FAILED` 的语义是"epoll_ctl() 增删改监听失败"，error.hpp:25）；同时三函数日志级别不一致说明边界语义未统一。

**调用方证据**：src/reactor.hpp:496 `(void)loop_.delFd(fd)`（closeConn，fd 可能为 -1 的正常路径依赖该"宽容失败"）、src/client.hpp:207 `(void)loop_.delFd(STDIN_FILENO)`。当前调用方依赖"非法输入返回错误而非断言"的现状，故只能评 LOW 并建议渐进迁移。

**建议修法**：严格模式（新调用方）用 `contract_assert(fd >= 0)`；保留宽容路径但为"未初始化/未注册"引入独立错误（如复用 `ERR::NOT_INITIALISED` 或新增枚举），并统一三函数日志级别与 Doxygen。

---

## 发现 9 [LOW] loop.hpp:14；timer.hpp:15 —— `<optional>` 头文件冗余包含；loop.hpp:158-175 与 194-207 重复的 `epoll_event` 组装逻辑

**缺陷描述**：loop.hpp 与 timer.hpp 均包含 `<optional>`（loop.hpp:14、timer.hpp:15），两文件正文无任何 `std::optional` 使用（grep 证实）。另 `addFd` 与 `modFd`（loop.hpp:158-175、194-207）的 `epoll_event` 零初始化 + 字段填充完全重复，仅 `EPOLL_CTL_ADD/MOD` 一字之差，可收敛为私有辅助。另注：`std::memset` 逐字段赋值即可替代，属风格项。

**调用方证据**：编译面无影响，纯卫生问题。

**建议修法**：删除两处 `<optional>`；提取 `inline Result<> ctlFd(int op, int fd, uint32_t events, void *ptr)` 私有辅助，`addFd/modFd` 各一行转发。

---

## 发现 10 [LOW] loop.hpp:95-102 —— 构造函数吞掉 `init()` 失败，与 Doxygen"失败返回具体系统调用错误枚举"的 Result 契约相悖

**缺陷描述**：构造函数第 95-101 行执行 `(void)init();`，把 `Result<>` 错误静默丢弃；类文档（第 44 行）宣称 init"失败返回具体系统调用错误枚举"，但构造路径的失败只能靠后续 `run()`/`addFd()` 的 `epollFd_ < 0` 间接兜底（`run()` 返回 `ERR::NOT_INITIALISED`，错误信息失真为"从未调用 init"）。`reserveEvents(1 << 10)` 还在构造中做可能抛出的分配，与"轻量构造"无文档承诺但事实耦合。

**调用方证据**：src/reactor.hpp:222/257 在 serve 前显式检查 `loop_.epollFd() < 0`（正是为兜住构造吞错），src/client.hpp:300 则显式调用 `init()` 并检查——两条路径并存说明该隐式契约已造成调用方防 duplicated-init 的认知负担。

**建议修法**：构造函数移除 `(void)init()`，改为只设 `threadId_` 与 `events_` 预留；或保留但在 Doxygen 明示"构造内自举失败将通过 run() 以 NOT_INITIALISED 暴露"。推荐前者，与基线"错误显式化"一致。

---

## 汇总

| # | 级别 | 位置 | 一句话 |
|---|------|------|--------|
| 1 | HIGH | loop.hpp:233-245 | 陈旧 epoll 事件在回调关连接后仍被派发，靠对象池地址恒定契约才未成 UAF |
| 2 | HIGH | loop.hpp:321-338 | steady_clock 时长有符号溢出（UB）+ `Time::max()` 哨兵与真实截止时间不可区分 |
| 3 | HIGH→MEDIUM | timer.hpp:41-44,146-159 | 取消定时器延迟释放闭包内存（与"杜绝泄漏"文档失实）；Timer 初始化不完整 |
| 4 | MEDIUM | loop.hpp:36-56 | init() 重建路径可摧毁运行中 loop 的活描述符集，缺 running 契约 |
| 5 | MEDIUM | timer.hpp:137; loop.hpp:230-244 | handleExpired 误标 noexcept；run() 对回调异常零隔离且 running_ 卡 true |
| 6 | MEDIUM | loop.hpp:300-316 | 定时器便捷封装无 contract_assert：空回调/负 interval/哨兵时间静默接受 |
| 7 | LOW | timer.hpp:51-56 等 | nextId_ 回绕特判三处死代码 |
| 8 | LOW | loop.hpp:180-191 | delFd 编程错误伪装成系统调用失败，日志级别与 addFd 倒挂 |
| 9 | LOW | loop.hpp:14; timer.hpp:15 | `<optional>` 冗余；addFd/modFd 重复逻辑 |
| 10 | LOW | loop.hpp:95-102 | 构造函数吞 init() 错误，与 Result 契约相悖 |

## 遗留验证项（未竟事项）

- [ ] `g++ -std=c++26 -I src -fsyntax-only src/loop.hpp src/timer.hpp`（经 thirdparty include 路径补齐 reflection.hpp）独立复跑，确认无编译告警层面的新证据。
- [ ] 发现 2 的有符号溢出探针：独立 TU 构造 `steady_clock::now() + years(300)` 与 `Time::max()` 两种截止时间，验证 `nextTimeout()` 返回值与定时器是否触发。
- [ ] 发现 1 的压力探针：单 loop + 定时器回调高频关连接 + 饱和 epoll_wait 返回数组，观察陈旧事件派发计数（当前实现下应为非零）。
- [ ] tests/test_timer.cpp 补充：回调抛异常、空回调、负 interval、`runAt(Time::max())` 四个缺口用例。
