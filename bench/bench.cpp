// 字节传输核心基准测试：涵盖 Buffer 缓冲区、帧编解码器、
// Handler 响应队列、ObjectPool 对象池与 Multiplexer 多路复用器。
//
// 测试框架设计刻意保持极简。Google Benchmark 非常优秀，但在一个已依赖
// 4 个系统包的库中引入它来测试几个循环，其依赖体量反而超过了被测代码本身。
// 测试逻辑主要包含：
//
//   * 校准 (calibrate)：逐步增加迭代次数，直到单次运行时间足够长 (~50 ms)，使时钟信号远大于噪声；
//   * 测量 (measure)：重复运行多次并取中位数，以反映常规干扰下的真实性能；
//   * 报告 (report)：归一化为单次操作耗时 (ns/op)，并在涉及字节量时换算为吞吐量 (MB/s)。
//
// 性能数据仅在相同测试条件下具备可比性。测试环境包括：优化编译、关闭 Sanitizer、
// 单进程运行，并将日志输出重定向至远离被测路径的终端。
//
// 运行命令：./bench 2>/dev/null （日志行输出至 stderr）
#include "buffer.hpp"
#include "handler.hpp"
#include "http/v2/frame.hpp"
#include "http/v2/multiplexer.hpp"
#include "log.hpp"
#include "objectPool.hpp"
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

namespace
{
    using namespace mynet;
    using Clock = std::chrono::steady_clock;

    // 存放所有基准测试的累加结果，每次运行循环后写入一次。先累加到局部变量，
    // 循环结束后再写入全局变量，避免将缓存行竞争误计入被测任务的开销。
    volatile uint64_t g_sink = 0;

    constexpr double kMinSeconds = 0.05;
    constexpr int kRepeats = 7;

    struct Sample
    {
        double bestNsPerOp = 0;
        double medianNsPerOp = 0;
        size_t iterations = 0;
    };

    // `body(iterations)` 执行 `iterations * opsPerIteration` 次逻辑操作。
    // 第二个参数用于将针对固定数据集的一轮扫描换算为单次操作的性能指标。
    template <typename Body>
    Sample run(Body &&body, size_t opsPerIteration = 1)
    {
        size_t iterations = 256;
        for (;;)
        {
            const auto start = Clock::now();
            body(iterations);
            const double elapsed = std::chrono::duration<double>(Clock::now() - start).count();
            if (elapsed >= kMinSeconds || iterations >= (1 << 26))
                break;
            iterations *= 8;
        }

        std::vector<double> perOp;
        perOp.reserve(kRepeats);
        for (int repeat = 0; repeat < kRepeats; ++repeat)
        {
            const auto start = Clock::now();
            body(iterations);
            const double elapsed = std::chrono::duration<double>(Clock::now() - start).count();
            perOp.push_back(elapsed * (1000.0 * 1000.0 * 1000.0) / static_cast<double>(iterations * opsPerIteration));
        }
        std::sort(perOp.begin(), perOp.end());
        return Sample{perOp.front(), perOp[perOp.size() / 2], iterations};
    }

    void report(const char *name, const Sample &sample, double bytesPerOp = 0)
    {
        char throughput[32] = "";
        if (bytesPerOp > 0)
            std::snprintf(throughput, sizeof throughput, "  %9.1f MB/s",
                          bytesPerOp * (1000.0 * 1.0) / sample.medianNsPerOp);
        std::printf("%-40s %10.1f ns/op%s  (best %8.1f, %zu x)\n", name, sample.medianNsPerOp, throughput,
                    sample.bestNsPerOp, sample.iterations);
    }

    [[nodiscard]] std::string frameStream(size_t count, size_t payloadBytes)
    {
        Frame frame;
        frame.streamId = 1;
        frame.type = FRAME_TYPE::DATA;
        frame.payload.assign(payloadBytes, 'x');
        std::string out;
        out.reserve(count * (frame::kHeaderBytes + payloadBytes));
        for (size_t i = 0; i < count; ++i)
            appendFrame(out, frame);
        return out;
    }

    // ---- 缓冲区 (Buffer) 基准测试 ----

    void benchBuffer()
    {
        const std::string block(1 << 10, 'x');
        const std::string sixteen("0123456789abcdef");
        const Sample appendRetrieve = run(
            [&](size_t iterations)
            {
                uint64_t sink = 0;
                Buffer buffer;
                for (size_t i = 0; i < iterations; ++i)
                {
                    [[maybe_unused]] auto _ = buffer.append(block);
                    sink += buffer.readableBytes();
                    buffer.retrieveAll();
                }
                g_sink += sink;
            });
        report("Buffer::append+retrieveAll (1KiB)", appendRetrieve, static_cast<double>(1 << 10));

        const Sample appendSmall = run(
            [&](size_t iterations)
            {
                uint64_t sink = 0;
                Buffer buffer;
                for (size_t i = 0; i < iterations; ++i)
                {
                    for (int k = 0; k < 64; ++k) [[maybe_unused]]
                        auto _ = buffer.append(sixteen);
                    sink += buffer.readableBytes();
                    buffer.retrieveAll();
                }
                g_sink += sink;
            },
            64);
        report("Buffer::append (16B) to 1KiB + drain", appendSmall);

        const Sample retrieve = run(
            [&](size_t iterations)
            {
                uint64_t sink = 0;
                Buffer buffer;
                std::string chunk(16, 'x');
                for (size_t i = 0; i < iterations; ++i)
                {
                    [[maybe_unused]] auto _ = buffer.append(chunk);
                    sink += buffer.readableBytes();
                    buffer.retrieve(16);
                }
                g_sink += sink;
            });
        report("Buffer::append+retrieve (16B)", retrieve, 16.0);
    }

    // ---- 分帧 (Framing) 基准测试 ----

    void benchFrameEncode(size_t payloadBytes)
    {
        Frame frame;
        frame.streamId = 1;
        frame.type = FRAME_TYPE::DATA;
        frame.payload.assign(payloadBytes, 'x');
        std::string out;
        const Sample sample = run(
            [&](size_t iterations)
            {
                uint64_t sink = 0;
                for (size_t i = 0; i < iterations; ++i)
                {
                    out.clear();
                    appendFrame(out, frame);
                    sink += out.size();
                }
                g_sink += sink;
            });
        char label[64];
        std::snprintf(label, sizeof label, "appendFrame (payload %zuB)", payloadBytes);
        report(label, sample, static_cast<double>(payloadBytes));
    }

    void benchFrameDecode(size_t payloadBytes)
    {
        // 无论负载大小，每轮扫描固定处理 1 MB 的分帧数据：单轮工作量必须保持固定
        // 才能使 ns/op 具备可比性，若固定帧数会导致 16 KiB 场景搬移 4096 倍的字节量。
        const size_t kFrames = std::max<size_t>(64, (1 << 20) / (payloadBytes + frame::kHeaderBytes));
        const std::string bytes = frameStream(kFrames, payloadBytes);
        const Sample sample = run(
            [&](size_t iterations)
            {
                uint64_t sink = 0;
                for (size_t pass = 0; pass < iterations; ++pass)
                {
                    Buffer in;
                    [[maybe_unused]] auto _ = in.append(bytes);
                    FrameDecoder decoder;
                    while (in.readableBytes() > 0)
                    {
                        auto parsed = decoder.next(in);
                        if (!parsed || !parsed->has_value())
                            break;
                        sink += parsed->value().payload.size();
                    }
                }
                g_sink += sink;
            },
            kFrames);
        char label[64];
        std::snprintf(label, sizeof label, "FrameDecoder::next (payload %zuB)", payloadBytes);
        report(label, sample, static_cast<double>(payloadBytes));
    }

    void benchBigEndian()
    {
        const Sample sample = run(
            [&](size_t iterations)
            {
                uint64_t sink = 0;
                char raw[4] = {'\x12', '\x34', '\x56', '\x78'};
                std::string out;
                for (size_t i = 0; i < iterations; ++i)
                {
                    sink += frame::readBigEndian32(raw);
                    out.clear();
                    frame::appendBigEndian32(out, static_cast<uint32_t>(sink));
                }
                g_sink += sink;
            });
        report("read+appendBigEndian32", sample);
    }

    // ---- 对象池 (ObjectPool) 基准测试 ----

    void benchObjectPool()
    {
        constexpr size_t kSlots = 128;
        ObjectPool<HandlerBase> pool;
        if (!pool.init(kSlots))
        {
            std::fprintf(stderr, "bench: pool init failed\n");
            std::exit(1);
        }
        std::vector<HandlerBase *> held(kSlots, nullptr);
        const Sample sample = run(
            [&](size_t iterations)
            {
                uint64_t sink = 0;
                for (size_t i = 0; i < iterations; ++i)
                {
                    for (size_t k = 0; k < kSlots; ++k)
                        held[k] = pool.acquire();
                    for (size_t k = 0; k < kSlots; ++k)
                    {
                        sink += held[k] != nullptr;
                        pool.release(held[k]);
                    }
                }
                g_sink += sink;
            },
            kSlots);
        report("ObjectPool acquire+release (128)", sample);
    }

    // ---- 协议处理器 (Handler) 基准测试 ----

    void benchHandlerQueue()
    {
        HandlerBase handler;
        const std::string body(1 << 10, 'x');
        const Sample pushTake = run(
            [&](size_t iterations)
            {
                uint64_t sink = 0;
                for (size_t i = 0; i < iterations; ++i)
                {
                    [[maybe_unused]] auto _ = handler.pushResponse(body);
                    sink += handler.takeResponse().size();
                }
                g_sink += sink;
            });
        report("HandlerBase::pushResponse+takeResponse (1KiB)", pushTake, static_cast<double>(1 << 10));

        const Sample echo = run(
            [&](size_t iterations)
            {
                uint64_t sink = 0;
                for (size_t i = 0; i < iterations; ++i)
                {
                    [[maybe_unused]] auto _ = handler.appendRequest(body.data(), static_cast<ssize_t>(body.size()));
                    handler.process();
                    sink += handler.takeResponse().size();
                }
                g_sink += sink;
            });
        report("HandlerBase::process echo (1KiB)", echo, static_cast<double>(1 << 10));
    }

    // ---- 多路复用器 (Multiplexer) 基准测试 ----

    void benchMultiplexerRoundTrip()
    {
        class NoopMux : public Multiplexer<HandlerBase>
        {
        };
        constexpr size_t kStreams = 64;

        // 每轮扫描复用同一条连接。构造多路复用器会构建流对象池，
        // 若每轮都新建对象池，会将池构造开销与往返测量混杂在一起。
        NoopMux mux;
        mux.process(); // 在测量路径之外预先宣告一次 SETTINGS 帧
        while (mux.hasResponse())
        {
            [[maybe_unused]] auto _ = mux.takeResponse();
        }

        const Sample sample = run(
            [&](size_t iterations)
            {
                uint64_t sink = 0;
                for (size_t pass = 0; pass < iterations; ++pass)
                {
                    for (size_t k = 0; k < kStreams; ++k)
                    {
                        const uint32_t id = static_cast<uint32_t>(k * 2 + 1);
                        std::string bytes;
                        appendFrame(bytes, Frame{.streamId = id,
                                                 .type = FRAME_TYPE::HEADERS,
                                                 .flags = FrameFlags::kEndHeaders,
                                                 .payload = "h"});
                        appendFrame(bytes, Frame{.streamId = id,
                                                 .type = FRAME_TYPE::DATA,
                                                 .flags = FrameFlags::kEndStream,
                                                 .payload = "payload"});
                        [[maybe_unused]] auto _ = mux.appendRequest(bytes.data(), static_cast<ssize_t>(bytes.size()));
                        mux.process();
                        while (mux.hasResponse())
                            sink += mux.takeResponse().size();
                    }
                }
                g_sink += sink;
            },
            kStreams);
        report("Multiplexer open+echo+close (64 streams)", sample);
    }
} // namespace

int main()
{
    mynet::log::init(); // 在首次产生 LOG_* 之前初始化日志输出
    std::printf("mynet benchmarks -- %s\n",
#ifdef __OPTIMIZE__
                "optimised build, no sanitizer"
#else
                "UNOPTIMISED build (results are not representative)"
#endif
    );
    std::printf("%-40s %10s %s\n", "benchmark", "ns/op", "throughput");

    benchBuffer();
    benchFrameEncode(16);
    benchFrameEncode(1 << 10);
    benchFrameEncode(16 << 10);
    benchFrameDecode(16);
    benchFrameDecode(1 << 10);
    benchFrameDecode(16 << 10);
    benchBigEndian();
    benchObjectPool();
    benchHandlerQueue();
    benchMultiplexerRoundTrip();

    std::printf("\nns/op is the median of %d runs of the same body; 'best' is the fastest of them.\n", kRepeats);
    std::printf("Log lines go to stderr: run ./bench 2>/dev/null for a clean report.\n");
    return EXIT_SUCCESS;
}
