// Benchmarks for the byte-moving core: the buffer, the frame codec, the
// handler queue, the object pool and the hexdump formatter.
//
// The harness is deliberately tiny. Google Benchmark is a fine project, but
// adding a distribution to time five loops inside a library that already
// depends on four system packages would be a heavier dependency than the code
// under test -- and the shape those frameworks give is short enough to write
// down here:
//
//   * calibrate: grow the iteration count until one run lasts long enough for
//     the clock to be a better signal than the noise (~50 ms);
//   * measure: repeat that run and keep the middle one, because the median is
//     the run that saw ordinary interference rather than none or lots;
//   * report: normalise to ns per operation and, where a byte count means
//     something, MB/s.
//
// Numbers are only comparable to numbers taken the same way. The conditions
// are printed at the top of the report: an optimised build, no sanitizer, one
// process, and log output aimed away from the measured path.
//
// Run it as:  ./bench_core 2>/dev/null     (log lines go to stderr)
#include "buffer.hpp"
#include "frame.hpp"
#include "handler.hpp"
#include "hexdump.hpp"
#include "log.hpp"
#include "multiplexer.hpp"
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
    using Clock = std::chrono::steady_clock;

    // Every benchmark's result ends up here, once per run of the body. Summing
    // into a local first and touching this after the loop is the difference
    // between measuring the work and measuring the cache line the result lands in.
    volatile uint64_t g_sink = 0;

    constexpr double kMinSeconds = 0.05;
    constexpr int kRepeats = 7;

    struct Sample
    {
        double bestNsPerOp = 0;
        double medianNsPerOp = 0;
        size_t iterations = 0;
    };

    // `body(iterations)` performs `iterations * opsPerIteration` logical
    // operations. The second argument is what turns a "pass" over a fixed data set
    // into a per-operation number.
    template <typename Body>
    Sample run(Body &&body, size_t opsPerIteration = 1)
    {
        size_t iterations = 1 << 8;
        for (;;)
        {
            const auto start = Clock::now();
            body(iterations);
            const double elapsed = std::chrono::duration<double>(Clock::now() - start).count();
            if (elapsed >= kMinSeconds || iterations >= (size_t{1} << 26))
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
            perOp.push_back(elapsed * 1e9 / static_cast<double>(iterations * opsPerIteration));
        }
        std::sort(perOp.begin(), perOp.end());
        return Sample{perOp.front(), perOp[perOp.size() / 2], iterations};
    }

    void report(const char *name, const Sample &sample, double bytesPerOp = 0)
    {
        char throughput[32] = "";
        if (bytesPerOp > 0)
            std::snprintf(throughput, sizeof throughput, "  %9.1f MB/s", bytesPerOp * 1e3 / sample.medianNsPerOp);
        std::printf("%-40s %10.1f ns/op%s  (best %8.1f, %zu x)\n", name, sample.medianNsPerOp, throughput,
                    sample.bestNsPerOp, sample.iterations);
    }

    [[nodiscard]] std::string frameStream(size_t count, size_t payloadBytes)
    {
        Frame frame;
        frame.streamId = 1;
        frame.type = FrameType::data;
        frame.payload.assign(payloadBytes, 'x');
        std::string out;
        out.reserve(count * (mynetframe::kHeaderBytes + payloadBytes));
        for (size_t i = 0; i < count; ++i)
            appendFrame(out, frame);
        return out;
    }

    // ---- buffer ----

    void benchBuffer()
    {
        const std::string block(1024, 'x');
        const std::string sixteen("0123456789abcdef");
        const Sample appendRetrieve = run([&](size_t iterations) {
            uint64_t sink = 0;
            Buffer buffer;
            for (size_t i = 0; i < iterations; ++i)
            {
                buffer.append(block);
                sink += buffer.readableBytes();
                buffer.retrieveAll();
            }
            g_sink += sink;
        });
        report("Buffer::append+retrieveAll (1KiB)", appendRetrieve, 1024.0);

        const Sample appendSmall = run([&](size_t iterations) {
            uint64_t sink = 0;
            Buffer buffer;
            for (size_t i = 0; i < iterations; ++i)
            {
                for (int k = 0; k < 64; ++k)
                    buffer.append(sixteen);
                sink += buffer.readableBytes();
                buffer.retrieveAll();
            }
            g_sink += sink;
        },
                                       64);
        report("Buffer::append (16B) to 1KiB + drain", appendSmall);

        const Sample retrieve = run([&](size_t iterations) {
            uint64_t sink = 0;
            Buffer buffer;
            std::string chunk(16, 'x');
            for (size_t i = 0; i < iterations; ++i)
            {
                buffer.append(chunk);
                sink += buffer.readableBytes();
                buffer.retrieve(16);
            }
            g_sink += sink;
        });
        report("Buffer::append+retrieve (16B)", retrieve, 16.0);
    }

    // ---- framing ----

    void benchFrameEncode(size_t payloadBytes)
    {
        Frame frame;
        frame.streamId = 1;
        frame.type = FrameType::data;
        frame.payload.assign(payloadBytes, 'x');
        std::string out;
        const Sample sample = run([&](size_t iterations) {
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
        // One megabyte of frames per pass, whatever the payload size: a pass has to
        // stay a fixed amount of work for ns/op to mean anything, and a fixed
        // frame count would make the 16 KiB case move 4096 times the bytes.
        const size_t kFrames = std::max<size_t>(64, (size_t{1} << 20) / (payloadBytes + mynetframe::kHeaderBytes));
        const std::string bytes = frameStream(kFrames, payloadBytes);
        const Sample sample = run(
            [&](size_t iterations) {
                uint64_t sink = 0;
                for (size_t pass = 0; pass < iterations; ++pass)
                {
                    Buffer in;
                    in.append(bytes.data(), static_cast<ssize_t>(bytes.size()));
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
        const Sample sample = run([&](size_t iterations) {
            uint64_t sink = 0;
            char raw[4] = {'\x12', '\x34', '\x56', '\x78'};
            std::string out;
            for (size_t i = 0; i < iterations; ++i)
            {
                sink += mynetframe::readBigEndian32(raw);
                out.clear();
                mynetframe::appendBigEndian32(out, static_cast<uint32_t>(sink));
            }
            g_sink += sink;
        });
        report("read+appendBigEndian32", sample);
    }

    // ---- pool ----

    void benchObjectPool()
    {
        constexpr size_t kSlots = 128;
        ObjectPool<HandlerBase> pool;
        pool.init(kSlots);
        std::vector<HandlerBase *> held(kSlots, nullptr);
        const Sample sample = run(
            [&](size_t iterations) {
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

    // ---- handler ----

    void benchHandlerQueue()
    {
        HandlerBase handler;
        const std::string body(1024, 'x');
        const Sample pushTake = run([&](size_t iterations) {
            uint64_t sink = 0;
            for (size_t i = 0; i < iterations; ++i)
            {
                handler.pushResponse(body);
                sink += handler.takeResponse().size();
            }
            g_sink += sink;
        });
        report("HandlerBase::pushResponse+takeResponse (1KiB)", pushTake, 1024.0);

        const Sample echo = run([&](size_t iterations) {
            uint64_t sink = 0;
            for (size_t i = 0; i < iterations; ++i)
            {
                handler.appendRequest(body.data(), static_cast<ssize_t>(body.size()));
                handler.process();
                sink += handler.takeResponse().size();
            }
            g_sink += sink;
        });
        report("HandlerBase::process echo (1KiB)", echo, 1024.0);
    }

    // ---- hexdump ----

    void benchHexdump()
    {
        const unsigned char bytes[16] = {0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x00,
                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        const Sample shape = run([&](size_t iterations) {
            uint64_t sink = 0;
            for (size_t i = 0; i < iterations; ++i)
                sink += mynetdump::shapeOf(bytes, sizeof bytes)[0];
            g_sink += sink;
        });
        report("mynetdump::shapeOf (16B)", shape);

        const Sample writeDown = run([&](size_t iterations) {
            uint64_t sink = 0;
            for (size_t i = 0; i < iterations; ++i)
            {
                mynetdump::writeDown("bench", bytes, sizeof bytes);
                sink += 1;
            }
            g_sink += sink;
        });
        report("mynetdump::writeDown (16B, logging on)", writeDown);
    }

    // ---- multiplexer ----

    void benchMultiplexerRoundTrip()
    {
        class NoopMux : public Multiplexer<HandlerBase>
        {
        };
        constexpr size_t kStreams = 64;

        // One connection, reused by every pass. Constructing the multiplexer builds
        // the stream pool, and a fresh pool per pass would put that construction on
        // the same line as the round trip it is supposed to measure.
        NoopMux mux;
        mux.process(); // announce SETTINGS once, outside the measurement
        while (mux.hasResponse())
            mux.takeResponse();

        const Sample sample = run(
            [&](size_t iterations) {
                uint64_t sink = 0;
                for (size_t pass = 0; pass < iterations; ++pass)
                {
                    for (size_t k = 0; k < kStreams; ++k)
                    {
                        const uint32_t id = static_cast<uint32_t>(k * 2 + 1);
                        std::string bytes;
                        appendFrame(bytes, Frame{.streamId = id,
                                                 .type = FrameType::headers,
                                                 .flags = FrameFlags::kEndHeaders,
                                                 .payload = "h"});
                        appendFrame(bytes, Frame{.streamId = id,
                                                 .type = FrameType::data,
                                                 .flags = FrameFlags::kEndStream,
                                                 .payload = "payload"});
                        mux.appendRequest(bytes.data(), static_cast<ssize_t>(bytes.size()));
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
    mynetlog::init(); // the sink must exist before the first LOG_*
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
    benchFrameEncode(1024);
    benchFrameEncode(16384);
    benchFrameDecode(16);
    benchFrameDecode(1024);
    benchFrameDecode(16384);
    benchBigEndian();
    benchObjectPool();
    benchHandlerQueue();
    benchHexdump();
    benchMultiplexerRoundTrip();

    std::printf("\nns/op is the median of %d runs of the same body; 'best' is the fastest of them.\n", kRepeats);
    std::printf("Log lines go to stderr: run ./bench_core 2>/dev/null for a clean report.\n");
    return EXIT_SUCCESS;
}
