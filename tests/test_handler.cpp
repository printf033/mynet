// HandlerBase, HandlerHttp and HandlerTrace: what a front end owes the
// connection that drives it -- the request buffer it reads into, the response
// queue it drains, and the back-pressure credit in between.
#include "handler.hpp"
#include <gtest/gtest.h>
#include <string>

namespace
{
    void feed(HandlerBase &handler, const std::string &bytes)
    {
        handler.appendRequest(bytes.data(), static_cast<ssize_t>(bytes.size()));
    }
} // namespace

TEST(HandlerBase, ProcessEchoesWhateverWasAppended)
{
    HandlerBase handler;
    feed(handler, "hello");
    EXPECT_FALSE(handler.hasResponse());
    handler.process();
    ASSERT_TRUE(handler.hasResponse());
    EXPECT_EQ(handler.takeResponse(), "hello");
    EXPECT_EQ(handler.requestBytes(), size_t{0}); // the echo consumed the request
}

TEST(HandlerBase, ProcessOnAnEmptyBufferProducesNothing)
{
    HandlerBase handler;
    handler.process();
    EXPECT_FALSE(handler.hasResponse());
}

TEST(HandlerBase, ResponseQueueIsFifo)
{
    HandlerBase handler;
    handler.pushResponse("first");
    handler.pushResponse(std::string("second"));
    EXPECT_EQ(handler.responseCount(), size_t{2});
    EXPECT_EQ(handler.takeResponse(), "first");
    EXPECT_EQ(handler.takeResponse(), "second");
    EXPECT_TRUE(handler.takeResponse().empty()); // draining an empty queue is not an error
    EXPECT_FALSE(handler.hasResponse());
}

TEST(HandlerBase, PushResponseFromABufferCopiesTheBytes)
{
    HandlerBase handler;
    const std::string bytes = "abcdef";
    handler.pushResponse(bytes.data(), 3);
    EXPECT_EQ(handler.takeResponse(), "abc");
}

TEST(HandlerBase, RequestLimitDrivesReadCredit)
{
    HandlerBase handler;
    handler.setMaxRequestBytes(8);
    EXPECT_EQ(handler.readCredit(), size_t{8});
    feed(handler, "abc");
    EXPECT_FALSE(handler.requestOverLimit());
    EXPECT_EQ(handler.readCredit(), size_t{5});
    feed(handler, "defghi");
    EXPECT_EQ(handler.requestBytes(), size_t{9});
    EXPECT_TRUE(handler.requestOverLimit());
    EXPECT_EQ(handler.readCredit(), size_t{0}); // no credit past the limit, never underflowed
}

TEST(HandlerBase, RequestConsumeAndClearMoveTheCursor)
{
    HandlerBase handler;
    feed(handler, "abcdef");
    handler.requestConsume(2);
    EXPECT_EQ(handler.requestBytes(), size_t{4});
    EXPECT_EQ(std::string(handler.requestBegin(), handler.requestBytes()), "cdef");
    handler.requestClear();
    EXPECT_EQ(handler.requestBytes(), size_t{0});
}

TEST(HandlerBase, CloseAfterResponseDefaultsOffAndIsSettable)
{
    HandlerBase handler;
    EXPECT_FALSE(handler.closeAfterResponse());
    handler.setCloseAfterResponse(true);
    EXPECT_TRUE(handler.closeAfterResponse());
}

TEST(HandlerBase, ResetClearsRequestsResponsesAndTheCloseFlag)
{
    HandlerBase handler;
    feed(handler, "request");
    handler.pushResponse("response");
    handler.setCloseAfterResponse(true);
    handler.reset();
    EXPECT_EQ(handler.requestBytes(), size_t{0});
    EXPECT_FALSE(handler.hasResponse());
    EXPECT_FALSE(handler.closeAfterResponse());
}

// ---- HandlerHttp ----

TEST(HandlerHttp, ParsesRequestLineHeadersAndBody)
{
    HandlerHttp<HttpMode::request> handler;
    feed(handler, "POST /submit?x=1 HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello");
    handler.process();

    EXPECT_EQ(handler.url(), "/submit?x=1");
    EXPECT_EQ(handler.body(), "hello");
    EXPECT_EQ(handler.headerValue("Host"), "example.com");
    EXPECT_EQ(handler.headerValue("host"), "example.com"); // lookup is case-insensitive
    EXPECT_EQ(handler.headerValue("Missing"), "");
    EXPECT_EQ(std::string(handler.methodName()), "POST");
    EXPECT_EQ(handler.httpMajor(), 1);
    EXPECT_EQ(handler.httpMinor(), 1);
    EXPECT_TRUE(handler.keepAlive());
    EXPECT_FALSE(handler.closeAfterResponse());
}

TEST(HandlerHttp, AnswersWithAMinimalKeepAliveEcho)
{
    HandlerHttp<HttpMode::request> handler;
    feed(handler, "POST / HTTP/1.1\r\nContent-Length: 2\r\n\r\nhi");
    handler.process();
    ASSERT_TRUE(handler.hasResponse());
    const std::string response = handler.takeResponse();
    EXPECT_EQ(response.rfind("HTTP/1.1 200 OK\r\n", 0), size_t{0});
    EXPECT_NE(response.find("Content-Length: 2\r\n"), std::string::npos);
    EXPECT_NE(response.find("Connection: keep-alive\r\n"), std::string::npos);
    EXPECT_EQ(response.substr(response.size() - 2), "hi");
}

TEST(HandlerHttp, Http10WithoutConnectionKeepAliveIsNotKeepAlive)
{
    HandlerHttp<HttpMode::request> handler;
    feed(handler, "GET / HTTP/1.0\r\n\r\n");
    handler.process();
    EXPECT_FALSE(handler.keepAlive());
}

TEST(HandlerHttp, ARequestSplitAcrossTwoAppendsStillParses)
{
    HandlerHttp<HttpMode::request> handler;
    feed(handler, "GET /split HTTP/1.1\r\nHost: ex");
    handler.process();
    // llhttp parses incrementally, so the request line is already understood
    // when the first append ends: the URL is readable while the header
    // section is still open, and the header value is not yet the final one.
    // What the test pins down is that the second append resumes the same
    // message rather than being read as a fresh one.
    EXPECT_EQ(handler.url(), "/split");
    EXPECT_NE(handler.headerValue("Host"), "example.com");
    feed(handler, "ample.com\r\n\r\n");
    handler.process();
    EXPECT_EQ(handler.url(), "/split");
    EXPECT_EQ(handler.headerValue("Host"), "example.com");
}

TEST(HandlerHttp, ParseErrorAnswers400AndCloses)
{
    HandlerHttp<HttpMode::request> handler;
    feed(handler, "\x01\x02 not a request \x03\r\n\r\n");
    handler.process();
    ASSERT_TRUE(handler.hasResponse());
    const std::string response = handler.takeResponse();
    EXPECT_NE(response.find("400 Bad Request"), std::string::npos);
    EXPECT_TRUE(handler.closeAfterResponse());
}

// ---- HandlerTrace ----

TEST(HandlerTrace, EchoesWhatItReceivesAndKeepsTheRequestContract)
{
    HandlerTrace handler;
    feed(handler, "raw bytes");
    handler.process();
    ASSERT_TRUE(handler.hasResponse());
    EXPECT_EQ(handler.takeResponse(), "raw bytes");
    EXPECT_FALSE(handler.closeAfterResponse());
}
