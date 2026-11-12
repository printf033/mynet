#include "handler/sockmap.hpp"
#include "connection.hpp"
#include <gtest/gtest.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace mynet;
using namespace mynet::handler::sockmap;

namespace
{
    struct MockConnectionHandler : HandlerConnection
    {
        void process() {}
    };
} // namespace

TEST(SockmapTest, IsSupportedCheck)
{
    // 验证探测函数可安全调用且不抛异常
    bool supported = SockmapManager::isSupported();
    (void)supported;
}

TEST(SockmapTest, FallbackToSpliceWhenNoBpfMap)
{
    int sv[2] = {-1, -1};
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);

    MockConnectionHandler handler;
    EXPECT_FALSE(handler.isSpliceActive());

    // 传入 sockmapFd = -1，应平滑回退至 Linux splice(2) 管道直通模式
    bool ok = SockmapManager::enableOffloadOrSplice(handler, sv[0], sv[1], -1);
    EXPECT_TRUE(ok);
    EXPECT_TRUE(handler.isSpliceActive());
    EXPECT_EQ(handler.spliceTarget(), sv[1]);

    ::close(sv[0]);
    ::close(sv[1]);
}

TEST(SockmapTest, InvalidFdRejection)
{
    MockConnectionHandler handler;
    EXPECT_FALSE(SockmapManager::enableOffloadOrSplice(handler, -1, -1, -1));
    EXPECT_FALSE(SockmapManager::attachPair(-1, 0, 1));
}
