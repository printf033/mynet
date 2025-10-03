#ifndef MYNET_SRC_PROTOCOL_HPP
#define MYNET_SRC_PROTOCOL_HPP

/*********************** Protocol **********************/
// ask（客户端操作类型）
enum class CLI : int
{
    CHECK_UNIVERSAL = 0,
    CHECK_ATTRIBUTE,
    CHECK_SERVEPLACE,
    CHECK_IMPROVEMENT,
    CHECK_INFORMATION,
    type_amount
};
// ack（服务器端回复类型）
enum class SER : int
{
    FAILURE = 0,
    SUCCESS,
    SERVER_IS_BUSY,
    NO_SUCH_DATA
};

#endif