#include "log_config.hpp"
#include <gtest/gtest.h>

using namespace mynet;

TEST(LogConfigTest, DefaultInitialization)
{
    // 默认无参初始化，输出到 stderr
    log::init();
    auto &logger = mylog::Logger::getInstance();
    auto cfg = logger.getConfig();
    EXPECT_TRUE(cfg.outputFunction.fn != nullptr);
}

TEST(LogConfigTest, ParameterizedConfiguration)
{
    log::LogConfig logCfg;
    logCfg.level = "DEBUG";
    logCfg.target = log::OutputTarget::None;
    logCfg.timestampUtc = true;
    logCfg.escapeControlChars = false;
    logCfg.fatalAction = "ABORT";
    logCfg.maxLogLength = 2048;

    log::init(logCfg);

    auto &logger = mylog::Logger::getInstance();
    auto cfg = logger.getConfig();
    EXPECT_TRUE(cfg.timestampUtc);
    EXPECT_FALSE(cfg.escapeControlChars);
    EXPECT_EQ(cfg.fatalAction, mylog::FATAL_ACTION::ABORT);
    EXPECT_EQ(cfg.maxLogLength, 2048);

    // 恢复默认配置
    log::init();
}
