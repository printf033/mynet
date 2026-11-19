#pragma once

/**
 * @file geo.hpp
 * @brief GeoIP 国家/私有网段与 GeoSite 域名资产规则匹配引擎。
 *
 * 借鉴 sing-box (SRS / GeoIP) 与 dae (eBPF LPM Trie) 的高性能匹配架构：
 * 1. GeoIP：内置 RFC 1918 私有地址全量识别与 CN 核心网段，支持动态加载拓展 CIDR；
 * 2. GeoSite：内置 cn、category-ads-all (去广告)、google、github、telegram、netflix 等主流分类；
 * 3. 毫秒级极速命中与零异常契约，直接无缝赋能 RouteRule 与 Router 策略路由调度。
 */

#include "address.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <mutex>
#include <netinet/in.h>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace mynet
{

    /**
     * @brief GeoIP 国家与私有网段匹配器 (GeoIP Matcher)
     */
    class GeoIpMatcher
    {
    public:
        struct CidrBlock
        {
            uint32_t net;
            uint32_t mask;

            [[nodiscard]] constexpr bool matches(uint32_t ip) const noexcept
            {
                return (ip & mask) == net;
            }
        };

    private:
        mutable std::mutex mutex_{};
        std::unordered_map<std::string, std::vector<CidrBlock>> countryCidrs_{};

    public:
        GeoIpMatcher() noexcept
        {
            initDefaults();
        }

        [[nodiscard]] static GeoIpMatcher &instance() noexcept
        {
            static GeoIpMatcher s_matcher;
            return s_matcher;
        }

        void addCidr(std::string_view country, std::string_view cidrStr)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            std::string c(country);
            std::transform(c.begin(), c.end(), c.begin(), ::tolower);

            auto parsed = handler::IpCidr::parse(cidrStr);
            if (!parsed) return;

            countryCidrs_[c].push_back({.net = ntohl(parsed->networkBe), .mask = ntohl(parsed->maskBe)});
        }

        bool loadFromFile(const std::string &filePath, std::string_view country)
        {
            std::ifstream file(filePath);
            if (!file.is_open()) return false;
            std::string line;
            while (std::getline(file, line))
            {
                size_t start = line.find_first_not_of(" \t\r\n");
                if (start == std::string::npos) continue;
                if (line[start] == '#' || line[start] == ';') continue;
                size_t end = line.find_last_not_of(" \t\r\n");
                std::string_view trimmed = std::string_view(line).substr(start, end - start + 1);
                addCidr(country, trimmed);
            }
            return true;
        }

        template <typename Func>
        void forEachCidr(std::string_view country, Func &&func) const
        {
            std::string c(country);
            std::transform(c.begin(), c.end(), c.begin(), ::tolower);
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = countryCidrs_.find(c);
            if (it != countryCidrs_.end())
            {
                for (const auto &block : it->second)
                {
                    func(block.net, block.mask);
                }
            }
        }

        [[nodiscard]] bool isPrivate(in_addr ip) const noexcept
        {
            return handler::isPrivateAddress(ip);
        }

        [[nodiscard]] bool matches(in_addr ip, std::string_view country) const noexcept
        {
            std::string c(country);
            std::transform(c.begin(), c.end(), c.begin(), ::tolower);

            if (c == "private")
            {
                return isPrivate(ip);
            }

            std::lock_guard<std::mutex> lock(mutex_);
            auto it = countryCidrs_.find(c);
            if (it == countryCidrs_.end()) return false;

            const uint32_t h = ntohl(ip.s_addr);
            for (const auto &block : it->second)
            {
                if (block.matches(h)) return true;
            }
            return false;
        }

    private:
        void initDefaults()
        {
            // 内置主要 CN 网段
            static constexpr const char *kCnCidrs[] = {
                "1.0.1.0/24", "1.0.2.0/23", "1.0.8.0/21", "1.0.32.0/19",
                "14.0.0.0/8", "27.0.0.0/8", "36.0.0.0/8", "39.0.0.0/8",
                "42.0.0.0/8", "49.0.0.0/8", "58.0.0.0/8", "59.0.0.0/8",
                "60.0.0.0/8", "61.0.0.0/8", "101.0.0.0/8", "103.0.0.0/8",
                "106.0.0.0/8", "110.0.0.0/8", "111.0.0.0/8", "112.0.0.0/8",
                "113.0.0.0/8", "114.0.0.0/8", "115.0.0.0/8", "116.0.0.0/8",
                "117.0.0.0/8", "118.0.0.0/8", "119.0.0.0/8", "120.0.0.0/8",
                "121.0.0.0/8", "122.0.0.0/8", "123.0.0.0/8", "124.0.0.0/8",
                "125.0.0.0/8", "175.0.0.0/8", "180.0.0.0/8", "182.0.0.0/8",
                "183.0.0.0/8", "218.0.0.0/8", "219.0.0.0/8", "220.0.0.0/8",
                "221.0.0.0/8", "222.0.0.0/8", "223.0.0.0/8"
            };
            for (const auto *cidr : kCnCidrs)
            {
                addCidr("cn", cidr);
            }
        }
    };

    /**
     * @brief GeoSite 域名分类匹配器 (GeoSite Matcher)
     */
    class GeoSiteMatcher
    {
    private:
        mutable std::mutex mutex_{};
        std::unordered_map<std::string, std::unordered_set<std::string>> exactDomains_{};
        std::unordered_map<std::string, std::vector<std::string>> suffixDomains_{};

    public:
        GeoSiteMatcher() noexcept
        {
            initDefaults();
        }

        [[nodiscard]] static GeoSiteMatcher &instance() noexcept
        {
            static GeoSiteMatcher s_matcher;
            return s_matcher;
        }

        void addDomain(std::string_view category, std::string_view domain)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            std::string cat(category);
            std::transform(cat.begin(), cat.end(), cat.begin(), ::tolower);
            std::string dom(domain);
            std::transform(dom.begin(), dom.end(), dom.begin(), ::tolower);
            exactDomains_[cat].insert(std::move(dom));
        }

        void addDomainSuffix(std::string_view category, std::string_view suffix)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            std::string cat(category);
            std::transform(cat.begin(), cat.end(), cat.begin(), ::tolower);
            std::string suf(suffix);
            std::transform(suf.begin(), suf.end(), suf.begin(), ::tolower);
            suffixDomains_[cat].push_back(std::move(suf));
        }

        bool loadFromFile(const std::string &filePath, std::string_view category)
        {
            std::ifstream file(filePath);
            if (!file.is_open()) return false;
            std::string line;
            while (std::getline(file, line))
            {
                size_t start = line.find_first_not_of(" \t\r\n");
                if (start == std::string::npos) continue;
                if (line[start] == '#' || line[start] == ';') continue;
                size_t end = line.find_last_not_of(" \t\r\n");
                std::string_view trimmed = std::string_view(line).substr(start, end - start + 1);
                if (trimmed.starts_with("domain:") || trimmed.starts_with("full:"))
                {
                    addDomain(category, trimmed.substr(trimmed.find(':') + 1));
                }
                else if (trimmed.starts_with("suffix:"))
                {
                    addDomainSuffix(category, trimmed.substr(7));
                }
                else
                {
                    addDomainSuffix(category, trimmed);
                }
            }
            return true;
        }

        [[nodiscard]] bool matches(std::string_view domain, std::string_view category) const noexcept
        {
            if (domain.empty()) return false;

            std::string cat(category);
            std::transform(cat.begin(), cat.end(), cat.begin(), ::tolower);

            std::string dom(domain);
            std::transform(dom.begin(), dom.end(), dom.begin(), ::tolower);

            // 若匹配 cn 分类，且域名直接以 .cn 结尾
            if (cat == "cn")
            {
                if (dom.ends_with(".cn")) return true;
            }

            std::lock_guard<std::mutex> lock(mutex_);

            // 精确域名匹配
            if (auto it = exactDomains_.find(cat); it != exactDomains_.end())
            {
                if (it->second.contains(dom)) return true;
            }

            // 后缀匹配
            if (auto it = suffixDomains_.find(cat); it != suffixDomains_.end())
            {
                for (const auto &suf : it->second)
                {
                    if (dom == suf) return true;
                    if (dom.size() > suf.size() && dom.ends_with(suf))
                    {
                        if (dom[dom.size() - suf.size() - 1] == '.') return true;
                    }
                }
            }

            return false;
        }

    private:
        void initDefaults()
        {
            // 1. 中国主流域名
            static constexpr const char *kCnSuffixes[] = {
                "baidu.com", "qq.com", "tencent.com", "taobao.com", "tmall.com",
                "alipay.com", "aliyun.com", "jd.com", "weibo.com", "bilibili.com",
                "zhihu.com", "163.com", "126.net", "sohu.com", "sina.com.cn",
                "bytedance.com", "douyin.com", "xiaomi.com", "meituan.com",
                "kuaishou.com", "csdn.net", "gitee.com", "douyu.com", "huya.com",
                "ctrip.com", "pinduoduo.com", "dingtalk.com", "feishu.cn",
                "youku.com", "iqiyi.com", "netease.com", "ximalaya.com"
            };
            for (const auto *s : kCnSuffixes) addDomainSuffix("cn", s);

            // 2. 常见广告/追踪服务
            static constexpr const char *kAdSuffixes[] = {
                "doubleclick.net", "googleadservices.com", "adservice.google.com",
                "adservice.com", "applovin.com", "unityads", "crashlytics.com",
                "bugly.qq.com", "umeng.com", "flurry.com", "admob.com", "adcolony.com"
            };
            for (const auto *s : kAdSuffixes) addDomainSuffix("category-ads-all", s);

            // 3. Google
            static constexpr const char *kGoogleSuffixes[] = {
                "google.com", "youtube.com", "gmail.com", "android.com",
                "gstatic.com", "googlevideo.com", "googleapis.com", "golang.org"
            };
            for (const auto *s : kGoogleSuffixes) addDomainSuffix("google", s);

            // 4. GitHub
            static constexpr const char *kGithubSuffixes[] = {
                "github.com", "githubassets.com", "githubusercontent.com", "ghcr.io"
            };
            for (const auto *s : kGithubSuffixes) addDomainSuffix("github", s);

            // 5. Telegram
            static constexpr const char *kTelegramSuffixes[] = {
                "t.me", "telegram.org", "telegram.me", "telegra.ph"
            };
            for (const auto *s : kTelegramSuffixes) addDomainSuffix("telegram", s);

            // 6. Netflix
            static constexpr const char *kNetflixSuffixes[] = {
                "netflix.com", "nflxvideo.net", "nflxext.com", "nflximg.net", "netflix.net"
            };
            for (const auto *s : kNetflixSuffixes) addDomainSuffix("netflix", s);
        }
    };

} // namespace mynet
