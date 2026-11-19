#pragma once

/**
 * @file pinning.hpp
 * @brief TLS 证书与 SPKI 公钥 SHA-256 锁定校验器 (借鉴 sing-box common/tls/std_client.go)
 *
 * 核心安全机制：
 * 1. 免疫系统 CA 投毒与企业/防火墙 MITM 解密：直接锁定服务端证书或其公钥的 SHA-256 密码学指纹；
 * 2. 支持 Certificate SHA-256 Pinning：校验对端叶子 DER 证书哈希；
 * 3. 支持 SPKI (SubjectPublicKeyInfo) SHA-256 Pinning：校验对端公钥哈希（证书轮换只要公钥不变即可保持连通）；
 * 4. 纯现代 C++26 实现，零异常 (-fno-exceptions)，安全嵌入 OpenSSL 校验回调。
 */

#include <cstdint>
#include <cstring>
#include <span>
#include <vector>
#include <string>
#include <string_view>
#include <optional>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include "../crypto.hpp"

namespace mynet::tls
{

    class CertPinner
    {
    public:
        /**
         * @brief 计算数据段的 SHA-256 哈希值 (复用 mynet::crypto::sha256 单一真实源)
         */
        [[nodiscard]] static std::vector<uint8_t> sha256(std::span<const uint8_t> data) noexcept
        {
            auto opt = mynet::crypto::sha256(data);
            if (!opt) return {};
            return std::vector<uint8_t>(opt->begin(), opt->end());
        }

        /**
         * @brief 计算 X509 叶子证书 DER 编码的 SHA-256 指纹 (Hex 字符串)
         */
        [[nodiscard]] static std::string getCertificateSha256Hex(X509* cert) noexcept
        {
            if (cert == nullptr) return "";
            uint8_t* der = nullptr;
            int len = ::i2d_X509(cert, &der);
            if (len <= 0 || der == nullptr) return "";

            auto hash = mynet::crypto::sha256(std::span<const uint8_t>(der, static_cast<size_t>(len)));
            ::OPENSSL_free(der);
            if (!hash) return "";
            return mynet::crypto::toHex(*hash);
        }

        /**
         * @brief 计算 X509 证书 SubjectPublicKeyInfo (SPKI) 的 SHA-256 指纹 (Hex 字符串)
         */
        [[nodiscard]] static std::string getPublicKeySha256Hex(X509* cert) noexcept
        {
            if (cert == nullptr) return "";
            const X509_PUBKEY* pubkey = ::X509_get_X509_PUBKEY(cert);
            if (pubkey == nullptr) return "";

            uint8_t* der = nullptr;
            int len = ::i2d_X509_PUBKEY(const_cast<X509_PUBKEY*>(pubkey), &der);
            if (len <= 0 || der == nullptr) return "";

            auto hash = mynet::crypto::sha256(std::span<const uint8_t>(der, static_cast<size_t>(len)));
            ::OPENSSL_free(der);
            if (!hash) return "";
            return mynet::crypto::toHex(*hash);
        }

        /**
         * @brief 验证对端证书是否匹配预设的证书或公钥 SHA-256 白名单
         *
         * @param cert 对端叶子证书
         * @param pinnedCertHashes 锁定的证书 SHA-256 列表 (全小写 Hex)
         * @param pinnedPubkeyHashes 锁定的公钥 SPKI SHA-256 列表 (全小写 Hex)
         * @return 命中任一锁定指纹返回 true，否则返回 false
         */
        [[nodiscard]] static bool verifyPeerCertificate(
            X509* cert,
            const std::vector<std::string>& pinnedCertHashes,
            const std::vector<std::string>& pinnedPubkeyHashes) noexcept
        {
            if (pinnedCertHashes.empty() && pinnedPubkeyHashes.empty())
            {
                return true; // 未配置 pinning 则直接通过
            }
            if (cert == nullptr) return false;

            // 1. 比对 Certificate SHA-256
            if (!pinnedCertHashes.empty())
            {
                std::string certHash = getCertificateSha256Hex(cert);
                for (const auto& target : pinnedCertHashes)
                {
                    if (!target.empty() && strcasecmp(certHash.c_str(), target.c_str()) == 0)
                    {
                        return true;
                    }
                }
            }

            // 2. 比对 Public Key (SPKI) SHA-256
            if (!pinnedPubkeyHashes.empty())
            {
                std::string pubkeyHash = getPublicKeySha256Hex(cert);
                for (const auto& target : pinnedPubkeyHashes)
                {
                    if (!target.empty() && strcasecmp(pubkeyHash.c_str(), target.c_str()) == 0)
                    {
                        return true;
                    }
                }
            }

            return false;
        }
    };

} // namespace mynet::tls
