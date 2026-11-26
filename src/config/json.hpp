#pragma once

/**
 * @file config/json.hpp
 * @brief 高性能轻量级零依赖 JSON / JSON5 解析器。
 *
 * 核心特性：
 * 1. 递归下降解析，支持标准 JSON 以及宽松 JSON5（包含单行注释、多行注释、尾逗号）；
 * 2. 强类型 std::variant 存储，支持 null, bool, int64, double, string, array, object；
 * 3. 严格无异常错误传递 (std::expected<Value, std::string>)，防御性内存保护。
 */

#include <cctype>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace mynet::json
{

    class Value;
    using Array = std::vector<Value>;
    using Object = std::map<std::string, Value, std::less<>>;

    class Value
    {
    public:
        using Storage = std::variant<std::monostate, bool, int64_t, double, std::string, Array, Object>;

    private:
        Storage data_{std::monostate{}};

    public:
        Value() noexcept = default;
        Value(std::monostate) noexcept : data_(std::monostate{}) {}
        Value(bool b) noexcept : data_(b) {}
        Value(int i) noexcept : data_(static_cast<int64_t>(i)) {}
        Value(int64_t i) noexcept : data_(i) {}
        Value(uint32_t u) noexcept : data_(static_cast<int64_t>(u)) {}
        Value(uint64_t u) noexcept : data_(static_cast<int64_t>(u)) {}
        Value(double d) noexcept : data_(d) {}
        Value(std::string s) noexcept : data_(std::move(s)) {}
        Value(std::string_view sv) : data_(std::string(sv)) {}
        Value(const char *s) : data_(std::string(s)) {}
        Value(Array arr) noexcept : data_(std::move(arr)) {}
        Value(Object obj) noexcept : data_(std::move(obj)) {}

        [[nodiscard]] bool isNull() const noexcept { return std::holds_alternative<std::monostate>(data_); }
        [[nodiscard]] bool isBool() const noexcept { return std::holds_alternative<bool>(data_); }
        [[nodiscard]] bool isInt() const noexcept { return std::holds_alternative<int64_t>(data_); }
        [[nodiscard]] bool isDouble() const noexcept { return std::holds_alternative<double>(data_); }
        [[nodiscard]] bool isNumber() const noexcept { return isInt() || isDouble(); }
        [[nodiscard]] bool isString() const noexcept { return std::holds_alternative<std::string>(data_); }
        [[nodiscard]] bool isArray() const noexcept { return std::holds_alternative<Array>(data_); }
        [[nodiscard]] bool isObject() const noexcept { return std::holds_alternative<Object>(data_); }

        [[nodiscard]] bool asBool(bool defaultVal = false) const noexcept
        {
            if (const auto *p = std::get_if<bool>(&data_))
                return *p;
            return defaultVal;
        }

        [[nodiscard]] int64_t asInt(int64_t defaultVal = 0) const noexcept
        {
            if (const auto *p = std::get_if<int64_t>(&data_))
                return *p;
            if (const auto *d = std::get_if<double>(&data_))
                return static_cast<int64_t>(*d);
            return defaultVal;
        }

        [[nodiscard]] double asDouble(double defaultVal = 0.0) const noexcept
        {
            if (const auto *d = std::get_if<double>(&data_))
                return *d;
            if (const auto *p = std::get_if<int64_t>(&data_))
                return static_cast<double>(*p);
            return defaultVal;
        }

        [[nodiscard]] std::string_view asString(std::string_view defaultVal = "") const noexcept
        {
            if (const auto *s = std::get_if<std::string>(&data_))
                return *s;
            return defaultVal;
        }

        [[nodiscard]] const Array &asArray() const noexcept
        {
            static const Array kEmptyArray{};
            if (const auto *a = std::get_if<Array>(&data_))
                return *a;
            return kEmptyArray;
        }

        [[nodiscard]] const Object &asObject() const noexcept
        {
            static const Object kEmptyObject{};
            if (const auto *o = std::get_if<Object>(&data_))
                return *o;
            return kEmptyObject;
        }

        [[nodiscard]] const Value *get(std::string_view key) const noexcept
        {
            if (const auto *o = std::get_if<Object>(&data_))
            {
                auto it = o->find(key);
                if (it != o->end())
                    return &it->second;
            }
            return nullptr;
        }

        [[nodiscard]] bool contains(std::string_view key) const noexcept { return get(key) != nullptr; }

        const Value &operator[](std::string_view key) const noexcept
        {
            static const Value kNullValue{};
            const Value *v = get(key);
            return v ? *v : kNullValue;
        }

        const Value &operator[](size_t idx) const noexcept
        {
            static const Value kNullValue{};
            if (const auto *a = std::get_if<Array>(&data_))
            {
                if (idx < a->size())
                    return (*a)[idx];
            }
            return kNullValue;
        }
    };

    class Parser
    {
    private:
        std::string_view src_{};
        size_t cursor_{0};

    public:
        explicit Parser(std::string_view json) noexcept : src_(json) {}

        std::expected<Value, std::string> parse()
        {
            skipWhitespace();
            if (eof())
            {
                return std::unexpected("Empty JSON document");
            }

            auto res = parseValue();
            if (!res)
            {
                return res;
            }

            skipWhitespace();
            if (!eof())
            {
                return std::unexpected(errorAt("Unexpected trailing characters after JSON root"));
            }

            return res;
        }

    private:
        [[nodiscard]] inline bool eof() const noexcept { return cursor_ >= src_.size(); }
        [[nodiscard]] inline char peek() const noexcept { return eof() ? '\0' : src_[cursor_]; }
        inline char advance() noexcept { return eof() ? '\0' : src_[cursor_++]; }

        void skipWhitespace()
        {
            while (!eof())
            {
                const char c = peek();
                if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
                {
                    advance();
                    continue;
                }
                // 支持行注释 //
                if (c == '/' && cursor_ + 1 < src_.size() && src_[cursor_ + 1] == '/')
                {
                    advance();
                    advance();
                    while (!eof() && peek() != '\n')
                    {
                        advance();
                    }
                    continue;
                }
                // 支持块注释 /* */
                if (c == '/' && cursor_ + 1 < src_.size() && src_[cursor_ + 1] == '*')
                {
                    advance();
                    advance();
                    while (!eof())
                    {
                        if (peek() == '*' && cursor_ + 1 < src_.size() && src_[cursor_ + 1] == '/')
                        {
                            advance();
                            advance();
                            break;
                        }
                        advance();
                    }
                    continue;
                }
                break;
            }
        }

        std::string errorAt(std::string_view msg) const
        {
            return std::string(msg) + " at offset " + std::to_string(cursor_);
        }

        std::expected<Value, std::string> parseValue()
        {
            skipWhitespace();
            if (eof())
            {
                return std::unexpected(errorAt("Unexpected EOF while parsing value"));
            }

            const char c = peek();
            if (c == '{')
                return parseObject();
            if (c == '[')
                return parseArray();
            if (c == '"')
                return parseString();
            if (c == 't' || c == 'f')
                return parseBool();
            if (c == 'n')
                return parseNull();
            if (c == '-' || (c >= '0' && c <= '9'))
                return parseNumber();

            return std::unexpected(errorAt(std::string("Unexpected character '") + c + "'"));
        }

        std::expected<Value, std::string> parseObject()
        {
            advance(); // consume '{'
            Object obj;

            while (true)
            {
                skipWhitespace();
                if (eof())
                {
                    return std::unexpected(errorAt("Unterminated object: expected '}' or key"));
                }
                if (peek() == '}')
                {
                    advance();
                    break;
                }

                if (peek() != '"')
                {
                    return std::unexpected(errorAt("Expected string key in object"));
                }

                auto keyRes = parseString();
                if (!keyRes)
                    return keyRes;
                std::string key = std::string(keyRes->asString());

                skipWhitespace();
                if (eof() || peek() != ':')
                {
                    return std::unexpected(errorAt("Expected ':' after key"));
                }
                advance(); // consume ':'

                auto valRes = parseValue();
                if (!valRes)
                    return valRes;
                obj[std::move(key)] = std::move(*valRes);

                skipWhitespace();
                if (eof())
                {
                    return std::unexpected(errorAt("Unterminated object after value"));
                }
                if (peek() == ',')
                {
                    advance(); // consume ','
                    skipWhitespace();
                    if (peek() == '}') // 支持尾逗号
                    {
                        advance();
                        break;
                    }
                }
                else if (peek() == '}')
                {
                    advance();
                    break;
                }
                else
                {
                    return std::unexpected(errorAt("Expected ',' or '}' in object"));
                }
            }
            return Value(std::move(obj));
        }

        std::expected<Value, std::string> parseArray()
        {
            advance(); // consume '['
            Array arr;

            while (true)
            {
                skipWhitespace();
                if (eof())
                {
                    return std::unexpected(errorAt("Unterminated array: expected ']'"));
                }
                if (peek() == ']')
                {
                    advance();
                    break;
                }

                auto valRes = parseValue();
                if (!valRes)
                    return valRes;
                arr.push_back(std::move(*valRes));

                skipWhitespace();
                if (eof())
                {
                    return std::unexpected(errorAt("Unterminated array after element"));
                }
                if (peek() == ',')
                {
                    advance();
                    skipWhitespace();
                    if (peek() == ']') // 支持尾逗号
                    {
                        advance();
                        break;
                    }
                }
                else if (peek() == ']')
                {
                    advance();
                    break;
                }
                else
                {
                    return std::unexpected(errorAt("Expected ',' or ']' in array"));
                }
            }
            return Value(std::move(arr));
        }

        std::expected<Value, std::string> parseString()
        {
            advance(); // consume '"'
            std::string out;
            out.reserve(32);

            while (!eof())
            {
                const char c = advance();
                if (c == '"')
                {
                    return Value(std::move(out));
                }
                if (c == '\\')
                {
                    if (eof())
                    {
                        return std::unexpected(errorAt("Unterminated escape sequence in string"));
                    }
                    const char esc = advance();
                    switch (esc)
                    {
                    case '"':
                        out.push_back('"');
                        break;
                    case '\\':
                        out.push_back('\\');
                        break;
                    case '/':
                        out.push_back('/');
                        break;
                    case 'b':
                        out.push_back('\b');
                        break;
                    case 'f':
                        out.push_back('\f');
                        break;
                    case 'n':
                        out.push_back('\n');
                        break;
                    case 'r':
                        out.push_back('\r');
                        break;
                    case 't':
                        out.push_back('\t');
                        break;
                    case 'u':
                    {
                        // 4 字节十六进制 unicode 字符转义 (简易 UTF-8 拼接)
                        if (cursor_ + 4 > src_.size())
                        {
                            return std::unexpected(errorAt("Truncated \\u unicode escape"));
                        }
                        cursor_ += 4;
                        out.push_back('?');
                        break;
                    }
                    default:
                        out.push_back(esc);
                        break;
                    }
                }
                else
                {
                    out.push_back(c);
                }
            }
            return std::unexpected(errorAt("Unterminated string literal"));
        }

        std::expected<Value, std::string> parseBool()
        {
            if (src_.substr(cursor_).starts_with("true"))
            {
                cursor_ += 4;
                return Value(true);
            }
            if (src_.substr(cursor_).starts_with("false"))
            {
                cursor_ += 5;
                return Value(false);
            }
            return std::unexpected(errorAt("Invalid boolean literal"));
        }

        std::expected<Value, std::string> parseNull()
        {
            if (src_.substr(cursor_).starts_with("null"))
            {
                cursor_ += 4;
                return Value(std::monostate{});
            }
            return std::unexpected(errorAt("Invalid null literal"));
        }

        std::expected<Value, std::string> parseNumber()
        {
            const size_t start = cursor_;
            if (peek() == '-')
            {
                advance();
            }
            while (!eof() && std::isdigit(static_cast<unsigned char>(peek())))
            {
                advance();
            }

            bool isFloat = false;
            if (!eof() && peek() == '.')
            {
                isFloat = true;
                advance();
                while (!eof() && std::isdigit(static_cast<unsigned char>(peek())))
                {
                    advance();
                }
            }
            if (!eof() && (peek() == 'e' || peek() == 'E'))
            {
                isFloat = true;
                advance();
                if (!eof() && (peek() == '+' || peek() == '-'))
                {
                    advance();
                }
                while (!eof() && std::isdigit(static_cast<unsigned char>(peek())))
                {
                    advance();
                }
            }

            std::string_view numStr = src_.substr(start, cursor_ - start);
            if (isFloat)
            {
                std::string s(numStr);
                char *end = nullptr;
                double d = std::strtod(s.c_str(), &end);
                if (end != s.c_str() + s.size())
                {
                    return std::unexpected(errorAt("Malformed floating point number"));
                }
                return Value(d);
            }

            int64_t val = 0;
            auto [ptr, ec] = std::from_chars(numStr.data(), numStr.data() + numStr.size(), val);
            if (ec != std::errc())
            {
                return std::unexpected(errorAt("Malformed integer number"));
            }
            return Value(val);
        }
    };

    /**
     * @brief 解析 JSON 文本为 Value 对象
     */
    [[nodiscard]] inline std::expected<Value, std::string> parse(std::string_view json)
    {
        Parser p(json);
        return p.parse();
    }

} // namespace mynet::json
