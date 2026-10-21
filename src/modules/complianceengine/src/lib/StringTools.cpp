// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <StringTools.h>
#include <algorithm>
#include <cctype>
#include <limits>
#include <stdexcept>

namespace ComplianceEngine
{

// Security: Escapes characters that have special meaning inside double-quoted shell strings.
// Characters escaped: \ " ` $
// The result MUST be used inside double quotes in the shell command.
std::string EscapeForShell(const std::string& str)
{
    std::string escapedStr;
    escapedStr.reserve(str.size() * 2); // Pre-allocate for worst case

    for (char c : str)
    {
        switch (c)
        {
            case '\\':
            case '"':
            case '`':
            case '$':
                escapedStr += '\\';
                // fall through
            default:
                escapedStr += c;
        }
    }
    return escapedStr;
}

std::string StringOrEmpty(const char* s)
{
    return (nullptr == s) ? std::string() : std::string(s);
}

bool IsAsciiWhitespace(unsigned char value)
{
    switch (value)
    {
        case ' ':
        case '\t':
        case '\n':
        case '\r':
        case '\v':
        case '\f':
            return true;
        default:
            return false;
    }
}

std::string TrimWhiteSpaces(const std::string& str)
{
    const auto isWhitespace = [](unsigned char character) { return std::isspace(character); };
    auto start = std::find_if_not(str.begin(), str.end(), isWhitespace);
    auto end = std::find_if_not(str.rbegin(), str.rend(), isWhitespace).base();
    if (start < end)
    {
        return std::string(start, end);
    }
    return std::string();
}

std::string StripComment(const std::string& str)
{
    return str.substr(0, str.find('#'));
}

std::string ToLower(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char character) { return static_cast<char>(std::tolower(character)); });
    return value;
}

Result<int> TryStringToInt(const std::string& str, int base)
{
    try
    {
        std::size_t consumed = 0;
        const int value = std::stoi(str, &consumed, base);
        if (str.size() != consumed)
        {
            return Error("Invalid integer value: " + str, EINVAL);
        }
        return value;
    }
    catch (const std::invalid_argument&)
    {
        return Error("Invalid integer value: " + str, EINVAL);
    }
    catch (const std::out_of_range&)
    {
        return Error("Integer value out of range: " + str, ERANGE);
    }
}
Result<unsigned int> TryStringToUint(const std::string& str, int base)
{
    try
    {
        const auto first = str.find_first_not_of(" \t\n\r\v\f");
        if ((first != std::string::npos) && ('-' == str[first]))
        {
            const auto signedValue = TryStringToInt(str, base);
            if (!signedValue.HasValue())
            {
                return signedValue.Error();
            }
            return Error("Invalid integer value (should be positive): " + std::to_string(signedValue.Value()), EINVAL);
        }

        std::size_t consumed = 0;
        const auto value = std::stoull(str, &consumed, base);
        if (str.size() != consumed)
        {
            return Error("Invalid integer value: " + str, EINVAL);
        }
        if (std::numeric_limits<unsigned int>::max() < value)
        {
            return Error("Integer value out of range: " + str, ERANGE);
        }
        return static_cast<unsigned int>(value);
    }
    catch (const std::invalid_argument&)
    {
        return Error("Invalid integer value: " + str, EINVAL);
    }
    catch (const std::out_of_range&)
    {
        return Error("Integer value out of range: " + str, ERANGE);
    }
}
} // namespace ComplianceEngine
