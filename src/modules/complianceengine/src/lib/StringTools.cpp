// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <StringTools.h>
#include <algorithm>
#include <cctype>
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
    auto try_int = TryStringToInt(str, base);
    if (!try_int.HasValue())
    {
        return try_int.Error();
    }
    if (try_int.Value() < 0)
    {
        return Error("Invalid integer value (should be positive): " + std::to_string(try_int.Value()));
    }

    return Result<unsigned int>(try_int.Value());
}
} // namespace ComplianceEngine
