// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <BindingParsers.h>
#include <StringTools.h>
#include <cctype>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>

namespace ComplianceEngine
{
namespace BindingParsers
{
using std::string;

template <>
Result<string> Parse<string>(const string& input)
{
    return input;
}

template <>
Result<int> Parse<int>(const std::string& input)
{
    auto result = TryStringToInt(input);
    if (!result.HasValue())
    {
        return result.Error();
    }

    return std::move(result.Value());
}

template <>
Result<regex> Parse<regex>(const string& input)
{
    try
    {
        return regex(input);
    }
    catch (const std::exception& e)
    {
        return Error("Regular expression '" + input + "' compilation failed: " + e.what(), EINVAL);
    }
}

template <>
Result<Pattern> Parse<Pattern>(const string& input)
{
    return Pattern::Make(input);
}

template <>
Result<bool> Parse<bool>(const string& input)
{
    if (0 == strcasecmp("true", input.c_str()) || 0 == strcasecmp("1", input.c_str()) || 0 == strcasecmp("yes", input.c_str()))
        return true;
    if (0 == strcasecmp("false", input.c_str()) || 0 == strcasecmp("0", input.c_str()) || 0 == strcasecmp("no", input.c_str()))
        return false;
    return Error("Unsupported boolean value string representation: " + input, EINVAL);
}

template <>
Result<mode_t> Parse<mode_t>(const string& input)
{
    errno = 0;
    char* end = nullptr;
    const auto value = std::strtol(input.c_str(), &end, 8);
    if (errno == ERANGE || end == input.c_str())
    {
        // Preserve the error detail previously returned by std::stol.
        return Error("Failed to parse octal value '" + input + "': stol", EINVAL);
    }
    if (end != input.c_str() + input.size())
    {
        return Error("Failed to parse octal value '" + input + "': Unconsumed suffix in octal value", EINVAL);
    }
    const char* first = input.c_str();
    while (std::isspace(static_cast<unsigned char>(*first)))
    {
        ++first;
    }
    if (*first == '-')
    {
        return Error("Failed to parse octal value '" + input + "': Negative octal value", EINVAL);
    }
    if (static_cast<std::uintmax_t>(value) > static_cast<std::uintmax_t>(std::numeric_limits<mode_t>::max()))
    {
        return Error("Failed to parse octal value '" + input + "': Octal value out of range for mode_t", EINVAL);
    }
    return static_cast<mode_t>(value);
}
} // namespace BindingParsers
} // namespace ComplianceEngine
