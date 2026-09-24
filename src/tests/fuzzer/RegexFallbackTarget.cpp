#define USE_REGEX_FALLBACK 1
#include <RegexFallback.h>
#include <cstddef>
#include <cstdlib>
#include <string>

int RegexFallbackSearchTarget(const char* data, std::size_t size)
{
    if (size < 4 || size > 4096)
    {
        return -1;
    }
    const auto controls = static_cast<unsigned char>(data[0]) ^ '0';
    const std::string input(data + 3, size - 3);
    const auto separator = input.find('\n');
    if (separator == std::string::npos || separator > 256)
    {
        return -1;
    }
    const auto patternText = input.substr(0, separator);
    const auto contents = input.substr(separator + 1);
    const auto beginOffset = (static_cast<unsigned char>(data[1]) ^ '0') % (contents.size() + 1);
    const auto endOffset = contents.size() - (static_cast<unsigned char>(data[2]) ^ '0') % (contents.size() - beginOffset + 1);
    auto flags = std::regex_constants::match_default;
    if (controls & 1)
    {
        flags |= std::regex_constants::match_continuous;
    }
    if (controls & 2)
    {
        flags |= std::regex_constants::match_not_null;
    }
    if ((controls & 4) && beginOffset > 0)
    {
        flags |= std::regex_constants::match_prev_avail;
    }
    if (controls & 8)
    {
        flags |= std::regex_constants::match_not_bol;
    }
    if (controls & 16)
    {
        flags |= std::regex_constants::match_not_eol;
    }
    auto syntax = std::regex_constants::extended;
    if (controls & 32)
    {
        syntax |= std::regex_constants::icase;
    }
    try
    {
        const regex pattern(patternText, syntax);
        smatch match;
        const bool found = regex_search(contents.cbegin() + beginOffset, contents.cbegin() + endOffset, match, pattern, flags);
        if (!match.ready() || match.empty() == found)
        {
            std::abort();
        }
        if (found)
        {
            if (((controls & 1) && match.position(0) != 0) || ((controls & 2) && match.length(0) == 0))
            {
                std::abort();
            }
            for (std::size_t index = 0; index < match.size(); ++index)
            {
                if (!match[index].matched)
                {
                    continue;
                }
                const auto position = match.position(index);
                const auto length = match.length(index);
                if (position > endOffset - beginOffset || length > endOffset - beginOffset - position ||
                    match[index].str() != contents.substr(beginOffset + position, length))
                {
                    std::abort();
                }
            }
        }
    }
    catch (const regex_error&)
    {
        return -1;
    }
    return 0;
}
