// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ContentVersion.hpp"

#include <cerrno>

namespace ComplianceEngine
{
namespace
{
int CompareDecimal(const std::string& left, const std::string& right)
{
    if (left.size() != right.size())
    {
        return left.size() < right.size() ? -1 : 1;
    }
    if (left != right)
    {
        return left < right ? -1 : 1;
    }
    return 0;
}

bool ValidComponent(const std::string& component)
{
    return !component.empty() && (component.size() == 1 || component[0] != '0') && component.find_first_not_of("0123456789") == std::string::npos;
}
} // namespace

Result<ContentVersion> ParseContentVersion(const std::string& text)
{
    const std::size_t first = text.find('.');
    const std::size_t second = (first == std::string::npos) ? std::string::npos : text.find('.', first + 1);
    if (first == std::string::npos || second == std::string::npos || text.find('.', second + 1) != std::string::npos)
    {
        return Error("Invalid content version '" + text + "': expected MAJOR.MINOR.PATCH", EINVAL);
    }
    ContentVersion version{text.substr(0, first), text.substr(first + 1, second - first - 1), text.substr(second + 1)};
    if (!ValidComponent(version.major) || !ValidComponent(version.minor) || !ValidComponent(version.patch))
    {
        return Error("Invalid content version '" + text + "': expected MAJOR.MINOR.PATCH", EINVAL);
    }
    return version;
}

int CompareContentVersion(const ContentVersion& left, const ContentVersion& right)
{
    const int major = CompareDecimal(left.major, right.major);
    if (major != 0)
    {
        return major;
    }
    const int minor = CompareDecimal(left.minor, right.minor);
    return (minor != 0) ? minor : CompareDecimal(left.patch, right.patch);
}

std::string ContentVersionToString(const ContentVersion& version)
{
    return version.major + "." + version.minor + "." + version.patch;
}
} // namespace ComplianceEngine
