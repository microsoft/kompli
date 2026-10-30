// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "FilesystemHelpers.hpp"

#include "ContextInterface.h"

#include <cerrno>
#include <sys/stat.h>

namespace ComplianceEngine
{
namespace Filesystem
{
namespace Detail
{
int SavedError() noexcept
{
    return (errno != 0) ? errno : EIO;
}

void LogSecondaryClose(const ContextInterface& context, int error)
{
    OsConfigLogError(context.GetLogHandle(), "Secondary filesystem helper close failure: %d", error);
}

bool SameIdentity(const struct stat& first, const struct stat& second) noexcept
{
    return (first.st_dev == second.st_dev) && (first.st_ino == second.st_ino) && ((first.st_mode & S_IFMT) == (second.st_mode & S_IFMT));
}

bool IsSingleChildComponent(const std::string& component) noexcept
{
    return !component.empty() && (component != ".") && (component != "..") && (component.find('/') == std::string::npos) &&
           (component.find('\0') == std::string::npos);
}
} // namespace Detail
} // namespace Filesystem
} // namespace ComplianceEngine
