// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#include "DirTools.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

namespace ComplianceEngine
{
bool MkdirRecursive(const std::string& path, mode_t mode)
{
    if (path.empty())
        return false;

    std::vector<std::string> components;
    for (size_t begin = 0; begin < path.size();)
    {
        begin = path.find_first_not_of('/', begin);
        if (begin == std::string::npos)
            break;

        const size_t end = path.find('/', begin);
        const std::string component = path.substr(begin, end - begin);
        if (component == "." || component == "..")
            return false;
        components.push_back(component);
        begin = end;
    }

    if (components.empty())
        return false;

    int directoryFd = ::open(path[0] == '/' ? "/" : ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directoryFd < 0)
        return false;

    for (const auto& component : components)
    {
        if (::mkdirat(directoryFd, component.c_str(), mode) != 0 && errno != EEXIST)
        {
            ::close(directoryFd);
            return false;
        }

        const int childFd = ::openat(directoryFd, component.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        ::close(directoryFd);
        if (childFd < 0)
            return false;
        directoryFd = childFd;
    }

    const bool success = ::fchmod(directoryFd, mode) == 0;
    ::close(directoryFd);
    return success;
}

} // namespace ComplianceEngine
