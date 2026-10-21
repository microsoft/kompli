// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ContextInterface.h"

#include <cerrno>
#include <fcntl.h>
#include <unistd.h>

namespace ComplianceEngine
{
// Provide a definition for the virtual destructor
ContextInterface::~ContextInterface() = default;

int ContextInterface::OpenExistingFile(const char* path, int flags) const
{
    if (0 != (flags & ~(O_PATH | O_CLOEXEC | O_NOFOLLOW)))
    {
        errno = EINVAL;
        return -1;
    }
    return ::open(path, flags);
}

int ContextInterface::StatFileDescriptor(int descriptor, struct stat* metadata) const
{
    return ::fstat(descriptor, metadata);
}

ssize_t ContextInterface::ReadFileDescriptor(int descriptor, void* buffer, std::size_t size) const
{
    return ::read(descriptor, buffer, size);
}

int ContextInterface::CloseFileDescriptor(int descriptor) const
{
    return ::close(descriptor);
}
} // namespace ComplianceEngine
