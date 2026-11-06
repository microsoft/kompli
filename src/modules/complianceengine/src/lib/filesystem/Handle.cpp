// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "ContextInterface.h"
#include "FTWDirectoryCursor.hpp"
#include "FilesystemHelpers.hpp"

#include <cerrno>
#include <cstring>
#include <utility>
namespace ComplianceEngine
{
namespace Filesystem
{
namespace FTW
{
namespace Detail
{

DirectoryCursor::DirectoryCursor(const ContextInterface& context, DIR* stream) noexcept
    : mContext(context),
      mDirectory(stream)
{
}

DirectoryCursor::DirectoryCursor(DirectoryCursor&& other) noexcept
    : mContext(other.mContext),
      mDirectory(other.mDirectory)
{
    other.mDirectory = nullptr;
}

DirectoryCursor& DirectoryCursor::operator=(DirectoryCursor&& other) & noexcept
{
    if (this != &other)
    {
        DirectoryCursor replaced(std::move(*this));
        mContext = other.mContext;
        mDirectory = other.mDirectory;
        other.mDirectory = nullptr;
    }
    return *this;
}

DirectoryCursor::~DirectoryCursor() noexcept
{
    Close();
}

void DirectoryCursor::Close() noexcept
{
    if (!mDirectory)
        return;
    DIR* stream = mDirectory;
    mDirectory = nullptr;
    const ContextInterface& context = mContext.get();
    Result<void> closed = context.CloseOwnedDirectoryCursor(stream);
    if (!closed)
    {
        const int saved = closed.Error().code;
        const OsConfigLogHandle log = context.GetLogHandle();
        OsConfigLogError(log, "Failed to close filesystem resource: %s%s", strerror(saved), EBADF == saved ? " (ownership bug)" : "");
    }
}

Result<Optional<DirectoryChild>> DirectoryCursor::NextEntry()
{
    if (!mDirectory)
    {
        return Error("Cannot read closed pinned directory", EBADF);
    }

    for (;;)
    {
        errno = 0;
        const struct dirent* entry = mContext.get().ReadDirectory(mDirectory);
        if (!entry)
        {
            if (errno != 0)
            {
                return Error("Cannot read pinned directory", ::ComplianceEngine::Filesystem::Detail::SavedError());
            }
            return Optional<DirectoryChild>();
        }
        const std::string name(entry->d_name);
        if (("." == name) || (".." == name))
        {
            continue;
        }

        if (!::ComplianceEngine::Filesystem::Detail::IsSingleChildComponent(name))
        {
            return Error("Pinned directory returned an invalid child name", EINVAL);
        }
        DirectoryChild child;
        child.name = name;
        child.type = entry->d_type;
        return Optional<DirectoryChild>(std::move(child));
    }
}

} // namespace Detail
} // namespace FTW
} // namespace Filesystem
} // namespace ComplianceEngine
