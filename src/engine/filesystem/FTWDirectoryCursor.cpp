// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "FTWDirectoryCursor.hpp"

#include "ContextInterface.h"
#include "Descriptor.hpp"
#include "FilesystemHelpers.hpp"

#include <cerrno>
#include <cstring>
#include <utility>
namespace ComplianceEngine
{
namespace Filesystem
{
using Detail::Descriptor;
using Detail::Pin;
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

Result<DirectoryCursor> DirectoryCursor::OpenChildren(::ComplianceEngine::Filesystem::Path::Component owner)
{
    const auto& acquisition = *owner.mAcquisition;
    if (acquisition.mMetadata.FileType() != Type::Directory)
        return Error("Directory enumeration requires a directory pin", EINVAL);
    const auto& context = acquisition.mDescriptor.Context();
    auto activated = Pin::ActivateReadOnly(context, acquisition.mDescriptor, acquisition.mMetadata.Stat(), Type::Directory);
    if (!activated.HasValue())
        return std::move(activated).Error();
    Descriptor operational = std::move(activated).Value();
    return context.OpenDirectoryCursor(std::move(operational));
}

} // namespace Detail
} // namespace FTW
} // namespace Filesystem
} // namespace ComplianceEngine

namespace ComplianceEngine
{
using Filesystem::Detail::Descriptor;

Result<void> ContextInterface::CloseOwnedDirectoryCursor(DIR* stream) const noexcept
{
    ReleaseManagedDescriptor();
    return CloseDirectory(stream);
}
Result<Filesystem::FTW::Detail::DirectoryCursor> ContextInterface::OpenDirectoryCursor(Descriptor&& owner) const&
{
    owner.RequireOwnership();
    if (&owner.mContext.get() != this)
    {
        return Error("Foreign directory stream descriptor", EINVAL);
    }
    DIR* stream = FdOpenDirectory(owner.mDescriptor);
    if (!stream)
    {
        return Error("Cannot open directory stream", errno ? errno : EIO);
    }
    owner.mDescriptor = -1;
    return Filesystem::FTW::Detail::DirectoryCursor(*this, stream);
}

} // namespace ComplianceEngine
