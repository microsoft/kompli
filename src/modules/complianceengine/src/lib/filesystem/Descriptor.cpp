// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "Descriptor.hpp"

#include "FTWDirectoryCursor.hpp"
#include "FilesystemHelpers.hpp"
#include "Handle.hpp" // Filesystem::Type (Directory/RegularFile): OpenAlias/OpenPinAlias mode selector.
#include "ProcfsDescriptorAccess.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <functional>
#include <stdexcept>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <utility>

namespace ComplianceEngine
{
namespace Filesystem
{
namespace Detail
{
namespace
{
// Scalar ownership needs no allocation after the fd is acquired. Only the
// owning wrapper and its trusted context operations can extract the integer;
// this helper never reaches into a Descriptor itself -- every caller below is
// a Descriptor member or a ContextInterface friend operation that has already
// extracted the field it owns, and passes the plain int explicitly.
int RequireOwned(int descriptor)
{
    if (0 > descriptor)
        throw std::logic_error("Descriptor: use after move (no ownership)");
    return descriptor;
}
} // namespace
Descriptor::Descriptor(const ContextInterface& context, int descriptor)
    : mContext(context),
      mDescriptor(descriptor)
{
    if (0 > descriptor)
        throw std::logic_error("Descriptor: construction requires ownership");
}
Descriptor::Descriptor(Descriptor&& other) noexcept
    : mContext(other.mContext),
      mDescriptor(other.mDescriptor)
{
    other.mDescriptor = -1;
}
Descriptor& Descriptor::operator=(Descriptor&& other) & noexcept
{
    if (this != &other)
    {
        ReleaseOwned();
        mContext = other.mContext;
        mDescriptor = other.mDescriptor;
        other.mDescriptor = -1;
    }
    return *this;
}
Descriptor::~Descriptor() noexcept
{
    ReleaseOwned();
}
void Descriptor::ReleaseOwned() noexcept
{
    if (0 > mDescriptor)
        return;
    const ContextInterface& context = mContext.get();
    Result<void> closed = context.CloseOwnedDescriptor(*this);
    if (!closed)
    {
        const int saved = closed.Error().code;
        const OsConfigLogHandle log = context.GetLogHandle();
        OsConfigLogError(log, "Failed to close filesystem resource: %s%s", strerror(saved), EBADF == saved ? " (ownership bug)" : "");
    }
}
} // namespace Detail
} // namespace Filesystem
} // namespace ComplianceEngine

namespace ComplianceEngine
{
class ContextInterface::Reservation
{
public:
    explicit Reservation(const ContextInterface& context)
        : mContext(context)
    {
        auto reserved = context.ReserveManagedDescriptor();
        if (reserved.HasValue())
            mReserved = true;
        else
            mError = std::move(reserved).Error();
    }
    // A temporary context would dangle within this RAII object's own scope:
    // it retains the context reference for mContext's lifetime below.
    explicit Reservation(const ContextInterface&&) = delete;
    // Only ever a local `Reservation charge(*this);`; an implicit copy would
    // double-release the reservation on destruction.
    Reservation(const Reservation&) = delete;
    Reservation& operator=(const Reservation&) = delete;
    Reservation(Reservation&&) = delete;
    Reservation& operator=(Reservation&&) = delete;
    ~Reservation() noexcept
    {
        if (mReserved)
            mContext.get().ReleaseManagedDescriptor();
    }
    bool Acquired() const noexcept
    {
        return mReserved;
    }
    Error Failure() const
    {
        return mError.Value();
    }
    void Transfer() noexcept
    {
        mReserved = false;
    }

private:
    std::reference_wrapper<const ContextInterface> mContext;
    bool mReserved = false;
    Optional<Error> mError;
};

using Filesystem::Detail::Descriptor;

Result<pid_t> ContextInterface::CurrentProcessId() const
{
    const pid_t id = NativeProcessId();
    if (0 >= id)
        return Error("Cannot identify current process", (0 > id) ? (errno ? errno : EIO) : EPROTO);
    return id;
}

Result<pid_t> ContextInterface::CurrentThreadId() const
{
    const pid_t id = NativeThreadId();
    if (0 >= id)
        return Error("Cannot identify current task", (0 > id) ? (errno ? errno : EIO) : EPROTO);
    return id;
}

Result<Descriptor> ContextInterface::OpenAbsolutePin(const char* path) const&
{
    if (!path || *path != '/')
    {
        return Error("Unsupported absolute pin path", EINVAL);
    }
    Reservation charge(*this);
    if (!charge.Acquired())
        return charge.Failure();
    const int fd = OpenNativePath(path, O_PATH | O_NOFOLLOW | O_CLOEXEC | O_DIRECTORY);
    if (fd < 0)
    {
        return Error("Cannot open absolute pin", errno ? errno : EIO);
    }
    charge.Transfer();
    return Descriptor(*this, fd);
}

Result<Descriptor> ContextInterface::OpenAt(const Descriptor& directory, const char* name, OpenProfile profile) const&
{
    Filesystem::Detail::RequireOwned(directory.mDescriptor);
    switch (profile)
    {
        case OpenProfile::PinSelfDirectory:
        case OpenProfile::ReadFdinfo:
        case OpenProfile::FollowAliasFile:
        case OpenProfile::FollowAliasDirectory:
        case OpenProfile::FollowAliasPin:
        case OpenProfile::FollowAliasPinDirectory:
            return Error("Procfs following and alias profiles require verified directories", EINVAL);
        default:
            return OpenVerifiedAt(directory, name, profile);
    }
}

Result<Descriptor> ContextInterface::OpenProcfsSelf(const Descriptor& proc) const&
{
    return OpenVerifiedAt(proc, "self", OpenProfile::PinSelfDirectory);
}

Result<Descriptor> ContextInterface::OpenVerifiedAt(const Descriptor& directory, const char* name, OpenProfile profile) const&
{
    Filesystem::Detail::RequireOwned(directory.mDescriptor);
    if (&directory.mContext.get() != this || !name || !*name || *name == '/')
    {
        return Error("Invalid directory context or relative name", EINVAL);
    }
    int flags = O_CLOEXEC;
    switch (profile)
    {
        case OpenProfile::PinDirectory:
            if (!Filesystem::Detail::IsSingleChildComponent(name))
                return Error("Child pin requires a single component", EINVAL);
            flags |= O_PATH | O_DIRECTORY | O_NOFOLLOW;
            break;
        case OpenProfile::PinSelfDirectory:
            flags |= O_PATH | O_DIRECTORY;
            break;
        case OpenProfile::PinChild:
            if (!Filesystem::Detail::IsSingleChildComponent(name))
                return Error("Child pin requires a single component", EINVAL);
            flags |= O_PATH | O_NOFOLLOW;
            break;
        case OpenProfile::PinChildDirectory:
            if (!Filesystem::Detail::IsSingleChildComponent(name))
                return Error("Child pin requires a single component", EINVAL);
            flags |= O_PATH | O_NOFOLLOW | O_DIRECTORY;
            break;
        case OpenProfile::ReadFdinfo:
            flags |= O_RDONLY | O_NOFOLLOW;
            break;
        case OpenProfile::FollowAliasFile:
            flags |= O_RDONLY;
            break;
        case OpenProfile::FollowAliasDirectory:
            flags |= O_RDONLY | O_DIRECTORY;
            break;
        case OpenProfile::FollowAliasPin:
            flags |= O_PATH;
            break;
        case OpenProfile::FollowAliasPinDirectory:
            flags |= O_PATH | O_DIRECTORY;
            break;
        default:
            return Error("Unsupported descriptor open profile", EINVAL);
    }
    Reservation charge(*this);
    if (!charge.Acquired())
        return charge.Failure();
    const int fd = OpenNativeAt(Filesystem::Detail::RequireOwned(directory.mDescriptor), name, flags);
    if (fd < 0)
    {
        return Error("Cannot open relative descriptor", errno ? errno : EIO);
    }
    charge.Transfer();
    return Descriptor(*this, fd);
}

Result<Descriptor> ContextInterface::OpenFdinfo(const Filesystem::Detail::ProcfsDescriptorAccess& procfs, const Descriptor& target) const&
{
    Filesystem::Detail::RequireOwned(target.mDescriptor);
    // The role-ownership check lives here (the only RequireOwned-visible
    // TU reachable by procfs code), before VerifyRole's own native pid/tid/
    // stat calls -- so a consumed procfs session still throws logic_error
    // before any native dispatch, matching the move-misuse-first ordering.
    Filesystem::Detail::RequireOwned(procfs.mRoles[static_cast<std::size_t>(Filesystem::Detail::ProcfsDescriptorAccess::Role::Fdinfo)].mDescriptor);
    if (!procfs.VerifyRole(*this, Filesystem::Detail::ProcfsDescriptorAccess::Role::Fdinfo))
        return Error("Unverified procfs fdinfo directory", EINVAL);
    Filesystem::Detail::RequireOwned(target.mDescriptor);
    if (&target.mContext.get() != this)
    {
        return Error("Foreign descriptor information target", EINVAL);
    }
    const std::string alias = std::to_string(Filesystem::Detail::RequireOwned(target.mDescriptor));
    return OpenVerifiedAt(procfs.mRoles[static_cast<std::size_t>(Filesystem::Detail::ProcfsDescriptorAccess::Role::Fdinfo)], alias.c_str(), OpenProfile::ReadFdinfo);
}

Result<Descriptor> ContextInterface::OpenAlias(const Filesystem::Detail::ProcfsDescriptorAccess& procfs, const Descriptor& target, Filesystem::Type directoryAlias) const&
{
    Filesystem::Detail::RequireOwned(target.mDescriptor);
    Filesystem::Detail::RequireOwned(procfs.mRoles[static_cast<std::size_t>(Filesystem::Detail::ProcfsDescriptorAccess::Role::Fd)].mDescriptor);
    if (!procfs.VerifyRole(*this, Filesystem::Detail::ProcfsDescriptorAccess::Role::Fd))
        return Error("Unverified procfs fd directory", EINVAL);
    Filesystem::Detail::RequireOwned(target.mDescriptor);
    if (&target.mContext.get() != this)
    {
        return Error("Foreign alias target", EINVAL);
    }
    const std::string alias = std::to_string(Filesystem::Detail::RequireOwned(target.mDescriptor));
    return OpenVerifiedAt(procfs.mRoles[static_cast<std::size_t>(Filesystem::Detail::ProcfsDescriptorAccess::Role::Fd)], alias.c_str(),
        directoryAlias == Filesystem::Type::Directory ? OpenProfile::FollowAliasDirectory : OpenProfile::FollowAliasFile);
}

Result<Descriptor> ContextInterface::OpenPinAlias(const Filesystem::Detail::ProcfsDescriptorAccess& procfs, const Descriptor& target,
    Filesystem::Type directoryAlias) const&
{
    Filesystem::Detail::RequireOwned(target.mDescriptor);
    Filesystem::Detail::RequireOwned(procfs.mRoles[static_cast<std::size_t>(Filesystem::Detail::ProcfsDescriptorAccess::Role::Fd)].mDescriptor);
    if (!procfs.VerifyRole(*this, Filesystem::Detail::ProcfsDescriptorAccess::Role::Fd))
        return Error("Unverified procfs fd directory", EINVAL);
    Filesystem::Detail::RequireOwned(target.mDescriptor);
    if (&target.mContext.get() != this)
    {
        return Error("Foreign alias target", EINVAL);
    }
    const std::string alias = std::to_string(Filesystem::Detail::RequireOwned(target.mDescriptor));
    return OpenVerifiedAt(procfs.mRoles[static_cast<std::size_t>(Filesystem::Detail::ProcfsDescriptorAccess::Role::Fd)], alias.c_str(),
        directoryAlias == Filesystem::Type::Directory ? OpenProfile::FollowAliasPinDirectory : OpenProfile::FollowAliasPin);
}

Result<Descriptor> ContextInterface::Duplicate(const Descriptor& source) const&
{
    Filesystem::Detail::RequireOwned(source.mDescriptor);
    if (&source.mContext.get() != this)
    {
        return Error("Cannot duplicate a foreign descriptor", EINVAL);
    }
    Reservation charge(*this);
    if (!charge.Acquired())
        return charge.Failure();
    const int fd = DuplicateDescriptor(Filesystem::Detail::RequireOwned(source.mDescriptor));
    if (fd < 0)
    {
        return Error("Cannot duplicate descriptor", errno ? errno : EIO);
    }
    charge.Transfer();
    return Descriptor(*this, fd);
}

#define CHECK_OWNER(owner, failure)                                                                                                                    \
    static_cast<void>(Filesystem::Detail::RequireOwned((owner).mDescriptor));                                                                          \
    if (&(owner).mContext.get() != this)                                                                                                               \
    {                                                                                                                                                  \
        errno = EINVAL;                                                                                                                                \
        return failure;                                                                                                                                \
    }

int ContextInterface::StatFile(const Descriptor& owner, struct stat* metadata) const
{
    CHECK_OWNER(owner, -1)
    return StatFileDescriptor(Filesystem::Detail::RequireOwned(owner.mDescriptor), metadata);
}
int ContextInterface::StatFilesystem(const Descriptor& owner, struct statfs* metadata) const
{
    CHECK_OWNER(owner, -1)
    return StatFilesystemDescriptor(Filesystem::Detail::RequireOwned(owner.mDescriptor), metadata);
}
ssize_t ContextInterface::ReadFile(const Descriptor& owner, void* buffer, std::size_t size) const
{
    CHECK_OWNER(owner, -1)
    return ReadFileDescriptor(Filesystem::Detail::RequireOwned(owner.mDescriptor), buffer, size);
}
ssize_t ContextInterface::ReadLink(const Descriptor& owner, char* buffer, std::size_t size) const
{
    CHECK_OWNER(owner, -1)
    return ReadLinkDescriptor(Filesystem::Detail::RequireOwned(owner.mDescriptor), buffer, size);
}
int ContextInterface::StatusFlags(const Descriptor& owner) const
{
    CHECK_OWNER(owner, -1)
    return StatusFlagsDescriptor(Filesystem::Detail::RequireOwned(owner.mDescriptor));
}
int ContextInterface::DescriptorFlags(const Descriptor& owner) const
{
    CHECK_OWNER(owner, -1)
    return DescriptorFlagsDescriptor(Filesystem::Detail::RequireOwned(owner.mDescriptor));
}
int ContextInterface::ChownPinned(const Descriptor& owner, uid_t user, gid_t group) const
{
    CHECK_OWNER(owner, -1)
    return ChownPinnedFileDescriptor(Filesystem::Detail::RequireOwned(owner.mDescriptor), user, group);
}
int ContextInterface::ChmodAlias(const Filesystem::Detail::ProcfsDescriptorAccess& procfs, const Descriptor& pin, mode_t mode) const
{
    CHECK_OWNER(pin, -1)
    Filesystem::Detail::RequireOwned(procfs.mRoles[static_cast<std::size_t>(Filesystem::Detail::ProcfsDescriptorAccess::Role::Fd)].mDescriptor);
    if (!procfs.VerifyRole(*this, Filesystem::Detail::ProcfsDescriptorAccess::Role::Fd))
    {
        errno = EINVAL;
        return -1;
    }
    const std::string alias = std::to_string(Filesystem::Detail::RequireOwned(pin.mDescriptor));
    return ChmodPinnedAlias(
        Filesystem::Detail::RequireOwned(procfs.mRoles[static_cast<std::size_t>(Filesystem::Detail::ProcfsDescriptorAccess::Role::Fd)].mDescriptor),
        alias.c_str(), mode);
}
Result<void> ContextInterface::CloseOwnedDescriptor(Descriptor& owner) const noexcept
{
    if (0 > owner.mDescriptor)
        return Result<void>::Success(); // Silent consumed owner.
    if (&owner.mContext.get() != this)
    {
        return Error(EINVAL); // A foreign live owner retains its fd and budget.
    }
    const int fd = owner.mDescriptor;
    owner.mDescriptor = -1;
    ReleaseManagedDescriptor();
    return CloseFileDescriptor(fd);
}
Result<void> ContextInterface::CloseOwnedDirectoryCursor(DIR* stream) const noexcept
{
    ReleaseManagedDescriptor();
    return CloseDirectory(stream);
}
Result<Filesystem::FTW::Detail::DirectoryCursor> ContextInterface::OpenDirectoryCursor(Descriptor&& owner) const&
{
    Filesystem::Detail::RequireOwned(owner.mDescriptor);
    if (&owner.mContext.get() != this)
    {
        return Error("Foreign directory stream descriptor", EINVAL);
    }
    DIR* stream = FdOpenDirectory(Filesystem::Detail::RequireOwned(owner.mDescriptor));
    if (!stream)
    {
        return Error("Cannot open directory stream", errno ? errno : EIO);
    }
    owner.mDescriptor = -1;
    return Filesystem::FTW::Detail::DirectoryCursor(*this, stream);
}
#undef CHECK_OWNER

} // namespace ComplianceEngine
