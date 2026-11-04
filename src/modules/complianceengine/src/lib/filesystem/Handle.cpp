// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "Handle.hpp"

#include "ContextInterface.h"
#include "FilesystemHelpers.hpp"
#include "Optional.h"
#include "ProcfsDescriptorAccess.hpp"
#include "ReadableFile.hpp"

#include <cerrno>
#include <cstdint>
#include <dirent.h>
#include <fcntl.h>
#include <utility>

namespace ComplianceEngine
{
namespace Filesystem
{
namespace Detail
{
using Detail::Descriptor;
using Detail::ProcfsDescriptorAccess;
using Detail::SameIdentity;
using Detail::SavedError;

// The live O_PATH pin holds its kernel path (including mount). A verified
// current-task procfd alias of that pin opens the same path; inode/type checks
// still reject a wrong-object alias. Direct-test pins without an acquisition
// mount retain the independent fdinfo comparisons below.
Result<bool> Handle::OpenAndVerifyAlias(const ContextInterface& context, const ProcfsDescriptorAccess& procfs, const Descriptor& pin,
    Descriptor& aliasOwner, const struct stat& before, bool directory, std::size_t fdinfoByteCap, const std::uint64_t* heldMount)
{
    Result<std::uint64_t> pinnedMount = heldMount ? Result<std::uint64_t>(*heldMount) : procfs.ReadMountId(pin, fdinfoByteCap);
    if (!pinnedMount.HasValue())
    {
        return std::move(pinnedMount).Error();
    }
    // Only the decimal alias of the held pin is followed intentionally.
    auto aliasResult = context.OpenAlias(procfs, pin, directory,
        directory ? ContextInterface::CloseDiagnostic::DirectoryActivation : ContextInterface::CloseDiagnostic::ReadableActivation);
    if (!aliasResult.HasValue())
    {
        return Error("Cannot open pinned descriptor alias for reading", aliasResult.Error().code);
    }
    aliasOwner = std::move(aliasResult).Value();
    // After acquisition, the caller owns this output even if later verification fails.
    if (!aliasOwner.HasValue())
    {
        return Error("Cannot open pinned descriptor alias for reading", EPROTO);
    }
    struct stat activated = {}, stillPinned = {};
    if ((context.StatFile(aliasOwner, &activated) != 0) || (context.StatFile(pin, &stillPinned) != 0))
    {
        return Error("Cannot inspect activated object and pin", SavedError());
    }

    if (!SameIdentity(before, activated) || !SameIdentity(before, stillPinned))
    {
        return Error("Activated object does not match live pin", EAGAIN);
    }
    if (!heldMount)
    {
        auto activatedMount = procfs.ReadMountId(aliasOwner, fdinfoByteCap);
        if (!activatedMount.HasValue())
            return std::move(activatedMount).Error();
        auto retainedMount = procfs.ReadMountId(pin, fdinfoByteCap);
        if (!retainedMount.HasValue())
            return std::move(retainedMount).Error();
        if ((pinnedMount.Value() != activatedMount.Value()) || (pinnedMount.Value() != retainedMount.Value()))
            return Error("Activated object mount does not match live pin", EAGAIN);
    }
    return true;
}

Result<Descriptor> Handle::ActivateReadOnlyImpl(const ContextInterface& context, const Descriptor& pin, const struct stat& snapshot, bool directory,
    std::size_t fdinfoByteCap, const std::uint64_t* heldMount)
{
    if (!pin.HasValue())
    {
        return Error("Read-only activation requires a live pin", EBADF);
    }

    if ((fdinfoByteCap == 0) || (fdinfoByteCap >= std::string().max_size()))
    {
        return Error("Invalid procfs descriptor information byte cap", EINVAL);
    }
    struct stat before = {};
    if (context.StatFile(pin, &before) != 0)
    {
        return Error("Cannot inspect pinned object", SavedError());
    }

    if (!SameIdentity(before, snapshot))
    {
        return Error("Pinned object identity changed", EAGAIN);
    }

    if ((directory && !S_ISDIR(before.st_mode)) || (!directory && !S_ISREG(before.st_mode)))
    {
        return Error("Pinned object has an unsupported type", EINVAL);
    }
    const int pinFlags = context.StatusFlags(pin);
    if (pinFlags < 0)
    {
        return Error("Cannot inspect pinned descriptor flags", SavedError());
    }
    const int pinDescriptorFlags = context.DescriptorFlags(pin);
    if (pinDescriptorFlags < 0)
    {
        return Error("Cannot inspect pinned descriptor flags", SavedError());
    }

    if (((pinFlags & O_PATH) == 0) || ((pinDescriptorFlags & FD_CLOEXEC) == 0))
    {
        return Error("Pinned object is not a close-on-exec O_PATH descriptor", EINVAL);
    }

    ProcfsDescriptorAccess procfs(context);
    auto verified = procfs.Open();
    if (!verified.HasValue())
    {
        return std::move(verified).Error();
    }
    Descriptor aliasOwner =
        context.EmptyDescriptor(directory ? ContextInterface::CloseDiagnostic::DirectoryActivation : ContextInterface::CloseDiagnostic::ReadableActivation);
    auto inspected = OpenAndVerifyAlias(context, procfs, pin, aliasOwner, before, directory, fdinfoByteCap, heldMount);
    procfs.Close();
    if (!inspected.HasValue())
    {
        auto primary = std::move(inspected).Error();
        aliasOwner.Close();
        return primary;
    }
    // The alias must remain owned until all procfs checks and
    // helper closes have succeeded; output transfer occurs below.
    return std::move(aliasOwner);
}

Result<Descriptor> Handle::ActivateReadOnly(const ContextInterface& context, const Descriptor& pin, const struct stat& snapshot, bool directory, std::size_t fdinfoByteCap)
{
    return ActivateReadOnlyImpl(context, pin, snapshot, directory, fdinfoByteCap, nullptr);
}

Handle::Handle(Descriptor descriptor, AcquisitionFacts facts, LookupSpelling lookup, EffectiveSpelling effective, std::size_t fdinfoByteCap)
    : mDescriptor(std::move(descriptor)),
      mFacts(facts),
      mLookupName(std::move(lookup)),
      mEffectiveName(std::move(effective)),
      mFdinfoBytes(fdinfoByteCap)
{
}

Handle::Handle(Handle&& other) noexcept
    : mDescriptor(std::move(other.mDescriptor)),
      mFacts(other.mFacts),
      mLookupName(std::move(other.mLookupName)),
      mEffectiveName(std::move(other.mEffectiveName)),
      mFdinfoBytes(other.mFdinfoBytes)
{
}

Handle& Handle::operator=(Handle&& other) & noexcept
{
    if (this != &other)
    {
        Handle incoming(std::move(other));
        Swap(incoming);
    }
    return *this;
}

AcquisitionFacts Handle::Acquired() const noexcept
{
    return mFacts;
}

std::string Handle::LookupName() const
{
    return mLookupName.value;
}

std::string Handle::EffectiveName() const
{
    return mEffectiveName.value;
}

Result<struct stat> Handle::Stat() const
{
    return Inspect();
}

Result<struct stat> Handle::Inspect() const
{
    if (!mDescriptor.HasValue())
        return Error("Fresh inspection requires a live pin", EBADF);
    // Inspection uses the sealed pin directly; no procfs roles are needed.
    const auto& context = mDescriptor.Context();
    const int flags = context.StatusFlags(mDescriptor);
    if (flags < 0)
        return Error("Cannot inspect pinned descriptor flags", SavedError());
    const int descriptorFlags = context.DescriptorFlags(mDescriptor);
    if (descriptorFlags < 0)
        return Error("Cannot inspect pinned descriptor flags", SavedError());
    if (((flags & O_PATH) == 0) || ((descriptorFlags & FD_CLOEXEC) == 0))
        return Error("Metadata operation requires a close-on-exec O_PATH pin", EINVAL);
    struct stat before = {}, after = {};
    if (context.StatFile(mDescriptor, &before) != 0)
        return Error("Cannot inspect pinned metadata", SavedError());
    if (!SameIdentity(before, mFacts.metadata) || ((mFacts.type == Type::RegularFile) && !S_ISREG(before.st_mode)) ||
        ((mFacts.type == Type::Directory) && !S_ISDIR(before.st_mode)))
        return Error("Pinned metadata has an unexpected identity or type", EAGAIN);
    if (context.StatFile(mDescriptor, &after) != 0)
        return Error("Cannot recheck pinned metadata", SavedError());
    if (!SameIdentity(before, after))
        return Error("Pinned metadata identity changed", EAGAIN);
    return after;
}

Result<bool> Handle::SetOwnership(UserId owner, GroupId group) const
{
    if (!mDescriptor.HasValue())
    {
        return Error("Ownership change requires a live pin", EBADF);
    }
    const auto& context = mDescriptor.Context();
    auto changed = [&]() -> Result<bool> {
        auto beforeMutation = Inspect();
        if (!beforeMutation.HasValue())
        {
            return std::move(beforeMutation).Error();
        }
        // AT_EMPTY_PATH acts on the O_PATH pin itself. No alias or target
        // pathname is needed, including for an unreadable regular file.
        if (context.ChownPinned(mDescriptor, owner.value, group.value) != 0)
        {
            return Error("Cannot change pinned ownership", SavedError());
        }
        auto after = Inspect();
        if (!after.HasValue())
        {
            return std::move(after).Error(); // The ownership syscall may already have succeeded.
        }

        return true;
    }();
    return changed;
}

Result<bool> Handle::SetModeWithProcfs(const ProcfsDescriptorAccess& procfs, mode_t mode) const
{
    const auto& context = mDescriptor.Context();
    auto beforeMutation = Inspect();
    if (!beforeMutation.HasValue())
    {
        return std::move(beforeMutation).Error();
    }
    // Only this verified procfs descriptor alias is followed. Opening it
    // with O_PATH validates the alias without requiring content-read
    // permission or triggering special-file open effects.
    auto aliasResult = context.OpenPinAlias(procfs, mDescriptor, mFacts.type == Type::Directory);
    if (!aliasResult.HasValue())
    {
        return Error("Cannot inspect pinned mode alias", aliasResult.Error().code);
    }
    Descriptor modeAlias = std::move(aliasResult).Value();
    auto changed = [&]() -> Result<bool> {
        if (!modeAlias.HasValue())
        {
            return Error("Cannot inspect pinned mode alias", EPROTO);
        }
        struct stat target = {};
        if (context.StatFile(modeAlias, &target) != 0)
        {
            return Error("Cannot inspect pinned mode target", SavedError());
        }

        if (!SameIdentity(beforeMutation.Value(), target))
        {
            return Error("Pinned mode alias identity differs", EAGAIN);
        }
        // A genuine current-task procfd alias of this live owner has the
        // same mount; the stat comparison above rejects wrong-object mocks.
        auto retained = Inspect();
        if (!retained.HasValue())
        {
            return std::move(retained).Error();
        }

        // Linux's baseline fchmodat follows the procfd magic link, rather
        // than attempting fchmod on O_PATH or requiring a readable fd.
        if (context.ChmodAlias(procfs, mDescriptor, mode) != 0)
        {
            return Error("Cannot change pinned mode", SavedError());
        }
        auto after = Inspect();
        if (!after.HasValue())
        {
            return std::move(after).Error(); // The chmod syscall may already have succeeded.
        }

        return true;
    }();
    modeAlias.Close();
    return changed;
}

Result<bool> Handle::SetMode(mode_t mode) const
{
    if (!mDescriptor.HasValue())
    {
        return Error("Mode change requires a live pin", EBADF);
    }
    const auto& context = mDescriptor.Context();
    ProcfsDescriptorAccess procfs(context);
    auto opened = procfs.Open();
    if (!opened.HasValue())
    {
        return std::move(opened).Error();
    }
    auto changed = SetModeWithProcfs(procfs, mode);
    procfs.Close();
    return changed;
}

Result<ReadableFile> Handle::OpenReadOnly() const
{
    return OpenReadOnly(ReadableFile::Policy{});
}

Result<ReadableFile> Handle::OpenReadOnly(ReadableFile::Policy policy) const
{
    if (!mDescriptor.HasValue())
    {
        return Error("Read-only activation requires a live file pin", EBADF);
    }

    if (mFacts.type != Type::RegularFile)
    {
        return Error("Read-only activation requires a regular file", EINVAL);
    }
    auto activated = ActivateReadOnlyImpl(mDescriptor.Context(), mDescriptor, mFacts.metadata, false, mFdinfoBytes, &mFacts.targetMount.value);
    if (!activated.HasValue())
    {
        return std::move(activated).Error();
    }
    return ReadableFile(std::move(activated).Value(), policy);
}

Result<DirectoryCursor> Handle::OpenChildren() const
{
    if (!mDescriptor.HasValue())
    {
        return Error("Directory enumeration requires a live directory pin", EBADF);
    }
    if (mFacts.type != Type::Directory)
    {
        return Error("Directory enumeration requires a directory pin", EINVAL);
    }
    const auto& context = mDescriptor.Context();
    auto activated = ActivateReadOnlyImpl(context, mDescriptor, mFacts.metadata, true, mFdinfoBytes, &mFacts.targetMount.value);
    if (!activated.HasValue())
    {
        return std::move(activated).Error();
    }
    // fdopendir consumes the verified operational descriptor on success;
    // on failure its typed owner retains it and closes exactly once.
    Descriptor operational = std::move(activated).Value();
    auto cursor = context.OpenDirectoryCursor(std::move(operational));
    if (!cursor.HasValue())
    {
        auto primary = std::move(cursor).Error();
        operational.Close();
        return primary;
    }
    return cursor;
}

void Handle::Swap(Handle& other) noexcept
{
    using std::swap;
    swap(mDescriptor, other.mDescriptor);
    swap(mFacts, other.mFacts);
    swap(mLookupName, other.mLookupName);
    swap(mEffectiveName, other.mEffectiveName);
    swap(mFdinfoBytes, other.mFdinfoBytes);
}

Result<Handle> Handle::PinProcessRoot(const ContextInterface& context, std::size_t fdinfoBytes)
{
    auto opened = context.OpenAbsolutePin("/");
    if (!opened.HasValue())
    {
        return Error("Cannot pin process root for absolute-prefix validation", opened.Error().code);
    }
    Descriptor acquired = std::move(opened).Value();
    auto pinned = [&]() -> Result<Handle> {
        if (!acquired.HasValue())
        {
            return Error("Cannot pin process root for absolute-prefix validation", EPROTO);
        }
        struct stat snapshot = {};
        if (context.StatFile(acquired, &snapshot) != 0)
        {
            return Error("Cannot inspect process root pin", SavedError());
        }

        if (!S_ISDIR(snapshot.st_mode))
        {
            return Error("Process root is not a directory", ENOTDIR);
        }
        ProcfsDescriptorAccess procfs(context);
        auto verified = procfs.Open();
        if (!verified.HasValue())
            return std::move(verified).Error();
        auto mount = procfs.ReadMountId(acquired, fdinfoBytes);
        procfs.Close();
        if (!mount.HasValue())
            return std::move(mount).Error();
        Handle root(std::move(acquired), AcquisitionFacts{Type::Directory, snapshot, LookupMountId(mount.Value()), TargetMountId(mount.Value())},
            LookupSpelling{"/"}, EffectiveSpelling{"/"}, fdinfoBytes);
        return std::move(root);
    }();
    acquired.Close();
    return pinned;
}

Result<bool> Handle::RecognizeAcceptedRoot(const Handle& acceptedRoot, const Handle& candidate, std::size_t fdinfoByteCap)
{
    if ((acceptedRoot.mFacts.type != Type::Directory) || (candidate.mFacts.type != Type::Directory) || !acceptedRoot.mDescriptor.HasValue() ||
        !candidate.mDescriptor.HasValue() || (fdinfoByteCap == 0))
    {
        return Error("Two live directory pins and a positive fdinfo cap are required", EINVAL);
    }
    if (&acceptedRoot.mDescriptor.Context() != &candidate.mDescriptor.Context())
    {
        return Error("Directory pins belong to different contexts", EINVAL);
    }
    struct stat root = {}, observed = {};
    const auto& context = acceptedRoot.mDescriptor.Context();
    if ((context.StatFile(acceptedRoot.mDescriptor, &root) != 0) || (context.StatFile(candidate.mDescriptor, &observed) != 0))
    {
        return Error("Cannot inspect accepted root and candidate pins", SavedError());
    }

    if (!SameIdentity(root, acceptedRoot.mFacts.metadata) || !SameIdentity(observed, candidate.mFacts.metadata) || !S_ISDIR(root.st_mode) ||
        !S_ISDIR(observed.st_mode))
    {
        return Error("Root or candidate pin identity changed", EAGAIN);
    }

    if (!SameIdentity(root, observed))
    {
        return false;
    }
    auto compared = [&]() -> Result<bool> {
        struct stat retainedRoot = {}, retainedCandidate = {};
        if ((context.StatFile(acceptedRoot.mDescriptor, &retainedRoot) != 0) || (context.StatFile(candidate.mDescriptor, &retainedCandidate) != 0))
        {
            return Error("Cannot recheck accepted root and candidate pins", SavedError());
        }

        if (!SameIdentity(root, retainedRoot) || !SameIdentity(observed, retainedCandidate))
        {
            return Error("Root or candidate pin changed during comparison", EAGAIN);
        }
        return acceptedRoot.mFacts.targetMount.value == candidate.mFacts.targetMount.value;
    }();
    return compared;
}

} // namespace Detail

DirectoryCursor::DirectoryCursor(const ContextInterface& context, DIR* stream) noexcept
    : mContext(&context),
      mStream(stream)
{
}

DirectoryCursor::DirectoryCursor(DirectoryCursor&& other) noexcept
    : mContext(other.mContext),
      mStream(other.mStream)
{
    other.mContext = nullptr;
    other.mStream = nullptr;
}

DirectoryCursor& DirectoryCursor::operator=(DirectoryCursor&& other) & noexcept
{
    if (this != &other)
    {
        DirectoryCursor replaced(std::move(*this));
        mContext = other.mContext;
        mStream = other.mStream;
        other.mContext = nullptr;
        other.mStream = nullptr;
    }
    return *this;
}

DirectoryCursor::~DirectoryCursor() noexcept
{
    Close();
}

void DirectoryCursor::Close() noexcept
{
    if (!mStream)
        return;
    DIR* stream = mStream;
    mStream = nullptr;
    const ContextInterface* context = mContext;
    int error = 0;
    try
    {
        errno = 0;
        if (context->CloseOwnedDirectoryCursor(stream) != 0)
            error = errno != 0 ? errno : EIO;
    }
    catch (...)
    {
        error = EIO;
    }
    if (error == 0)
        return;
    OsConfigLogHandle log = nullptr;
    try
    {
        log = context->GetLogHandle();
    }
    catch (...)
    {
    }
    try
    {
        if (error == EBADF)
        {
            OsConfigLogError(log, "Cannot close pinned directory cursor (ownership bug, EBADF): %d", error);
        }
        else
        {
            OsConfigLogError(log, "Cannot close pinned directory cursor: %d", error);
        }
    }
    catch (...)
    {
    }
}

Result<Optional<std::string>> DirectoryCursor::Next()
{
    auto next = NextEntry();
    if (!next.HasValue())
    {
        return std::move(next).Error();
    }

    if (!next.Value().HasValue())
    {
        return Optional<std::string>();
    }
    return Optional<std::string>(std::move(next).Value().Value().name);
}

Result<Optional<DirectoryChild>> DirectoryCursor::NextEntry()
{
    if (!mStream)
    {
        return Error("Cannot read closed pinned directory", EBADF);
    }

    for (;;)
    {
        errno = 0;
        const struct dirent* entry = mContext->ReadDirectory(mStream);
        if (!entry)
        {
            if (errno != 0)
            {
                return Error("Cannot read pinned directory", Detail::SavedError());
            }
            return Optional<DirectoryChild>();
        }
        const std::string name(entry->d_name);
        if (("." == name) || (".." == name))
        {
            continue;
        }

        if (!Detail::IsSingleChildComponent(name))
        {
            return Error("Pinned directory returned an invalid child name", EINVAL);
        }
        DirectoryChild child;
        child.name = name;
        child.type = entry->d_type;
        return Optional<DirectoryChild>(std::move(child));
    }
}

} // namespace Filesystem
} // namespace ComplianceEngine
