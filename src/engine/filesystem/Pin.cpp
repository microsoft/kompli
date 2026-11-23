// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "Pin.hpp"

#include "ContextInterface.h"
#include "Descriptor.hpp"
#include "FilesystemHelpers.hpp"
#include "PrefixLimits.hpp"
#include "ProcfsDescriptorAccess.hpp"
#include "ReadableFile.hpp"

#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
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
// still reject a wrong-object alias. The pin's mount was already established
// and stored at acquisition time (Path resolution or PinProcessRoot); a live
// O_PATH pin cannot change mount, so activation performs no mount re-read here.
Result<Descriptor> Pin::OpenAndVerifyAlias(const ContextInterface& context, const ProcfsDescriptorAccess& procfs, const Descriptor& pin,
    const struct stat& before, Type directory)
{
    // Only the decimal alias of the held pin is followed intentionally.
    auto aliasResult = context.OpenAlias(procfs, pin, directory);
    if (!aliasResult.HasValue())
    {
        return Error("Cannot open pinned descriptor alias for reading", aliasResult.Error().code);
    }
    Descriptor aliasOwner = std::move(aliasResult).Value();
    struct stat activated = {}, stillPinned = {};
    if ((context.StatFile(aliasOwner, &activated) != 0) || (context.StatFile(pin, &stillPinned) != 0))
    {
        return Error("Cannot inspect activated object and pin", SavedError());
    }

    if (!SameIdentity(before, activated) || !SameIdentity(before, stillPinned))
    {
        return Error("Activated object does not match live pin", EAGAIN);
    }
    return aliasOwner;
}

Result<Descriptor> Pin::ActivateReadOnly(const ContextInterface& context, const Descriptor& pin, const struct stat& snapshot, Type directory)
{
    struct stat before = {};
    if (context.StatFile(pin, &before) != 0)
    {
        return Error("Cannot inspect pinned object", SavedError());
    }

    if (!SameIdentity(before, snapshot))
    {
        return Error("Pinned object identity changed", EAGAIN);
    }

    if ((directory == Type::Directory && !S_ISDIR(before.st_mode)) || (directory == Type::RegularFile && !S_ISREG(before.st_mode)))
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

    auto opened = ProcfsDescriptorAccess::Make(context);
    if (!opened.HasValue())
        return std::move(opened).Error();
    ProcfsDescriptorAccess procfs = std::move(opened).Value();
    return OpenAndVerifyAlias(context, procfs, pin, before, directory);
}

Pin::Pin(Descriptor descriptor, ::ComplianceEngine::Filesystem::Metadata metadata)
    : mDescriptor(std::move(descriptor)),
      mMetadata(std::move(metadata))
{
}
Pin::Pin(Pin&& other) noexcept
    : mDescriptor(std::move(other.mDescriptor)),
      mMetadata(std::move(other.mMetadata))
{
}
Pin& Pin::operator=(Pin&& other) & noexcept
{
    if (this != &other)
    {
        mDescriptor = std::move(other.mDescriptor);
        mMetadata = std::move(other.mMetadata);
    }
    return *this;
}
::ComplianceEngine::Filesystem::Metadata Pin::Metadata() const
{
    return mMetadata;
}
Result<struct stat> Pin::Stat() const
{
    return Inspect(*this);
}

Result<struct stat> Pin::Inspect(const Pin& owner)
{
    // Inspection uses the sealed pin directly; no procfs roles are needed.
    const auto& context = owner.mDescriptor.Context();
    const int flags = context.StatusFlags(owner.mDescriptor);
    if (flags < 0)
        return Error("Cannot inspect pinned descriptor flags", SavedError());
    const int descriptorFlags = context.DescriptorFlags(owner.mDescriptor);
    if (descriptorFlags < 0)
        return Error("Cannot inspect pinned descriptor flags", SavedError());
    if (((flags & O_PATH) == 0) || ((descriptorFlags & FD_CLOEXEC) == 0))
        return Error("Metadata operation requires a close-on-exec O_PATH pin", EINVAL);
    struct stat before = {}, after = {};
    if (context.StatFile(owner.mDescriptor, &before) != 0)
        return Error("Cannot inspect pinned metadata", SavedError());
    if (!SameIdentity(before, owner.mMetadata.mStat) || ((owner.mMetadata.mType == Type::RegularFile) && !S_ISREG(before.st_mode)) ||
        ((owner.mMetadata.mType == Type::Directory) && !S_ISDIR(before.st_mode)))
        return Error("Pinned metadata has an unexpected identity or type", EAGAIN);
    if (context.StatFile(owner.mDescriptor, &after) != 0)
        return Error("Cannot recheck pinned metadata", SavedError());
    if (!SameIdentity(before, after))
        return Error("Pinned metadata identity changed", EAGAIN);
    return after;
}

Result<bool> Pin::SetOwnership(UserId owner, GroupId group) const
{
    const auto& context = mDescriptor.Context();
    auto beforeMutation = Inspect(*this);
    if (!beforeMutation.HasValue())
    {
        return std::move(beforeMutation).Error();
    }
    // AT_EMPTY_PATH acts on the O_PATH pin itself. No alias or target
    // pathname is needed, including for an unreadable regular file.
    if (context.ChownPinned(mDescriptor, owner.Value(), group.Value()) != 0)
    {
        return Error("Cannot change pinned ownership", SavedError());
    }
    auto after = Inspect(*this);
    if (!after.HasValue())
    {
        return std::move(after).Error(); // The ownership syscall may already have succeeded.
    }

    return true;
}

Result<bool> Pin::SetModeWithProcfs(const Pin& owner, const ProcfsDescriptorAccess& procfs, mode_t mode)
{
    const auto& context = owner.mDescriptor.Context();
    auto beforeMutation = Inspect(owner);
    if (!beforeMutation.HasValue())
    {
        return std::move(beforeMutation).Error();
    }
    // Only this verified procfs descriptor alias is followed. Opening it
    // with O_PATH validates the alias without requiring content-read
    // permission or triggering special-file open effects.
    auto aliasResult = context.OpenPinAlias(procfs, owner.mDescriptor, owner.mMetadata.mType);
    if (!aliasResult.HasValue())
    {
        return Error("Cannot inspect pinned mode alias", aliasResult.Error().code);
    }
    Descriptor modeAlias = std::move(aliasResult).Value();
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
    auto retained = Inspect(owner);
    if (!retained.HasValue())
    {
        return std::move(retained).Error();
    }

    // Linux's baseline fchmodat follows the procfd magic link, rather
    // than attempting fchmod on O_PATH or requiring a readable fd.
    if (context.ChmodAlias(procfs, owner.mDescriptor, mode) != 0)
    {
        return Error("Cannot change pinned mode", SavedError());
    }
    auto after = Inspect(owner);
    if (!after.HasValue())
    {
        return std::move(after).Error(); // The chmod syscall may already have succeeded.
    }

    return true;
}

Result<bool> Pin::SetMode(mode_t mode) const
{
    const auto& context = mDescriptor.Context();
    // Check ownership at the sealed boundary before acquiring procfs roles.
    if (context.StatusFlags(mDescriptor) < 0)
        return Error("Cannot inspect pinned descriptor flags", SavedError());
    auto opened = ProcfsDescriptorAccess::Make(context);
    if (!opened.HasValue())
        return std::move(opened).Error();
    ProcfsDescriptorAccess procfs = std::move(opened).Value();
    return SetModeWithProcfs(*this, procfs, mode);
}

Result<ReadableFile> Pin::OpenReadOnly(ReadableFile::Policy policy) const
{
    if (mMetadata.mType != Type::RegularFile)
    {
        return Error("Read-only activation requires a regular file", EINVAL);
    }
    auto activated = ActivateReadOnly(mDescriptor.Context(), mDescriptor, mMetadata.mStat, Type::RegularFile);
    if (!activated.HasValue())
    {
        return std::move(activated).Error();
    }
    return ReadableFile(std::move(activated).Value(), policy);
}

Result<Pin::AcquiredPin> Pin::AcquirePinnedObject(const ContextInterface& context, Descriptor pin, std::size_t fdinfoByteCap, const char* statFailureMessage)
{
    struct stat snapshot = {};
    if (context.StatFile(pin, &snapshot) != 0)
    {
        return Error(statFailureMessage, SavedError());
    }
    auto verified = ProcfsDescriptorAccess::Make(context);
    if (!verified.HasValue())
        return std::move(verified).Error();
    ProcfsDescriptorAccess procfs = std::move(verified).Value();
    auto mount = procfs.ReadMountId(pin, fdinfoByteCap);
    if (!mount.HasValue())
        return std::move(mount).Error();
    return AcquiredPin{std::move(pin), snapshot, mount.Value()};
}

Result<Pin> Pin::PinProcessRoot(const ContextInterface& context, PrefixLimits limits)
{
    auto opened = context.OpenAbsolutePin("/");
    if (!opened.HasValue())
    {
        return Error("Cannot pin process root for absolute-prefix validation", opened.Error().code);
    }
    auto acquired = AcquirePinnedObject(context, std::move(opened).Value(), limits.fdinfoBytes, "Cannot inspect process root pin");
    if (!acquired.HasValue())
    {
        return std::move(acquired).Error();
    }
    AcquiredPin object = std::move(acquired).Value();
    if (!S_ISDIR(object.snapshot.st_mode))
    {
        return Error("Process root is not a directory", ENOTDIR);
    }
    // Metadata lives inline in Pin, so constructing it here allocates
    // nothing on the heap; the next heap allocation is the shared Pin
    // wrapper below, at the point where the root Pin is first wrapped
    // for sharing.
    ::ComplianceEngine::Filesystem::Metadata facts(Type::Directory, object.snapshot, LookupMountId(object.mount), TargetMountId(object.mount),
        LookupSpelling("/"), EffectiveSpelling("/"));
    Pin root(std::move(object.pin), std::move(facts));
    return root;
}

} // namespace Detail
} // namespace Filesystem
} // namespace ComplianceEngine
