// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "Path.hpp"

#include "ContextInterface.h"
#include "FTWDirectoryCursor.hpp"
#include "FilesystemCollection.hpp"
#include "FilesystemHelpers.hpp"
#include "PathLinkAccess.hpp"
#include "ProcfsDescriptorAccess.hpp"

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstring>
#include <deque>
#include <exception>
#include <fcntl.h>
#include <functional>
#include <limits>
#include <linux/magic.h>
#include <memory>
#include <sys/statfs.h>
#include <type_traits>
#include <unistd.h>
#include <utility>
#include <vector>
namespace ComplianceEngine
{
namespace Filesystem
{
using Detail::Descriptor;
using Detail::Handle;
using Detail::LinkTarget;
using Detail::ProcfsDescriptorAccess;
using Detail::SavedError;
namespace
{
bool Fits(std::size_t used, std::size_t addition, std::size_t limit) noexcept
{
    return (used <= limit) && (addition <= limit - used);
}
std::size_t BoundedSum(std::initializer_list<std::size_t> terms) noexcept
{
    std::size_t total = 0;
    for (std::size_t term : terms)
    {
        if (term > std::numeric_limits<std::size_t>::max() - total)
            return std::numeric_limits<std::size_t>::max();
        total += term;
    }
    return total;
}
// Procfs bootstrap holds at most three verified directories; the published
// fd/fdinfo pair plus one fdinfo reader also holds three. A new child pin
// remains owned during either phase. Shared stack copies do not duplicate fds.
constexpr std::size_t kProcfsBootstrapPeak = 3;
constexpr std::size_t kProcfsRetained = 2;
constexpr std::size_t kProcfsReadPeak = kProcfsRetained + 1;
constexpr std::size_t kProcfsTemporaryPeak = kProcfsBootstrapPeak > kProcfsReadPeak ? kProcfsBootstrapPeak : kProcfsReadPeak;
constexpr std::size_t kNewChildPeak = 1 + kProcfsTemporaryPeak;
constexpr std::size_t kMinimumPathPeak = 1 + kProcfsTemporaryPeak; // root and procfs
std::string Join(const std::string& parent, const std::string& child)
{
    return parent == "/" ? parent + child : parent + "/" + child;
}
bool AtBoundary(const std::string& text, const std::string& prefix)
{
    return text.compare(0, prefix.size(), prefix) == 0 && (prefix == "/" || text.size() == prefix.size() || text[prefix.size()] == 47);
}
std::string CollapseSeparators(const std::string& name)
{
    std::string result;
    result.reserve(name.size());
    for (char c : name)
        if (c != 47 || result.empty() || result.back() != 47)
            result += c;
    if (result.size() > 1 && result.back() == 47)
        result.pop_back();
    return result;
}
Optional<Error> Validate(const Path::Policy& policy, const ResolverLimits& limits)
{
    if ((policy.prefixLinks != PrefixLinkPolicy::Reject && policy.prefixLinks != PrefixLinkPolicy::Follow) ||
        (policy.fileLinks != FileLinkPolicy::Reject && policy.fileLinks != FileLinkPolicy::Follow) ||
        (policy.directoryLinks != DirectoryLinkPolicy::Reject && policy.directoryLinks != DirectoryLinkPolicy::Follow) ||
        (policy.rejectedLinks != RejectedLinkDisposition::Error && policy.rejectedLinks != RejectedLinkDisposition::Skip) ||
        (policy.unsupportedTypes != UnsupportedTypeDisposition::Error && policy.unsupportedTypes != UnsupportedTypeDisposition::Skip) ||
        (policy.missingFiles != MissingFileDisposition::Error && policy.missingFiles != MissingFileDisposition::Report) ||
        (policy.mounts != MountPolicy::CrossMounts && policy.mounts != MountPolicy::StayOnRootMount))
        return Error("Invalid path policy", EINVAL);
    if (limits.shared.work == 0 || limits.shared.components == 0 || limits.shared.liveDescriptors < kMinimumPathPeak || limits.shared.fdinfoBytes == 0 ||
        limits.shared.targetBytes == 0 || limits.linkTargetBytes == 0 || limits.linkExpansions == 0 || limits.depth == 0 ||
        limits.linkTargetBytes >= std::vector<char>().max_size() - 1 || limits.linkTargetBytes >= static_cast<std::size_t>(std::numeric_limits<ssize_t>::max()) ||
        limits.shared.fdinfoBytes >= static_cast<std::size_t>(std::numeric_limits<ssize_t>::max()))
        return Error("Invalid path resolver limits", EINVAL);
    return {};
}
} // namespace
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
Result<Descriptor> Handle::OpenAndVerifyAlias(const ContextInterface& context, const ProcfsDescriptorAccess& procfs, const Descriptor& pin,
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

Result<Descriptor> Handle::ActivateReadOnly(const ContextInterface& context, const Descriptor& pin, const struct stat& snapshot, Type directory)
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

Handle::Handle(Descriptor descriptor, ::ComplianceEngine::Filesystem::Metadata metadata)
    : mDescriptor(std::move(descriptor)),
      mMetadata(std::move(metadata))
{
}
Handle::Handle(Handle&& other) noexcept
    : mDescriptor(std::move(other.mDescriptor)),
      mMetadata(std::move(other.mMetadata))
{
}
Handle& Handle::operator=(Handle&& other) & noexcept
{
    if (this != &other)
    {
        mDescriptor = std::move(other.mDescriptor);
        mMetadata = std::move(other.mMetadata);
    }
    return *this;
}
::ComplianceEngine::Filesystem::Metadata Handle::Metadata() const
{
    return mMetadata;
}
Result<struct stat> Handle::Stat() const
{
    return Inspect(*this);
}

Result<struct stat> Handle::Inspect(const Handle& owner)
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

Result<bool> Handle::SetOwnership(UserId owner, GroupId group) const
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

Result<bool> Handle::SetModeWithProcfs(const Handle& owner, const ProcfsDescriptorAccess& procfs, mode_t mode)
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

Result<bool> Handle::SetMode(mode_t mode) const
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

Result<ReadableFile> Handle::OpenReadOnly() const
{
    return OpenReadOnly(ReadableFile::Policy{});
}

Result<ReadableFile> Handle::OpenReadOnly(ReadableFile::Policy policy) const
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

Result<Handle::AcquiredPin> Handle::AcquirePinnedObject(const ContextInterface& context, Descriptor pin, std::size_t fdinfoByteCap, const char* statFailureMessage)
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

Result<Handle> Handle::PinProcessRoot(const ContextInterface& context, PrefixLimits limits)
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
    // Metadata lives inline in Handle, so constructing it here allocates
    // nothing on the heap; the next heap allocation is the shared Handle
    // wrapper below, at the point where the root Handle is first wrapped
    // for sharing.
    ::ComplianceEngine::Filesystem::Metadata facts(Type::Directory, object.snapshot, LookupMountId(object.mount), TargetMountId(object.mount),
        LookupSpelling("/"), EffectiveSpelling("/"));
    Handle root(std::move(object.pin), std::move(facts));
    return root;
}

} // namespace Detail

namespace FTW
{
namespace Detail
{
Result<DirectoryCursor> DirectoryCursor::OpenChildren(::ComplianceEngine::Filesystem::Path::Component owner)
{
    const auto& handle = *owner.mAcquisition;
    if (handle.mMetadata.FileType() != Type::Directory)
        return Error("Directory enumeration requires a directory pin", EINVAL);
    const auto& context = handle.mDescriptor.Context();
    auto activated = Handle::ActivateReadOnly(context, handle.mDescriptor, handle.mMetadata.Stat(), Type::Directory);
    if (!activated.HasValue())
        return std::move(activated).Error();
    Descriptor operational = std::move(activated).Value();
    return context.OpenDirectoryCursor(std::move(operational));
}
} // namespace Detail
} // namespace FTW

// The shared owner is immutable. Moving a Component copies its shared pin,
// leaving the source usable without a second metadata allocation.
bool Path::Component::SameAcquisition(const Component& first, const Component& second) noexcept
{
    return first.mAcquisition == second.mAcquisition;
}
std::size_t Path::Component::LookupNameBytes(const Component& owner) noexcept
{
    return owner.mAcquisition->mMetadata.mLookupName.mValue.size();
}
std::size_t Path::Component::EffectiveNameBytes(const Component& owner) noexcept
{
    return owner.mAcquisition->mMetadata.mEffectiveName.mValue.size();
}
std::string Path::Component::LookupName(const Component& owner)
{
    return owner.mAcquisition->mMetadata.mLookupName.mValue;
}
std::string Path::Component::EffectiveName(const Component& owner)
{
    return owner.mAcquisition->mMetadata.mEffectiveName.mValue;
}
Path::Component::Component(Detail::Handle owned)
    : mAcquisition(std::make_shared<const Detail::Handle>(std::move(owned)))
{
}
Path::Component::Component(const Component& other) noexcept
    : mAcquisition(other.mAcquisition)
{
}
Path::Component& Path::Component::operator=(const Component& other) & noexcept
{
    mAcquisition = other.mAcquisition;
    return *this;
}
Path::Component::Component(Component&& other) noexcept
    : mAcquisition(other.mAcquisition)
{
}
Path::Component& Path::Component::operator=(Component&& other) & noexcept
{
    mAcquisition = other.mAcquisition;
    return *this;
}
Path::Component::~Component() noexcept = default;
::ComplianceEngine::Filesystem::Metadata Path::Component::Metadata() const
{
    return mAcquisition->Metadata();
}
Result<struct stat> Path::Component::Stat() const
{
    return mAcquisition->Stat();
}
Result<bool> Path::Component::SetOwnership(UserId owner, GroupId group) const
{
    return mAcquisition->SetOwnership(owner, group);
}
Result<bool> Path::Component::SetMode(mode_t mode) const
{
    return mAcquisition->SetMode(mode);
}
Result<ReadableFile> Path::Component::OpenReadOnly() const
{
    return mAcquisition->OpenReadOnly();
}
Result<ReadableFile> Path::Component::OpenReadOnly(ReadableFile::Policy policy) const
{
    return mAcquisition->OpenReadOnly(policy);
}

namespace
{
// Resolver work units charged against limits.shared.work; shared by every
// snapshot of one Path so copying the stack can't reset the count.
struct WorkAllowance
{
    std::size_t spent = 0;
};
} // namespace

// The cumulative work allowance alone is shared and mutable across immutable stack snapshots.
struct Path::State
{
    State(const ContextInterface& owner, ResolverLimits caps, Component root)
        : context(owner),
          limits(caps),
          allowance(std::make_shared<WorkAllowance>()),
          pins{root},
          boundaryLookup(Component::LookupName(root)),
          boundaryEffective(Component::EffectiveName(root)),
          lookup(boundaryLookup),
          effective(boundaryEffective),
          baseline(root.Metadata().TargetMount().Value())
    {
    }
    // A temporary context would dangle past construction: State retains the
    // context reference for its own lifetime (see `context` below). State is
    // only ever constructed from the `context` Path::Make already received
    // (whose own deleted `const ContextInterface&&` overload rejects a
    // temporary at that boundary), so this is defense in depth, not a
    // currently reachable call.
    State(const ContextInterface&&, ResolverLimits, Component) = delete;
    std::reference_wrapper<const ContextInterface> context;
    ResolverLimits limits;
    std::shared_ptr<WorkAllowance> allowance;
    std::vector<Component> pins;
    std::size_t boundary = 0;
    std::string boundaryLookup;
    std::string boundaryEffective;
    std::string lookup;
    std::string effective;
    std::uint64_t baseline;
};
struct Path::Step::Data
{
    Data(std::size_t depth, Component anchor, Component barrier, std::size_t boundaryIndex, std::string bindingLookup, std::string bindingEffective, std::uint64_t mount)
        : sourceDepth(depth),
          attach(std::move(anchor)),
          boundaryPin(std::move(barrier)),
          boundary(boundaryIndex),
          boundaryLookup(std::move(bindingLookup)),
          boundaryEffective(std::move(bindingEffective)),
          baseline(mount)
    {
    }
    std::size_t sourceDepth;
    Component attach;
    std::vector<Component> popped;
    std::vector<Component> pushed;
    Component boundaryPin;
    std::size_t boundary;
    std::string boundaryLookup;
    std::string boundaryEffective;
    std::uint64_t baseline;
    std::string sourceLookup;
    std::string sourceEffective;
    std::string targetLookup;
    std::string targetEffective;
    // The requested source link can differ from a reused target pin.
    std::uint64_t lookupMount = 0;
    bool hasLookupMount = false;
};
::ComplianceEngine::Filesystem::Metadata Path::Step::Metadata() const
{
    auto acquired = Target().Metadata();
    if (!mData->hasLookupMount)
        return acquired;
    return ::ComplianceEngine::Filesystem::Metadata(acquired.mType, acquired.mStat, LookupMountId(mData->lookupMount), acquired.mTargetMount,
        acquired.mLookupName, acquired.mEffectiveName);
}
Path::Component Path::Step::Target() const noexcept
{
    return mData->pushed.empty() ? mData->attach : mData->pushed.back();
}
std::size_t Path::Step::RetainedDescriptors() const noexcept
{
    return 2 + mData->popped.size() + mData->pushed.size();
}
Path::Component Path::Root() const noexcept
{
    return mState->pins.front();
}
Path::Component Path::Leaf() const noexcept
{
    return mState->pins.back();
}
std::string Path::LookupName() const
{
    return mState->lookup;
}
std::string Path::ToString() const
{
    return mState->effective;
}
std::size_t Path::Size() const noexcept
{
    return mState->pins.size();
}
std::size_t Path::RetainedDescriptors() const noexcept
{
    return mState->pins.size();
}
ResolverLimits Path::Limits() const noexcept
{
    return mState->limits;
}
const ContextInterface& Path::Context() const noexcept
{
    return mState->context.get();
}
// Checked pinned-link readers and the root-component factory dispatch
// through ContextInterface's friend-gated native surface or Component's
// private constructor, so they stay direct private members of Path (the
// narrowest friend that already has both), not anonymous-namespace functions.
Path::Component Path::MakeRootComponent(Handle root)
{
    return Component(std::move(root));
}

// A live O_PATH pin cannot change mount (see Handle::OpenAndVerifyAlias
// above), and the resolver observes this pin's mount once at acquisition,
// before deciding to follow it as a link (Resolver::Run, the mount read
// immediately after the child pin's stat). So this reader does not re-read
// or compare the pin's fdinfo mount id around the readlink; it only
// re-checks identity (stat), which a link's target text/content must still
// satisfy independent of mount. It therefore needs no procfs session and no
// fdinfo byte cap.
Result<LinkTarget> Path::ReadVerifiedLinkText(const Descriptor& linkPin, const struct stat& before, std::size_t targetByteCap)
{
    const ContextInterface& context = linkPin.Context();
    // A single read into a buffer sized to the platform's maximum possible
    // link length: symlink(2) targets are at most PATH_MAX bytes, so a full
    // buffer means the read was truncated, not that more text remains.
    const std::size_t bufferBytes = (targetByteCap < static_cast<std::size_t>(PATH_MAX) ? targetByteCap : static_cast<std::size_t>(PATH_MAX)) + 1;
    std::vector<char> buffer(bufferBytes);
    const ssize_t count = context.ReadLink(linkPin, buffer.data(), buffer.size());
    if (count < 0)
        return Error("Cannot read pinned link", SavedError());
    if (count == 0 || static_cast<std::size_t>(count) > targetByteCap)
        return Error("Pinned link exceeds byte cap or is empty", E2BIG);
    if (static_cast<std::size_t>(count) == buffer.size())
        return Error("Pinned link target exceeds platform path length", ENAMETOOLONG);
    struct stat after = {};
    if (context.StatFile(linkPin, &after) != 0)
        return Error("Cannot recheck pinned link", SavedError());
    if (!Detail::SameIdentity(before, after))
        return Error("Pinned link identity changed", EAGAIN);
    LinkTarget target;
    target.text.assign(buffer.data(), static_cast<std::size_t>(count));
    if (target.text.find(char(0)) != std::string::npos)
        return Error("Pinned link contains NUL", EINVAL);
    return target;
}
Result<LinkTarget> Path::ReadPinnedLink(const Descriptor& linkPin, std::size_t targetByteCap)
{
    const ContextInterface& context = linkPin.Context();
    if (targetByteCap == 0 || targetByteCap >= std::vector<char>().max_size() - 1 ||
        targetByteCap >= static_cast<std::size_t>(std::numeric_limits<ssize_t>::max()))
        return Error("Invalid pinned link cap", EINVAL);
    const int flags = context.StatusFlags(linkPin);
    if (flags < 0)
        return Error("Cannot inspect pinned link flags", SavedError());
    const int descriptorFlags = context.DescriptorFlags(linkPin);
    if (descriptorFlags < 0)
        return Error("Cannot inspect pinned link flags", SavedError());
    if ((flags & O_PATH) == 0 || (descriptorFlags & FD_CLOEXEC) == 0)
        return Error("Pinned link must be close-on-exec O_PATH", EINVAL);
    struct stat before = {};
    struct statfs filesystem = {};
    if (context.StatFile(linkPin, &before) != 0 || context.StatFilesystem(linkPin, &filesystem) != 0)
        return Error("Cannot inspect pinned link", SavedError());
    if (!S_ISLNK(before.st_mode) || PROC_SUPER_MAGIC == filesystem.f_type)
        return Error("Not an ordinary filesystem symlink", ELOOP);
    return ReadVerifiedLinkText(linkPin, before, targetByteCap);
}

class Path::Resolver
{
public:
    Resolver(const Path& path, Policy policy, InputRole role, std::size_t& followed)
        : mState(path.mState),
          mPolicy(policy),
          mRole(role),
          mFollowed(followed)
    {
    }

    Result<Variant<Step, RejectionReason>> Run(const std::string& name)
    {
        auto source = mState;
        if (source->pins.back().Metadata().FileType() != Type::Directory)
            return Error("Cannot resolve beneath a file", ENOTDIR);
        if (source->pins.size() > source->limits.shared.liveDescriptors - kProcfsTemporaryPeak)
            return Error("Path budget exhausted before resolution", E2BIG);
        // The logical lookup never grows past targetBytes, independent of
        // physical depth, so a lookup rejected here has not consumed any
        // snapshot work.
        if (BoundedSum({source->lookup.size(), std::size_t{1}, name.size()}) > source->limits.shared.targetBytes)
            return Error("Logical lookup exceeds target byte limit", ENAMETOOLONG);
        const std::size_t snapshotCost = source->pins.size();
        if (!Fits(source->allowance->spent, snapshotCost, source->limits.shared.work))
            return Error("Resolver snapshot work budget exhausted", E2BIG);
        source->allowance->spent += snapshotCost;
        mStack = source->pins;
        mSourceLookup = Join(source->lookup, name);
        std::deque<Pending> pending;
        pending.push_back(Pending{name, false});
        ++mQueuedComponents;
        std::size_t frameDepth = 1;
        bool direct = true;
        bool finalDirectory = mRole == InputRole::Prefix;
        bool directLink = false;
        while (!pending.empty())
        {
            Pending item = std::move(pending.front());
            pending.pop_front();
            if (item.endFrame)
            {
                --frameDepth;
                continue;
            }
            --mQueuedComponents;
            if (!Charge())
                return Error("Resolver work budget exhausted", E2BIG);
            if (item.name.empty() || item.name == ".")
                continue;
            if (item.name == "..")
            {
                if (mStack.size() <= source->boundary + 1)
                    return Error("Parent crosses traversal barrier", EXDEV);
                mStack.pop_back();
                continue;
            }
            if (!Detail::IsSingleChildComponent(item.name))
                return Error("Invalid resolved component", EINVAL);
            const bool intermediate = HasComponent(pending) || finalDirectory;
            if (mStack.back().Metadata().FileType() != Type::Directory)
                return Error("Intermediate component is not a directory", ENOTDIR);
            const std::string parent = Effective();
            const std::string lookup = Join(parent, item.name);
            auto held = FindHeld(lookup);
            if (!held.HasValue())
                return std::move(held).Error();
            if (held.Value().HasValue())
            {
                const HeldMatch match = held.Value().Value();
                if (match.alias)
                {
                    if (direct)
                    {
                        directLink = true;
                        mDirectLookup = lookup;
                        mDirectMount = match.pin.Metadata().LookupMount().Value();
                    }
                    if (!Following(intermediate))
                    {
                        if (direct && !HasComponent(pending) && mRole == InputRole::Leaf && mPolicy.rejectedLinks == RejectedLinkDisposition::Skip)
                            return Variant<Step, RejectionReason>(InPlaceType<RejectionReason>{}, RejectionReason::Excluded);
                        return Error("Held symlink following is disabled", ELOOP);
                    }
                    if (mFollowed >= source->limits.linkExpansions)
                        return Error("Link expansion budget exhausted", ELOOP);
                    ++mFollowed;
                }
                const auto facts = match.pin.Metadata();
                if (mPolicy.mounts == MountPolicy::StayOnRootMount &&
                    (facts.LookupMount().Value() != source->baseline || facts.TargetMount().Value() != source->baseline))
                    return Error("Held component crosses root mount", EXDEV);
                if (match.index < source->boundary)
                    return Error("Held component crosses traversal barrier", EXDEV);
                // The selected held pin carries its original physical lineage.
                const std::size_t lineageWork = match.fromStack ? mStack.size() - match.index - 1 : match.index + 1;
                if (!Fits(source->allowance->spent, lineageWork, source->limits.shared.work))
                    return Error("Held lineage work budget exhausted", E2BIG);
                source->allowance->spent += lineageWork;
                if (match.fromStack)
                    mStack.erase(mStack.begin() + match.index + 1, mStack.end());
                else
                {
                    mStack.assign(source->pins.begin(), source->pins.begin() + match.index + 1);
                }
                direct = false;
                continue;
            }
            if (source->pins.size() > source->limits.shared.liveDescriptors - kNewChildPeak ||
                mNewPins > source->limits.shared.liveDescriptors - kNewChildPeak - source->pins.size())
                return Error("Resolver descriptor budget exhausted", EMFILE);
            auto opened = source->context.get().OpenAt(mStack.back().mAcquisition->mDescriptor, item.name.c_str(),
                intermediate ? ContextInterface::OpenProfile::PinChildDirectory : ContextInterface::OpenProfile::PinChild);
            if (!opened.HasValue() && opened.Error().code == ENOTDIR && intermediate)
                opened = source->context.get().OpenAt(mStack.back().mAcquisition->mDescriptor, item.name.c_str(), ContextInterface::OpenProfile::PinChild);
            if (!opened.HasValue())
            {
                // Make resolves each input component separately, including Prefix roles.
                // Only this direct child lookup can report absence; expanded link targets
                // and trusted helper failures retain their error provenance.
                if (direct && !HasComponent(pending) && opened.Error().code == ENOENT && mPolicy.missingFiles == MissingFileDisposition::Report)
                    return Variant<Step, RejectionReason>(InPlaceType<RejectionReason>{}, RejectionReason::Missing);
                return Error("Cannot pin confined component", opened.Error().code);
            }
            // Stat and mount are observed together, through the shared
            // acquisition helper; its procfs session retires before it
            // returns, so only the new child pin remains owned afterward.
            auto acquired = Handle::AcquirePinnedObject(source->context.get(), std::move(opened).Value(), source->limits.shared.fdinfoBytes,
                "Cannot inspect confined component");
            if (!acquired.HasValue())
                return std::move(acquired).Error();
            Handle::AcquiredPin object = std::move(acquired).Value();
            Descriptor pin = std::move(object.pin);
            const struct stat snapshot = object.snapshot;
            const std::uint64_t mount = object.mount;
            if (mPolicy.mounts == MountPolicy::StayOnRootMount && mount != source->baseline)
                return Error("Component crosses root mount", EXDEV);
            if (S_ISLNK(snapshot.st_mode))
            {
                if (direct)
                {
                    directLink = true;
                    mDirectLookup = lookup;
                    mDirectMount = mount;
                }
                if (!Following(intermediate))
                {
                    if (direct && !HasComponent(pending) && mRole == InputRole::Leaf && mPolicy.rejectedLinks == RejectedLinkDisposition::Skip)
                        return Variant<Step, RejectionReason>(InPlaceType<RejectionReason>{}, RejectionReason::Excluded);
                    return Error("Symlink following is disabled", ELOOP);
                }
                if (mFollowed >= source->limits.linkExpansions)
                    return Error("Link expansion budget exhausted", ELOOP);
                ++mFollowed;
                // The pin's mount is observed just above (and compared
                // against StayOnRootMount's baseline); a live O_PATH pin
                // cannot change mount, so ReadPinnedLink does not re-read or
                // re-compare it around the readlink.
                auto target = Path::ReadPinnedLink(pin, source->limits.linkTargetBytes);
                if (!target.HasValue())
                    return std::move(target).Error();
                std::string text = std::move(target).Value().text;
                if (text.size() > source->limits.shared.targetBytes)
                    return Error("Link target exceeds target byte limit", E2BIG);
                if (text.back() == 47 && !HasComponent(pending))
                    finalDirectory = true;
                if (text.front() == 47)
                {
                    const std::string absolute = CollapseSeparators(text);
                    bool matched = false;
                    std::string suffix;
                    for (const std::string& binding : {source->boundaryLookup, source->boundaryEffective})
                    {
                        if (!AtBoundary(absolute, binding))
                            continue;
                        const std::string candidate = absolute.substr(binding == "/" ? 1 : binding.size());
                        if (matched && suffix != candidate)
                            return Error("Ambiguous acquired boundary binding", EXDEV);
                        suffix = candidate;
                        matched = true;
                    }
                    if (!matched)
                        return Error("Absolute link outside traversal barrier", EXDEV);
                    text = std::move(suffix);
                    mStack.erase(mStack.begin() + source->boundary + 1, mStack.end());
                }
                if (frameDepth >= 64)
                    return Error("Symlink frame ceiling exhausted", ELOOP);
                // Count and validate components before allocating the
                // expansion queue: the queued-component cap below is
                // checked before the deque is built.
                std::size_t componentCount = 0;
                for (std::size_t scan = 0; scan < text.size();)
                {
                    const std::size_t slash = text.find(47, scan);
                    const std::size_t end = slash == std::string::npos ? text.size() : slash;
                    if (end != scan)
                    {
                        if (end - scan > NAME_MAX)
                            return Error("Link target component exceeds NAME_MAX", ENAMETOOLONG);
                        ++componentCount;
                    }
                    scan = end + 1;
                }
                std::size_t remainingComponents = 0;
                if (Fits(mSteps, mQueuedComponents, source->limits.shared.components))
                    remainingComponents = source->limits.shared.components - mSteps - mQueuedComponents;
                if (componentCount > remainingComponents)
                    return Error("Symlink expansion exceeds resolver component budget", E2BIG);
                std::deque<Pending> expansion;
                std::size_t start = 0;
                while (start < text.size())
                {
                    const std::size_t slash = text.find(47, start);
                    const std::size_t end = slash == std::string::npos ? text.size() : slash;
                    if (end != start)
                    {
                        expansion.push_back(Pending{text.substr(start, end - start), false});
                        ++mQueuedComponents;
                    }
                    start = end + 1;
                }
                expansion.push_back(Pending{std::string(), true});
                while (!pending.empty())
                {
                    expansion.push_back(std::move(pending.front()));
                    pending.pop_front();
                }
                pending.swap(expansion);
                ++frameDepth;
                direct = false;
                continue;
            }
            if (!S_ISDIR(snapshot.st_mode) && !S_ISREG(snapshot.st_mode))
            {
                if (!HasComponent(pending) && mRole == InputRole::Leaf && mPolicy.unsupportedTypes == UnsupportedTypeDisposition::Skip)
                    return Variant<Step, RejectionReason>(InPlaceType<RejectionReason>{}, RejectionReason::UnsupportedType);
                return Error("Unsupported confined object", EOPNOTSUPP);
            }
            if (intermediate && !S_ISDIR(snapshot.st_mode))
                return Error("Intermediate component is not a directory", ENOTDIR);
            // Prefixes of a followed link retain their own acquisition names;
            // only its terminal pin carries the requested link provenance.
            const bool linkTerminal = !mDirectLookup.empty() && !HasComponent(pending);
            ::ComplianceEngine::Filesystem::Metadata metadata(S_ISDIR(snapshot.st_mode) ? Type::Directory : Type::RegularFile, snapshot,
                LookupMountId(linkTerminal ? mDirectMount : mount), TargetMountId(mount), Detail::LookupSpelling(linkTerminal ? mDirectLookup : lookup),
                Detail::EffectiveSpelling(lookup));
            Handle handle(std::move(pin), std::move(metadata));
            Component pushed(std::move(handle));
            mStack.push_back(std::move(pushed));
            ++mNewPins;
            if (mStack.size() - 1 > source->limits.depth)
                return Error("Physical resolution depth exhausted", E2BIG);
            direct = false;
        }
        if (finalDirectory && mStack.back().Metadata().FileType() != Type::Directory)
            return Error("Trailing slash requires directory", ENOTDIR);
        if (directLink && mRole == InputRole::Leaf && !FollowingFinal(mStack.back().Metadata().FileType()))
        {
            if (mPolicy.rejectedLinks == RejectedLinkDisposition::Skip)
                return Variant<Step, RejectionReason>(InPlaceType<RejectionReason>{}, RejectionReason::Excluded);
            return Error("Terminal symlink policy rejects target", ELOOP);
        }
        return Prepare();
    }

private:
    struct Pending
    {
        std::string name;
        bool endFrame;
    };
    struct HeldMatch
    {
        HeldMatch(Component owner, std::size_t position, bool isAlias, bool stackOwner)
            : pin(std::move(owner)),
              index(position),
              alias(isAlias),
              fromStack(stackOwner)
        {
        }
        Component pin;
        std::size_t index;
        bool alias;
        bool fromStack;
    };
    static bool HasComponent(const std::deque<Pending>& pending)
    {
        for (const Pending& item : pending)
            if (!item.endFrame)
                return true;
        return false;
    }
    bool Charge()
    {
        const ResolverLimits limits = mState->limits;
        const std::size_t chunks = limits.shared.fdinfoBytes / 256 + ((limits.shared.fdinfoBytes % 256) != 0);
        if (chunks > (std::numeric_limits<std::size_t>::max() - 128) / 4 || mSteps >= limits.shared.components)
            return false;
        const std::size_t cost = 128 + 4 * chunks;
        auto allowance = mState->allowance;
        if (!Fits(allowance->spent, cost, limits.shared.work))
            return false;
        ++mSteps;
        allowance->spent += cost;
        return true;
    }
    bool Following(bool intermediate) const
    {
        if (intermediate)
            return mPolicy.prefixLinks == PrefixLinkPolicy::Follow;
        return (mPolicy.fileLinks == FileLinkPolicy::Follow || mPolicy.directoryLinks == DirectoryLinkPolicy::Follow);
    }
    bool FollowingFinal(Type type) const
    {
        return type == Type::Directory ? mPolicy.directoryLinks == DirectoryLinkPolicy::Follow : mPolicy.fileLinks == FileLinkPolicy::Follow;
    }
    std::string Effective() const
    {
        if (Component::SameAcquisition(mStack.back(), mState->pins.back()))
            return mState->effective;
        if (Component::SameAcquisition(mStack.back(), mState->pins[mState->boundary]))
            return mState->boundaryEffective;
        return Component::EffectiveName(mStack.back());
    }
    Result<Optional<HeldMatch>> FindHeld(const std::string& lookup)
    {
        Optional<HeldMatch> match;
        for (std::size_t scope = 0; scope < 2; ++scope)
        {
            const std::size_t count = scope == 0 ? mState->pins.size() : mStack.size();
            for (std::size_t index = mState->boundary; index < count; ++index)
            {
                // Copy only the owner being inspected; never retain an alias to
                // either published or mutable stack across subsequent work.
                Component pin = scope == 0 ? mState->pins[index] : mStack[index];
                if (pin.Metadata().FileType() != Type::Directory)
                    continue;
                const std::size_t names = BoundedSum({Component::LookupNameBytes(pin), Component::EffectiveNameBytes(pin)});
                const std::size_t cost = BoundedSum({std::size_t{1}, lookup.size(), names});
                if (!Fits(mState->allowance->spent, cost, mState->limits.shared.work))
                    return Error("Held search work budget exhausted", E2BIG);
                mState->allowance->spent += cost;
                const std::string acquiredLookup = Component::LookupName(pin);
                const std::string acquiredEffective = Component::EffectiveName(pin);
                if (acquiredLookup != lookup && acquiredEffective != lookup)
                    continue;
                if (match.HasValue() && !Component::SameAcquisition(match.Value().pin, pin))
                    return Error("Ambiguous held directory binding", EXDEV);
                if (!match.HasValue())
                    match = HeldMatch(pin, index, acquiredLookup == lookup && acquiredEffective != lookup, scope != 0);
            }
        }
        return match;
    }
    Result<Variant<Step, RejectionReason>> Prepare()
    {
        auto source = mState;
        std::size_t common = 0;
        while (common < source->pins.size() && common < mStack.size() && Component::SameAcquisition(source->pins[common], mStack[common]))
            ++common;
        if (common <= source->boundary || common == 0)
            return Error("Resolution displaced traversal barrier", EXDEV);
        const std::size_t finalSize = mStack.size();
        if (finalSize - 1 > source->limits.depth || finalSize > source->limits.shared.liveDescriptors - kProcfsTemporaryPeak)
            return Error("Resolved stack exceeds physical budget", E2BIG);
        const std::string targetEffective = Effective();
        auto data = std::make_shared<Step::Data>(source->pins.size(), source->pins[common - 1], source->pins[source->boundary], source->boundary,
            source->boundaryLookup, source->boundaryEffective, source->baseline);
        data->popped.assign(source->pins.begin() + common, source->pins.end());
        data->pushed.assign(mStack.begin() + common, mStack.end());
        data->sourceLookup = source->lookup;
        data->sourceEffective = source->effective;
        data->targetLookup = mSourceLookup;
        data->targetEffective = targetEffective;
        data->hasLookupMount = !mDirectLookup.empty();
        data->lookupMount = mDirectMount;
        return Variant<Step, RejectionReason>(InPlaceType<Step>{}, Step(std::move(data)));
    }
    std::shared_ptr<const State> mState;
    Policy mPolicy;
    InputRole mRole;
    std::size_t& mFollowed;
    std::vector<Component> mStack;
    std::string mSourceLookup;
    std::string mDirectLookup;
    std::uint64_t mDirectMount = 0;
    std::size_t mSteps = 0;
    std::size_t mNewPins = 0;
    std::size_t mQueuedComponents = 0;
};

Result<Variant<Path::Step, Path::RejectionReason>> Path::ResolveInput(const Path& path, std::string name, Policy policy, InputRole role, std::size_t& followed)
{
    auto validation = Validate(policy, path.Limits());
    if (validation.HasValue())
        return std::move(validation).Value();
    if (!Detail::IsSingleChildComponent(name) && role == InputRole::Leaf)
        return Error("Resolve requires a single child name", EINVAL);
    if (name.empty() || name.find(47) != std::string::npos || name.find(char(0)) != std::string::npos)
        return Error("Invalid path component", EINVAL);
    if (name.size() > NAME_MAX)
        return Error("Path component exceeds NAME_MAX", ENAMETOOLONG);
    Resolver resolver(path, policy, role, followed);
    return resolver.Run(name);
}
Result<Variant<Path::Step, Path::RejectionReason>> Path::Resolve(std::string name, Policy policy) const
{
    std::size_t followed = 0;
    return ResolveInput(*this, std::move(name), policy, InputRole::Leaf, followed);
}
Result<Path::Step> Path::Apply(Step&& step) &
{
    auto delta = step.mData;
    auto source = mState;
    if (source->pins.size() != delta->sourceDepth || delta->popped.size() >= delta->sourceDepth)
        return Error("Stale Path step depth", ESTALE);
    const std::size_t attachIndex = delta->sourceDepth - delta->popped.size() - 1;
    if (source->boundary >= source->pins.size())
        return Error("Step is detached from its acquisition context", ESTALE);
    // Check the physical suffix and source route before classifying a pop
    // across a newly frozen barrier. An unrelated same-depth path is stale.
    if (!Component::SameAcquisition(source->pins[attachIndex], delta->attach) || source->lookup != delta->sourceLookup || source->effective != delta->sourceEffective)
        return Error("Step is detached from its acquisition context", ESTALE);
    for (std::size_t index = 0; index < delta->popped.size(); ++index)
        if (!Component::SameAcquisition(source->pins[attachIndex + index + 1], delta->popped[index]))
            return Error("Step physical suffix changed", ESTALE);
    if (attachIndex < source->boundary)
        return Error("Step crosses traversal barrier", EXDEV);
    if (source->boundary != delta->boundary || !Component::SameAcquisition(source->pins[source->boundary], delta->boundaryPin) ||
        source->boundaryLookup != delta->boundaryLookup || source->boundaryEffective != delta->boundaryEffective || source->baseline != delta->baseline)
        return Error("Step is detached from its acquisition context", ESTALE);
    if (delta->pushed.size() > std::numeric_limits<std::size_t>::max() - attachIndex - 1)
        return Error("Step physical depth overflows", E2BIG);
    const std::size_t finalSize = attachIndex + 1 + delta->pushed.size();
    if (finalSize - 1 > source->limits.depth || finalSize > source->limits.shared.liveDescriptors - kProcfsTemporaryPeak)
        return Error("Step exceeds physical stack budget", E2BIG);
    if (finalSize > std::numeric_limits<std::size_t>::max() - source->pins.size())
        return Error("Snapshot work overflows", E2BIG);
    const std::size_t work = source->pins.size() + finalSize;
    if (!Fits(source->allowance->spent, work, source->limits.shared.work))
        return Error("Apply snapshot work budget exhausted", E2BIG);
    // Failed preparation is work too; consume before fallible allocations.
    source->allowance->spent += work;
    // All allocations, inverse construction, and bounded name copies precede
    // publication. No descriptor is duplicated, reopened or reclassified.
    auto inverse = std::make_shared<Step::Data>(finalSize, delta->attach, source->pins[source->boundary], source->boundary, source->boundaryLookup,
        source->boundaryEffective, source->baseline);
    inverse->popped = delta->pushed;
    inverse->pushed = delta->popped;
    inverse->sourceLookup = delta->targetLookup;
    inverse->sourceEffective = delta->targetEffective;
    inverse->targetLookup = delta->sourceLookup;
    inverse->targetEffective = delta->sourceEffective;
    // Build the exact final allocation; vector::erase would retain capacity
    // for popped pins and under-report a long-lived Path footprint.
    std::vector<Component> replacement;
    replacement.reserve(finalSize);
    for (std::size_t index = 0; index <= attachIndex; ++index)
        replacement.push_back(source->pins[index]);
    for (Component pin : delta->pushed)
        replacement.push_back(pin);
    auto candidate = std::make_shared<State>(*source);
    candidate->pins.swap(replacement);
    candidate->lookup = delta->targetLookup;
    candidate->effective = delta->targetEffective;
    std::shared_ptr<const State> published(std::move(candidate));
    std::shared_ptr<const Step::Data> undo(std::move(inverse));
    mState.swap(published);
    return Step(std::move(undo));
}
Result<bool> Path::Freeze() &
{
    auto source = mState;
    if (source->boundary == source->pins.size() - 1)
        return false;
    if (!Fits(source->allowance->spent, source->pins.size(), source->limits.shared.work))
        return Error("Freeze snapshot work budget exhausted", E2BIG);
    source->allowance->spent += source->pins.size();
    auto candidate = std::make_shared<State>(*source);
    candidate->boundary = source->pins.size() - 1;
    candidate->boundaryLookup = source->lookup;
    candidate->boundaryEffective = source->effective;
    candidate->baseline = source->pins.back().Metadata().TargetMount().Value();
    if (candidate->pins.size() > source->limits.shared.liveDescriptors - kProcfsTemporaryPeak)
        return Error("Freeze preparation exceeds retained resource budget", E2BIG);
    std::shared_ptr<const State> published(std::move(candidate));
    mState.swap(published);
    return true;
}
Result<Variant<Path, Path::RejectionReason>> Path::Make(const ContextInterface& context, std::string absolutePath, Policy policy, ResolverLimits limits)
{
    auto validation = Validate(policy, limits);
    if (validation.HasValue())
        return std::move(validation).Value();
    if (absolutePath.empty() || absolutePath.front() != 47 || absolutePath.find(char(0)) != std::string::npos)
        return Error("Make requires a bounded absolute path", EINVAL);
    if (absolutePath.size() > limits.shared.targetBytes)
        return Error("Make input exceeds target byte limit", ENAMETOOLONG);
    for (std::size_t prescan = absolutePath.find_first_not_of("/", 1); prescan != std::string::npos;)
    {
        const std::size_t slash = absolutePath.find(47, prescan);
        const std::size_t end = slash == std::string::npos ? absolutePath.size() : slash;
        if (end - prescan > NAME_MAX)
            return Error("Path component exceeds NAME_MAX", ENAMETOOLONG);
        prescan = absolutePath.find_first_not_of("/", end);
    }
    const std::size_t chunks = limits.shared.fdinfoBytes / 256 + ((limits.shared.fdinfoBytes % 256) != 0);
    if (chunks > (std::numeric_limits<std::size_t>::max() - 128) / 4 || !Fits(0, 128 + 4 * chunks, limits.shared.work))
        return Error("Path work budget exhausted", E2BIG);
    const std::size_t rootWork = 128 + 4 * chunks;
    auto root = Handle::PinProcessRoot(context, limits.shared);
    if (!root.HasValue())
        return std::move(root).Error();
    Component rootComponent = MakeRootComponent(std::move(root).Value());
    auto state = std::make_shared<State>(context, limits, std::move(rootComponent));
    Path result(std::move(state));
    result.mState->allowance->spent = rootWork;
    // Factory input absence is a typed selection regardless of the caller's
    // traversal disposition; public Resolve still uses the supplied policy.
    Policy factoryPolicy = policy;
    factoryPolicy.missingFiles = MissingFileDisposition::Report;
    std::size_t followed = 0;
    std::size_t start = absolutePath.find_first_not_of("/", 1);
    while (start != std::string::npos)
    {
        const std::size_t slash = absolutePath.find(47, start);
        const std::size_t end = slash == std::string::npos ? absolutePath.size() : slash;
        const std::size_t next = absolutePath.find_first_not_of("/", end);
        const bool prefix = next != std::string::npos || absolutePath.back() == 47;
        auto resolved = ResolveInput(result, absolutePath.substr(start, end - start), factoryPolicy, prefix ? InputRole::Prefix : InputRole::Leaf, followed);
        if (!resolved.HasValue())
            return std::move(resolved).Error();
        if (resolved.Value().Is<RejectionReason>())
            return Variant<Path, RejectionReason>(InPlaceType<RejectionReason>{}, resolved.Value().Get<RejectionReason>());
        auto applied = result.Apply(std::move(resolved.Value().Get<Step>()));
        if (!applied.HasValue())
            return std::move(applied).Error();
        start = next;
    }
    return Variant<Path, RejectionReason>(InPlaceType<Path>{}, std::move(result));
}

// Co-located FTW continuation requires the complete private directory cursor
// factory and Handle activation helper above; no generic Component API.
namespace
{
using Detail::PathOperationSlots;
using Detail::StartingCursorSlots;
FilesystemTraversalPolicy Continuation(const ResolvedFilesystemCollectionRequest& request)
{
    FilesystemTraversalPolicy policy;
    policy.direction = request.direction;
    policy.maxDepth = request.maxDepth;
    policy.childFileLinkAction = request.childFileLinkAction;
    policy.childDirectoryLinkAction = request.childDirectoryLinkAction;
    policy.scope = request.scope;
    policy.yieldType = request.yieldType;
    policy.unsupported = request.unsupported;
    policy.depthAction = request.depthAction;
    policy.missingChildAction = request.missingChildAction;
    policy.limits = request.limits;
    return policy;
}

Filesystem::ResolverLimits AcquisitionBudget(const ResolvedFilesystemCollectionRequest& request)
{
    const auto limits = request.limits;
    const std::size_t components = std::count(request.rootPath.begin(), request.rootPath.end(), '/') + 1;
    const std::size_t work = limits.entryWork > (std::numeric_limits<std::size_t>::max() - 32768) / 512 ? std::numeric_limits<std::size_t>::max() :
                                                                                                          limits.entryWork * 512 + 32768;
    Filesystem::ResolverLimits budget;
    budget.shared.targetBytes = limits.fullPathBytes;
    budget.shared.components = limits.operationalDescent + components + 1;
    budget.shared.work = work;
    budget.shared.liveDescriptors = limits.openDirectories + components + PathOperationSlots() + StartingCursorSlots();
    budget.shared.fdinfoBytes = limits.fdinfoBytes;
    budget.linkTargetBytes = limits.fullPathBytes;
    budget.linkExpansions = limits.entryWork;
    budget.depth = limits.operationalDescent + components + 1;
    return budget;
}

Path::Policy AcquisitionPolicy(const ResolvedFilesystemCollectionRequest& request)
{
    Path::Policy policy;
    policy.prefixLinks = request.rootFileLinkAction == SymlinkPolicy::Follow || request.rootDirectoryLinkAction == SymlinkPolicy::Follow ?
                             PrefixLinkPolicy::Follow :
                             PrefixLinkPolicy::Reject;
    policy.fileLinks = request.rootFileLinkAction == SymlinkPolicy::Follow ? FileLinkPolicy::Follow : FileLinkPolicy::Reject;
    policy.directoryLinks = request.rootDirectoryLinkAction == SymlinkPolicy::Follow ? DirectoryLinkPolicy::Follow : DirectoryLinkPolicy::Reject;
    policy.rejectedLinks = RejectedLinkDisposition::Skip;
    policy.unsupportedTypes = UnsupportedTypeDisposition::Error;
    policy.missingFiles = MissingFileDisposition::Report;
    policy.mounts = MountPolicy::CrossMounts;
    return policy;
}

Path::Policy ChildPolicy(const FilesystemTraversalPolicy& request)
{
    Path::Policy policy;
    policy.prefixLinks = PrefixLinkPolicy::Follow;
    policy.fileLinks = request.childFileLinkAction == SymlinkPolicy::Follow ? FileLinkPolicy::Follow : FileLinkPolicy::Reject;
    policy.directoryLinks = request.childDirectoryLinkAction == SymlinkPolicy::Follow ? DirectoryLinkPolicy::Follow : DirectoryLinkPolicy::Reject;
    policy.rejectedLinks = RejectedLinkDisposition::Skip;
    policy.unsupportedTypes = request.unsupported == UnsupportedTypeDisposition::Skip ? UnsupportedTypeDisposition::Skip : UnsupportedTypeDisposition::Error;
    policy.missingFiles =
        request.missingChildAction == FilesystemMissingChildAction::ReportRegularFile ? MissingFileDisposition::Report : MissingFileDisposition::Error;
    // Collection mount scope is a filter on BOTH acquired mount facts. Confinement
    // is enforced independently by the frozen Path barrier, even with CrossMounts.
    policy.mounts = MountPolicy::CrossMounts;
    return policy;
}

Error OperationError(const char* operation, const std::string& path, int code)
{
    return Error(std::string("Failed to ") + operation + " '" + path + "': " + std::strerror(code), code);
}

bool Yield(FilesystemYieldType type, const struct stat& metadata)
{
    switch (type)
    {
        case FilesystemYieldType::All:
            return true;
        case FilesystemYieldType::RegularFiles:
            return S_ISREG(metadata.st_mode);
        case FilesystemYieldType::Directories:
            return S_ISDIR(metadata.st_mode);
        case FilesystemYieldType::SymbolicLinks:
            return S_ISLNK(metadata.st_mode);
    }
    return false;
}

FilesystemCollectionEntry Snapshot(const FilesystemCollectionEntry& live)
{
    FilesystemCollectionEntry copy;
    copy.path = live.path;
    copy.metadata = live.metadata;
    copy.missing = live.missing;
    return copy;
}

} // namespace
FilesystemTraversalPolicy CollectionContinuation(const ResolvedFilesystemCollectionRequest& request)
{
    return Continuation(request);
}
Path::Policy CollectionRootPolicy(const ResolvedFilesystemCollectionRequest& request)
{
    return AcquisitionPolicy(request);
}
ResolverLimits CollectionRootLimits(const ResolvedFilesystemCollectionRequest& request)
{
    return AcquisitionBudget(request);
}

namespace FTW
{
namespace
{
struct DescriptorSlots
{
    explicit DescriptorSlots(std::size_t n = 0)
        : value(n)
    {
    }
    std::size_t value;
};
// Pin retention is bounded by descriptor slots only; there is no byte
// component to this charge.
struct PinCharge
{
    explicit PinCharge(DescriptorSlots slots = DescriptorSlots())
        : descriptors(slots)
    {
    }
    DescriptorSlots descriptors;
};
// Only scalar retention, never State, Path, Component or a cursor. Entries may
// outlive the range; their final owner refunds the counter without allocations.
struct RetentionCounter
{
    std::size_t descriptors = 0;
};
struct EntryCharge
{
    explicit EntryCharge(std::shared_ptr<RetentionCounter> counter) noexcept
        : owner(std::move(counter))
    {
    }
    ~EntryCharge() noexcept
    {
        // A corrupted retention ledger must not wrap and admit more pins.
        if (owner->descriptors < pins.descriptors.value)
        {
            std::terminate();
        }
        owner->descriptors -= pins.descriptors.value;
    }
    std::shared_ptr<RetentionCounter> owner;
    PinCharge pins;
};
} // namespace

struct FileRange::State
{
    struct Frame
    {
        std::string logicalName;
        Optional<Detail::DirectoryCursor> cursor;
        Optional<Path::Step> inverse; // only the selected start has no inverse
        PinCharge inverseCharge;
        std::size_t width = 0;
        dev_t device = 0;
        ino_t inode = 0;
    };

    explicit State(FilesystemTraversalPolicy policy)
        : request(std::move(policy)),
          pins(std::make_shared<RetentionCounter>())
    {
    }

    State(FilesystemTraversalPolicy policy, Path accepted)
        : request(std::move(policy)),
          current(std::move(accepted)),
          pins(std::make_shared<RetentionCounter>())
    {
    }

    ~State() noexcept
    {
        Stop();
    }

    Result<bool> CanObserve(const std::string& at) const
    {
        if (observations >= request.limits.retainedObservations)
            return Error("Filesystem retained observation count exceeded at " + at, E2BIG);
        return true;
    }

    Result<bool> CheckPins(PinCharge extra) const
    {
        if (!current.HasValue())
            return Error("Filesystem traversal is not active", EINVAL);
        const ResolverLimits limits = current.Value().Limits();
        if (pins->descriptors > limits.shared.liveDescriptors || extra.descriptors.value > limits.shared.liveDescriptors - pins->descriptors)
            return Error("Filesystem pin retention exceeds descriptor budget", EMFILE);
        return true;
    }

    Result<bool> ReservePins(PinCharge extra)
    {
        auto budget = CheckPins(extra);
        if (!budget.HasValue())
            return budget;
        pins->descriptors += extra.descriptors.value;
        return true;
    }

    void RefundPins(PinCharge charge) noexcept
    {
        if (pins->descriptors < charge.descriptors.value)
        {
            std::terminate();
        }
        pins->descriptors -= charge.descriptors.value;
    }

    Result<bool> PrepareFrame()
    {
        if (frames.size() == std::numeric_limits<std::size_t>::max())
            return Error("Filesystem frame count overflow", EOVERFLOW);
        // Reserve storage before Apply so a later failure can't disturb an
        // already-published frame (vector may grow by more than one slot).
        static_assert(std::is_nothrow_move_constructible<Frame>::value, "Frame publication after Apply must not throw");
        frames.reserve(frames.size() + 1);
        return true;
    }

    Result<bool> Exclude(const std::string& name, const char* reason)
    {
        auto observable = CanObserve(name);
        if (!observable.HasValue())
            return observable;
        result.exclusions.push_back({name, reason});
        ++observations;
        return true;
    }

    Result<bool> Offer(FilesystemCollectionEntry entry, PinCharge ownerCharge = PinCharge())
    {
        if (!entry.missing && !Yield(request.yieldType, entry.metadata))
            return true;
        if (retainEntries)
        {
            auto observable = CanObserve(entry.path);
            if (!observable.HasValue())
                return observable;
            result.entries.push_back(Snapshot(entry));
            ++observations;
        }
        if (entry.mComponent.HasValue())
        {
            auto record = std::make_shared<EntryCharge>(pins);
            auto charged = ReservePins(ownerCharge);
            if (!charged.HasValue())
                return charged;
            record->pins = ownerCharge;
            entry.mRetentionCharge = std::move(record);
        }
        static_assert(std::is_nothrow_move_constructible<FilesystemCollectionEntry>::value, "Entry publication after Apply must not throw");
        pending = std::move(entry);
        return true;
    }

    Result<bool> Initialize(std::string rootName)
    {
        auto budget = CheckPins(PinCharge());
        if (!budget.HasValue())
            return budget;
        const auto facts = current.Value().Leaf().Metadata();
        const auto factsStat = facts.Stat();
        baseline = facts.TargetMount().Value();
        FilesystemCollectionEntry entry;
        entry.path = rootName;
        entry.metadata = factsStat;
        entry.OwnComponent(current.Value().Leaf());
        if (Type::Directory == facts.FileType())
        {
            Frame frame;
            frame.logicalName = std::move(rootName);
            frame.device = factsStat.st_dev;
            frame.inode = factsStat.st_ino;
            auto prepared = PrepareFrame();
            if (!prepared.HasValue())
                return prepared;
            // Budget first, open the native cursor next, then charge. If the
            // charge somehow failed after a successful open, RAII on `opened`
            // closes the just-opened cursor; there is no window where a
            // charge exists without an installed cursor, or an installed
            // cursor is uncharged.
            auto cursorBudget = CheckPins(PinCharge(DescriptorSlots(1)));
            if (!cursorBudget.HasValue())
                return cursorBudget;
            auto opened = Detail::DirectoryCursor::OpenChildren(current.Value().Leaf());
            if (!opened.HasValue())
                return std::move(opened).Error();
            auto charged = ReservePins(PinCharge(DescriptorSlots(1)));
            if (!charged.HasValue())
                return charged;
            frame.cursor = std::move(opened).Value();
            frames.push_back(std::move(frame));
        }
        return Offer(std::move(entry), PinCharge(DescriptorSlots(current.Value().RetainedDescriptors())));
    }

    Result<bool> MissingChild(const Detail::DirectoryChild& child, const std::string& full)
    {
        if ((FilesystemMissingChildAction::ReportRegularFile != request.missingChildAction) || (DT_REG != child.type))
            return OperationError("acquire child", full, ENOENT);
        FilesystemCollectionEntry missing;
        missing.path = full;
        missing.missing = true;
        return Offer(std::move(missing));
    }

    Result<bool> Child(Detail::DirectoryChild child)
    {
        const std::size_t cap = request.limits.fullPathBytes;
        if (frames.back().logicalName.size() >= cap || child.name.size() >= cap - frames.back().logicalName.size())
            return Error("Filesystem path exceeds full path budget", ENAMETOOLONG);
        const std::string full = frames.back().logicalName + "/" + child.name;
        if (full.size() >= cap)
            return Error("Filesystem path exceeds full path budget at " + full, ENAMETOOLONG);
        FilesystemCollectionEntry entry;
        entry.path = full;
        auto budget = CheckPins(PinCharge());
        if (!budget.HasValue())
            return budget;
        PinCharge targetCharge;
        {
            // Resolve only the cursor name. The reporting label is not authority.
            auto resolved = current.Value().Resolve(std::move(child.name), ChildPolicy(request));
            if (!resolved.HasValue())
                return std::move(resolved).Error();
            if (resolved.Value().Is<Path::RejectionReason>())
            {
                switch (As<Path::RejectionReason>(resolved.Value()))
                {
                    case Path::RejectionReason::Missing:
                        return MissingChild(child, full);
                    case Path::RejectionReason::Excluded:
                        return Exclude(full, "link policy");
                    case Path::RejectionReason::UnsupportedType:
                        return Exclude(full, "unsupported type");
                }
            }
            const auto facts = As<Path::Step>(resolved.Value()).Metadata();
            const auto factsStat = facts.Stat();
            entry.metadata = factsStat;
            if ((FilesystemScope::All != request.scope) && ((baseline != facts.LookupMount().Value()) || (baseline != facts.TargetMount().Value())))
                return Exclude(full, "filesystem scope");
            const bool directory = Type::Directory == facts.FileType();
            bool descend = directory && FilesystemDirection::Down == request.direction;
            if (descend && (-1 != request.maxDepth) && (frames.size() > static_cast<std::size_t>(request.maxDepth)))
            {
                if (FilesystemDepthAction::Error == request.depthAction)
                    return Error("Maximum recursion depth reached");
                descend = false;
            }
            if (descend && frames.size() > request.limits.operationalDescent)
                return Error("Operational descent budget exceeded at " + full, E2BIG);
            if (descend)
            {
                for (std::size_t i = 0; i < frames.size(); ++i)
                    if ((frames[i].device == factsStat.st_dev) && (frames[i].inode == factsStat.st_ino))
                        return Error("Directory ancestor cycle at " + full, ELOOP);
            }
            targetCharge = PinCharge(DescriptorSlots(As<Path::Step>(resolved.Value()).RetainedDescriptors()));
            // Target is an owning Component. A file/observed directory never Applys.
            entry.OwnComponent(As<Path::Step>(resolved.Value()).Target());
            if (descend)
            {
                Frame frame;
                frame.logicalName = full;
                frame.device = factsStat.st_dev;
                frame.inode = factsStat.st_ino;
                auto prepared = PrepareFrame();
                if (!prepared.HasValue())
                    return prepared;
                // Prepare allocation before mutation; any later failure aborts the
                // private traversal without losing a published undo history.
                auto applied = current.Value().Apply(std::move(resolved.Value().Get<Path::Step>()));
                if (!applied.HasValue())
                    return std::move(applied).Error();
                if (current.Value().RetainedDescriptors() > current.Value().Limits().shared.liveDescriptors)
                    return Error("Applied path exceeds physical descriptor budget", EMFILE);
                const PinCharge inverseCharge(DescriptorSlots(applied.Value().RetainedDescriptors()));
                auto charged = ReservePins(inverseCharge);
                if (!charged.HasValue())
                    return charged;
                frame.inverse = std::move(applied).Value();
                frame.inverseCharge = inverseCharge;
                frames.push_back(std::move(frame));
            }
        } // Release forward Step/Result before publishing the entry.
        return Offer(std::move(entry), targetCharge);
    }

    Result<Optional<FilesystemCollectionEntry>> Pull()
    {
        if (pending.HasValue())
        {
            auto entry = std::move(pending).Value();
            pending.Reset();
            return Optional<FilesystemCollectionEntry>(std::move(entry));
        }
        while (!frames.empty())
        {
            if (!frames.back().cursor.HasValue())
            {
                if (frames.size() > request.limits.openDirectories)
                    return Error("Filesystem directory continuation exceeds open directory budget", EMFILE);
                // Same ordering as Initialize(): budget, native open, then
                // charge, so RAII on `opened` closes the cursor if the charge
                // itself ever failed, with no uncharged-installed or
                // charged-without-a-cursor window.
                auto budget = CheckPins(PinCharge(DescriptorSlots(1)));
                if (!budget.HasValue())
                    return budget.Error();
                auto opened = Detail::DirectoryCursor::OpenChildren(current.Value().Leaf());
                if (!opened.HasValue())
                    return std::move(opened).Error();
                auto charged = ReservePins(PinCharge(DescriptorSlots(1)));
                if (!charged.HasValue())
                    return charged.Error();
                frames.back().cursor = std::move(opened).Value();
            }
            auto name = frames.back().cursor->NextEntry();
            if (!name.HasValue())
                return OperationError("read directory", frames.back().logicalName, name.Error().code);
            if (!name.Value().HasValue())
            {
                frames.back().cursor->Close();
                frames.back().cursor.Reset();
                RefundPins(PinCharge(DescriptorSlots(1)));
                if (frames.back().inverse.HasValue())
                {
                    auto restored = current.Value().Apply(std::move(frames.back().inverse.Value()));
                    if (!restored.HasValue())
                        return std::move(restored).Error();
                    frames.back().inverse.Reset();
                    RefundPins(frames.back().inverseCharge);
                }
                frames.pop_back();
                continue;
            }
            if (work >= request.limits.entryWork)
                return Error("Filesystem entry work budget exhausted at " + frames.back().logicalName, E2BIG);
            ++work;
            if (frames.back().width >= request.limits.directoryWidth)
                return Error("Filesystem directory width budget exceeded at " + frames.back().logicalName, E2BIG);
            ++frames.back().width;
            auto processed = Child(std::move(name.Value()).Value());
            if (!processed.HasValue())
                return std::move(processed).Error();
            if (pending.HasValue())
            {
                auto entry = std::move(pending).Value();
                pending.Reset();
                return Optional<FilesystemCollectionEntry>(std::move(entry));
            }
        }
        Finish();
        return Optional<FilesystemCollectionEntry>();
    }

    // After an exception escapes Pull(), the range must not continue
    // traversal: `interrupted` is set before Pull() runs and cleared only
    // once it returns normally. An exception leaves it set, so a later call
    // fails closed without any native dispatch.
    // Destruction still releases every pin and cursor exactly once: Pull()
    // only mutates `frames`/`pins` at points that either fully commit (the
    // charge and the owning structure are both updated) or fully roll back
    // (nothing is charged) before a throw can occur, so State's destructor
    // (Stop/Finish) replays correctly regardless of where Pull() stopped.
    Result<Optional<FilesystemCollectionEntry>> Next()
    {
        if (failure.HasValue())
            return failure.Value();
        if (closed)
            return Optional<FilesystemCollectionEntry>();
        if (interrupted)
            return Error("Filesystem traversal was interrupted", ECANCELED);
        interrupted = true;
        auto next = Pull();
        // Record the failure (Abort copies an Error, which can allocate and
        // throw) before clearing `interrupted`: if that copy throws, the flag
        // must still read interrupted so a later Next() fails closed instead
        // of resuming native traversal on a half-recorded failure.
        if (!next.HasValue())
            Abort(next.Error());
        interrupted = false;
        // A named local returned here already binds as an rvalue (NRVO); an
        // explicit std::move would only block elision, not add safety.
        return next;
    }

    void Abort(const Error& primary)
    {
        failure = primary;
        Stop();
    }

    // Successful exhaustion releases traversal resources but keeps completed
    // observations available to StopVisitor. Abandonment additionally discards
    // the observations, without replaying any remaining inverse history.
    void Finish() noexcept
    {
        if (closed)
            return;
        closed = true;
        pending.Reset();
        for (std::size_t i = 0; i < frames.size(); ++i)
        {
            if (frames[i].cursor.HasValue())
            {
                frames[i].cursor->Close();
                RefundPins(PinCharge(DescriptorSlots(1)));
            }
            if (frames[i].inverse.HasValue())
                RefundPins(frames[i].inverseCharge);
        }
        std::vector<Frame> remainingFrames;
        remainingFrames.swap(frames); // Drop inverses, never replay on disposal.
        current.Reset();
    }

    void Stop() noexcept
    {
        Finish();
        FilesystemCollectionResult remainingResult;
        result.entries.swap(remainingResult.entries);
        result.exclusions.swap(remainingResult.exclusions);
        observations = 0;
    }

    FilesystemTraversalPolicy request;
    Optional<Path> current;
    std::vector<Frame> frames;
    FilesystemCollectionResult result;
    Optional<FilesystemCollectionEntry> pending;
    Optional<Error> failure;
    std::shared_ptr<RetentionCounter> pins;
    std::uint64_t baseline = 0;
    std::size_t observations = 0;
    std::size_t work = 0;
    bool rootExists = true;
    bool retainEntries = false;
    bool closed = false;
    bool interrupted = false;
};

Result<Optional<FilesystemCollectionEntry>> FileRange::Source::Next()
{
    if (!state)
        return Optional<FilesystemCollectionEntry>();
    return state->Next();
}

FileRange::FileRange(std::shared_ptr<State> state)
    : mState(std::move(state)),
      mView(Source{mState})
{
}

FileRange::~FileRange() noexcept
{
    Stop();
}

Result<bool> ValidateContinuation(const Path& root, const std::string& reportingName, const FilesystemTraversalPolicy& policy)
{
    const auto limits = policy.limits;
    if (reportingName.empty() || reportingName.front() != '/' || reportingName.find('\0') != std::string::npos)
        return Error("Continuation requires an absolute reporting name", EINVAL);
    if (policy.direction == FilesystemDirection::Up)
        return Error("Upward filesystem collection is not supported", ENOTSUP);
    if (policy.direction != FilesystemDirection::None && policy.direction != FilesystemDirection::Down)
        return Error("Invalid filesystem collection direction", EINVAL);
    if (policy.maxDepth < -1 || limits.operationalDescent == 0 || limits.entryWork == 0 || limits.directoryWidth == 0 || limits.fullPathBytes == 0 ||
        limits.fdinfoBytes == 0 || limits.fdinfoBytes >= std::string().max_size() || limits.fdinfoBytes > std::vector<char>().max_size() ||
        limits.fdinfoBytes > static_cast<std::size_t>(std::numeric_limits<ssize_t>::max()) || limits.retainedObservations == 0 || limits.openDirectories == 0)
        return Error("Invalid filesystem continuation limits", EINVAL);
    if (limits.fdinfoBytes < root.Limits().shared.fdinfoBytes)
        return Error("Filesystem continuation fdinfo byte limit is below the acquired root's bound inspection limit", EINVAL);
    if (policy.childFileLinkAction != SymlinkPolicy::Follow && policy.childFileLinkAction != SymlinkPolicy::DoNotFollow)
        return Error("Invalid child file link policy", EINVAL);
    if (policy.childDirectoryLinkAction != SymlinkPolicy::Follow && policy.childDirectoryLinkAction != SymlinkPolicy::DoNotFollow)
        return Error("Invalid child directory link policy", EINVAL);
    if (policy.scope == FilesystemScope::Local)
        return Error("Local filesystem classification is not supported", ENOTSUP);
    if (policy.scope != FilesystemScope::RootDevice && policy.scope != FilesystemScope::All && policy.scope != FilesystemScope::Defined)
        return Error("Invalid filesystem scope", EINVAL);
    if (policy.yieldType != FilesystemYieldType::All && policy.yieldType != FilesystemYieldType::RegularFiles &&
        policy.yieldType != FilesystemYieldType::Directories && policy.yieldType != FilesystemYieldType::SymbolicLinks)
        return Error("Invalid filesystem yield type", EINVAL);
    if (policy.unsupported != UnsupportedTypeDisposition::Error && policy.unsupported != UnsupportedTypeDisposition::Skip)
        return Error("Invalid unsupported filesystem type action", EINVAL);
    if (policy.depthAction != FilesystemDepthAction::Stop && policy.depthAction != FilesystemDepthAction::Error)
        return Error("Invalid depth action", EINVAL);
    if (policy.missingChildAction != FilesystemMissingChildAction::Error && policy.missingChildAction != FilesystemMissingChildAction::ReportRegularFile)
        return Error("Invalid missing-child action", EINVAL);
    if (policy.missingChildAction == FilesystemMissingChildAction::ReportRegularFile && policy.yieldType != FilesystemYieldType::RegularFiles)
        return Error("Missing observations require regular-file selection", ENOTSUP);
    if (reportingName.size() >= limits.fullPathBytes)
        return Error("Filesystem collection root path exceeds the full path byte limit", ENAMETOOLONG);
    return true;
}

Result<FileRange> Files(Path path, std::string reportingName, FilesystemTraversalPolicy continuation)
{
    auto valid = ValidateContinuation(path, reportingName, continuation);
    if (!valid.HasValue())
        return valid.Error();
    // TM-9: the selected leaf is the barrier, even for an unfrozen
    // multi-component Path. Do not resolve a child before this succeeds.
    auto frozen = path.Freeze();
    if (!frozen.HasValue())
        return std::move(frozen).Error();
    auto state = std::make_shared<FileRange::State>(std::move(continuation), std::move(path));
    auto initialized = state->Initialize(std::move(reportingName));
    if (!initialized.HasValue())
    {
        state->Abort(initialized.Error());
        return initialized.Error();
    }
    return FileRange(std::move(state));
}

Result<FileRange> Files(const FilesystemCollectionRequest& policy, ContextInterface& context)
{
    auto resolved = ResolveFilesystemCollectionRequest(policy);
    if (!resolved.HasValue())
    {
        return resolved.Error();
    }
    auto request = std::move(resolved).Value();
    auto acquired = Path::Make(context, request.rootPath, AcquisitionPolicy(request), AcquisitionBudget(request));
    if (!acquired.HasValue())
        return std::move(acquired).Error();
    if (acquired.Value().Is<Path>())
    {
        Path accepted = As<Path>(std::move(acquired).Value());
        if (request.rootKind == FilesystemRootKind::Directory && accepted.Leaf().Metadata().FileType() != Type::Directory)
            return Error("Expected directory root at '" + request.rootPath + "'", ENOTDIR);
        if (request.rootKind == FilesystemRootKind::File && accepted.Leaf().Metadata().FileType() != Type::RegularFile)
            return Error("Expected file root at '" + request.rootPath + "'", EISDIR);
        return Files(std::move(accepted), request.rootPath, Continuation(request));
    }
    const auto reason = As<Path::RejectionReason>(acquired.Value());
    auto state = std::make_shared<FileRange::State>(Continuation(request));
    if (reason == Path::RejectionReason::Missing)
        state->rootExists = false;
    else if (reason == Path::RejectionReason::Excluded)
    {
        auto excluded = state->Exclude(request.rootPath, "link policy");
        if (!excluded.HasValue())
            return std::move(excluded).Error();
    }
    else
        return Error("Unsupported collection root", EOPNOTSUPP);
    return FileRange(std::move(state));
}

Result<FilesystemCollectionResult> FileRange::StopVisitor()
{
    if (!mState)
        return Error("Cannot finish a moved-from filesystem range", EINVAL);
    if (mState->failure.HasValue())
        return mState->failure.Value();
    // Defense-in-depth: an exception escaping Next() leaves `interrupted` set
    // and also unwinds every frame between it and here (CollectFilesystem and
    // StreamFilesystemCollection do not catch), so this is not reachable
    // through the public API today. Guard it anyway so a future caller that
    // somehow still reaches StopVisitor after an escaped exception cannot
    // observe the partial observations as a success.
    if (mState->interrupted)
        return Error("Filesystem traversal was interrupted", ECANCELED);
    auto result = std::move(mState->result);
    Stop();
    return result;
}
void FileRange::Abort(const Error& error)
{
    if (mState)
        mState->Abort(error);
}
bool FileRange::RootExists() const
{
    return mState && mState->rootExists;
}
void FileRange::Stop() noexcept
{
    if (mState)
        mState->Stop();
}
Result<bool> FileRange::RetainEntries()
{
    if (!mState)
        return Error("Cannot retain entries from a moved-from filesystem range", EINVAL);
    if (mState->pending.HasValue())
    {
        auto observable = mState->CanObserve(mState->pending.Value().path);
        if (!observable.HasValue())
        {
            return observable;
        }
        mState->result.entries.push_back(Snapshot(mState->pending.Value()));
        ++mState->observations;
    }
    mState->retainEntries = true;
    return true;
}
} // namespace FTW

} // namespace Filesystem
} // namespace ComplianceEngine
