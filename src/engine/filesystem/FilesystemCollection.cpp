// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "FilesystemCollection.hpp"

#include "FTWDirectoryCursor.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <exception>
#include <limits>
#include <type_traits>
#include <utility>

namespace ComplianceEngine
{
namespace Filesystem
{
namespace
{
using Detail::PathOperationSlots;
using Detail::StartingCursorSlots;

Result<std::size_t> Limit(long long number, const char* name)
{
    if (0 >= number)
    {
        return Error(std::string("Filesystem collection ") + name + " must be positive", EINVAL);
    }
    if (static_cast<unsigned long long>(number) > std::numeric_limits<std::size_t>::max())
    {
        return Error(std::string("Filesystem collection ") + name + " is too large", EOVERFLOW);
    }
    return static_cast<std::size_t>(number);
}

Result<bool> Validate(const ResolvedFilesystemCollectionRequest& request)
{
    if (request.limits.fdinfoBytes == 0 || request.limits.fdinfoBytes >= std::string().max_size() || request.limits.fdinfoBytes > std::vector<char>().max_size() ||
        request.limits.fdinfoBytes > static_cast<std::size_t>(std::numeric_limits<ssize_t>::max()))
    {
        return Error("Invalid procfs descriptor information byte limit", EINVAL);
    }
    if (request.rootPath.empty())
    {
        return Error("Filesystem collection root path must not be empty", EINVAL);
    }
    if (std::string::npos != request.rootPath.find('\0'))
    {
        return Error("Filesystem collection root path must not contain NUL", EINVAL);
    }
    if ('/' != request.rootPath.front())
    {
        return Error("Filesystem collection root path must be absolute", EINVAL);
    }
    if ((FilesystemRootKind::File != request.rootKind) && (FilesystemRootKind::Directory != request.rootKind))
    {
        return Error("Invalid filesystem root kind", EINVAL);
    }
    if (FilesystemDirection::Up == request.direction)
    {
        return Error("Upward filesystem collection is not supported", ENOTSUP);
    }
    if ((FilesystemDirection::None != request.direction) && (FilesystemDirection::Down != request.direction))
    {
        return Error("Invalid filesystem collection direction", EINVAL);
    }
    if (-1 > request.maxDepth)
    {
        return Error("Filesystem collection maximum depth must be -1 or nonnegative", EINVAL);
    }
    for (SymlinkPolicy action : {request.rootFileLinkAction, request.rootDirectoryLinkAction, request.childFileLinkAction, request.childDirectoryLinkAction})
    {
        if ((SymlinkPolicy::Follow != action) && (SymlinkPolicy::DoNotFollow != action))
        {
            return Error("Invalid filesystem symlink following policy", EINVAL);
        }
    }
    if (FilesystemScope::Local == request.scope)
    {
        return Error("Local filesystem classification is not supported", ENOTSUP);
    }
    if ((FilesystemScope::RootDevice != request.scope) && (FilesystemScope::All != request.scope) && (FilesystemScope::Defined != request.scope))
    {
        return Error("Invalid filesystem scope", EINVAL);
    }
    if ((FilesystemYieldType::All != request.yieldType) && (FilesystemYieldType::RegularFiles != request.yieldType) &&
        (FilesystemYieldType::Directories != request.yieldType) && (FilesystemYieldType::SymbolicLinks != request.yieldType))
    {
        return Error("Invalid filesystem yield type", EINVAL);
    }
    if (request.unsupported != UnsupportedTypeDisposition::Error && request.unsupported != UnsupportedTypeDisposition::Skip)
    {
        return Error("Invalid unsupported filesystem type action", EINVAL);
    }
    if ((FilesystemDepthAction::Stop != request.depthAction) && (FilesystemDepthAction::Error != request.depthAction))
    {
        return Error("Invalid filesystem depth action", EINVAL);
    }
    if ((FilesystemMissingChildAction::Error != request.missingChildAction) && (FilesystemMissingChildAction::ReportRegularFile != request.missingChildAction))
    {
        return Error("Invalid missing-child collection action", EINVAL);
    }
    if ((FilesystemMissingChildAction::ReportRegularFile == request.missingChildAction) && (FilesystemYieldType::RegularFiles != request.yieldType))
    {
        return Error("Missing regular-file observations require regular-file selection", ENOTSUP);
    }
    if (request.rootPath.size() >= request.limits.fullPathBytes)
    {
        return Error("Filesystem collection root path exceeds the full path byte limit", ENAMETOOLONG);
    }
    const std::size_t components = std::count(request.rootPath.begin(), request.rootPath.end(), '/') + 1;
    if ((components >= std::numeric_limits<std::size_t>::max() - PathOperationSlots() - StartingCursorSlots()) ||
        (request.limits.operationalDescent > std::numeric_limits<std::size_t>::max() - components - 1) ||
        (request.limits.openDirectories > std::numeric_limits<std::size_t>::max() - components - PathOperationSlots() - StartingCursorSlots()))
    {
        return Error("Filesystem resolver budget is not representable", EOVERFLOW);
    }
    return true;
}

Result<FilesystemVisitAction> InvokeVisitor(const FilesystemCollectionVisitor& visitor, const FilesystemCollectionEntry& entry)
{
    return visitor(entry);
}
} // namespace

Result<ResolvedFilesystemCollectionRequest> ResolveFilesystemCollectionRequest(const FilesystemCollectionRequest& request)
{
    ResolvedFilesystemCollectionRequest resolved;
    // Resolve and check the full path byte limit before copying rootPath, so
    // an over-long root is rejected before Path's own allocation.
    auto limit = Limit(request.fullPathBytes, "full path byte limit");
    if (!limit.HasValue())
    {
        return limit.Error();
    }
    resolved.limits.fullPathBytes = limit.Value();
    if (request.rootPath.size() >= resolved.limits.fullPathBytes)
    {
        return Error("Filesystem collection root path exceeds the full path byte limit", ENAMETOOLONG);
    }
    resolved.rootPath = request.rootPath;
    resolved.rootKind = request.rootKind;
    resolved.direction = request.direction;
    resolved.maxDepth = request.maxDepth;
    resolved.rootFileLinkAction = request.rootFileLinkAction;
    resolved.rootDirectoryLinkAction = request.rootDirectoryLinkAction;
    resolved.childFileLinkAction = request.childFileLinkAction;
    resolved.childDirectoryLinkAction = request.childDirectoryLinkAction;
    resolved.scope = request.scope;
    resolved.yieldType = request.yieldType;
    resolved.unsupported = request.unsupported;
    resolved.depthAction = request.depthAction;
    resolved.missingChildAction = request.missingChildAction;
    limit = Limit(request.operationalDescent, "operational descent limit");
    if (!limit.HasValue())
    {
        return limit.Error();
    }
    resolved.limits.operationalDescent = limit.Value();
    limit = Limit(request.entryWork, "entry work limit");
    if (!limit.HasValue())
    {
        return limit.Error();
    }
    resolved.limits.entryWork = limit.Value();
    limit = Limit(request.directoryWidth, "directory width limit");
    if (!limit.HasValue())
    {
        return limit.Error();
    }
    resolved.limits.directoryWidth = limit.Value();
    limit = Limit(request.fdinfoBytes, "fdinfo byte limit");
    if (!limit.HasValue())
    {
        return limit.Error();
    }
    resolved.limits.fdinfoBytes = limit.Value();
    limit = Limit(request.retainedObservations, "retained observation limit");
    if (!limit.HasValue())
    {
        return limit.Error();
    }
    resolved.limits.retainedObservations = limit.Value();
    limit = Limit(request.openDirectories, "open directory limit");
    if (!limit.HasValue())
    {
        return limit.Error();
    }
    resolved.limits.openDirectories = limit.Value();
    auto valid = Validate(resolved);
    if (!valid.HasValue())
    {
        return valid.Error();
    }
    return resolved;
}

Result<FilesystemCollectionResult> StreamFilesystemCollection(const FilesystemCollectionRequest& request, const FilesystemCollectionVisitor& visitor,
    ContextInterface& context)
{
    if (!visitor)
    {
        return Error("Filesystem collection visitor must not be empty", EINVAL);
    }
    auto opened = FTW::Files(request, context);
    if (!opened.HasValue())
    {
        return opened.Error();
    }
    auto files = std::move(opened).Value();
    for (const auto& entry : files)
    {
        if (!entry.HasValue())
        {
            return entry.Error();
        }
        auto action = InvokeVisitor(visitor, entry.Value());
        if (!action.HasValue())
        {
            files.Abort(action.Error());
            return action.Error();
        }
        if (FilesystemVisitAction::Stop == action.Value())
        {
            return files.StopVisitor();
        }
        if (FilesystemVisitAction::Continue != action.Value())
        {
            const Error error("Invalid filesystem visitor action", EINVAL);
            files.Abort(error);
            return error;
        }
    }
    return files.StopVisitor();
}

Result<FilesystemCollectionResult> CollectFilesystem(const FilesystemCollectionRequest& request, ContextInterface& context)
{
    auto opened = FTW::Files(request, context);
    if (!opened.HasValue())
    {
        return opened.Error();
    }
    auto files = std::move(opened).Value();
    auto retaining = files.RetainEntries();
    if (!retaining.HasValue())
    {
        files.Abort(retaining.Error());
        return retaining.Error();
    }
    for (const auto& entry : files)
    {
        if (!entry.HasValue())
        {
            return entry.Error();
        }
    }
    return files.StopVisitor();
}

// Validated request-to-policy mapping shared by Make-first FTW callers.
// Directory cursor acquisition (FTWDirectoryCursor.hpp) and Pin activation
// (Pin.hpp) are declared elsewhere; this anonymous namespace only maps
// collection requests onto Path/FTW policy types. PathOperationSlots/
// StartingCursorSlots are already pulled in by the anonymous namespace above
// (the same unnamed namespace, for this translation unit).
namespace
{
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
    EntryCharge(const EntryCharge&) = delete;
    EntryCharge& operator=(const EntryCharge&) = delete;
    EntryCharge(EntryCharge&&) = delete;
    EntryCharge& operator=(EntryCharge&&) = delete;
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
static_assert(!std::is_copy_constructible<EntryCharge>::value && !std::is_copy_assignable<EntryCharge>::value,
    "EntryCharge is only ever held by shared_ptr, never copied");
static_assert(!std::is_move_constructible<EntryCharge>::value && !std::is_move_assignable<EntryCharge>::value,
    "EntryCharge is only ever held by shared_ptr, never moved");
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
        if (entry.metadata.HasValue() && !Yield(request.yieldType, entry.metadata.Value()))
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
