// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "FilesystemCollection.hpp"

#include "FilesystemHelpers.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <exception>
#include <limits>
#include <new>
#include <type_traits>
#include <utility>

#ifdef KOMPLI_TEST_ROOT_COPY_ALLOCATION
// Only the isolated allocation-fault test builds this translation unit with
// instrumentation. The ordinary library never arms an allocator interceptor.
extern "C" void ArmFilesystemCollectionRootCopy(std::size_t bytes) noexcept;
extern "C" void DisarmFilesystemCollectionRootCopy() noexcept;
// Fixed, test-TU-only fault sites. The hook disarms before throwing or
// diagnostic disposal; no allocator interception runs through native seams.
extern "C" bool TripFilesystemCollectionCheckpoint(unsigned site) noexcept;
extern "C" void ArmFilesystemCollectionInverseAllocation() noexcept;
extern "C" void DisarmFilesystemCollectionInverseAllocation() noexcept;
enum class TestCheckpoint : unsigned
{
    FrameReserve = 1,
    InversePreparation,
    AfterApply,
    BeforeOffer,
    InverseRestore,
};

namespace ComplianceEngine
{
namespace Filesystem
{
namespace
{
class ScopedRootCopyAllocationFault
{
public:
    explicit ScopedRootCopyAllocationFault(std::size_t bytes) noexcept
    {
        ArmFilesystemCollectionRootCopy(bytes);
    }

    ~ScopedRootCopyAllocationFault() noexcept
    {
        DisarmFilesystemCollectionRootCopy();
    }

    void Disarm() noexcept
    {
        DisarmFilesystemCollectionRootCopy();
    }
};

// Only the first allocation made *inside* the non-noexcept Path::Apply is
// failed. Path prepares its inverse before publishing; the wrapper disarms
// before stack unwinding, and this guard covers an unexpected early return.
class ScopedInversePreparationFault
{
public:
    explicit ScopedInversePreparationFault(bool enabled) noexcept
        : armed(enabled)
    {
        if (armed)
            ArmFilesystemCollectionInverseAllocation();
    }

    ~ScopedInversePreparationFault() noexcept
    {
        Disarm();
    }

    void Disarm() noexcept
    {
        if (armed)
        {
            DisarmFilesystemCollectionInverseAllocation();
            armed = false;
        }
    }

private:
    bool armed;
};
} // namespace
} // namespace Filesystem
} // namespace ComplianceEngine
#endif

namespace ComplianceEngine
{
namespace Filesystem
{
namespace
{
// Path reserves three temporary procfs descriptors: either the bootstrap
// directories or the published fd/fdinfo pair plus one fdinfo reader.
// Physical pins are charged by Path; the starting cursor needs a separate slot.
constexpr std::size_t PathOperationSlots = 3;
constexpr std::size_t StartingCursorSlots = 1;

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
    if (request.rootPath.size() >= request.limits.retainedPathBytes)
    {
        return Error("Filesystem collection root path exceeds the retained path byte limit", E2BIG);
    }
    const std::size_t components = std::count(request.rootPath.begin(), request.rootPath.end(), '/') + 1;
    if ((components >= std::numeric_limits<std::size_t>::max() - PathOperationSlots - StartingCursorSlots) ||
        (request.limits.operationalDescent > std::numeric_limits<std::size_t>::max() - components - 1) ||
        (request.limits.openDirectories > std::numeric_limits<std::size_t>::max() - components - PathOperationSlots - StartingCursorSlots))
    {
        return Error("Filesystem resolver budget is not representable", EOVERFLOW);
    }
    return true;
}

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
    const std::size_t max = std::numeric_limits<std::size_t>::max();
    // Path charges each physical pin plus its bounded spelling/accounting storage.
    const std::size_t perPrefix = sizeof(Path::Component) + 128;
    const std::size_t overhead = components > (max - 65536) / perPrefix ? max : 65536 + components * perPrefix;
    const std::size_t minimum = request.rootPath.size() > max - overhead ? max : overhead + request.rootPath.size();
    Filesystem::ResolverLimits budget;
    budget.shared.targetBytes = limits.fullPathBytes;
    budget.shared.components = limits.operationalDescent + components + 1;
    budget.shared.work = work;
    budget.shared.liveDescriptors = limits.openDirectories + components + PathOperationSlots + StartingCursorSlots;
    budget.shared.retainedBytes = std::max(limits.retainedPathBytes, minimum);
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

Result<FilesystemVisitAction> InvokeVisitor(const FilesystemCollectionVisitor& visitor, const FilesystemCollectionEntry& entry)
{
    try
    {
        return visitor(entry);
    }
    catch (const std::bad_alloc&)
    {
        return Error("Filesystem collection allocation failed", ENOMEM);
    }
    catch (const std::exception& exception)
    {
        return Error(std::string("Filesystem collection failed: ") + exception.what(), EIO);
    }
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

Result<ResolvedFilesystemCollectionRequest> ResolveFilesystemCollectionRequest(const FilesystemCollectionRequest& request)
{
    try
    {
        ResolvedFilesystemCollectionRequest resolved;
#ifdef KOMPLI_TEST_ROOT_COPY_ALLOCATION
        ScopedRootCopyAllocationFault copyFault(request.rootPath.size() + 1);
#endif
        resolved.rootPath = request.rootPath;
#ifdef KOMPLI_TEST_ROOT_COPY_ALLOCATION
        copyFault.Disarm();
#endif
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
        auto limit = Limit(request.operationalDescent, "operational descent limit");
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
        limit = Limit(request.fullPathBytes, "full path byte limit");
        if (!limit.HasValue())
        {
            return limit.Error();
        }
        resolved.limits.fullPathBytes = limit.Value();
        limit = Limit(request.fdinfoBytes, "fdinfo byte limit");
        if (!limit.HasValue())
        {
            return limit.Error();
        }
        resolved.limits.fdinfoBytes = limit.Value();
        limit = Limit(request.retainedPathBytes, "retained path byte limit");
        if (!limit.HasValue())
        {
            return limit.Error();
        }
        resolved.limits.retainedPathBytes = limit.Value();
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
    catch (const std::bad_alloc&)
    {
        return Error("Filesystem collection allocation failed", ENOMEM);
    }
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
struct PinBytes
{
    explicit PinBytes(std::size_t n = 0)
        : value(n)
    {
    }
    std::size_t value;
};
struct PinCharge
{
    PinCharge(DescriptorSlots slots = DescriptorSlots(), PinBytes size = PinBytes())
        : descriptors(slots),
          bytes(size)
    {
    }
    DescriptorSlots descriptors;
    PinBytes bytes;
};
// Only scalar retention, never State, Path, Component or a cursor. Entries may
// outlive the range; their final owner refunds the counter without allocations.
struct RetentionCounter
{
    std::size_t descriptors = 0;
    std::size_t bytes = sizeof(RetentionCounter) + 64; // shared control block
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
        if ((owner->descriptors < pins.descriptors.value) || (owner->bytes < pins.bytes.value))
        {
            std::terminate();
        }
        owner->descriptors -= pins.descriptors.value;
        owner->bytes -= pins.bytes.value;
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
        Optional<DirectoryCursor> cursor;
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

    Result<bool> Budget(std::size_t extra, const std::string& name) const
    {
        const std::size_t cap = request.limits.retainedPathBytes;
        if ((retained > cap) || (extra > cap - retained))
            return Error("Filesystem retained path byte budget exceeded at " + name, E2BIG);
        return true;
    }

    Result<bool> Charge(std::size_t amount, const std::string& name)
    {
        auto budget = Budget(amount, name);
        if (!budget.HasValue())
            return budget;
        retained += amount;
        return true;
    }

    void ReleaseObservation(std::size_t amount) noexcept
    {
        if (retained < amount)
        {
            std::terminate();
        }
        retained -= amount;
    }

    Result<bool> CheckPins(PinCharge extra) const
    {
        if (!current.HasValue())
            return Error("Filesystem traversal is not active", EINVAL);
        const ResolverLimits limits = current.Value().Limits();
        if (pins->descriptors > limits.shared.liveDescriptors || extra.descriptors.value > limits.shared.liveDescriptors - pins->descriptors)
            return Error("Filesystem pin retention exceeds descriptor budget", EMFILE);
        if (pins->bytes > limits.shared.retainedBytes || extra.bytes.value > limits.shared.retainedBytes - pins->bytes)
            return Error("Filesystem pin retention exceeds byte budget", E2BIG);
        return true;
    }

    Result<bool> ReservePins(PinCharge extra)
    {
        auto budget = CheckPins(extra);
        if (!budget.HasValue())
            return budget;
        pins->descriptors += extra.descriptors.value;
        pins->bytes += extra.bytes.value;
        return true;
    }

    void RefundPins(PinCharge charge) noexcept
    {
        if ((pins->descriptors < charge.descriptors.value) || (pins->bytes < charge.bytes.value))
        {
            std::terminate();
        }
        pins->descriptors -= charge.descriptors.value;
        pins->bytes -= charge.bytes.value;
    }

    Result<bool> PrepareFrame(const std::string& name)
    {
        if (frames.size() == std::numeric_limits<std::size_t>::max())
            return Error("Filesystem frame count overflow", EOVERFLOW);
        // Reserve storage before Apply; charge the actual growth, not an
        // assumed one-frame increment (vector may grow by more than one).
        const std::size_t before = frames.capacity();
        static_assert(std::is_nothrow_move_constructible<Frame>::value, "Frame publication after Apply must not throw");
#ifdef KOMPLI_TEST_ROOT_COPY_ALLOCATION
        if (TripFilesystemCollectionCheckpoint(static_cast<unsigned>(TestCheckpoint::FrameReserve)))
            throw std::bad_alloc();
#endif
        frames.reserve(frames.size() + 1);
        const std::size_t added = frames.capacity() - before;
        if (added > std::numeric_limits<std::size_t>::max() / sizeof(Frame))
            return Error("Filesystem frame storage overflow", EOVERFLOW);
        auto charged = ReservePins(PinCharge(DescriptorSlots(), PinBytes(added * sizeof(Frame))));
        if (!charged.HasValue())
            return charged;
        frameStorage += added * sizeof(Frame);
        return Charge(name.size() + 1, name);
    }

    Result<bool> Exclude(const std::string& name, const char* reason)
    {
        auto charged = Charge(name.size() + 1, name);
        if (!charged.HasValue())
            return charged;
        result.exclusions.push_back({name, reason});
        return true;
    }

    Result<bool> Offer(FilesystemCollectionEntry entry, PinCharge ownerCharge = PinCharge())
    {
        if (!entry.missing && !Yield(request.yieldType, entry.metadata))
            return true;
        const std::size_t bytes = entry.path.size() + 1;
        auto charged = Charge(bytes, entry.path);
        if (!charged.HasValue())
            return charged;
        if (retainEntries)
        {
            charged = Charge(bytes, entry.path);
            if (!charged.HasValue())
                return charged;
            result.entries.push_back(Snapshot(entry));
        }
        if (entry.mComponent.HasValue())
        {
            const std::size_t overhead = sizeof(EntryCharge) + 64;
            if (ownerCharge.bytes.value > std::numeric_limits<std::size_t>::max() - overhead)
                return Error("Filesystem entry charge overflow", EOVERFLOW);
            auto record = std::make_shared<EntryCharge>(pins);
            PinCharge full(ownerCharge.descriptors, PinBytes(ownerCharge.bytes.value + overhead));
            charged = ReservePins(full);
            if (!charged.HasValue())
                return charged;
            record->pins = full;
            entry.mRetentionCharge = std::move(record);
        }
        static_assert(std::is_nothrow_move_constructible<FilesystemCollectionEntry>::value, "Entry publication after Apply must not throw");
        pendingBytes = bytes;
        pending = std::move(entry);
        return true;
    }

    Result<bool> Initialize(std::string rootName)
    {
        auto budget = CheckPins(PinCharge());
        if (!budget.HasValue())
            return budget;
        const AcquisitionFacts facts = current.Value().Leaf().Acquired();
        baseline = facts.targetMount.value;
        FilesystemCollectionEntry entry;
        entry.path = rootName;
        entry.metadata = facts.metadata;
        entry.OwnComponent(current.Value().Leaf());
        if (Type::Directory == facts.type)
        {
            Frame frame;
            frame.logicalName = std::move(rootName);
            frame.device = facts.metadata.st_dev;
            frame.inode = facts.metadata.st_ino;
            auto prepared = PrepareFrame(frame.logicalName);
            if (!prepared.HasValue())
                return prepared;
            auto charged = ReservePins(PinCharge(DescriptorSlots(1)));
            if (!charged.HasValue())
                return charged;
            auto opened = current.Value().Leaf().OpenChildren();
            if (!opened.HasValue())
            {
                RefundPins(PinCharge(DescriptorSlots(1)));
                return std::move(opened).Error();
            }
            frame.cursor = std::move(opened).Value();
            frames.push_back(std::move(frame));
        }
        return Offer(std::move(entry), PinCharge(DescriptorSlots(current.Value().RetainedDescriptors()), PinBytes(current.Value().RetainedBytes())));
    }

    Result<bool> MissingChild(const DirectoryChild& child, const std::string& full)
    {
        if ((FilesystemMissingChildAction::ReportRegularFile != request.missingChildAction) || (DT_REG != child.type))
            return OperationError("acquire child", full, ENOENT);
        FilesystemCollectionEntry missing;
        missing.path = full;
        missing.missing = true;
        return Offer(std::move(missing));
    }

    Result<bool> Child(DirectoryChild child)
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
            const AcquisitionFacts facts = As<Path::Step>(resolved.Value()).Acquired();
            entry.metadata = facts.metadata;
            if ((FilesystemScope::All != request.scope) && ((baseline != facts.lookupMount.value) || (baseline != facts.targetMount.value)))
                return Exclude(full, "filesystem scope");
            const bool directory = Type::Directory == facts.type;
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
                    if ((frames[i].device == facts.metadata.st_dev) && (frames[i].inode == facts.metadata.st_ino))
                        return Error("Directory ancestor cycle at " + full, ELOOP);
            }
            targetCharge = PinCharge(DescriptorSlots(As<Path::Step>(resolved.Value()).RetainedDescriptors()),
                PinBytes(As<Path::Step>(resolved.Value()).RetainedBytes()));
            // Target is an owning Component. A file/observed directory never Applys.
            entry.OwnComponent(As<Path::Step>(resolved.Value()).Target());
            if (descend)
            {
                Frame frame;
                frame.logicalName = full;
                frame.device = facts.metadata.st_dev;
                frame.inode = facts.metadata.st_ino;
                auto prepared = PrepareFrame(frame.logicalName);
                if (!prepared.HasValue())
                    return prepared;
                    // Prepare allocation before mutation; any later failure aborts the
                    // private traversal without losing a published undo history.
#ifdef KOMPLI_TEST_ROOT_COPY_ALLOCATION
                ScopedInversePreparationFault inverseFault(TripFilesystemCollectionCheckpoint(static_cast<unsigned>(TestCheckpoint::InversePreparation)));
#endif
                auto applied = current.Value().Apply(std::move(resolved.Value().Get<Path::Step>()));
#ifdef KOMPLI_TEST_ROOT_COPY_ALLOCATION
                inverseFault.Disarm();
#endif
                if (!applied.HasValue())
                    return std::move(applied).Error();
#ifdef KOMPLI_TEST_ROOT_COPY_ALLOCATION
                if (TripFilesystemCollectionCheckpoint(static_cast<unsigned>(TestCheckpoint::AfterApply)))
                    throw std::bad_alloc();
#endif
                if (current.Value().RetainedDescriptors() > current.Value().Limits().shared.liveDescriptors)
                    return Error("Applied path exceeds physical descriptor budget", EMFILE);
                if (current.Value().RetainedBytes() > current.Value().Limits().shared.retainedBytes)
                    return Error("Applied path exceeds physical retention budget", E2BIG);
                const PinCharge inverseCharge(DescriptorSlots(applied.Value().RetainedDescriptors()), PinBytes(applied.Value().RetainedBytes()));
                auto charged = ReservePins(inverseCharge);
                if (!charged.HasValue())
                    return charged;
                frame.inverse = std::move(applied).Value();
                frame.inverseCharge = inverseCharge;
                frames.push_back(std::move(frame));
#ifdef KOMPLI_TEST_ROOT_COPY_ALLOCATION
                // The inverse is already owned by the frame before testing
                // failed output publication. Abort drops it exactly once.
                if (TripFilesystemCollectionCheckpoint(static_cast<unsigned>(TestCheckpoint::BeforeOffer)))
                    throw std::bad_alloc();
#endif
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
            ReleaseObservation(pendingBytes);
            pendingBytes = 0;
            return Optional<FilesystemCollectionEntry>(std::move(entry));
        }
        while (!frames.empty())
        {
            if (!frames.back().cursor.HasValue())
            {
                if (frames.size() > request.limits.openDirectories)
                    return Error("Filesystem directory continuation exceeds open directory budget", EMFILE);
                auto charged = ReservePins(PinCharge(DescriptorSlots(1)));
                if (!charged.HasValue())
                    return charged.Error();
                auto opened = current.Value().Leaf().OpenChildren();
                if (!opened.HasValue())
                {
                    RefundPins(PinCharge(DescriptorSlots(1)));
                    return std::move(opened).Error();
                }
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
#ifdef KOMPLI_TEST_ROOT_COPY_ALLOCATION
                    if (TripFilesystemCollectionCheckpoint(static_cast<unsigned>(TestCheckpoint::InverseRestore)))
                        return Error("Filesystem inverse restoration failed", ESTALE);
#endif
                    auto restored = current.Value().Apply(std::move(frames.back().inverse.Value()));
                    if (!restored.HasValue())
                        return std::move(restored).Error();
                    frames.back().inverse.Reset();
                    RefundPins(frames.back().inverseCharge);
                }
                ReleaseObservation(frames.back().logicalName.size() + 1);
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
                ReleaseObservation(pendingBytes);
                pendingBytes = 0;
                return Optional<FilesystemCollectionEntry>(std::move(entry));
            }
        }
        Finish();
        return Optional<FilesystemCollectionEntry>();
    }

    Result<Optional<FilesystemCollectionEntry>> Next()
    {
        if (failure.HasValue())
            return failure.Value();
        if (closed)
            return Optional<FilesystemCollectionEntry>();
        try
        {
            auto next = Pull();
            if (!next.HasValue())
                Abort(next.Error());
            return next;
        }
        catch (const std::bad_alloc&)
        {
            const Error error("Filesystem collection allocation failed", ENOMEM);
            Abort(error);
            return error;
        }
        catch (const std::exception& exception)
        {
            const Error error(std::string("Filesystem collection failed: ") + exception.what(), EIO);
            Abort(error);
            return error;
        }
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
        pendingBytes = 0;
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
        RefundPins(PinCharge(DescriptorSlots(), PinBytes(frameStorage)));
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
        retained = 0;
    }

    FilesystemTraversalPolicy request;
    Optional<Path> current;
    std::vector<Frame> frames;
    FilesystemCollectionResult result;
    Optional<FilesystemCollectionEntry> pending;
    Optional<Error> failure;
    std::shared_ptr<RetentionCounter> pins;
    std::uint64_t baseline = 0;
    std::size_t retained = 0;
    std::size_t frameStorage = 0;
    std::size_t pendingBytes = 0;
    std::size_t work = 0;
    bool rootExists = true;
    bool retainEntries = false;
    bool closed = false;
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
        limits.fdinfoBytes > static_cast<std::size_t>(std::numeric_limits<ssize_t>::max()) || limits.retainedPathBytes == 0 || limits.openDirectories == 0)
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
    if (reportingName.size() >= limits.retainedPathBytes)
        return Error("Filesystem collection root path exceeds the retained path byte limit", E2BIG);
    return true;
}

Result<FileRange> Files(Path path, std::string reportingName, FilesystemTraversalPolicy continuation)
{
    auto valid = ValidateContinuation(path, reportingName, continuation);
    if (!valid.HasValue())
        return valid.Error();
    try
    {
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
    catch (const std::bad_alloc&)
    {
        return Error("Filesystem collection allocation failed", ENOMEM);
    }
    catch (const std::exception& exception)
    {
        return Error(std::string("Filesystem collection failed: ") + exception.what(), EIO);
    }
}

Result<FileRange> Files(const FilesystemCollectionRequest& policy, ContextInterface& context)
{
    auto resolved = ResolveFilesystemCollectionRequest(policy);
    if (!resolved.HasValue())
    {
        return resolved.Error();
    }
    try
    {
        auto request = std::move(resolved).Value();
        auto acquired = Path::Make(context, request.rootPath, AcquisitionPolicy(request), AcquisitionBudget(request));
        if (!acquired.HasValue())
            return std::move(acquired).Error();
        if (acquired.Value().Is<Path>())
        {
            Path accepted = As<Path>(std::move(acquired).Value());
            if (request.rootKind == FilesystemRootKind::Directory && accepted.Leaf().Acquired().type != Type::Directory)
                return Error("Expected directory root at '" + request.rootPath + "'", ENOTDIR);
            if (request.rootKind == FilesystemRootKind::File && accepted.Leaf().Acquired().type != Type::RegularFile)
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
    catch (const std::bad_alloc&)
    {
        return Error("Filesystem collection allocation failed", ENOMEM);
    }
    catch (const std::exception& exception)
    {
        return Error(std::string("Filesystem collection failed: ") + exception.what(), EIO);
    }
}

Result<FilesystemCollectionResult> FileRange::StopVisitor()
{
    if (!mState)
        return Error("Cannot finish a moved-from filesystem range", EINVAL);
    if (mState->failure.HasValue())
        return mState->failure.Value();
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
    try
    {
        if (mState->pending.HasValue())
        {
            auto charged = mState->Charge(mState->pending.Value().path.size() + 1, mState->pending.Value().path);
            if (!charged.HasValue())
            {
                return charged;
            }
            mState->result.entries.push_back(Snapshot(mState->pending.Value()));
        }
        mState->retainEntries = true;
        return true;
    }
    catch (const std::bad_alloc&)
    {
        return Error("Filesystem collection allocation failed", ENOMEM);
    }
}
} // namespace FTW

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
} // namespace Filesystem
} // namespace ComplianceEngine
