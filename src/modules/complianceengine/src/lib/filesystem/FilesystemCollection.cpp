// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "FilesystemCollection.hpp"

#include "FilesystemHelpers.hpp"

#include <algorithm>
#include <cerrno>
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
    if (request.unsupported != UnsupportedTypeAction::Reject && request.unsupported != UnsupportedTypeAction::Skip)
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
    if ((components >= std::numeric_limits<std::size_t>::max() - 8) ||
        (request.limits.operationalDescent > std::numeric_limits<std::size_t>::max() - components - 1) ||
        (request.limits.openDirectories > std::numeric_limits<std::size_t>::max() - components - 8))
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
    const auto& limits = request.limits;
    const std::size_t components = std::count(request.rootPath.begin(), request.rootPath.end(), '/') + 1;
    const std::size_t work = limits.entryWork > (std::numeric_limits<std::size_t>::max() - 32768) / 512 ? std::numeric_limits<std::size_t>::max() :
                                                                                                          limits.entryWork * 512 + 32768;
    const std::size_t max = std::numeric_limits<std::size_t>::max();
    const std::size_t perPrefix = 8 * sizeof(Handle);
    const std::size_t overhead = components > (max - 65536) / perPrefix ? max : 65536 + components * perPrefix;
    const std::size_t minimum = request.rootPath.size() > max - overhead ? max : overhead + request.rootPath.size();
    Filesystem::ResolverLimits budget;
    budget.shared.targetBytes = limits.fullPathBytes;
    budget.shared.components = limits.operationalDescent + components + 1;
    budget.shared.work = work;
    budget.shared.liveDescriptors = limits.openDirectories + components + 8;
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
    policy.symlinks = request.rootFileLinkAction == SymlinkPolicy::Follow || request.rootDirectoryLinkAction == SymlinkPolicy::Follow ?
                          SymlinkPolicy::Follow :
                          SymlinkPolicy::DoNotFollow;
    policy.mounts = MountPolicy::AllowCrossing;
    policy.fileLinks = request.rootFileLinkAction;
    policy.directoryLinks = request.rootDirectoryLinkAction;
    policy.nonFollowedLinks = NonFollowedLinkAction::Skip;
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
struct FileRange::State
{
    struct Frame
    {
        std::string path;
        Optional<Filesystem::DirectoryCursor> cursor;
        // The logical parent may differ from the selected physical parent
        // after a link. Path retains these held pins until this frame unwinds.
        Optional<Path::Restoration> prior;
        std::size_t width = 0;
        std::size_t bytes = 0;
        dev_t device = 0;
        ino_t inode = 0;
    };

    State(FilesystemTraversalPolicy policy, const ContextInterface& owner)
        : request(std::move(policy)),
          context(owner)
    {
    }

    State(FilesystemTraversalPolicy policy, Path accepted)
        : request(std::move(policy)),
          context(accepted.Context()),
          path(new Path(std::move(accepted)))
    {
    }

    ~State()
    {
        if (!closed)
        {
            const auto cleanup = Close();
            if (!cleanup.HasValue())
            {
                OsConfigLogError(context.GetLogHandle(), "Abandoned filesystem range cleanup failed: %s", cleanup.Error().message.c_str());
            }
        }
    }

    Result<bool> Budget(std::size_t extra, const std::string& name) const
    {
        const std::size_t cap = request.limits.retainedPathBytes;
        if ((retained > cap) || (extra > cap - retained))
        {
            return Error("Filesystem retained path byte budget exceeded at '" + name + "'", E2BIG);
        }
        return true;
    }

    Result<bool> Charge(std::size_t amount, const std::string& name)
    {
        auto budget = Budget(amount, name);
        if (!budget.HasValue())
        {
            return budget;
        }
        retained += amount;
        return true;
    }

    Result<bool> Exclude(const std::string& name, const char* reason)
    {
        auto charged = Charge(name.size() + 1, name);
        if (!charged.HasValue())
        {
            return charged;
        }
        result.exclusions.push_back({name, reason});
        return true;
    }

    Result<bool> Offer(FilesystemCollectionEntry entry)
    {
        if (entry.missing || Yield(request.yieldType, entry.metadata))
        {
            const std::size_t bytes = entry.path.size() + 1;
            auto liveCharge = Charge(bytes, entry.path);
            if (!liveCharge.HasValue())
            {
                return liveCharge;
            }
            if (retainEntries)
            {
                auto charged = Charge(bytes, entry.path);
                if (!charged.HasValue())
                {
                    return charged;
                }
                result.entries.push_back(Snapshot(entry));
            }
            pendingBytes = bytes;
            pending = std::move(entry);
        }
        return true;
    }

    Filesystem::ResolverLimits ResolverBudget() const
    {
        return path->Limits();
    }

    Result<bool> Initialize(std::string rootName)
    {
        const bool directory = path->Root().AcquiredType() == Handle::Type::Directory;
        auto rootMount = path->Root().MountIdentity();
        if (!rootMount.HasValue())
        {
            return std::move(rootMount).Error();
        }
        baseline = rootMount.Value();
        FilesystemCollectionEntry entry;
        entry.path = rootName;
        const auto metadata = path->LeafMetadata();
        entry.metadata = metadata.accepted;
        if (!directory)
        {
            auto detached = path->Pop();
            if (!detached.HasValue())
            {
                return std::move(detached).Error();
            }
            entry.OwnHandle(std::move(detached).Value());
        }
        else
        {
            entry.BorrowHandle(path->Leaf());
            Frame frame;
            frame.path = std::move(rootName);
            frame.bytes = frame.path.size() + 1;
            frame.device = path->Leaf().AcquiredMetadata().st_dev;
            frame.inode = path->Leaf().AcquiredMetadata().st_ino;
            auto charged = Charge(frame.bytes, rootName);
            if (!charged.HasValue())
            {
                return charged;
            }
            auto opened = path->Leaf().OpenChildren();
            if (!opened.HasValue())
            {
                return std::move(opened).Error();
            }
            frame.cursor = std::move(opened).Value();
            frames.push_back(std::move(frame));
        }
        return Offer(std::move(entry));
    }

    Result<bool> MissingChild(const Filesystem::DirectoryChild& child, const std::string& full)
    {
        if ((FilesystemMissingChildAction::ReportRegularFile != request.missingChildAction) || (DT_REG != child.type))
        {
            return OperationError("acquire child", full, ENOENT);
        }
        FilesystemCollectionEntry missing;
        missing.path = full;
        missing.missing = true;
        return Offer(std::move(missing));
    }

    Result<bool> PushChild(const Filesystem::DirectoryChild& child, FilesystemCollectionEntry& entry)
    {
        ExtensionPolicy extension;
        extension.mounts = MountPolicy::AllowCrossing;
        extension.unsupported = request.unsupported;
        extension.fileLinks = request.childFileLinkAction;
        extension.directoryLinks = request.childDirectoryLinkAction;
        extension.nonFollowedLinks = NonFollowedLinkAction::Skip;
        extension.reportMissingRegularFile = request.missingChildAction == FilesystemMissingChildAction::ReportRegularFile && child.type == DT_REG;
        const std::size_t live = path->RetainedDescriptors() + frames.size();
        const std::size_t cap = ResolverBudget().shared.liveDescriptors;
        if ((live > cap) || (cap - live < 7))
        {
            return Error("Filesystem pin retention exceeds descriptor budget", EMFILE);
        }
        auto prior = path->Capture();
        auto pushed = path->Push(child.name, extension);
        if (!pushed.HasValue())
            return std::move(pushed).Error();
        if (pushed.Value().Is<Path::RejectionReason>())
        {
            switch (As<Path::RejectionReason>(pushed.Value()))
            {
                case Path::RejectionReason::Missing:
                    return MissingChild(child, entry.path);
                case Path::RejectionReason::UnsupportedType:
                    return Exclude(entry.path, "unsupported type");
                case Path::RejectionReason::Excluded:
                    return Exclude(entry.path, "link policy");
            }
        }
        const Path& accepted = As<const Path&>(pushed.Value());
        const auto& handle = accepted.Leaf();
        const auto metadata = accepted.LeafMetadata();
        entry.metadata = metadata.accepted;
        if ((FilesystemScope::All != request.scope) && (baseline != metadata.mountId))
        {
            auto restored = path->Restore(std::move(prior));
            if (!restored.HasValue())
                return std::move(restored).Error();
            return Exclude(entry.path, "filesystem scope");
        }
        auto mount = handle.MountIdentity();
        if (!mount.HasValue())
        {
            return std::move(mount).Error();
        }
        if ((FilesystemScope::All != request.scope) && (baseline != mount.Value()))
        {
            auto restored = path->Restore(std::move(prior));
            if (!restored.HasValue())
                return std::move(restored).Error();
            return Exclude(entry.path, "filesystem scope");
        }
        const bool directory = Filesystem::Handle::Type::Directory == handle.AcquiredType();
        if (directory)
        {
            const std::size_t depth = frames.size();
            bool descend = FilesystemDirection::Down == request.direction;
            if (descend && (-1 != request.maxDepth) && (depth > static_cast<std::size_t>(request.maxDepth)))
            {
                if (FilesystemDepthAction::Error == request.depthAction)
                {
                    return Error("Maximum recursion depth reached");
                }
                descend = false;
            }
            if (descend && (depth > request.limits.operationalDescent))
            {
                return Error("Operational descent budget exceeded at '" + entry.path + "'", E2BIG);
            }
            if (descend)
            {
                for (const auto& ancestor : frames)
                {
                    if ((ancestor.device == handle.AcquiredMetadata().st_dev) && (ancestor.inode == handle.AcquiredMetadata().st_ino))
                    {
                        return Error("Directory ancestor cycle at '" + entry.path + "'", ELOOP);
                    }
                }
                Frame frame;
                frame.path = entry.path;
                if (frame.path.size() >= request.limits.retainedPathBytes || prior.StorageBytes() > request.limits.retainedPathBytes - frame.path.size() - 1)
                    return Error("Filesystem restoration storage exceeds retained path budget", E2BIG);
                frame.bytes = frame.path.size() + 1;
                frame.bytes += prior.StorageBytes();
                frame.device = handle.AcquiredMetadata().st_dev;
                frame.inode = handle.AcquiredMetadata().st_ino;
                frame.prior = std::move(prior);
                auto charged = Charge(frame.bytes, entry.path);
                if (!charged.HasValue())
                {
                    return charged;
                }
                frames.push_back(std::move(frame));
            }
            entry.BorrowHandle(handle);
            if (!descend)
            {
                auto detached = path->DuplicateLeaf();
                if (!detached.HasValue())
                {
                    return std::move(detached).Error();
                }
                // Non-descended directories still need an owned live pin.
                entry.OwnHandle(std::move(detached).Value());
                auto restored = path->Restore(std::move(prior));
                if (!restored.HasValue())
                    return std::move(restored).Error();
            }
        }
        else
        {
            auto detached = path->DuplicateLeaf();
            if (!detached.HasValue())
            {
                return std::move(detached).Error();
            }
            entry.OwnHandle(std::move(detached).Value());
            auto restored = path->Restore(std::move(prior));
            if (!restored.HasValue())
                return std::move(restored).Error();
        }
        return Offer(std::move(entry));
    }

    Result<bool> Child(const Filesystem::DirectoryChild& child)
    {
        const std::string full = frames.back().path + "/" + child.name;
        if (full.size() >= request.limits.fullPathBytes)
        {
            return Error("Filesystem path exceeds full path budget at '" + full + "'", ENAMETOOLONG);
        }
        FilesystemCollectionEntry entry;
        entry.path = full;
        return PushChild(child, entry);
    }

    Result<Optional<FilesystemCollectionEntry>> Pull()
    {
        if (pending.HasValue())
        {
            auto entry = std::move(pending).Value();
            pending.Reset();
            retained -= pendingBytes;
            pendingBytes = 0;
            return Optional<FilesystemCollectionEntry>(std::move(entry));
        }
        while (!frames.empty())
        {
            Frame& frame = frames.back();
            if (!frame.cursor.HasValue())
            {
                if ((frames.size() > request.limits.openDirectories) || (path->RetainedDescriptors() + frames.size() + 10 > ResolverBudget().shared.liveDescriptors))
                {
                    return Error("Filesystem directory continuation exceeds descriptor budget", EMFILE);
                }
                auto budget = Budget(0, frame.path);
                if (!budget.HasValue())
                {
                    return budget.Error();
                }
                auto opened = path->Leaf().OpenChildren();
                if (!opened.HasValue())
                {
                    return std::move(opened).Error();
                }
                frame.cursor = std::move(opened).Value();
            }
            auto name = frame.cursor->NextEntry();
            if (!name.HasValue())
            {
                return OperationError("read directory", frame.path, name.Error().code);
            }
            if (!name.Value().HasValue())
            {
                auto closedCursor = frame.cursor->Close();
                if (!closedCursor.HasValue())
                {
                    return std::move(closedCursor).Error();
                }
                auto prior = std::move(frame.prior);
                retained -= frame.bytes;
                frames.pop_back();
                if (prior.HasValue())
                {
                    auto restored = path->Restore(std::move(prior).Value());
                    if (!restored.HasValue())
                        return std::move(restored).Error();
                }
                continue;
            }
            if (work >= request.limits.entryWork)
            {
                return Error("Filesystem entry work budget exhausted at '" + frame.path + "'", E2BIG);
            }
            ++work;
            if (frame.width >= request.limits.directoryWidth)
            {
                return Error("Filesystem directory width budget exceeded at '" + frame.path + "'", E2BIG);
            }
            ++frame.width;
            auto processed = Child(name.Value().Value());
            if (!processed.HasValue())
            {
                return std::move(processed).Error();
            }
            if (pending.HasValue())
            {
                auto entry = std::move(pending).Value();
                pending.Reset();
                retained -= pendingBytes;
                pendingBytes = 0;
                return Optional<FilesystemCollectionEntry>(std::move(entry));
            }
        }
        auto closedResult = Close();
        if (!closedResult.HasValue())
        {
            return std::move(closedResult).Error();
        }
        return Optional<FilesystemCollectionEntry>();
    }

    Result<Optional<FilesystemCollectionEntry>> Next()
    {
        if (failure.HasValue())
        {
            return failure.Value();
        }
        if (closed)
        {
            return Optional<FilesystemCollectionEntry>();
        }
        try
        {
            auto next = Pull();
            if (!next.HasValue())
            {
                Abort(next.Error());
            }
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
        (void)Close();
    }

    Result<bool> Close()
    {
        if (closed)
        {
            return failure.HasValue() ? Result<bool>(failure.Value()) : Result<bool>(true);
        }
        // Transfer every remaining owner before a native close or diagnostic
        // can throw. The detached owners finish cleanup on exception, while
        // consumed cursors and pins cannot be retried by a later Close.
        static_assert(std::is_nothrow_move_constructible<Optional<FilesystemCollectionEntry>>::value,
            "Pending range ownership must detach without throwing");
        std::vector<Frame> remainingFrames;
        remainingFrames.swap(frames);
        auto remainingPending = std::move(pending);
        auto remainingPath = std::move(path);
        pendingBytes = 0;
        retained = 0;
        closed = true;
        Optional<Error> cleanup;
        auto record = [this, &cleanup](const Error& error) {
            if (!cleanup.HasValue())
            {
                cleanup = error;
            }
            else
            {
                OsConfigLogError(context.GetLogHandle(), "Secondary filesystem range cleanup failure: %s", error.message.c_str());
            }
        };
        for (auto& frame : remainingFrames)
        {
            if (frame.cursor.HasValue())
            {
                auto ended = frame.cursor->Close();
                if (!ended.HasValue())
                {
                    record(ended.Error());
                }
                frame.cursor.Reset();
            }
        }
        remainingFrames.clear();
        if (remainingPending.HasValue())
        {
            if (remainingPending.Value().OwnsHandle())
            {
                auto ended = remainingPending.Value().CloseHandle();
                if (!ended.HasValue())
                {
                    record(ended.Error());
                }
            }
            remainingPending.Reset();
        }
        if (remainingPath)
        {
            auto ended = remainingPath->Close();
            if (!ended.HasValue())
            {
                record(ended.Error());
            }
        }
        remainingPath.reset();
        if (failure.HasValue())
        {
            if (cleanup.HasValue())
            {
                OsConfigLogError(context.GetLogHandle(), "Filesystem cleanup failed after primary error: %s", cleanup.Value().message.c_str());
            }
            return failure.Value();
        }
        if (cleanup.HasValue())
        {
            failure = cleanup;
            return cleanup.Value();
        }
        return true;
    }

    FilesystemTraversalPolicy request;
    const ContextInterface& context;
    std::unique_ptr<Filesystem::Path> path;
    std::vector<Frame> frames;
    FilesystemCollectionResult result;
    Optional<FilesystemCollectionEntry> pending;
    Optional<Error> failure;
    std::uint64_t baseline = 0;
    std::size_t retained = 0;
    std::size_t pendingBytes = 0;
    std::size_t work = 0;
    bool rootExists = true;
    bool retainEntries = false;
    bool closed = false;
};

Result<Optional<FilesystemCollectionEntry>> FileRange::Source::Next()
{
    return state->Next();
}

FileRange::FileRange(std::shared_ptr<State> state)
    : mState(std::move(state)),
      mView(Source{mState})
{
}

FileRange::~FileRange() = default;

Result<bool> ValidateContinuation(const Path& root, const std::string& reportingName, const FilesystemTraversalPolicy& policy)
{
    const auto& limits = policy.limits;
    if (!root.IsFrozen() || root.Size() != 1 || reportingName.empty() || reportingName.front() != '/' || reportingName.find('\0') != std::string::npos)
        return Error("Continuation requires one accepted absolute root", EINVAL);
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
    if (policy.unsupported != UnsupportedTypeAction::Reject && policy.unsupported != UnsupportedTypeAction::Skip)
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
        const auto& request = resolved.Value();
        auto acquired = Path::Make(context, request.rootPath, AcquisitionPolicy(request), AcquisitionBudget(request));
        if (!acquired.HasValue())
            return std::move(acquired).Error();
        if (acquired.Value().Is<Path>())
        {
            Path accepted = As<Path>(std::move(acquired).Value());
            auto frozen = accepted.FreezeRoot();
            if (!frozen.HasValue())
                return std::move(frozen).Error();
            if (request.rootKind == FilesystemRootKind::Directory && accepted.Root().AcquiredType() != Handle::Type::Directory)
                return Error("Expected directory root at '" + request.rootPath + "'", ENOTDIR);
            if (request.rootKind == FilesystemRootKind::File && accepted.Root().AcquiredType() != Handle::Type::RegularFile)
                return Error("Expected file root at '" + request.rootPath + "'", EISDIR);
            return Files(std::move(accepted), request.rootPath, Continuation(request));
        }
        const auto reason = As<Path::RejectionReason>(acquired.Value());
        auto state = std::make_shared<FileRange::State>(Continuation(request), context);
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
    auto closed = Close();
    return closed.HasValue() ? Result<FilesystemCollectionResult>(std::move(mState->result)) : Result<FilesystemCollectionResult>(closed.Error());
}
void FileRange::Abort(const Error& error)
{
    mState->Abort(error);
}
bool FileRange::RootExists() const
{
    return mState->rootExists;
}
Result<bool> FileRange::Close()
{
    return mState->Close();
}
Result<bool> FileRange::RetainEntries()
{
    try
    {
        if (mState->pending.HasValue())
        {
            const auto& entry = mState->pending.Value();
            auto charged = mState->Charge(entry.path.size() + 1, entry.path);
            if (!charged.HasValue())
            {
                return charged;
            }
            mState->result.entries.push_back(Snapshot(entry));
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
    auto& files = opened.Value();
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
    auto& files = opened.Value();
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
