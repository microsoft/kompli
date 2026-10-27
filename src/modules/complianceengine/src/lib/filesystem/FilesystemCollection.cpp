// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "FilesystemCollection.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <exception>
#include <limits>
#include <new>
#include <utility>

#ifdef KOMPLI_TEST_ROOT_COPY_ALLOCATION
// Only the isolated allocation-fault test builds this translation unit with
// instrumentation. The ordinary library never arms an allocator interceptor.
extern "C" void ArmFilesystemCollectionRootCopy(std::size_t bytes) noexcept;
extern "C" void DisarmFilesystemCollectionRootCopy() noexcept;

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
#endif

namespace ComplianceEngine
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
    for (SymlinkFollowing action : {request.rootFileLinkAction, request.rootDirectoryLinkAction, request.childFileLinkAction, request.childDirectoryLinkAction})
    {
        if ((SymlinkFollowing::Follow != action) && (SymlinkFollowing::DoNotFollow != action))
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
    copy.linkMetadata = live.linkMetadata;
    copy.targetMetadata = live.targetMetadata;
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
        std::size_t width = 0;
        std::size_t bytes = 0;
        dev_t device = 0;
        ino_t inode = 0;
    };

    State(ResolvedFilesystemCollectionRequest policy, ContextInterface& owner)
        : request(std::move(policy)),
          context(owner)
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
        if (entry.missing || Yield(request.yieldType, entry.targetMetadata.HasValue() ? entry.targetMetadata.Value() : entry.linkMetadata))
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
        const auto& limits = request.limits;
        const std::size_t components = std::count(request.rootPath.begin(), request.rootPath.end(), '/') + 1;
        // The resolver charges each operation (including fdinfo reads)
        // independently of the collection's one-per-entry work budget.
        const std::size_t work = limits.entryWork > (std::numeric_limits<std::size_t>::max() - 32768) / 512 ? std::numeric_limits<std::size_t>::max() :
                                                                                                              limits.entryWork * 512 + 32768;
        return {{limits.fullPathBytes, limits.operationalDescent + components + 1, work, limits.openDirectories + components + 8,
                    limits.retainedPathBytes, limits.fullPathBytes},
            limits.fullPathBytes, limits.entryWork, limits.operationalDescent + components + 1};
    }

    Result<bool> Initialize()
    {
        const std::string& rootName = request.rootPath;
        // This lookup classifies an explicitly selected root. Once acquired,
        // no pathname is used for descent or for subsequent operations.
        struct stat link = {};
        if (0 != context.LstatPath(rootName.c_str(), &link))
        {
            if (ENOENT == errno)
            {
                rootExists = false;
                return true;
            }
            return OperationError("lstat", rootName, errno);
        }
        struct stat target = link;
        bool followed = false;
        if (S_ISLNK(link.st_mode))
        {
            const auto fileAction = request.rootFileLinkAction;
            const auto dirAction = request.rootDirectoryLinkAction;
            if ((fileAction != dirAction) || (SymlinkFollowing::Follow == fileAction))
            {
                if (0 != context.StatPath(rootName.c_str(), &target))
                {
                    return OperationError("stat link target", rootName, errno);
                }
                if (!S_ISREG(target.st_mode) && !S_ISDIR(target.st_mode))
                {
                    return Error("Cannot classify link target as file or directory at '" + rootName + "'", EINVAL);
                }
            }
            const auto action = S_ISDIR(target.st_mode) ? dirAction : fileAction;
            if (SymlinkFollowing::DoNotFollow == action)
            {
                return Exclude(rootName, "link policy");
            }
            followed = true;
        }
        if ((FilesystemRootKind::Directory == request.rootKind) && !S_ISDIR(target.st_mode))
        {
            return Error("Expected directory root at '" + rootName + "'", ENOTDIR);
        }
        if ((FilesystemRootKind::File == request.rootKind) && !S_ISREG(target.st_mode))
        {
            return Error("Expected file root at '" + rootName + "'", EISDIR);
        }
        const Filesystem::RootPolicy rootPolicy{
            followed || (SymlinkFollowing::Follow == request.rootDirectoryLinkAction && FilesystemRootKind::Directory == request.rootKind) ?
                Filesystem::SymlinkPolicy::FollowWithinRoot :
                Filesystem::SymlinkPolicy::Reject,
            Filesystem::MountPolicy::AllowCrossing};
        auto acquired = Filesystem::Path::AcquireRoot(context, rootName, rootPolicy, ResolverBudget(), FilesystemRootKind::File == request.rootKind);
        if (!acquired.HasValue())
        {
            return std::move(acquired).Error();
        }
        path.reset(new Filesystem::Path(std::move(acquired).Value()));
        if (!S_ISLNK(link.st_mode) && ((link.st_dev != path->Root().Snapshot().st_dev) || (link.st_ino != path->Root().Snapshot().st_ino) ||
                                          ((link.st_mode & S_IFMT) != (path->Root().Snapshot().st_mode & S_IFMT))))
        {
            return Error("Filesystem root changed during acquisition at '" + rootName + "'", ESTALE);
        }
        auto rootMount = path->Root().MountIdentity(request.limits.fullPathBytes);
        if (!rootMount.HasValue())
        {
            return std::move(rootMount).Error();
        }
        baseline = rootMount.Value();
        FilesystemCollectionEntry entry;
        entry.path = rootName;
        entry.linkMetadata = link;
        if (followed)
        {
            const auto pinnedLink = path->LeafLinkMetadata();
            if (!pinnedLink.HasValue() || (link.st_dev != pinnedLink.Value().st_dev) || (link.st_ino != pinnedLink.Value().st_ino) ||
                ((link.st_mode & S_IFMT) != (pinnedLink.Value().st_mode & S_IFMT)))
            {
                return Error("Filesystem root link changed during acquisition at '" + rootName + "'", ESTALE);
            }
            entry.linkMetadata = pinnedLink.Value();
            entry.targetMetadata = path->Leaf().Snapshot();
        }
        if (FilesystemRootKind::File == request.rootKind)
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
            frame.path = rootName;
            frame.bytes = frame.path.size() + 1;
            frame.device = path->Leaf().Snapshot().st_dev;
            frame.inode = path->Leaf().Snapshot().st_ino;
            auto charged = Charge(frame.bytes, rootName);
            if (!charged.HasValue())
            {
                return charged;
            }
            auto opened = path->Leaf().OpenChildren(request.limits.fullPathBytes);
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

    Result<bool> PushChild(const Filesystem::DirectoryChild& child, FilesystemCollectionEntry& entry, bool follow)
    {
        const auto extension = Filesystem::ExtensionPolicy{follow ? Filesystem::SymlinkPolicy::FollowWithinRoot : Filesystem::SymlinkPolicy::Reject,
            (FilesystemScope::All == request.scope) ? Filesystem::MountPolicy::AllowCrossing : Filesystem::MountPolicy::StayOnRootMount,
            Filesystem::HardlinkPolicy::Permit};
        const std::size_t live = path->RetainedDescriptors() + frames.size();
        const std::size_t cap = ResolverBudget().shared.liveDescriptors;
        if ((live > cap) || (cap - live < 7))
        {
            return Error("Filesystem pin retention exceeds descriptor budget", EMFILE);
        }
        auto pushed = path->Push(child.name, extension);
        if (!pushed.HasValue())
        {
            // Only a failed direct child open is a missing-name observation.
            // ENOENT from trusted procfs, an absolute link, or any other
            // resolution step must remain a factory/continuation error.
            if (!follow && (ENOENT == pushed.Error().code) && ("Cannot pin confined component" == pushed.Error().message))
            {
                return MissingChild(child, entry.path);
            }
            if ((EXDEV == pushed.Error().code) && ("Component crosses accepted root mount" == pushed.Error().message))
            {
                return Exclude(entry.path, "filesystem scope");
            }
            return std::move(pushed).Error();
        }
        const auto& handle = path->Leaf();
        if (S_ISLNK(entry.linkMetadata.st_mode))
        {
            const auto pinnedLink = path->LeafLinkMetadata();
            if (!pinnedLink.HasValue() || (entry.linkMetadata.st_dev != pinnedLink.Value().st_dev) ||
                (entry.linkMetadata.st_ino != pinnedLink.Value().st_ino) || ((entry.linkMetadata.st_mode & S_IFMT) != (pinnedLink.Value().st_mode & S_IFMT)))
            {
                return Error("Filesystem child link changed during acquisition at '" + entry.path + "'", ESTALE);
            }
            entry.linkMetadata = pinnedLink.Value();
            entry.targetMetadata = handle.Snapshot();
            const auto selected = (Filesystem::Handle::Type::Directory == handle.AcquiredType()) ? request.childDirectoryLinkAction : request.childFileLinkAction;
            if (SymlinkFollowing::DoNotFollow == selected)
            {
                auto dropped = path->Pop();
                if (!dropped.HasValue())
                {
                    return std::move(dropped).Error();
                }
                return Exclude(entry.path, "link policy");
            }
        }
        else if ((entry.linkMetadata.st_dev != handle.Snapshot().st_dev) || (entry.linkMetadata.st_ino != handle.Snapshot().st_ino) ||
                 ((entry.linkMetadata.st_mode & S_IFMT) != (handle.Snapshot().st_mode & S_IFMT)))
        {
            return Error("Filesystem child changed during acquisition at '" + entry.path + "'", ESTALE);
        }
        auto mount = handle.MountIdentity(request.limits.fullPathBytes);
        if (!mount.HasValue())
        {
            return std::move(mount).Error();
        }
        if ((FilesystemScope::All != request.scope) && (baseline != mount.Value()))
        {
            auto dropped = path->Pop();
            if (!dropped.HasValue())
            {
                return std::move(dropped).Error();
            }
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
                    if ((ancestor.device == handle.Snapshot().st_dev) && (ancestor.inode == handle.Snapshot().st_ino))
                    {
                        return Error("Directory ancestor cycle at '" + entry.path + "'", ELOOP);
                    }
                }
                Frame frame;
                frame.path = entry.path;
                frame.bytes = frame.path.size() + 1;
                frame.device = handle.Snapshot().st_dev;
                frame.inode = handle.Snapshot().st_ino;
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
                auto dropped = path->Pop();
                if (!dropped.HasValue())
                {
                    return std::move(dropped).Error();
                }
                // Non-descended directories still need an owned live pin.
                entry.OwnHandle(std::move(dropped).Value());
            }
        }
        else
        {
            auto detached = path->Pop();
            if (!detached.HasValue())
            {
                return std::move(detached).Error();
            }
            entry.OwnHandle(std::move(detached).Value());
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
        auto observed = path->ObserveChild(child.name, request.limits.fullPathBytes);
        if (!observed.HasValue())
        {
            return std::move(observed).Error();
        }
        if (!observed.Value().HasValue())
        {
            return MissingChild(child, full);
        }
        FilesystemCollectionEntry entry;
        entry.path = full;
        entry.linkMetadata = observed.Value().Value().metadata;
        if (S_ISLNK(entry.linkMetadata.st_mode))
        {
            const auto fileAction = request.childFileLinkAction;
            const auto dirAction = request.childDirectoryLinkAction;
            if ((fileAction == dirAction) && (SymlinkFollowing::DoNotFollow == fileAction))
            {
                return Exclude(full, "link policy");
            }
            if ((FilesystemScope::All != request.scope) && (baseline != observed.Value().Value().mountId))
            {
                return Exclude(full, "filesystem scope");
            }
            // Classification of a selected link is performed by confined
            // acquisition, not an unrestricted stat of the spelled name.
            return PushChild(child, entry, true);
        }
        if ((FilesystemScope::All != request.scope) && (baseline != observed.Value().Value().mountId))
        {
            return Exclude(full, "filesystem scope");
        }
        if (!S_ISDIR(entry.linkMetadata.st_mode) && !S_ISREG(entry.linkMetadata.st_mode))
        {
            // Special files have no supported operational Handle. They may
            // be observed as metadata but never activated through this API.
            return Offer(std::move(entry));
        }
        return PushChild(child, entry, false);
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
                auto opened = path->Leaf().OpenChildren(request.limits.fullPathBytes);
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
                retained -= frame.bytes;
                frames.pop_back();
                if (!frames.empty())
                {
                    auto popped = path->Pop();
                    if (!popped.HasValue())
                    {
                        return std::move(popped).Error();
                    }
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
        for (auto& frame : frames)
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
        frames.clear();
        if (pending.HasValue())
        {
            if (pending.Value().OwnsHandle())
            {
                auto ended = pending.Value().CloseHandle();
                if (!ended.HasValue())
                {
                    record(ended.Error());
                }
            }
            pending.Reset();
            retained -= pendingBytes;
            pendingBytes = 0;
        }
        if (path)
        {
            auto ended = path->Close();
            if (!ended.HasValue())
            {
                record(ended.Error());
            }
        }
        path.reset();
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

    ResolvedFilesystemCollectionRequest request;
    ContextInterface& context;
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

Result<FileRange> Files(const FilesystemCollectionRequest& policy, ContextInterface& context)
{
    auto resolved = ResolveFilesystemCollectionRequest(policy);
    if (!resolved.HasValue())
    {
        return resolved.Error();
    }
    try
    {
        auto state = std::make_shared<FileRange::State>(std::move(resolved).Value(), context);
        auto initialized = state->Initialize();
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
} // namespace ComplianceEngine
