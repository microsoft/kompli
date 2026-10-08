// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "FilesystemCollection.h"

#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <exception>
#include <limits>
#include <memory>
#include <new>
#include <utility>

namespace ComplianceEngine
{
namespace
{
template <typename T>
T Resolve(const Optional<T>& value, T defaultValue)
{
    return value.ValueOr(std::move(defaultValue));
}

Result<bool> ValidateRootKind(FilesystemRootKind rootKind)
{
    switch (rootKind)
    {
        case FilesystemRootKind::File:
        case FilesystemRootKind::Directory:
            return true;
    }

    return Error("Invalid filesystem root kind", EINVAL);
}

Result<bool> ValidateDirection(FilesystemDirection direction)
{
    switch (direction)
    {
        case FilesystemDirection::None:
        case FilesystemDirection::Down:
            return true;
        case FilesystemDirection::Up:
            return Error("Upward filesystem collection is not supported", ENOTSUP);
    }

    return Error("Invalid filesystem collection direction", EINVAL);
}

Result<bool> ValidateLinkAction(FilesystemLinkAction action)
{
    switch (action)
    {
        case FilesystemLinkAction::Record:
        case FilesystemLinkAction::Follow:
        case FilesystemLinkAction::Exclude:
            return true;
    }

    return Error("Invalid filesystem link action", EINVAL);
}

Result<bool> ValidateScope(FilesystemScope scope)
{
    switch (scope)
    {
        case FilesystemScope::RootDevice:
        case FilesystemScope::All:
        case FilesystemScope::Defined:
            return true;
        case FilesystemScope::Local:
            return Error("Local filesystem classification is not supported", ENOTSUP);
    }

    return Error("Invalid filesystem scope", EINVAL);
}

Result<std::size_t> ResolveLimit(const Optional<long long>& value, std::size_t defaultValue, const std::string& name)
{
    if (!value.HasValue())
    {
        return defaultValue;
    }

    const long long requestedValue = value.Value();
    if (0 >= requestedValue)
    {
        return Error("Filesystem collection " + name + " must be positive", EINVAL);
    }

    const unsigned long long unsignedValue = static_cast<unsigned long long>(requestedValue);
    if (std::numeric_limits<std::size_t>::max() < unsignedValue)
    {
        return Error("Filesystem collection " + name + " is too large", EOVERFLOW);
    }

    return static_cast<std::size_t>(unsignedValue);
}

Result<bool> ValidateRequest(const ResolvedFilesystemCollectionRequest& request)
{
    if (request.rootPath.empty())
    {
        return Error("Filesystem collection root path must not be empty", EINVAL);
    }

    Result<bool> validation = ValidateRootKind(request.rootKind);
    if (!validation.HasValue())
    {
        return validation;
    }

    validation = ValidateDirection(request.direction);
    if (!validation.HasValue())
    {
        return validation;
    }

    if (-1 > request.maxDepth)
    {
        return Error("Filesystem collection maximum depth must be -1 or nonnegative", EINVAL);
    }

    for (const FilesystemLinkAction action : {request.rootFileLinkAction, request.rootDirectoryLinkAction, request.childFileLinkAction, request.childDirectoryLinkAction})
    {
        validation = ValidateLinkAction(action);
        if (!validation.HasValue())
        {
            return validation;
        }
    }

    validation = ValidateScope(request.scope);
    if (!validation.HasValue())
    {
        return validation;
    }

    if (request.rootPath.size() == std::numeric_limits<std::size_t>::max())
    {
        return Error("Filesystem collection root path size overflows accounting", EOVERFLOW);
    }

    const std::size_t retainedRootBytes = request.rootPath.size() + 1;
    if (request.limits.fullPathBytes < retainedRootBytes)
    {
        return Error("Filesystem collection root path exceeds the full path byte limit", ENAMETOOLONG);
    }

    if (request.limits.retainedPathBytes < retainedRootBytes)
    {
        return Error("Filesystem collection root path exceeds the retained path byte limit", E2BIG);
    }

    return true;
}
} // namespace

Result<ResolvedFilesystemCollectionRequest> ResolveFilesystemCollectionRequest(const FilesystemCollectionRequest& request)
{
    ResolvedFilesystemCollectionRequest resolved;
    resolved.rootPath = request.rootPath;
    resolved.rootKind = request.rootKind;
    resolved.direction = Resolve(request.direction, FilesystemDirection::None);
    resolved.maxDepth = Resolve(request.maxDepth, 32);
    resolved.rootFileLinkAction = Resolve(request.rootFileLinkAction, FilesystemLinkAction::Record);
    resolved.rootDirectoryLinkAction = Resolve(request.rootDirectoryLinkAction, FilesystemLinkAction::Record);
    resolved.childFileLinkAction = Resolve(request.childFileLinkAction, FilesystemLinkAction::Record);
    resolved.childDirectoryLinkAction = Resolve(request.childDirectoryLinkAction, FilesystemLinkAction::Record);
    resolved.scope = Resolve(request.scope, FilesystemScope::RootDevice);

    Result<std::size_t> limit = ResolveLimit(request.operationalDescent, resolved.limits.operationalDescent, "operational descent limit");
    if (!limit.HasValue())
    {
        return limit.Error();
    }
    resolved.limits.operationalDescent = limit.Value();

    limit = ResolveLimit(request.entryWork, resolved.limits.entryWork, "entry work limit");
    if (!limit.HasValue())
    {
        return limit.Error();
    }
    resolved.limits.entryWork = limit.Value();

    limit = ResolveLimit(request.directoryWidth, resolved.limits.directoryWidth, "directory width limit");
    if (!limit.HasValue())
    {
        return limit.Error();
    }
    resolved.limits.directoryWidth = limit.Value();

    limit = ResolveLimit(request.fullPathBytes, resolved.limits.fullPathBytes, "full path byte limit");
    if (!limit.HasValue())
    {
        return limit.Error();
    }
    resolved.limits.fullPathBytes = limit.Value();

    limit = ResolveLimit(request.retainedPathBytes, resolved.limits.retainedPathBytes, "retained path byte limit");
    if (!limit.HasValue())
    {
        return limit.Error();
    }
    resolved.limits.retainedPathBytes = limit.Value();

    limit = ResolveLimit(request.openDirectories, resolved.limits.openDirectories, "open directory limit");
    if (!limit.HasValue())
    {
        return limit.Error();
    }
    resolved.limits.openDirectories = limit.Value();

    const Result<bool> validation = ValidateRequest(resolved);
    if (!validation.HasValue())
    {
        return validation.Error();
    }

    return resolved;
}

namespace
{
Error OperationError(const char* operation, const std::string& path, int code)
{
    return Error(std::string("Failed to ") + operation + " '" + path + "': " + std::strerror(code), code);
}

struct PrefixEntry
{
    PrefixEntry(std::string name, ino_t inode)
        : name(std::move(name)),
          inode(inode)
    {
    }

    std::string name;
    ino_t inode;
};

struct DirectoryFrame
{
    std::string path;
    dev_t device = 0;
    ino_t inode = 0;
    DIR* stream = nullptr;
    std::vector<PrefixEntry> prefix;
    std::size_t width = 0;
    std::size_t chargedBytes = 0;
};

struct DirectoryCloser
{
    const Detail::FilesystemCollectionOperations* operations;

    void operator()(DIR* stream) const
    {
        if (nullptr != stream)
        {
            (void)operations->closeDirectory(stream);
        }
    }
};

class Traversal
{
public:
    Traversal(ResolvedFilesystemCollectionRequest request, const FilesystemCollectionVisitor& visitor, bool retainEntries,
        const Detail::FilesystemCollectionOperations& operations, OsConfigLogHandle log)
        : mRequest(std::move(request)),
          mVisitor(visitor),
          mRetainEntries(retainEntries),
          mOperations(operations),
          mLog(log)
    {
    }

    Result<FilesystemCollectionResult> Run()
    {
        Result<FilesystemCollectionResult> result = Error("Filesystem collection did not start", EIO);
        try
        {
            const Result<bool> rootCharge = Charge(mRequest.rootPath.size() + 1, mRequest.rootPath);
            result = rootCharge.HasValue() ? Walk() : Result<FilesystemCollectionResult>(rootCharge.Error());
        }
        catch (const std::bad_alloc&)
        {
            result = Error("Filesystem collection allocation failed", ENOMEM);
        }
        catch (const std::exception& exception)
        {
            result = Error(std::string("Filesystem collection failed: ") + exception.what(), EIO);
        }
        for (auto frame = mFrames.rbegin(); frame != mFrames.rend(); ++frame)
        {
            if (nullptr == frame->stream)
            {
                continue;
            }
            DIR* stream = frame->stream;
            frame->stream = nullptr;
            if (0 != mOperations.closeDirectory(stream))
            {
                const int code = errno;
                if (result.HasValue())
                {
                    result = OperationError("close directory", frame->path, code);
                }
                else
                {
                    OsConfigLogError(mLog, "Closing directory '%s' failed (%d) after primary error: %s", frame->path.c_str(), code,
                        result.Error().message.c_str());
                }
            }
        }
        return result;
    }

private:
    Result<bool> Charge(std::size_t bytes, const std::string& path)
    {
        if (mRequest.limits.retainedPathBytes - mRetainedBytes < bytes)
        {
            return Error("Retained filesystem paths exceed budget at '" + path + "'", E2BIG);
        }
        mRetainedBytes += bytes;
        return true;
    }

    Result<bool> Work(const std::string& path)
    {
        if (mRequest.limits.entryWork == mWork)
        {
            return Error("Filesystem entry work budget exhausted at '" + path + "'", E2BIG);
        }
        ++mWork;
        return true;
    }

    Result<bool> OpenFrame(std::string path, const struct stat& expected)
    {
        if (mOpenDirectories == mRequest.limits.openDirectories)
        {
            bool suspended = false;
            for (DirectoryFrame& frame : mFrames)
            {
                if (nullptr == frame.stream)
                {
                    continue;
                }
                DIR* stream = frame.stream;
                frame.stream = nullptr;
                --mOpenDirectories;
                if (0 != mOperations.closeDirectory(stream))
                {
                    return OperationError("close directory", frame.path, errno);
                }
                suspended = true;
                break;
            }
            if (!suspended)
            {
                return Error("No directory available for descriptor continuation", EMFILE);
            }
        }

        std::unique_ptr<DIR, DirectoryCloser> ownedStream(mOperations.openDirectory(path.c_str()), DirectoryCloser{&mOperations});
        if (!ownedStream)
        {
            return OperationError("open directory", path, errno);
        }
        struct stat opened = {};
        if (0 != mOperations.statDescriptor(dirfd(ownedStream.get()), &opened))
        {
            const int code = errno;
            if (0 != mOperations.closeDirectory(ownedStream.release()))
            {
                OsConfigLogError(mLog, "Closing directory '%s' after stat failure failed (%d)", path.c_str(), errno);
            }
            return OperationError("stat directory", path, code);
        }
        if ((expected.st_dev != opened.st_dev) || (expected.st_ino != opened.st_ino))
        {
            if (0 != mOperations.closeDirectory(ownedStream.release()))
            {
                OsConfigLogError(mLog, "Closing replaced directory '%s' failed (%d)", path.c_str(), errno);
            }
            return Error("Directory identity changed at '" + path + "'", ESTALE);
        }
        const std::size_t bytes = path.size() + 1;
        const Result<bool> charge = Charge(bytes, path);
        if (!charge.HasValue())
        {
            if (0 != mOperations.closeDirectory(ownedStream.release()))
            {
                OsConfigLogError(mLog, "Closing directory '%s' after budget failure failed (%d)", path.c_str(), errno);
            }
            return charge.Error();
        }
        DirectoryFrame frame;
        frame.path = std::move(path);
        frame.device = opened.st_dev;
        frame.inode = opened.st_ino;
        frame.chargedBytes = bytes;
        mFrames.push_back(std::move(frame));
        mFrames.back().stream = ownedStream.release();
        ++mOpenDirectories;
        return true;
    }

    Result<bool> Reopen(DirectoryFrame& frame)
    {
        if (mOpenDirectories == mRequest.limits.openDirectories)
        {
            bool suspended = false;
            for (DirectoryFrame& ancestor : mFrames)
            {
                if ((&ancestor != &frame) && (nullptr != ancestor.stream))
                {
                    DIR* stream = ancestor.stream;
                    ancestor.stream = nullptr;
                    --mOpenDirectories;
                    if (0 != mOperations.closeDirectory(stream))
                    {
                        return OperationError("close directory", ancestor.path, errno);
                    }
                    suspended = true;
                    break;
                }
            }
            if (!suspended)
            {
                return Error("No directory available for replay within descriptor budget", EMFILE);
            }
        }
        DIR* stream = mOperations.openDirectory(frame.path.c_str());
        if (nullptr == stream)
        {
            return OperationError("reopen directory", frame.path, errno);
        }
        struct stat opened = {};
        if (0 != mOperations.statDescriptor(dirfd(stream), &opened))
        {
            const int code = errno;
            if (0 != mOperations.closeDirectory(stream))
            {
                OsConfigLogError(mLog, "Closing reopened directory '%s' failed (%d)", frame.path.c_str(), errno);
            }
            return OperationError("stat reopened directory", frame.path, code);
        }
        if ((frame.device != opened.st_dev) || (frame.inode != opened.st_ino))
        {
            if (0 != mOperations.closeDirectory(stream))
            {
                OsConfigLogError(mLog, "Closing replaced directory '%s' failed (%d)", frame.path.c_str(), errno);
            }
            return Error("Directory identity changed during replay at '" + frame.path + "'", ESTALE);
        }
        frame.stream = stream;
        ++mOpenDirectories;
        for (const PrefixEntry& expected : frame.prefix)
        {
            const struct dirent* entry = nullptr;
            do
            {
                errno = 0;
                entry = mOperations.readDirectory(stream);
            } while ((nullptr != entry) && ((0 == std::strcmp(entry->d_name, ".")) || (0 == std::strcmp(entry->d_name, ".."))));
            if (nullptr == entry)
            {
                const int code = errno;
                if (0 != code)
                {
                    return OperationError("replay directory", frame.path, code);
                }
                return Error("Directory prefix changed during replay at '" + frame.path + "'", ESTALE);
            }
            const Result<bool> work = Work(frame.path);
            if (!work.HasValue())
            {
                return work.Error();
            }
            if ((expected.name != entry->d_name) || ((0 != expected.inode) && (0 != entry->d_ino) && (expected.inode != entry->d_ino)))
            {
                return Error("Directory prefix changed during replay at '" + frame.path + "'", ESTALE);
            }
        }
        return true;
    }

    Result<bool> Deliver(FilesystemCollectionEntry entry)
    {
        const std::size_t bytes = entry.path.size() + 1;
        const Result<bool> charge = Charge(bytes, entry.path);
        if (!charge.HasValue())
        {
            return charge.Error();
        }
        Result<FilesystemVisitAction> action = mVisitor(entry);
        if (!action.HasValue())
        {
            mRetainedBytes -= bytes;
            return action.Error();
        }
        if (FilesystemVisitAction::Stop == action.Value())
        {
            mResult.outcome = FilesystemCollectionOutcome::Stopped;
            mResult.stopReason = "Visitor requested stop";
        }
        else if (FilesystemVisitAction::Continue != action.Value())
        {
            mRetainedBytes -= bytes;
            return Error("Invalid filesystem visitor action", EINVAL);
        }
        if (mRetainEntries)
        {
            mResult.entries.push_back(std::move(entry));
        }
        else
        {
            mRetainedBytes -= bytes;
        }
        return true;
    }

    Result<bool> Exclude(std::string path, const char* reason)
    {
        const Result<bool> charge = Charge(path.size() + 1, path);
        if (!charge.HasValue())
        {
            return charge.Error();
        }
        mResult.exclusions.push_back({std::move(path), reason});
        return true;
    }

    Result<bool> Entry(const std::string& path, bool root)
    {
        if (mRequest.limits.fullPathBytes <= path.size())
        {
            return Error("Filesystem path exceeds full path budget at '" + path + "'", ENAMETOOLONG);
        }
        struct stat metadata = {};
        if (0 != mOperations.lstatPath(path.c_str(), &metadata))
        {
            return OperationError("lstat", path, errno);
        }
        FilesystemCollectionEntry entry;
        entry.path = path;
        entry.linkMetadata = metadata;
        bool directory = S_ISDIR(metadata.st_mode);
        bool file = S_ISREG(metadata.st_mode);
        if (S_ISLNK(metadata.st_mode))
        {
            const FilesystemLinkAction fileAction = root ? mRequest.rootFileLinkAction : mRequest.childFileLinkAction;
            const FilesystemLinkAction directoryAction = root ? mRequest.rootDirectoryLinkAction : mRequest.childDirectoryLinkAction;
            if ((fileAction != directoryAction) || (FilesystemLinkAction::Follow == fileAction))
            {
                struct stat target = {};
                if (0 != mOperations.statPath(path.c_str(), &target))
                {
                    return OperationError("stat link target", path, errno);
                }
                entry.targetMetadata = target;
                directory = S_ISDIR(target.st_mode);
                file = S_ISREG(target.st_mode);
                if ((!directory) && (!file) && (fileAction != directoryAction))
                {
                    return Error("Cannot classify link target as file or directory at '" + path + "'", EINVAL);
                }
            }
            const FilesystemLinkAction action = directory ? directoryAction : fileAction;
            if (FilesystemLinkAction::Exclude == action)
            {
                return Exclude(path, "link policy");
            }
            if (FilesystemLinkAction::Record == action)
            {
                return Deliver(std::move(entry));
            }
            if ((!directory) && (!file))
            {
                return Error("Unsupported followed link target at '" + path + "'", EINVAL);
            }
            metadata = entry.targetMetadata.Value();
        }
        if (root && (FilesystemRootKind::Directory == mRequest.rootKind) && !directory)
        {
            return Error("Expected directory root at '" + path + "'", ENOTDIR);
        }
        if (root && (FilesystemRootKind::File == mRequest.rootKind) && !file)
        {
            return Error("Expected file root at '" + path + "'", EISDIR);
        }
        if (root)
        {
            mRootDevice = metadata.st_dev;
        }
        if (!root && (FilesystemScope::All != mRequest.scope) && (mRootDevice != metadata.st_dev))
        {
            return Exclude(path, "filesystem scope");
        }
        Result<bool> delivery = Deliver(std::move(entry));
        if (!delivery.HasValue() || (FilesystemCollectionOutcome::Stopped == mResult.outcome) || !directory)
        {
            return delivery;
        }
        if (!root)
        {
            const std::size_t descent = mFrames.size();
            if ((FilesystemDirection::None == mRequest.direction) || ((-1 != mRequest.maxDepth) && (static_cast<std::size_t>(mRequest.maxDepth) < descent)))
            {
                return true;
            }
            if (mRequest.limits.operationalDescent < descent)
            {
                return Error("Operational descent budget exceeded at '" + path + "'", E2BIG);
            }
            for (const DirectoryFrame& frame : mFrames)
            {
                if ((frame.device == metadata.st_dev) && (frame.inode == metadata.st_ino))
                {
                    return Error("Directory ancestor cycle at '" + path + "'", ELOOP);
                }
            }
        }
        return OpenFrame(path, metadata);
    }

    Result<FilesystemCollectionResult> Walk()
    {
        struct stat root = {};
        if (0 != mOperations.lstatPath(mRequest.rootPath.c_str(), &root))
        {
            const int code = errno;
            if (ENOENT == code)
            {
                mResult.outcome = FilesystemCollectionOutcome::Absent;
                return std::move(mResult);
            }
            return OperationError("lstat", mRequest.rootPath, code);
        }
        const Result<bool> rootResult = Entry(mRequest.rootPath, true);
        if (!rootResult.HasValue())
        {
            return rootResult.Error();
        }
        while ((!mFrames.empty()) && (FilesystemCollectionOutcome::Stopped != mResult.outcome))
        {
            DirectoryFrame& frame = mFrames.back();
            if (nullptr == frame.stream)
            {
                const Result<bool> reopened = Reopen(frame);
                if (!reopened.HasValue())
                {
                    return reopened.Error();
                }
            }
            errno = 0;
            const struct dirent* dirEntry = mOperations.readDirectory(frame.stream);
            if (nullptr == dirEntry)
            {
                const int code = errno;
                if (0 != code)
                {
                    return OperationError("read directory", frame.path, code);
                }
                DIR* stream = frame.stream;
                frame.stream = nullptr;
                --mOpenDirectories;
                if (0 != mOperations.closeDirectory(stream))
                {
                    return OperationError("close directory", frame.path, errno);
                }
                mRetainedBytes -= frame.chargedBytes;
                mFrames.pop_back();
                continue;
            }
            if ((0 == std::strcmp(dirEntry->d_name, ".")) || (0 == std::strcmp(dirEntry->d_name, "..")))
            {
                continue;
            }
            const Result<bool> work = Work(frame.path);
            if (!work.HasValue())
            {
                return work.Error();
            }
            if (mRequest.limits.directoryWidth == frame.width)
            {
                return Error("Directory width budget exceeded at '" + frame.path + "'", E2BIG);
            }
            ++frame.width;
            const std::string name = dirEntry->d_name;
            const ino_t inode = dirEntry->d_ino;
            const std::size_t prefixBytes = sizeof(PrefixEntry) + name.size() + 1;
            const Result<bool> chargedPrefix = Charge(prefixBytes, frame.path);
            if (!chargedPrefix.HasValue())
            {
                return chargedPrefix.Error();
            }
            frame.chargedBytes += prefixBytes;
            frame.prefix.push_back({name, inode});
            const std::string childPath = frame.path + "/" + name;
            const std::size_t pathBytes = childPath.size() + 1;
            const Result<bool> chargedPath = Charge(pathBytes, childPath);
            if (!chargedPath.HasValue())
            {
                return chargedPath.Error();
            }
            const Result<bool> processed = Entry(childPath, false);
            mRetainedBytes -= pathBytes;
            if (!processed.HasValue())
            {
                return processed.Error();
            }
        }
        return std::move(mResult);
    }

    ResolvedFilesystemCollectionRequest mRequest;
    const FilesystemCollectionVisitor& mVisitor;
    bool mRetainEntries = false;
    const Detail::FilesystemCollectionOperations& mOperations;
    OsConfigLogHandle mLog = nullptr;
    FilesystemCollectionResult mResult;
    std::vector<DirectoryFrame> mFrames;
    std::size_t mOpenDirectories = 0;
    std::size_t mRetainedBytes = 0;
    std::size_t mWork = 0;
    dev_t mRootDevice = 0;
};
} // namespace

Result<FilesystemCollectionResult> StreamFilesystemCollection(const FilesystemCollectionRequest& request, const FilesystemCollectionVisitor& visitor, OsConfigLogHandle log)
{
    const Detail::FilesystemCollectionOperations operations;
    return Detail::StreamFilesystemCollectionWithOperations(request, visitor, operations, log);
}

Result<FilesystemCollectionResult> CollectFilesystem(const FilesystemCollectionRequest& request, OsConfigLogHandle log)
{
    const Detail::FilesystemCollectionOperations operations;
    return Detail::CollectFilesystemWithOperations(request, operations, log);
}

namespace Detail
{
Result<FilesystemCollectionResult> StreamFilesystemCollectionWithOperations(const FilesystemCollectionRequest& request,
    const FilesystemCollectionVisitor& visitor, const FilesystemCollectionOperations& operations, OsConfigLogHandle log)
{
    const Result<ResolvedFilesystemCollectionRequest> resolved = ResolveFilesystemCollectionRequest(request);
    if (!resolved.HasValue())
    {
        return resolved.Error();
    }
    if (!visitor)
    {
        return Error("Filesystem collection visitor must not be empty", EINVAL);
    }
    Traversal traversal(resolved.Value(), visitor, false, operations, log);
    return traversal.Run();
}

Result<FilesystemCollectionResult> CollectFilesystemWithOperations(const FilesystemCollectionRequest& request,
    const FilesystemCollectionOperations& operations, OsConfigLogHandle log)
{
    const Result<ResolvedFilesystemCollectionRequest> resolved = ResolveFilesystemCollectionRequest(request);
    if (!resolved.HasValue())
    {
        return resolved.Error();
    }
    const FilesystemCollectionVisitor visitor = [](const FilesystemCollectionEntry&) {
        return Result<FilesystemVisitAction>(FilesystemVisitAction::Continue);
    };
    Traversal traversal(resolved.Value(), visitor, true, operations, log);
    return traversal.Run();
}
} // namespace Detail
} // namespace ComplianceEngine
