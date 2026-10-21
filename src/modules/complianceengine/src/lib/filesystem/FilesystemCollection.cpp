// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "FilesystemCollection.hpp"

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

Result<bool> ValidateYieldType(FilesystemYieldType type)
{
    switch (type)
    {
        case FilesystemYieldType::All:
        case FilesystemYieldType::RegularFiles:
        case FilesystemYieldType::Directories:
        case FilesystemYieldType::SymbolicLinks:
            return true;
    }
    return Error("Invalid filesystem yield type", EINVAL);
}

Result<bool> ValidateDepthAction(FilesystemDepthAction action)
{
    switch (action)
    {
        case FilesystemDepthAction::Stop:
        case FilesystemDepthAction::Error:
            return true;
    }
    return Error("Invalid filesystem depth action", EINVAL);
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

    validation = ValidateYieldType(request.yieldType);
    if (!validation.HasValue())
    {
        return validation;
    }
    validation = ValidateDepthAction(request.depthAction);
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
    resolved.yieldType = Resolve(request.yieldType, FilesystemYieldType::All);
    resolved.depthAction = Resolve(request.depthAction, FilesystemDepthAction::Stop);

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

struct PrefixEntry
{
    PrefixEntry(std::string name, ino_t inode, unsigned char type)
        : name(std::move(name)),
          inode(inode),
          type(type)
    {
    }

    std::string name;
    ino_t inode;
    unsigned char type;
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
    bool postorder = false;
};

struct DirectoryCloser
{
    ContextInterface* context;

    void operator()(DIR* stream) const
    {
        if (nullptr != stream)
        {
            (void)context->CloseDirectory(stream);
        }
    }
};

class Traversal
{
public:
    Traversal(ResolvedFilesystemCollectionRequest request, ContextInterface& context, bool retainEntries, bool legacy)
        : mRequest(std::move(request)),
          mRetainEntries(retainEntries),
          mLegacy(legacy),
          mContext(context),
          mLog(context.GetLogHandle())
    {
    }

    ~Traversal()
    {
        if (!mFinalized)
        {
            const Optional<Error> error = CloseFrames(Optional<Error>());
            if (error.HasValue())
            {
                OsConfigLogError(mLog, "Closing incomplete filesystem traversal failed: %s", error.Value().message.c_str());
            }
        }
    }

    Result<bool> Initialize()
    {
        try
        {
            const auto initialized = InitializeRoot();
            if (!initialized.HasValue())
            {
                const Error error = initialized.Error();
                (void)Fail(error);
                return error;
            }
            return true;
        }
        catch (const std::bad_alloc&)
        {
            const Error error("Filesystem collection allocation failed", ENOMEM);
            (void)Fail(error);
            return error;
        }
        catch (const std::exception& exception)
        {
            const Error error(std::string("Filesystem collection failed: ") + exception.what(), EIO);
            (void)Fail(error);
            return error;
        }
    }

    Result<Optional<FilesystemCollectionEntry>> Next()
    {
        if (mFinalized)
        {
            return Optional<FilesystemCollectionEntry>();
        }
        try
        {
            const Result<Optional<FilesystemCollectionEntry>> next = Pull();
            if (!next.HasValue())
            {
                return Fail(next.Error());
            }
            return next;
        }
        catch (const std::bad_alloc&)
        {
            return Fail(Error("Filesystem collection allocation failed", ENOMEM));
        }
        catch (const std::exception& exception)
        {
            return Fail(Error(std::string("Filesystem collection failed: ") + exception.what(), EIO));
        }
    }

    Result<FilesystemCollectionResult> Stop()
    {
        if (mFailure.HasValue())
        {
            return mFailure.Value();
        }
        if (mFinalized)
        {
            return mResult;
        }
        const Optional<Error> closed = CloseFrames(Optional<Error>());
        return closed.HasValue() ? Result<FilesystemCollectionResult>(closed.Value()) : Result<FilesystemCollectionResult>(mResult);
    }

    void Abort(const Error& error)
    {
        if (!mFinalized)
        {
            (void)CloseFrames(Optional<Error>(error));
        }
    }

    Result<FilesystemCollectionResult> CloseResult()
    {
        if (mFailure.HasValue())
        {
            return mFailure.Value();
        }
        if (!mFinalized)
        {
            const Optional<Error> closed = CloseFrames(Optional<Error>());
            if (closed.HasValue())
            {
                return closed.Value();
            }
        }
        return mResult;
    }

    bool RootExists() const
    {
        return mRootExists;
    }
    Result<bool> Close()
    {
        const auto result = CloseResult();
        if (!result.HasValue())
        {
            return result.Error();
        }
        return true;
    }
    Result<bool> RetainEntries()
    {
        // Factory initialization may have prepared the root observation before
        // the collecting adapter opts into retaining entries.
        try
        {
            if (mPendingEntry.HasValue())
            {
                const auto& entry = mPendingEntry.Value();
                const auto charged = Charge(entry.path.size() + 1, entry.path);
                if (!charged.HasValue())
                {
                    return charged.Error();
                }
                mResult.entries.push_back(entry);
            }
            mRetainEntries = true;
            return true;
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

private:
    Optional<Error> CloseFrames(Optional<Error> primary)
    {
        mFinalized = true;
        for (auto frame = mFrames.rbegin(); frame != mFrames.rend(); ++frame)
        {
            if (nullptr == frame->stream)
            {
                continue;
            }
            DIR* stream = frame->stream;
            frame->stream = nullptr;
            if (0 != mContext.CloseDirectory(stream))
            {
                const int code = errno;
                if (!primary.HasValue())
                {
                    primary = OperationError("close directory", frame->path, code);
                }
                else
                {
                    OsConfigLogError(mLog, "Closing directory '%s' failed (%d) after primary error: %s", frame->path.c_str(), code,
                        primary.Value().message.c_str());
                }
            }
        }
        if (primary.HasValue())
        {
            mFailure = primary;
        }
        return primary;
    }

    Result<Optional<FilesystemCollectionEntry>> Fail(Error error)
    {
        (void)CloseFrames(Optional<Error>(error));
        return error;
    }

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

    Result<bool> OpenFrame(std::string path, const struct stat* expected, bool postorder = false, bool root = false)
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
                if (0 != mContext.CloseDirectory(stream))
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

        std::unique_ptr<DIR, DirectoryCloser> ownedStream(mContext.OpenDirectory(path.c_str()), DirectoryCloser{&mContext});
        if (!ownedStream)
        {
            if (root && (ENOENT == errno))
            {
                mRootExists = false;
                return true;
            }
            return OperationError("open directory", path, errno);
        }
        struct stat opened = {};
        if (0 != mContext.StatFileDescriptor(dirfd(ownedStream.get()), &opened))
        {
            const int code = errno;
            if (0 != mContext.CloseDirectory(ownedStream.release()))
            {
                OsConfigLogError(mLog, "Closing directory '%s' after stat failure failed (%d)", path.c_str(), errno);
            }
            return OperationError("stat directory", path, code);
        }
        if ((nullptr != expected) && ((expected->st_dev != opened.st_dev) || (expected->st_ino != opened.st_ino)))
        {
            if (0 != mContext.CloseDirectory(ownedStream.release()))
            {
                OsConfigLogError(mLog, "Closing replaced directory '%s' failed (%d)", path.c_str(), errno);
            }
            return Error("Directory identity changed at '" + path + "'", ESTALE);
        }
        const std::size_t bytes = path.size() + 1;
        const Result<bool> charge = Charge(bytes, path);
        if (!charge.HasValue())
        {
            if (0 != mContext.CloseDirectory(ownedStream.release()))
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
        frame.postorder = postorder;
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
                    if (0 != mContext.CloseDirectory(stream))
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
        DIR* stream = mContext.OpenDirectory(frame.path.c_str());
        if (nullptr == stream)
        {
            return OperationError("reopen directory", frame.path, errno);
        }
        struct stat opened = {};
        if (0 != mContext.StatFileDescriptor(dirfd(stream), &opened))
        {
            const int code = errno;
            if (0 != mContext.CloseDirectory(stream))
            {
                OsConfigLogError(mLog, "Closing reopened directory '%s' failed (%d)", frame.path.c_str(), errno);
            }
            return OperationError("stat reopened directory", frame.path, code);
        }
        if ((frame.device != opened.st_dev) || (frame.inode != opened.st_ino))
        {
            if (0 != mContext.CloseDirectory(stream))
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
                entry = mContext.ReadDirectory(stream);
            } while ((nullptr != entry) && Skip(entry));
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
            if ((expected.name != entry->d_name) || ((0 != expected.inode) && (0 != entry->d_ino) && (expected.inode != entry->d_ino)) ||
                (mLegacy && (expected.type != entry->d_type)))
            {
                return Error("Directory prefix changed during replay at '" + frame.path + "'", ESTALE);
            }
        }
        return true;
    }

    bool Skip(const struct dirent* entry) const
    {
        return ((!mLegacy || (DT_DIR == entry->d_type)) && ((0 == std::strcmp(entry->d_name, ".")) || (0 == std::strcmp(entry->d_name, ".."))));
    }

    Result<bool> Deliver(FilesystemCollectionEntry entry)
    {
        const std::size_t bytes = entry.path.size() + 1;
        const Result<bool> charge = Charge(bytes, entry.path);
        if (!charge.HasValue())
        {
            return charge.Error();
        }
        if (mRetainEntries)
        {
            mResult.entries.push_back(entry);
        }
        else
        {
            mRetainedBytes -= bytes;
        }
        mPendingEntry = std::move(entry);
        return true;
    }

    bool ShouldYield(const struct stat& effective) const
    {
        switch (mRequest.yieldType)
        {
            case FilesystemYieldType::All:
                return true;
            case FilesystemYieldType::RegularFiles:
                return S_ISREG(effective.st_mode);
            case FilesystemYieldType::Directories:
                return S_ISDIR(effective.st_mode);
            case FilesystemYieldType::SymbolicLinks:
                return S_ISLNK(effective.st_mode);
        }
        return false; // The policy is validated before traversal.
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

    Result<bool> Entry(const std::string& path, bool root, const struct stat* known = nullptr)
    {
        if (mRequest.limits.fullPathBytes <= path.size())
        {
            return Error("Filesystem path exceeds full path budget at '" + path + "'", ENAMETOOLONG);
        }
        struct stat metadata = {};
        if (nullptr != known)
        {
            metadata = *known;
        }
        else if (0 != mContext.LstatPath(path.c_str(), &metadata))
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
                if (0 != mContext.StatPath(path.c_str(), &target))
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
                return ShouldYield(entry.linkMetadata) ? Deliver(std::move(entry)) : Result<bool>(true);
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
        if (ShouldYield(metadata))
        {
            const Result<bool> delivery = Deliver(std::move(entry));
            if (!delivery.HasValue())
            {
                return delivery;
            }
        }
        if (!directory)
        {
            return true;
        }
        if (!root)
        {
            const std::size_t descent = mFrames.size();
            if (FilesystemDirection::None == mRequest.direction)
            {
                return true;
            }
            if ((-1 != mRequest.maxDepth) && (static_cast<std::size_t>(mRequest.maxDepth) < descent))
            {
                if (FilesystemDepthAction::Error == mRequest.depthAction)
                {
                    return Error("Maximum recursion depth reached");
                }
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
        // The directory's open/stat (and any error) belongs to the next pull,
        // after the entry has been observed by the caller.
        const Result<bool> retained = Charge(path.size() + 1, path);
        if (!retained.HasValue())
        {
            return retained.Error();
        }
        mPendingDirectory = path;
        mPendingMetadata = metadata;
        return true;
    }

    Result<bool> LegacyEntry(const std::string& path)
    {
        if (mRequest.limits.fullPathBytes <= path.size())
        {
            return Error("Filesystem path exceeds full path budget at '" + path + "'", ENAMETOOLONG);
        }
        struct stat metadata = {};
        if (0 != mContext.LstatPath(path.c_str(), &metadata))
        {
            return OperationError("lstat", path, errno);
        }
        FilesystemCollectionEntry entry;
        entry.path = path;
        entry.linkMetadata = metadata;
        return Deliver(std::move(entry));
    }

    Result<bool> OpenPendingDirectory()
    {
        const std::string path = std::move(mPendingDirectory).Value();
        mPendingDirectory.Reset();
        const struct stat expected = mPendingMetadata.Value();
        mPendingMetadata.Reset();
        mRetainedBytes -= path.size() + 1;
        return OpenFrame(path, &expected);
    }

    Result<bool> InitializeRoot()
    {
        if (mStarted)
        {
            return true;
        }
        mStarted = true;
        const Result<bool> rootCharge = Charge(mRequest.rootPath.size() + 1, mRequest.rootPath);
        if (!rootCharge.HasValue())
        {
            return rootCharge.Error();
        }
        if (mLegacy)
        {
            return OpenFrame(mRequest.rootPath, nullptr, false, true);
        }
        struct stat root = {};
        if (0 != mContext.LstatPath(mRequest.rootPath.c_str(), &root))
        {
            const int code = errno;
            if (ENOENT == code)
            {
                mRootExists = false;
                return true;
            }
            return OperationError("lstat", mRequest.rootPath, code);
        }
        const Result<bool> rootResult = Entry(mRequest.rootPath, true, &root);
        if (!rootResult.HasValue())
        {
            return rootResult.Error();
        }
        // Acquire the requested directory before returning the range, but do
        // not read any entries. Its first observation stays pending for Next().
        if (mPendingDirectory.HasValue())
        {
            return OpenPendingDirectory();
        }
        return true;
    }

    Result<Optional<FilesystemCollectionEntry>> Pull()
    {
        if (!mStarted)
        {
            const Result<bool> initialized = InitializeRoot();
            if (!initialized.HasValue())
            {
                return initialized.Error();
            }
        }
        if (mPendingEntry.HasValue())
        {
            FilesystemCollectionEntry entry = std::move(mPendingEntry).Value();
            mPendingEntry.Reset();
            return Optional<FilesystemCollectionEntry>(std::move(entry));
        }
        if (mPendingDirectory.HasValue())
        {
            const Result<bool> opened = OpenPendingDirectory();
            if (!opened.HasValue())
            {
                return opened.Error();
            }
        }
        while (!mFrames.empty())
        {
            // A filtered directory has no yielded entry to trigger another
            // pull; open it now so required descent cannot be silently lost.
            if (mPendingDirectory.HasValue())
            {
                const Result<bool> opened = OpenPendingDirectory();
                if (!opened.HasValue())
                {
                    return opened.Error();
                }
            }
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
            const struct dirent* dirEntry = mContext.ReadDirectory(frame.stream);
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
                if (0 != mContext.CloseDirectory(stream))
                {
                    return OperationError("close directory", frame.path, errno);
                }
                if (frame.postorder)
                {
                    const Result<bool> delivered = LegacyEntry(frame.path);
                    if (!delivered.HasValue())
                    {
                        return delivered.Error();
                    }
                }
                mRetainedBytes -= frame.chargedBytes;
                mFrames.pop_back();
                if (mPendingEntry.HasValue())
                {
                    FilesystemCollectionEntry entry = std::move(mPendingEntry).Value();
                    mPendingEntry.Reset();
                    return Optional<FilesystemCollectionEntry>(std::move(entry));
                }
                continue;
            }
            if (Skip(dirEntry))
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
            const unsigned char type = dirEntry->d_type;
            const std::size_t prefixBytes = sizeof(PrefixEntry) + name.size() + 1;
            const Result<bool> chargedPrefix = Charge(prefixBytes, frame.path);
            if (!chargedPrefix.HasValue())
            {
                return chargedPrefix.Error();
            }
            frame.chargedBytes += prefixBytes;
            frame.prefix.push_back({name, inode, type});
            const std::string childPath = frame.path + "/" + name;
            if (mLegacy && (mRequest.limits.fullPathBytes <= childPath.size()))
            {
                return Error("Filesystem path exceeds full path budget at '" + childPath + "'", ENAMETOOLONG);
            }
            const std::size_t pathBytes = childPath.size() + 1;
            const Result<bool> chargedPath = Charge(pathBytes, childPath);
            if (!chargedPath.HasValue())
            {
                return chargedPath.Error();
            }
            Result<bool> processed = true;
            if (mLegacy)
            {
                if (DT_DIR == type)
                {
                    if (mFrames.size() > 32)
                    {
                        return Error("Maximum recursion depth reached");
                    }
                    if (mRequest.limits.operationalDescent < mFrames.size())
                    {
                        return Error("Operational descent budget exceeded at '" + childPath + "'", E2BIG);
                    }
                    processed = OpenFrame(childPath, nullptr, true);
                }
                else
                {
                    processed = LegacyEntry(childPath);
                }
            }
            else
            {
                processed = Entry(childPath, false);
            }
            mRetainedBytes -= pathBytes;
            if (!processed.HasValue())
            {
                return processed.Error();
            }
            if (mPendingEntry.HasValue())
            {
                FilesystemCollectionEntry entry = std::move(mPendingEntry).Value();
                mPendingEntry.Reset();
                return Optional<FilesystemCollectionEntry>(std::move(entry));
            }
        }
        const Optional<Error> closed = CloseFrames(Optional<Error>());
        if (closed.HasValue())
        {
            return closed.Value();
        }
        return Optional<FilesystemCollectionEntry>();
    }

    ResolvedFilesystemCollectionRequest mRequest;
    bool mRetainEntries = false;
    bool mLegacy = false;
    ContextInterface& mContext;
    OsConfigLogHandle mLog = nullptr;
    FilesystemCollectionResult mResult;
    std::vector<DirectoryFrame> mFrames;
    std::size_t mOpenDirectories = 0;
    std::size_t mRetainedBytes = 0;
    std::size_t mWork = 0;
    dev_t mRootDevice = 0;
    bool mStarted = false;
    bool mFinalized = false;
    bool mRootExists = true;
    Optional<Error> mFailure;
    Optional<FilesystemCollectionEntry> mPendingEntry;
    Optional<std::string> mPendingDirectory;
    Optional<struct stat> mPendingMetadata;
};
} // namespace

namespace FTW
{
struct FileRange::State
{
    State(FilesystemCollectionRequest request, ContextInterface& context, bool legacy)
    {
        const auto resolved = ResolveFilesystemCollectionRequest(request);
        if (resolved.HasValue())
        {
            traversal.reset(new Traversal(resolved.Value(), context, false, legacy));
        }
        else
        {
            failure = resolved.Error();
        }
    }

    Optional<Error> failure;
    std::unique_ptr<Traversal> traversal;
};

Result<Optional<FilesystemCollectionEntry>> FileRange::Source::Next()
{
    return state->traversal->Next();
}

FileRange::FileRange(std::shared_ptr<State> state)
    : mState(std::move(state)),
      mView(Source{mState})
{
}

FileRange::~FileRange() = default;

Result<FileRange> Files(const FilesystemCollectionRequest& policy, ContextInterface& context)
{
    auto state = std::make_shared<FileRange::State>(policy, context, false);
    if (state->failure.HasValue())
    {
        return state->failure.Value();
    }
    const auto initialized = state->traversal->Initialize();
    if (!initialized.HasValue())
    {
        return initialized.Error();
    }
    return FileRange(std::move(state));
}

Result<Optional<FilesystemCollectionEntry>> FileRange::Next()
{
    return mView.Next();
}

Result<FilesystemCollectionResult> FileRange::StopVisitor()
{
    return mState->traversal->Stop();
}

void FileRange::Abort(const Error& error)
{
    mState->traversal->Abort(error);
}

bool FileRange::RootExists() const
{
    return mState->traversal->RootExists();
}

Result<bool> FileRange::Close()
{
    return mState->traversal->Close();
}

Result<bool> FileRange::RetainEntries()
{
    return mState->traversal->RetainEntries();
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
    for (const Result<FilesystemCollectionEntry>& entry : files)
    {
        if (!entry.HasValue())
        {
            return entry.Error();
        }
        const Result<FilesystemVisitAction> action = InvokeVisitor(visitor, entry.Value());
        if (!action.HasValue())
        {
            // Preserve the callback failure as primary; cleanup is best-effort.
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
            return Error("Invalid filesystem visitor action", EINVAL);
        }
    }
    return files.mState->traversal->CloseResult();
}

Result<FilesystemCollectionResult> CollectFilesystem(const FilesystemCollectionRequest& request, ContextInterface& context)
{
    auto opened = FTW::Files(request, context);
    if (!opened.HasValue())
    {
        return opened.Error();
    }
    auto& files = opened.Value();
    const auto retained = files.RetainEntries();
    if (!retained.HasValue())
    {
        files.Abort(retained.Error());
        return retained.Error();
    }
    for (const Result<FilesystemCollectionEntry>& entry : files)
    {
        if (!entry.HasValue())
        {
            return entry.Error();
        }
    }
    return files.mState->traversal->CloseResult();
}

namespace Detail
{
Result<FilesystemCollectionResult> StreamLegacyFileTreeWalk(const std::string& rootPath, const FilesystemCollectionVisitor& visitor, ContextInterface& context)
{
    FilesystemCollectionRequest request(rootPath, FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    request.maxDepth = -1;
    request.scope = FilesystemScope::All;
    if (!visitor)
    {
        return Error("Filesystem collection visitor must not be empty", EINVAL);
    }
    FTW::FileRange::State state(request, context, true);
    if (state.failure.HasValue())
    {
        return state.failure.Value();
    }
    for (;;)
    {
        const auto next = state.traversal->Next();
        if (!next.HasValue())
        {
            return next.Error();
        }
        if (!next.Value().HasValue())
        {
            return state.traversal->CloseResult();
        }
        const auto action = InvokeVisitor(visitor, next.Value().Value());
        if (!action.HasValue())
        {
            state.traversal->Abort(action.Error());
            return action.Error();
        }
        if (FilesystemVisitAction::Stop == action.Value())
        {
            return state.traversal->Stop();
        }
        if (FilesystemVisitAction::Continue != action.Value())
        {
            state.traversal->Abort(Error("Invalid filesystem visitor action", EINVAL));
            return Error("Invalid filesystem visitor action", EINVAL);
        }
    }
}
} // namespace Detail
} // namespace ComplianceEngine
