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
