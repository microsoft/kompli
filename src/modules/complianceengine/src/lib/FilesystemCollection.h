// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_FILESYSTEM_COLLECTION_H
#define COMPLIANCEENGINE_FILESYSTEM_COLLECTION_H

#include "Logging.h"
#include "Optional.h"
#include "Result.h"

#include <cstddef>
#include <dirent.h>
#include <functional>
#include <string>
#include <sys/stat.h>
#include <utility>
#include <vector>

namespace ComplianceEngine
{
enum class FilesystemRootKind
{
    File,
    Directory,
};

enum class FilesystemDirection
{
    None,
    Down,
    Up,
};

enum class FilesystemLinkAction
{
    Record,
    Follow,
    Exclude,
};

enum class FilesystemScope
{
    RootDevice,
    All,
    Local,
    Defined,
};

struct FilesystemCollectionLimits
{
    std::size_t operationalDescent = 128;
    std::size_t entryWork = 100000;
    std::size_t directoryWidth = 4096;
    std::size_t fullPathBytes = 4096;
    std::size_t retainedPathBytes = 32 * 1024 * 1024;
    std::size_t openDirectories = 16;
};

struct FilesystemCollectionRequest
{
    FilesystemCollectionRequest(std::string rootPath, FilesystemRootKind rootKind)
        : rootPath(std::move(rootPath)),
          rootKind(rootKind)
    {
    }

    std::string rootPath;
    FilesystemRootKind rootKind;
    Optional<FilesystemDirection> direction;
    Optional<int> maxDepth;
    Optional<FilesystemLinkAction> rootFileLinkAction;
    Optional<FilesystemLinkAction> rootDirectoryLinkAction;
    Optional<FilesystemLinkAction> childFileLinkAction;
    Optional<FilesystemLinkAction> childDirectoryLinkAction;
    Optional<FilesystemScope> scope;
    Optional<long long> operationalDescent;
    Optional<long long> entryWork;
    Optional<long long> directoryWidth;
    Optional<long long> fullPathBytes;
    Optional<long long> retainedPathBytes;
    Optional<long long> openDirectories;
};

struct ResolvedFilesystemCollectionRequest
{
    std::string rootPath;
    FilesystemRootKind rootKind = FilesystemRootKind::File;
    FilesystemDirection direction = FilesystemDirection::None;
    int maxDepth = 32;
    FilesystemLinkAction rootFileLinkAction = FilesystemLinkAction::Record;
    FilesystemLinkAction rootDirectoryLinkAction = FilesystemLinkAction::Record;
    FilesystemLinkAction childFileLinkAction = FilesystemLinkAction::Record;
    FilesystemLinkAction childDirectoryLinkAction = FilesystemLinkAction::Record;
    FilesystemScope scope = FilesystemScope::RootDevice;
    FilesystemCollectionLimits limits;
};

enum class FilesystemCollectionOutcome
{
    Complete,
    Absent,
    Stopped,
};

enum class FilesystemVisitAction
{
    Continue,
    Stop,
};

struct FilesystemCollectionEntry
{
    std::string path;
    struct stat linkMetadata = {};
    Optional<struct stat> targetMetadata;
};

struct FilesystemCollectionExclusion
{
    std::string path;
    std::string reason;
};

struct FilesystemCollectionResult
{
    FilesystemCollectionOutcome outcome = FilesystemCollectionOutcome::Complete;
    std::vector<FilesystemCollectionEntry> entries;
    std::vector<FilesystemCollectionExclusion> exclusions;
    std::string stopReason;
};

using FilesystemCollectionVisitor = std::function<Result<FilesystemVisitAction>(const FilesystemCollectionEntry&)>;

Result<ResolvedFilesystemCollectionRequest> ResolveFilesystemCollectionRequest(const FilesystemCollectionRequest& request);
Result<FilesystemCollectionResult> StreamFilesystemCollection(const FilesystemCollectionRequest& request, const FilesystemCollectionVisitor& visitor,
    OsConfigLogHandle log = nullptr);
Result<FilesystemCollectionResult> CollectFilesystem(const FilesystemCollectionRequest& request, OsConfigLogHandle log = nullptr);

namespace Detail
{
struct FilesystemCollectionOperations
{
    std::function<DIR*(const char*)> openDirectory = ::opendir;
    std::function<struct dirent*(DIR*)> readDirectory = ::readdir;
    std::function<int(DIR*)> closeDirectory = ::closedir;
    std::function<int(const char*, struct stat*)> statPath = ::stat;
    std::function<int(const char*, struct stat*)> lstatPath = ::lstat;
    std::function<int(int, struct stat*)> statDescriptor = ::fstat;
};

Result<FilesystemCollectionResult> StreamFilesystemCollectionWithOperations(const FilesystemCollectionRequest& request,
    const FilesystemCollectionVisitor& visitor, const FilesystemCollectionOperations& operations, OsConfigLogHandle log = nullptr);
Result<FilesystemCollectionResult> CollectFilesystemWithOperations(const FilesystemCollectionRequest& request,
    const FilesystemCollectionOperations& operations, OsConfigLogHandle log = nullptr);
} // namespace Detail
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_FILESYSTEM_COLLECTION_H
