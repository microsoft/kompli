// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_FILESYSTEM_COLLECTION_HPP
#define COMPLIANCEENGINE_FILESYSTEM_COLLECTION_HPP

#include "ContextInterface.h"
#include "Optional.h"
#include "Result.h"
#include "ranges/View.hpp"

#include <cstddef>
#include <functional>
#include <memory>
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

// Select observations independently of directory traversal and link handling.
enum class FilesystemYieldType
{
    All,
    RegularFiles,
    Directories,
    SymbolicLinks,
};

enum class FilesystemDepthAction
{
    Stop,
    Error,
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
    Optional<FilesystemYieldType> yieldType;
    Optional<FilesystemDepthAction> depthAction;
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
    FilesystemYieldType yieldType = FilesystemYieldType::All;
    FilesystemDepthAction depthAction = FilesystemDepthAction::Stop;
    FilesystemCollectionLimits limits;
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
    std::vector<FilesystemCollectionEntry> entries;
    std::vector<FilesystemCollectionExclusion> exclusions;
};

using FilesystemCollectionVisitor = std::function<Result<FilesystemVisitAction>(const FilesystemCollectionEntry&)>;

Result<ResolvedFilesystemCollectionRequest> ResolveFilesystemCollectionRequest(const FilesystemCollectionRequest& request);
Result<FilesystemCollectionResult> StreamFilesystemCollection(const FilesystemCollectionRequest& request, const FilesystemCollectionVisitor& visitor,
    ContextInterface& context);
Result<FilesystemCollectionResult> CollectFilesystem(const FilesystemCollectionRequest& request, ContextInterface& context);

namespace FTW
{
// Single-pass live filesystem range. Files() validates policy and acquires the
// root before returning it; descendants are pulled lazily. Context must
// outlive the range. Abandoned ranges clean up best-effort without certifying
// the observations already yielded.
class FileRange
{
public:
    struct State;
    struct Source
    {
        using value_type = FilesystemCollectionEntry;
        std::shared_ptr<State> state;
        Result<Optional<value_type>> Next();
    };
    FileRange(const FileRange&) = delete;
    FileRange& operator=(const FileRange&) = delete;
    FileRange(FileRange&&) = default;
    FileRange& operator=(FileRange&&) = default;
    ~FileRange();

    Result<Optional<FilesystemCollectionEntry>> Next();
    // Checked, idempotent cleanup without draining unseen entries.
    Result<bool> Close();
    // False only when the requested root was missing during initial lookup.
    bool RootExists() const;

    using Iterator = Ranges::View<Source>::Iterator;
    Iterator begin() // NOLINT(*-identifier-naming)
    {
        return mView.begin();
    }
    Iterator end() // NOLINT(*-identifier-naming)
    {
        return mView.end();
    }

private:
    friend Result<FileRange> Files(const FilesystemCollectionRequest&, ContextInterface&);
    friend auto ::ComplianceEngine::CollectFilesystem(const FilesystemCollectionRequest&, ContextInterface&) -> Result<FilesystemCollectionResult>;
    friend auto ::ComplianceEngine::StreamFilesystemCollection(const FilesystemCollectionRequest&, const FilesystemCollectionVisitor&, ContextInterface&)
        -> Result<FilesystemCollectionResult>;
    explicit FileRange(std::shared_ptr<State> state);
    Result<FilesystemCollectionResult> StopVisitor();
    void Abort(const Error& error);
    std::shared_ptr<State> mState;
    Ranges::View<Source> mView;
    Result<bool> RetainEntries();
};

// A missing root is a successful empty range with RootExists() == false.
Result<FileRange> Files(const FilesystemCollectionRequest& policy, ContextInterface& context);
} // namespace FTW

namespace Detail
{
Result<FilesystemCollectionResult> StreamLegacyFileTreeWalk(const std::string& rootPath, const FilesystemCollectionVisitor& visitor, ContextInterface& context);
} // namespace Detail
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_FILESYSTEM_COLLECTION_HPP
