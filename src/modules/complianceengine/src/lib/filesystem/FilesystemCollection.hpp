// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_FILESYSTEM_COLLECTION_HPP
#define COMPLIANCEENGINE_FILESYSTEM_COLLECTION_HPP

#include "ContextInterface.h"
#include "Optional.h"
#include "Result.h"
#include "filesystem/FilesystemPolicy.hpp"
#include "filesystem/Path.hpp"
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
namespace Filesystem
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
    // Collection-owned observation path strings retained in pending/result
    // entries, traversal frames and exclusions (including their NUL bytes).
    // Not a total-memory limit: the resolver separately applies its broader
    // retainedBytes accounting using this value; the request root, yielded
    // caller-owned entries, objects, metadata and allocator capacity are not
    // charged to the collection's observation-path counter.
    std::size_t retainedPathBytes = 32 * 1024 * 1024;
    // Must retain every active ancestor pin and cursor without pathname replay.
    std::size_t openDirectories = 16;
};

enum class FilesystemMissingChildAction
{
    Error,
    ReportRegularFile,
};

struct FilesystemCollectionRequest
{
    FilesystemCollectionRequest(std::string rootPath, FilesystemRootKind rootKind)
        : rootPath(std::move(rootPath)),
          rootKind(rootKind)
    {
    }

    // Acquisition root must be absolute, nonempty and contain no NUL.
    // Invalid roots fail with EINVAL before any filesystem lookup.
    std::string rootPath;
    FilesystemRootKind rootKind;
    FilesystemDirection direction = FilesystemDirection::None;
    int maxDepth = 32;
    // DoNotFollow excludes links with their path and reason; Follow uses target metadata.
    SymlinkFollowing rootFileLinkAction = SymlinkFollowing::DoNotFollow;
    SymlinkFollowing rootDirectoryLinkAction = SymlinkFollowing::DoNotFollow;
    SymlinkFollowing childFileLinkAction = SymlinkFollowing::DoNotFollow;
    SymlinkFollowing childDirectoryLinkAction = SymlinkFollowing::DoNotFollow;
    FilesystemScope scope = FilesystemScope::RootDevice;
    FilesystemYieldType yieldType = FilesystemYieldType::All;
    FilesystemDepthAction depthAction = FilesystemDepthAction::Stop;
    // A vanished name hinted DT_REG by the pinned directory enumeration may
    // be reported without metadata or a handle. DT_UNKNOWN still fails.
    FilesystemMissingChildAction missingChildAction = FilesystemMissingChildAction::Error;
    long long operationalDescent = FilesystemCollectionLimits{}.operationalDescent;
    long long entryWork = FilesystemCollectionLimits{}.entryWork;
    long long directoryWidth = FilesystemCollectionLimits{}.directoryWidth;
    long long fullPathBytes = FilesystemCollectionLimits{}.fullPathBytes;
    long long retainedPathBytes = FilesystemCollectionLimits{}.retainedPathBytes;
    long long openDirectories = FilesystemCollectionLimits{}.openDirectories;
};

struct ResolvedFilesystemCollectionRequest
{
    std::string rootPath;
    FilesystemRootKind rootKind = FilesystemRootKind::File;
    FilesystemDirection direction = FilesystemDirection::None;
    int maxDepth = 32;
    SymlinkFollowing rootFileLinkAction = SymlinkFollowing::DoNotFollow;
    SymlinkFollowing rootDirectoryLinkAction = SymlinkFollowing::DoNotFollow;
    SymlinkFollowing childFileLinkAction = SymlinkFollowing::DoNotFollow;
    SymlinkFollowing childDirectoryLinkAction = SymlinkFollowing::DoNotFollow;
    FilesystemScope scope = FilesystemScope::RootDevice;
    FilesystemYieldType yieldType = FilesystemYieldType::All;
    FilesystemDepthAction depthAction = FilesystemDepthAction::Stop;
    FilesystemMissingChildAction missingChildAction = FilesystemMissingChildAction::Error;
    FilesystemCollectionLimits limits;
};

enum class FilesystemVisitAction
{
    Continue,
    Stop,
};

struct FilesystemCollectionEntry
{
    FilesystemCollectionEntry() = default;
    FilesystemCollectionEntry(FilesystemCollectionEntry&&) = default;
    FilesystemCollectionEntry& operator=(FilesystemCollectionEntry&&) = default;
    FilesystemCollectionEntry(const FilesystemCollectionEntry&) = delete;
    FilesystemCollectionEntry& operator=(const FilesystemCollectionEntry&) = delete;
    std::string path;
    struct stat linkMetadata = {};
    Optional<struct stat> targetMetadata;
    // A regular-file name observed in readdir but lost before acquisition;
    // this is not a stat snapshot, file identity, or mutation authority.
    bool missing = false;
    // Live pin for a regular file or directory only. A directory pin borrows
    // from the range and expires at its next advancement or Close(); a
    // regular-file pin is owned by this entry and can outlive the range.
    // Snapshot adapters deliberately leave both empty. Paths/stat snapshots
    // are never mutation authority.
    const Handle* LiveHandle() const noexcept
    {
        return mOwnedHandle.HasValue() ? &mOwnedHandle.Value() : mBorrowedHandle;
    }
    void OwnHandle(Handle handle)
    {
        mOwnedHandle = std::move(handle);
    }
    void BorrowHandle(const Handle& handle) noexcept
    {
        mBorrowedHandle = &handle;
    }
    // Checked release is only for a pin not yet transferred to a caller.
    bool OwnsHandle() const noexcept
    {
        return mOwnedHandle.HasValue();
    }
    Result<bool> CloseHandle()
    {
        return mOwnedHandle.Value().Close();
    }

private:
    Optional<Handle> mOwnedHandle;
    const Handle* mBorrowedHandle = nullptr;
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
private:
    struct State;
    struct Source
    {
        using value_type = FilesystemCollectionEntry;
        std::shared_ptr<State> state;
        Result<Optional<value_type>> Next();
    };

public:
    FileRange(const FileRange&) = delete;
    FileRange& operator=(const FileRange&) = delete;
    FileRange(FileRange&&) = default;
    FileRange& operator=(FileRange&&) = default;
    ~FileRange();

    // Checked, idempotent cleanup of all still-owned pins and cursors without
    // draining unseen entries. Yielded regular-file entries own their pins;
    // borrowed directory pins expire on Close. Failed closes are not retried.
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
    friend auto ::ComplianceEngine::Filesystem::CollectFilesystem(const FilesystemCollectionRequest&, ContextInterface&) -> Result<FilesystemCollectionResult>;
    friend auto ::ComplianceEngine::Filesystem::StreamFilesystemCollection(const FilesystemCollectionRequest&, const FilesystemCollectionVisitor&,
        ContextInterface&) -> Result<FilesystemCollectionResult>;
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

} // namespace Filesystem
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_FILESYSTEM_COLLECTION_HPP
