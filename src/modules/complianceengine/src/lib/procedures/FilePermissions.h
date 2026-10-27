// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_PROCEDURES_FILE_PERMISSIONS_H
#define COMPLIANCEENGINE_PROCEDURES_FILE_PERMISSIONS_H

#include <Behavior.h>
#include <Evaluator.h>
#include <Pattern.h>
#include <Separated.h>
#include <cstddef>
#include <sys/types.h>

namespace ComplianceEngine
{
struct FilePermissionsParams
{
    /// Path to the file
    std::string path;

    /// Required owner of the file, single or | separated, first one is used for remediation
    Optional<Separated<Pattern, '|'>> owner;

    /// Required group of the file, single or | separated, first one is used for remediation
    Optional<Separated<Pattern, '|'>> group;

    /// Expected numeric group ID
    Optional<int> groupId;

    /// Required octal permissions of the file
    /// pattern: ^[0-7]{3,4}$
    Optional<mode_t> permissions;

    /// Required octal permissions of the file - mask
    /// pattern: ^[0-7]{3,4}$
    Optional<mode_t> mask;

    /// Behavior when checking file existence
    Optional<Behavior> behavior = Behavior::AtLeastOneExists;
};

Result<Status> AuditFilePermissions(const FilePermissionsParams& params, IndicatorsTree& indicators, ContextInterface& context);
Result<Status> RemediateFilePermissions(const FilePermissionsParams& params, IndicatorsTree& indicators, ContextInterface& context);
// Historical observation for compatibility with callers still using path
// remediation. Comparison detects a different inode at reopen time, but does
// not preserve the collector's pin or provide atomic namespace confinement.
struct FileIdentity
{
    dev_t device;
    ino_t inode;
};

// Equivalent to RemediateFilePermissions, but refuses to change ownership or mode unless the
// resolved target's device/inode and link count match expectedIdentity. Intended for callers that
// already observed the target via a separate traversal. Pinned collection
// callers instead use EnforcePinnedFilePermissions below.
Result<Status> EnforceFilePermissionsAtIdentity(const FilePermissionsParams& params, const FileIdentity& expectedIdentity, IndicatorsTree& indicators,
    ContextInterface& context);

struct FilePermissionsCollectionParams
{
    /// Directory path
    std::string directory;

    /// Whether to recurse
    Optional<bool> recurse = true;

    Optional<bool> directoriesOnly = false;

    Optional<bool> allFileTypes = false;

    Optional<bool> excludeSymlinks = false;

    Optional<bool> excludeDirectories = false;

    Optional<int> maximumUid;

    Optional<int> maximumGid;

    /// File pattern
    std::string filePattern;

    Optional<bool> filePatternIsRegex = false;

    /// Required owner of the file, single or | separated, first one is used for remediation
    Optional<Separated<Pattern, '|'>> owner;

    /// Required group of the file, single or | separated, first one is used for remediation
    Optional<Separated<Pattern, '|'>> group;

    /// Expected numeric group ID
    Optional<int> groupId;

    /// Required octal permissions of the file
    /// pattern: ^[0-7]{3,4}$
    Optional<mode_t> permissions;

    /// Required octal permissions of the file - mask
    /// pattern: ^[0-7]{3,4}$
    Optional<mode_t> mask;

    /// Behavior when checking file existence
    Optional<Behavior> behavior = Behavior::AtLeastOneExists;
};

Result<Status> AuditFilePermissionsCollection(const FilePermissionsCollectionParams& params, IndicatorsTree& indicators, ContextInterface& context);
Result<Status> RemediateFilePermissionsCollection(const FilePermissionsCollectionParams& params, IndicatorsTree& indicators, ContextInterface& context);

namespace Filesystem
{
class Handle;
}

// Synchronous borrow: the caller keeps the acquired regular-file pin live
// throughout inspection/mutation. path is diagnostic only, never reopened.
// requireUnique retains the dotfile rule's fresh hard-link safeguard.
Result<Status> CheckPinnedFilePermissions(const FilePermissionsParams& params, const Filesystem::Handle& handle, std::size_t fdinfoByteCap,
    IndicatorsTree& indicators, ContextInterface& context);
Result<Status> EnforcePinnedFilePermissions(const FilePermissionsParams& params, const Filesystem::Handle& handle, std::size_t fdinfoByteCap,
    bool requireUnique, IndicatorsTree& indicators, ContextInterface& context);
} // namespace ComplianceEngine
#endif // COMPLIANCEENGINE_PROCEDURES_FILE_PERMISSIONS_H
