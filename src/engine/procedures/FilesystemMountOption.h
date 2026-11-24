// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef KOMPLI_PROCEDURES_FILESYSTEM_MOUNT_OPTION_H
#define KOMPLI_PROCEDURES_FILESYSTEM_MOUNT_OPTION_H

#include <Evaluator.h>
#include <Separated.h>

namespace Kompli
{
struct FilesystemMountOptionParams
{
    /// Filesystem mount point
    std::string mountpoint;

    /// Treat mountpoint as a regular expression and audit every matching mounted filesystem; remediation is not supported in this mode
    Optional<bool> mountpointIsPattern = false;

    /// Fail the audit when no mounted filesystem matches mountpoint; otherwise a missing mount is compliant
    Optional<bool> requireMountpoint = false;

    /// Comma-separated list of options that must be set
    Optional<Separated<std::string, ','>> optionsSet;

    /// Comma-separated list of options that must not be set
    Optional<Separated<std::string, ','>> optionsNotSet;
};

Result<Status> AuditFilesystemMountOption(const FilesystemMountOptionParams& params, IndicatorsTree& indicators, ContextInterface& context);
Result<Status> RemediateFilesystemMountOption(const FilesystemMountOptionParams& params, IndicatorsTree& indicators, ContextInterface& context);
} // namespace Kompli
#endif // KOMPLI_PROCEDURES_FILESYSTEM_MOUNT_OPTION_H
