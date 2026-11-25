// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef KOMPLI_PROCEDURES_LOG_FILE_PERMISSIONS_H
#define KOMPLI_PROCEDURES_LOG_FILE_PERMISSIONS_H

#include <Evaluator.h>

namespace Kompli
{
struct LogFilePermissionsParams
{
    /// Path to log directory to check, default /var/log
    Optional<std::string> path = std::string("/var/log");
};

Result<Status> AuditLogFilePermissions(const LogFilePermissionsParams& params, IndicatorsTree& indicators, ContextInterface& context);
Result<Status> RemediateLogFilePermissions(const LogFilePermissionsParams& params, IndicatorsTree& indicators, ContextInterface& context);
} // namespace Kompli
#endif // KOMPLI_PROCEDURES_LOG_FILE_PERMISSIONS_H
