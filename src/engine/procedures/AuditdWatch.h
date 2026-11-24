// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_PROCEDURES_AUDITD_WATCH_H
#define COMPLIANCEENGINE_PROCEDURES_AUDITD_WATCH_H

#include <Evaluator.h>

namespace ComplianceEngine
{
struct AuditdWatchParams
{
    /// Existing absolute file or directory to watch; shell syntax and traversal are not accepted.
    std::string path;

    /// Explicit nonempty subset of audit watch permissions in rwxa order.
    /// pattern: ^(r|r?w|r?w?x|r?w?x?a)$
    std::string permissions;
};

Result<Status> AuditAuditdWatch(const AuditdWatchParams& params, IndicatorsTree& indicators, ContextInterface& context);
Result<Status> RemediateAuditdWatch(const AuditdWatchParams& params, IndicatorsTree& indicators, ContextInterface& context);
} // namespace ComplianceEngine
#endif // COMPLIANCEENGINE_PROCEDURES_AUDITD_WATCH_H
