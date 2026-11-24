// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef KOMPLI_PROCEDURES_SYSCTL_VALUE_H
#define KOMPLI_PROCEDURES_SYSCTL_VALUE_H

#include <Evaluator.h>
#include <Optional.h>
#include <Pattern.h>

namespace Kompli
{
struct SysctlValueParams
{
    /// Name of the sysctl
    /// pattern: ^([a-zA-Z0-9_]+[\.a-zA-Z0-9_-]+)$
    std::string sysctlName;

    /// Regex that the value of sysctl has to match
    Pattern value;

    /// When true, only the runtime value in /proc/sys is checked (default: false)
    /// When false (default), also audits and remediates persistent sysctl configuration
    Optional<bool> runtimeOnly = false;
};

Result<Status> AuditSysctlValue(const SysctlValueParams& params, IndicatorsTree& indicators, ContextInterface& context);
Result<Status> RemediateSysctlValue(const SysctlValueParams& params, IndicatorsTree& indicators, ContextInterface& context);
} // namespace Kompli
#endif // KOMPLI_PROCEDURES_SYSCTL_VALUE_H
