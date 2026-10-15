// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_PROCEDURES_NAMESERVER_COUNT_H
#define COMPLIANCEENGINE_PROCEDURES_NAMESERVER_COUNT_H

#include <Evaluator.h>

namespace ComplianceEngine
{
struct NameserverCountParams
{
    /// Logical source path. Defaults to /etc/resolv.conf.
    /// pattern: ^/.*$
    Optional<std::string> path = std::string("/etc/resolv.conf");
};

Result<Status> AuditNameserverCount(const NameserverCountParams& params, IndicatorsTree& indicators, ContextInterface& context);
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_PROCEDURES_NAMESERVER_COUNT_H
