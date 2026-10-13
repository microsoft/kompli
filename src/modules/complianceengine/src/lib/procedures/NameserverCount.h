// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_PROCEDURES_NAMESERVER_COUNT_H
#define COMPLIANCEENGINE_PROCEDURES_NAMESERVER_COUNT_H

#include <Evaluator.h>

namespace ComplianceEngine
{
struct NameserverCountParams
{
    /// Logical source path. Only /etc/resolv.conf is supported.
    /// pattern: ^/etc/resolv[.]conf$
    std::string path;
};

Result<Status> AuditNameserverCount(const NameserverCountParams& params, IndicatorsTree& indicators, ContextInterface& context);
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_PROCEDURES_NAMESERVER_COUNT_H
