// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef KOMPLI_PROCEDURES_NAMESERVER_COUNT_H
#define KOMPLI_PROCEDURES_NAMESERVER_COUNT_H

#include <Evaluator.h>

namespace Kompli
{
struct NameserverCountParams
{
    /// Logical source path. Defaults to /etc/resolv.conf.
    /// pattern: ^/.*$
    Optional<std::string> path = std::string("/etc/resolv.conf");
};

Result<Status> AuditNameserverCount(const NameserverCountParams& params, IndicatorsTree& indicators, ContextInterface& context);
} // namespace Kompli

#endif // KOMPLI_PROCEDURES_NAMESERVER_COUNT_H
