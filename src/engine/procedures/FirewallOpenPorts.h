// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef KOMPLI_PROCEDURES_FIREWALL_OPEN_PORTS_H
#define KOMPLI_PROCEDURES_FIREWALL_OPEN_PORTS_H

#include <Evaluator.h>

namespace Kompli
{
Result<Status> AuditIptablesOpenPorts(IndicatorsTree& indicators, ContextInterface& context);
Result<Status> AuditIp6tablesOpenPorts(IndicatorsTree& indicators, ContextInterface& context);
Result<Status> AuditUfwOpenPorts(IndicatorsTree& indicators, ContextInterface& context);
} // namespace Kompli
#endif // KOMPLI_PROCEDURES_FIREWALL_OPEN_PORTS_H
