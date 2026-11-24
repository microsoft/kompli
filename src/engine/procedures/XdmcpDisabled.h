// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef KOMPLI_PROCEDURES_XDMCP_DISABLED_H
#define KOMPLI_PROCEDURES_XDMCP_DISABLED_H

#include <Evaluator.h>

namespace Kompli
{
Result<Status> AuditXdmcpDisabled(IndicatorsTree& indicators, ContextInterface& context);
Result<Status> RemediateXdmcpDisabled(IndicatorsTree& indicators, ContextInterface& context);
} // namespace Kompli
#endif // KOMPLI_PROCEDURES_XDMCP_DISABLED_H
