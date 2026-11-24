// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef KOMPLI_PROCEDURES_FIREWALLD_ZONE_TARGETS_H
#define KOMPLI_PROCEDURES_FIREWALLD_ZONE_TARGETS_H

#include <Evaluator.h>

namespace Kompli
{
Result<Status> AuditFirewalldZoneTargets(IndicatorsTree& indicators, ContextInterface& context);
} // namespace Kompli
#endif // KOMPLI_PROCEDURES_FIREWALLD_ZONE_TARGETS_H
