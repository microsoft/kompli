// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef KOMPLI_PROCEDURES_NO_SHADOW_PRIMARY_GROUP_H
#define KOMPLI_PROCEDURES_NO_SHADOW_PRIMARY_GROUP_H

#include <Evaluator.h>

namespace Kompli
{
Result<Status> AuditNoShadowPrimaryGroup(IndicatorsTree& indicators, ContextInterface& context);
} // namespace Kompli
#endif // KOMPLI_PROCEDURES_NO_SHADOW_PRIMARY_GROUP_H
