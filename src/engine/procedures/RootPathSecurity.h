// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef KOMPLI_PROCEDURES_ROOT_PATH_SECURITY_H
#define KOMPLI_PROCEDURES_ROOT_PATH_SECURITY_H

#include <Evaluator.h>

namespace Kompli
{
Result<Status> AuditRootPathSecurity(IndicatorsTree& indicators, ContextInterface& context);
} // namespace Kompli
#endif // KOMPLI_PROCEDURES_ROOT_PATH_SECURITY_H
