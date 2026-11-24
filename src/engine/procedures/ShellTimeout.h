// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef KOMPLI_PROCEDURES_SHELL_TIMEOUT_H
#define KOMPLI_PROCEDURES_SHELL_TIMEOUT_H

#include <Evaluator.h>

namespace Kompli
{
Result<Status> AuditShellTimeout(IndicatorsTree& indicators, ContextInterface& context);
Result<Status> RemediateShellTimeout(IndicatorsTree& indicators, ContextInterface& context);
} // namespace Kompli

#endif // KOMPLI_PROCEDURES_SHELL_TIMEOUT_H
