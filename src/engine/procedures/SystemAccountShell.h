// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef KOMPLI_PROCEDURES_SYSTEM_ACCOUNT_SHELL_H
#define KOMPLI_PROCEDURES_SYSTEM_ACCOUNT_SHELL_H

#include <BindingParsers.h>
#include <Evaluator.h>

namespace Kompli
{
Result<Status> AuditSystemAccountShell(IndicatorsTree& indicators, ContextInterface& context);
} // namespace Kompli
#endif // KOMPLI_PROCEDURES_SYSTEM_ACCOUNT_SHELL_H
