// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef KOMPLI_PROCEDURES_PASSWORD_CHANGE_DATE_H
#define KOMPLI_PROCEDURES_PASSWORD_CHANGE_DATE_H

#include <Evaluator.h>

namespace Kompli
{
Result<Status> AuditPasswordChangeDate(IndicatorsTree& indicators, ContextInterface& context);
} // namespace Kompli
#endif // KOMPLI_PROCEDURES_PASSWORD_CHANGE_DATE_H
