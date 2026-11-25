// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef KOMPLI_PROCEDURES_NO_UNOWNED_FILES_H
#define KOMPLI_PROCEDURES_NO_UNOWNED_FILES_H

#include <Evaluator.h>

namespace Kompli
{
Result<Status> AuditNoUnownedFiles(IndicatorsTree& indicators, ContextInterface& context);
} // namespace Kompli
#endif // KOMPLI_PROCEDURES_NO_UNOWNED_FILES_H
