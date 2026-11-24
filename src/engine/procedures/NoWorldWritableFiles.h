// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef KOMPLI_PROCEDURES_NO_WORLD_WRITABLE_FILES_H
#define KOMPLI_PROCEDURES_NO_WORLD_WRITABLE_FILES_H

#include <Evaluator.h>
namespace Kompli
{

Result<Status> AuditNoWorldWritableFiles(IndicatorsTree& indicators, ContextInterface& context);

} // namespace Kompli
#endif // KOMPLI_PROCEDURES_NO_WORLD_WRITABLE_FILES_H
