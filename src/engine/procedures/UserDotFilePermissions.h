// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef KOMPLI_PROCEDURES_USER_DOT_FILE_PERMISSIONS_H
#define KOMPLI_PROCEDURES_USER_DOT_FILE_PERMISSIONS_H

#include <Evaluator.h>

namespace Kompli
{
Result<Status> AuditUserDotFilePermissions(IndicatorsTree& indicators, ContextInterface& context);
Result<Status> RemediateUserDotFilePermissions(IndicatorsTree& indicators, ContextInterface& context);
} // namespace Kompli
#endif // KOMPLI_PROCEDURES_USER_DOT_FILE_PERMISSIONS_H
