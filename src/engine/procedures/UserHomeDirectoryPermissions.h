// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef KOMPLI_PROCEDURES_USER_HOME_DIRECTORY_PERMISSIONS_H
#define KOMPLI_PROCEDURES_USER_HOME_DIRECTORY_PERMISSIONS_H

#include <Evaluator.h>

namespace Kompli
{
Result<Status> AuditUserHomeDirectoryPermissions(IndicatorsTree& indicators, ContextInterface& context);
Result<Status> RemediateUserHomeDirectoryPermissions(IndicatorsTree& indicators, ContextInterface& context);
} // namespace Kompli
#endif // KOMPLI_PROCEDURES_USER_HOME_DIRECTORY_PERMISSIONS_H
