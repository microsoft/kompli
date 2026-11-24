// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef KOMPLI_PROCEDURES_PASSWD_GROUPS_EXIST_H
#define KOMPLI_PROCEDURES_PASSWD_GROUPS_EXIST_H

#include <Evaluator.h>

namespace Kompli
{
Result<Status> AuditPasswdGroupsExist(IndicatorsTree& indicators, ContextInterface& context);
Result<Status> RemediatePasswdGroupsExist(IndicatorsTree& indicators, ContextInterface& context);
} // namespace Kompli
#endif // KOMPLI_PROCEDURES_PASSWD_GROUPS_EXIST_H
