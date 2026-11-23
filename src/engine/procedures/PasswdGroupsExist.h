// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_PROCEDURES_PASSWD_GROUPS_EXIST_H
#define COMPLIANCEENGINE_PROCEDURES_PASSWD_GROUPS_EXIST_H

#include <Evaluator.h>
#include <functional>
#include <grp.h>
#include <pwd.h>

namespace ComplianceEngine
{
// Testable core of AuditPasswdGroupsExist, parameterized over the set*ent/get*ent/end*ent
// primitives. Each `next*` callable follows getgrent()/getpwent(): it is called with errno reset to
// 0, and a nullptr return with errno 0 or ENOENT ends enumeration; any other errno is an error.
Result<Status> EvaluatePasswdGroupsExist(IndicatorsTree& indicators, const std::function<void()>& beginGroups,
    const std::function<struct group*()>& nextGroup, const std::function<void()>& endGroups, const std::function<void()>& beginUsers,
    const std::function<struct passwd*()>& nextUser, const std::function<void()>& endUsers);

Result<Status> AuditPasswdGroupsExist(IndicatorsTree& indicators, ContextInterface& context);
Result<Status> RemediatePasswdGroupsExist(IndicatorsTree& indicators, ContextInterface& context);
} // namespace ComplianceEngine
#endif // COMPLIANCEENGINE_PROCEDURES_PASSWD_GROUPS_EXIST_H
