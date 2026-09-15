// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <CommonUtils.h>
#include <Evaluator.h>
#include <NoShadowPrimaryGroup.h>
#include <Result.h>

namespace ComplianceEngine
{
Result<Status> AuditNoShadowPrimaryGroup(IndicatorsTree& indicators, ContextInterface& context)
{
    auto shadow = context.GetAccountDatabase().FindGroupByName("shadow");
    if (!shadow.HasValue())
    {
        return shadow.Error();
    }
    if (nullptr == shadow.Value())
    {
        return Error("Group 'shadow' not found", EINVAL);
    }

    auto users = context.GetAccountDatabase().GetUsers();
    if (!users.HasValue())
    {
        return users.Error();
    }

    for (const auto& user : *users.Value())
    {
        if (shadow.Value()->gid == user.gid)
        {
            return indicators.NonCompliant("User's '" + user.name + "' primary group is 'shadow'");
        }
    }

    return indicators.Compliant("No user has 'shadow' as primary group");
}

} // namespace ComplianceEngine
