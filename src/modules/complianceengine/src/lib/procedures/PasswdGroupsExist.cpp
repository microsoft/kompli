// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <CommonUtils.h>
#include <Evaluator.h>
#include <PasswdGroupsExist.h>
#include <Result.h>
#include <set>
#include <string>

namespace ComplianceEngine
{
Result<Status> AuditPasswdGroupsExist(IndicatorsTree& indicators, ContextInterface& context)
{
    std::set<gid_t> groupIds;
    auto groups = context.GetAccountDatabase().GetGroups();
    if (!groups.HasValue())
    {
        return groups.Error();
    }
    for (const auto& group : *groups.Value())
    {
        groupIds.insert(group.gid);
    }

    auto users = context.GetAccountDatabase().GetUsers();
    if (!users.HasValue())
    {
        return users.Error();
    }
    Status result = Status::Compliant;
    for (const auto& user : *users.Value())
    {
        if (groupIds.find(user.gid) == groupIds.end())
        {
            result = indicators.NonCompliant("User's '" + user.name + "' group " + std::to_string(user.gid) +
                                             " from /etc/passwd does not exist in /etc/group");
        }
    }

    if (result == Status::Compliant)
    {
        indicators.Compliant("All user groups from '/etc/passwd' exist in '/etc/group'");
    }
    return result;
}

Result<Status> RemediatePasswdGroupsExist(IndicatorsTree& indicators, ContextInterface& context)
{
    auto result = AuditPasswdGroupsExist(indicators, context);
    if (!result.HasValue())
    {
        return result.Error();
    }
    if (result.Value() == Status::Compliant)
    {
        return indicators.Compliant("Audit passed, remediation not required");
    }

    return indicators.NonCompliant("Manual remediation is required to ensure all groups from /etc/passwd exist in /etc/group");
}
} // namespace ComplianceEngine
