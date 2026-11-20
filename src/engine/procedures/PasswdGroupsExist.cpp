// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <Evaluator.h>
#include <GroupsIterator.h>
#include <PasswdGroupsExist.h>
#include <Result.h>
#include <UsersIterator.h>
#include <set>
#include <string>

namespace ComplianceEngine
{
Result<Status> AuditPasswdGroupsExist(IndicatorsTree& indicators, ContextInterface& context)
{
    // This rule checks local files, not NSS sources such as SSSD or systemd.
    auto groups = GroupsRange::Make(context.GetSpecialFilePath("/etc/group"), context.GetLogHandle());
    if (!groups.HasValue())
    {
        return groups.Error();
    }

    std::set<gid_t> etcGroupGroups;
    for (const auto& group : groups.Value())
    {
        etcGroupGroups.insert(group.gr_gid);
    }

    auto users = UsersRange::Make(context.GetSpecialFilePath("/etc/passwd"), context.GetLogHandle());
    if (!users.HasValue())
    {
        return users.Error();
    }

    Status result = Status::Compliant;
    for (const auto& user : users.Value())
    {
        if (etcGroupGroups.find(user.pw_gid) == etcGroupGroups.end())
        {
            result = indicators.NonCompliant(std::string("User's '") + std::string(user.pw_name) + "' group " + std::to_string(user.pw_gid) +
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
