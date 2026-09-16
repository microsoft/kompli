// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <CommonUtils.h>
#include <UniqueUserId.h>
#include <shadow.h>
#include <vector>

using std::map;
using std::string;
using std::vector;

namespace ComplianceEngine
{
Result<Status> AuditUniqueUserId(const UniqueUserIdParams& params, IndicatorsTree& indicators, ContextInterface& context)
{
    bool hasUid = false;
    bool hasGid = false;

    auto users = context.GetAccountDatabase().GetUsers();
    if (!users.HasValue())
    {
        return users.Error();
    }

    for (const auto& item : *users.Value())
    {
        if (params.uid.HasValue() && item.uid == static_cast<decltype(item.uid)>(params.uid.Value()))
        {
            if (item.name != params.username)
            {
                OsConfigLogDebug(context.GetLogHandle(), "User '%s' has UID %d, but expected '%s'.", item.name.c_str(), item.uid, params.username.c_str());
                return indicators.NonCompliant("A user other than '" + params.username + "' has UID " + std::to_string(item.uid));
            }

            hasUid = true;
        }

        if (params.gid.HasValue() && item.gid == static_cast<decltype(item.uid)>(params.gid.Value()))
        {
            if (item.name != params.username)
            {
                OsConfigLogDebug(context.GetLogHandle(), "User '%s' has GID %d, but expected '%s'.", item.name.c_str(), item.gid, params.username.c_str());
                return indicators.NonCompliant("A user other than '" + params.username + "' has GID " + std::to_string(item.gid));
            }

            hasGid = true;
        }
    }

    if (params.uid.HasValue() && !hasUid)
    {
        OsConfigLogDebug(context.GetLogHandle(), "No user with UID %d found.", params.uid.Value());
        return indicators.NonCompliant("No user with UID " + std::to_string(params.uid.Value()) + " found");
    }

    if (params.gid.HasValue() && !hasGid)
    {
        OsConfigLogDebug(context.GetLogHandle(), "No user with GID %d found.", params.gid.Value());
        return indicators.NonCompliant("No user with GID " + std::to_string(params.gid.Value()) + " found");
    }

    return indicators.Compliant("All criteria has been met for user '" + params.username + "'");
}
} // namespace ComplianceEngine
