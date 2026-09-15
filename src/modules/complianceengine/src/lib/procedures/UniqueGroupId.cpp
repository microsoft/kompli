// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <CommonUtils.h>
#include <Evaluator.h>
#include <StringTools.h>
#include <UniqueGroupId.h>
#include <vector>

using std::map;
using std::string;
using std::vector;

namespace ComplianceEngine
{
Result<Status> AuditUniqueGroupId(const UniqueGroupIdParams& params, IndicatorsTree& indicators, ContextInterface& context)
{
    bool hasGid = false;

    auto groups = context.GetAccountDatabase().GetGroups();
    if (!groups.HasValue())
    {
        return groups.Error();
    }

    for (const auto& item : *groups.Value())
    {
        if (params.gid.HasValue() && item.gid == static_cast<decltype(item.gid)>(params.gid.Value()))
        {
            if (item.name != params.groupName)
            {
                OsConfigLogDebug(context.GetLogHandle(), "Group '%s' has GID %d, but expected '%s'.", item.name.c_str(), item.gid, params.groupName.c_str());
                return indicators.NonCompliant("A group other than '" + params.groupName + "' has GID " + std::to_string(item.gid));
            }

            hasGid = true;
        }
    }

    if (params.gid.HasValue() && !hasGid)
    {
        OsConfigLogDebug(context.GetLogHandle(), "No group with GID %d found.", params.gid.Value());
        return indicators.NonCompliant("No group with GID " + std::to_string(params.gid.Value()) + " found");
    }

    return indicators.Compliant("All criteria has been met for group '" + params.groupName + "'");
}
} // namespace ComplianceEngine
