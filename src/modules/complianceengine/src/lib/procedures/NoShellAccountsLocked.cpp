// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <CommonUtils.h>
#include <ListValidShells.h>
#include <NoShellAccountsLocked.h>
#include <PasswordEntriesIterator.h>
#include <Result.h>
#include <Telemetry.h>
#include <Users.h>
#include <set>
#include <shadow.h>

namespace ComplianceEngine
{
using std::set;
using std::string;

Result<Status> AuditNoShellAccountsLocked(const NoShellAccountsLockedParams& params, IndicatorsTree& indicators, ContextInterface& context)
{
    Result<unsigned int> uidMin = Error("Uninitialised UID_MIN");
    if (params.skipBelowUidMin.HasValue() && params.skipBelowUidMin.Value())
    {
        uidMin = GetUidMin(context);
    }

    const auto validShells = ListValidShells(context);

    if (!validShells.HasValue())
    {
        OsConfigLogError(context.GetLogHandle(), "Failed to get valid shells: %s", validShells.Error().message.c_str());
        OSConfigTelemetryStatusTrace("ListValidShells", validShells.Error().code);
        return validShells.Error();
    }

    auto passwords = PasswordEntryRange::Make(context.GetSpecialFilePath("/etc/shadow"), context.GetLogHandle());
    if (!passwords.HasValue())
    {
        return passwords.Error();
    }

    set<string> lockedUsers;
    for (const auto& item : passwords.Value())
    {
        if (0 == strlen(item.sp_pwdp))
        {
            continue;
        }

        if (item.sp_pwdp[0] == '!' || item.sp_pwdp[0] == '*')
        {
            lockedUsers.insert(item.sp_namp);
        }
    }

    auto users = context.GetAccountDatabase().GetUsers();
    if (!users.HasValue())
    {
        return users.Error();
    }

    for (const auto& user : *users.Value())
    {
        const auto& shell = user.shell;
        const auto it = validShells->find(shell);
        if (it != validShells->end())
        {
            OsConfigLogDebug(context.GetLogHandle(), "User '%s' has a valid shell '%s'", user.name.c_str(), user.shell.c_str());
            continue;
        }

        OsConfigLogDebug(context.GetLogHandle(), "User '%s' does not have a valid shell: '%s'", user.name.c_str(), user.shell.c_str());
        if (user.name == "root")
        {
            continue;
        }

        bool shouldSkip = false;
        assert(params.skipInvalidShells.HasValue());
        if (params.skipInvalidShells.Value())
        {
            OsConfigLogDebug(context.GetLogHandle(), "Skip User '%s' as it's does not have valid shell %s", user.name.c_str(), user.shell.c_str());
            shouldSkip = true;
        }

        if (params.excludeUsers.HasValue())
        {
            for (const auto& excludeUser : params.excludeUsers->items)
            {
                if (user.name == excludeUser)
                {
                    OsConfigLogDebug(context.GetLogHandle(), "Skip User '%s' as it's on exclude list ", user.name.c_str());
                    shouldSkip = true;
                    break;
                }
            }
        }
        if (shouldSkip)
        {
            continue;
        }
        if (params.skipBelowUidMin && uidMin.HasValue())
        {
            if (user.uid < uidMin.Value())
            {
                OsConfigLogDebug(context.GetLogHandle(), "Skip User '%s' as it's id %d is lower than UID_MIN %d", user.name.c_str(), user.uid, uidMin.Value());
                continue;
            }
        }

        if (lockedUsers.find(user.name) == lockedUsers.end())
        {
            return indicators.NonCompliant(string("User ") + std::to_string(user.uid) + " does not have a valid shell, but the account is not locked");
        }

        indicators.Compliant(string("User ") + std::to_string(user.uid) + " does not have a valid shell, but the account is locked");
    }

    return indicators.Compliant("All non-root users without a login shell are locked");
}
} // namespace ComplianceEngine
