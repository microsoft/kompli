// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <CommonUtils.h>
#include <Evaluator.h>
#include <PasswdGroupsExist.h>
#include <Result.h>
#include <functional>
#include <grp.h>
#include <pwd.h>
#include <set>
#include <string>

namespace ComplianceEngine
{
// AuditPasswdGroupsExist enumerates every backend configured in nsswitch.conf, not just
// /etc/passwd and /etc/group. EvaluatePasswdGroupsExist is the enumerator-agnostic core used by tests.
Result<Status> EvaluatePasswdGroupsExist(IndicatorsTree& indicators, const std::function<void()>& beginGroups,
    const std::function<struct group*()>& nextGroup, const std::function<void()>& endGroups, const std::function<void()>& beginUsers,
    const std::function<struct passwd*()>& nextUser, const std::function<void()>& endUsers)
{
    struct group* grp = nullptr;
    struct passwd* pwd = nullptr;
    std::set<gid_t> etcGroupGroups;

    beginGroups();
    for (errno = 0, grp = nextGroup(); nullptr != grp; errno = 0, grp = nextGroup())
    {
        etcGroupGroups.insert(grp->gr_gid);
    }
    int status = errno;
    endGroups();
    // glibc NSS modules other than `files` end enumeration with errno set to ENOENT (NOTFOUND or
    // UNAVAIL), which glibc's reentrant get*ent_r also reports as "no more entries"
    // (nss/getnssent_r.c). `files` leaves errno at 0. Any other nonzero errno is a genuine failure.
    if (0 != status && ENOENT != status)
    {
        return Error(std::string("getgrent failed: ") + strerror(status), status);
    }

    beginUsers();
    Status result = Status::Compliant;
    for (errno = 0, pwd = nextUser(); nullptr != pwd; errno = 0, pwd = nextUser())
    {
        if (etcGroupGroups.find(pwd->pw_gid) == etcGroupGroups.end())
        {
            result = indicators.NonCompliant(std::string("User's '") + std::string(pwd->pw_name) + "' group " + std::to_string(pwd->pw_gid) +
                                             " from /etc/passwd does not exist in /etc/group");
        }
    }
    status = errno;
    endUsers();
    if (0 != status && ENOENT != status)
    {
        return Error(std::string("getpwent failed: ") + strerror(status), status);
    }

    if (result == Status::Compliant)
    {
        indicators.Compliant("All user groups from '/etc/passwd' exist in '/etc/group'");
    }
    return result;
}

Result<Status> AuditPasswdGroupsExist(IndicatorsTree& indicators, ContextInterface& context)
{
    UNUSED(context);
    return EvaluatePasswdGroupsExist(indicators, &setgrent, &getgrent, &endgrent, &setpwent, &getpwent, &endpwent);
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
