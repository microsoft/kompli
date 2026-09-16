// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//
// NoUnownedFiles: Fails if any file in the scanned filesystem snapshot has a UID
// that is not present in the context's account database. Stops at
// the first unowned file (early exit) and returns NonCompliant. If all files
// are owned by known UIDs, returns Compliant.

#include <CommonUtils.h>
#include <Evaluator.h>
#include <FilesystemScanner.h>
#include <NoUnownedFiles.h>
#include <fnmatch.h>
#include <set>
#include <sys/stat.h>

namespace ComplianceEngine
{
static constexpr int maxUnowned = 3;

Result<Status> AuditNoUnownedFiles(IndicatorsTree& indicators, ContextInterface& context)
{
    const std::vector<std::string> ommited_paths = {"/run/*", "/proc/*", "*/containerd/*", "*/kubelet/*", "/sys/fs/cgroup/memory/*", "/var/*/private/*"};
    // Build set of known uids and gids
    std::set<uid_t> knownUids;
    auto usersRange = context.GetAccountDatabase().GetUsers();
    if (!usersRange.HasValue())
    {
        return usersRange.Error();
    }
    for (const auto& user : *usersRange.Value())
    {
        knownUids.insert(user.uid);
    }
    std::set<uid_t> knownGids;
    auto groupsRange = context.GetAccountDatabase().GetGroups();
    if (!groupsRange.HasValue())
    {
        return groupsRange.Error();
    }
    for (const auto& group : *groupsRange.Value())
    {
        knownGids.insert(group.gid);
    }

    // Get filesystem snapshot
    FilesystemScanner& scanner = context.GetFilesystemScanner();
    auto fsRes = scanner.GetFullFilesystem();
    if (!fsRes)
    {
        return fsRes.Error();
    }
    const auto& entries = fsRes.Value()->entries;

    int unowned = 0;
    for (const auto& kv : entries)
    {
        if (unowned >= maxUnowned)
        {
            break;
        }
        const auto& path = kv.first;
        const auto& st = kv.second.st;
        bool omit = false;
        for (const auto& pattern : ommited_paths)
        {
            if (fnmatch(pattern.c_str(), path.c_str(), 0) == 0)
            {
                OsConfigLogDebug(context.GetLogHandle(), "Skipping path %s matching omit pattern %s", path.c_str(), pattern.c_str());
                omit = true;
                break;
            }
        }
        if (omit)
        {
            continue;
        }
        if (knownUids.find(st.st_uid) == knownUids.end())
        {
            indicators.NonCompliant("Unowned file '" + path + "' with uid " + std::to_string(static_cast<long long>(st.st_uid)));
            unowned++;
        }
        if (knownGids.find(st.st_gid) == knownGids.end())
        {
            indicators.NonCompliant("Unowned file '" + path + "' with gid " + std::to_string(static_cast<long long>(st.st_gid)));
            unowned++;
        }
    }
    if (unowned > 0)
    {
        return indicators.NonCompliant("Unowned files found in the filesystem (up to " + std::to_string(maxUnowned) + " listed)");
    }
    return indicators.Compliant("All files owned by known users");
}

} // namespace ComplianceEngine
