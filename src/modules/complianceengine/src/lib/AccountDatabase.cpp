// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "AccountDatabase.h"

#include "ContextInterface.h"
#include "Telemetry.h"

#include <cerrno>
#include <cstring>

namespace ComplianceEngine
{
namespace
{
std::mutex gNssEnumerationMutex;
}

AccountDatabase::AccountDatabase(ContextInterface& context, Loader loader)
    : mContext(context),
      mLoader(std::move(loader))
{
}

void AccountDatabase::SetLoaderForTesting(Loader loader)
{
    std::lock_guard<std::mutex> lock(mMutex);
    if (!mLoadAttempted)
    {
        mLoader = std::move(loader);
    }
}

Result<AccountDatabaseRecords> AccountDatabase::LoadFromNss()
{
    std::lock_guard<std::mutex> nssLock(gNssEnumerationMutex);
    AccountDatabaseRecords records;
    std::vector<char> buffer(1024);
    struct passwd storage;
    struct passwd* entry = nullptr;
    setpwent();
    while (true)
    {
        const int status = getpwent_r(&storage, buffer.data(), buffer.size(), &entry);
        if (ERANGE == status)
        {
            buffer.resize(buffer.size() * 2);
            continue;
        }
        if (ENOENT == status || (0 == status && nullptr == entry))
        {
            break;
        }
        if (0 != status)
        {
            endpwent();
            OsConfigLogError(mContext.GetLogHandle(), "Failed to enumerate users: %s", strerror(status));
            OSConfigTelemetryStatusTrace("getpwent_r", status);
            return Error("Failed to enumerate users: " + std::string(strerror(status)), status);
        }
        records.users.push_back({entry->pw_name, entry->pw_uid, entry->pw_gid, entry->pw_dir, entry->pw_shell});
    }
    endpwent();

    buffer.resize(1024);
    struct group groupStorage;
    struct group* groupEntry = nullptr;
    setgrent();
    while (true)
    {
        const int status = getgrent_r(&groupStorage, buffer.data(), buffer.size(), &groupEntry);
        if (ERANGE == status)
        {
            buffer.resize(buffer.size() * 2);
            continue;
        }
        if (ENOENT == status || (0 == status && nullptr == groupEntry))
        {
            break;
        }
        if (0 != status)
        {
            endgrent();
            OsConfigLogError(mContext.GetLogHandle(), "Failed to enumerate groups: %s", strerror(status));
            OSConfigTelemetryStatusTrace("getgrent_r", status);
            return Error("Failed to enumerate groups: " + std::string(strerror(status)), status);
        }
        records.groups.push_back({groupEntry->gr_name, groupEntry->gr_gid});
    }
    endgrent();
    return records;
}

Result<bool> AccountDatabase::Load()
{
    auto records = mLoader ? mLoader() : LoadFromNss();
    if (!records.HasValue())
    {
        return records.Error();
    }

    mUsers = std::move(records.Value().users);
    mGroups = std::move(records.Value().groups);
    for (std::size_t index = 0; index < mUsers.size(); ++index)
    {
        mUsersByName.emplace(mUsers[index].name, index);
        mUsersById.emplace(mUsers[index].uid, index);
    }
    for (std::size_t index = 0; index < mGroups.size(); ++index)
    {
        mGroupsByName.emplace(mGroups[index].name, index);
        mGroupsById.emplace(mGroups[index].gid, index);
    }
    return true;
}

Result<bool> AccountDatabase::EnsureLoaded()
{
    std::lock_guard<std::mutex> lock(mMutex);
    if (!mLoadAttempted)
    {
        mLoadAttempted = true;
        auto result = Load();
        if (!result.HasValue())
        {
            mLoadError.reset(new Error(result.Error()));
        }
    }
    if (mLoadError)
    {
        return *mLoadError;
    }
    return true;
}

Result<const std::vector<UserRecord>*> AccountDatabase::GetUsers()
{
    auto result = EnsureLoaded();
    return result.HasValue() ? Result<const std::vector<UserRecord>*>(&mUsers) : Result<const std::vector<UserRecord>*>(result.Error());
}

Result<const std::vector<GroupRecord>*> AccountDatabase::GetGroups()
{
    auto result = EnsureLoaded();
    return result.HasValue() ? Result<const std::vector<GroupRecord>*>(&mGroups) : Result<const std::vector<GroupRecord>*>(result.Error());
}

Result<const UserRecord*> AccountDatabase::FindUserByName(const std::string& name)
{
    auto result = EnsureLoaded();
    if (!result.HasValue())
    {
        return result.Error();
    }
    const auto item = mUsersByName.find(name);
    return item == mUsersByName.end() ? nullptr : &mUsers[item->second];
}

Result<const UserRecord*> AccountDatabase::FindUserById(uid_t uid)
{
    auto result = EnsureLoaded();
    if (!result.HasValue())
    {
        return result.Error();
    }
    const auto item = mUsersById.find(uid);
    return item == mUsersById.end() ? nullptr : &mUsers[item->second];
}

Result<const GroupRecord*> AccountDatabase::FindGroupByName(const std::string& name)
{
    auto result = EnsureLoaded();
    if (!result.HasValue())
    {
        return result.Error();
    }
    const auto item = mGroupsByName.find(name);
    return item == mGroupsByName.end() ? nullptr : &mGroups[item->second];
}

Result<const GroupRecord*> AccountDatabase::FindGroupById(gid_t gid)
{
    auto result = EnsureLoaded();
    if (!result.HasValue())
    {
        return result.Error();
    }
    const auto item = mGroupsById.find(gid);
    return item == mGroupsById.end() ? nullptr : &mGroups[item->second];
}
} // namespace ComplianceEngine
