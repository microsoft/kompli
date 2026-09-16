// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_ACCOUNTDATABASE_H
#define COMPLIANCEENGINE_ACCOUNTDATABASE_H

#include "Result.h"

#include <functional>
#include <grp.h>
#include <memory>
#include <mutex>
#include <pwd.h>
#include <string>
#include <unordered_map>
#include <vector>

namespace ComplianceEngine
{
class ContextInterface;

struct UserRecord
{
    std::string name;
    uid_t uid;
    gid_t gid;
    std::string homeDirectory;
    std::string shell;
};

struct GroupRecord
{
    std::string name;
    gid_t gid;
};

struct AccountDatabaseRecords
{
    std::vector<UserRecord> users;
    std::vector<GroupRecord> groups;
};

class AccountDatabase
{
public:
    using Loader = std::function<Result<AccountDatabaseRecords>()>;

    explicit AccountDatabase(ContextInterface& context, Loader loader = Loader());
    AccountDatabase(const AccountDatabase&) = delete;
    AccountDatabase& operator=(const AccountDatabase&) = delete;

    Result<const std::vector<UserRecord>*> GetUsers();
    Result<const std::vector<GroupRecord>*> GetGroups();
    Result<const UserRecord*> FindUserByName(const std::string& name);
    Result<const UserRecord*> FindUserById(uid_t uid);
    Result<const GroupRecord*> FindGroupByName(const std::string& name);
    Result<const GroupRecord*> FindGroupById(gid_t gid);
    void SetLoaderForTesting(Loader loader);

private:
    Result<bool> EnsureLoaded();
    Result<bool> Load();
    Result<AccountDatabaseRecords> LoadFromNss();

    ContextInterface& mContext;
    Loader mLoader;
    std::mutex mMutex;
    bool mLoadAttempted = false;
    std::unique_ptr<Error> mLoadError;
    std::vector<UserRecord> mUsers;
    std::vector<GroupRecord> mGroups;
    std::unordered_map<std::string, std::size_t> mUsersByName;
    std::unordered_map<uid_t, std::size_t> mUsersById;
    std::unordered_map<std::string, std::size_t> mGroupsByName;
    std::unordered_map<gid_t, std::size_t> mGroupsById;
};
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_ACCOUNTDATABASE_H
