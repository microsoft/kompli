// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <CommonUtils.h>
#include <Evaluator.h>
#include <ListValidShells.h>
#include <Result.h>
#include <UsersIterator.h>
#include <fstream>
#include <parsers/LoginDefs.h>
#include <set>
#include <shadow.h>
#include <sys/stat.h>
#include <utility>

namespace ComplianceEngine
{
using std::set;
using std::string;

namespace
{
static const set<string> GetAllowlistedAccounts()
{
    static const set<string> sAccounts = {"root", "halt", "sync", "shutdown", "nfsnobody"};
    return sAccounts;
}

Result<uid_t> LoadMinUID(ContextInterface& context)
{
    static const uid_t defaultUID = 1000;
    const auto filename = context.GetSpecialFilePath("/etc/login.defs");

    struct stat st;
    if (0 != stat(filename.c_str(), &st))
    {
        int status = errno;
        if (ENOENT == status)
        {
            OsConfigLogInfo(context.GetLogHandle(), "/etc/login.defs file is missing, assuming minimum user UID is %d", defaultUID);
            return defaultUID;
        }

        return Error(string("Failed to read ") + filename + " file: " + strerror(status), status);
    }

    std::ifstream file(filename);
    if (!file.is_open())
    {
        OsConfigLogError(context.GetLogHandle(), "Failed to read %s", filename.c_str());
        return Error(string("Failed to read ") + filename, EINVAL);
    }

    string contents(LoginDefs::MaxBytes + 1, '\0');
    file.read(&contents[0], static_cast<std::streamsize>(contents.size()));
    if (file.bad() || (file.fail() && !file.eof()))
    {
        OsConfigLogError(context.GetLogHandle(), "Failed to read %s", filename.c_str());
        return Error(string("Failed to read ") + filename, EIO);
    }
    contents.resize(static_cast<size_t>(file.gcount()));
    const auto parsed = LoginDefs::Parse(std::move(contents), filename, context.GetLogHandle());
    if (!parsed.HasValue())
    {
        OsConfigLogError(context.GetLogHandle(), "Failed to parse %s: %s", filename.c_str(), parsed.Error().message.c_str());
        return parsed.Error();
    }
    if (!parsed.Value().uidMin.HasValue())
    {
        return defaultUID;
    }

    return parsed.Value().uidMin.Value();
}
} // anonymous namespace

Result<Status> AuditSystemAccountShell(IndicatorsTree& indicators, ContextInterface& context)
{
    const auto& allowlistedAccounts = GetAllowlistedAccounts();
    const auto validShells = ListValidShells(context);
    if (!validShells.HasValue())
    {
        OsConfigLogError(context.GetLogHandle(), "Failed to get valid shells: %s", validShells.Error().message.c_str());
        return validShells.Error();
    }

    const auto minUID = LoadMinUID(context);
    if (!minUID.HasValue())
    {
        OsConfigLogError(context.GetLogHandle(), "Failed to get minimum user UID: %s", minUID.Error().message.c_str());
        return minUID.Error();
    }

    auto users = UsersRange::Make(context.GetSpecialFilePath("/etc/passwd"), context.GetLogHandle());
    if (!users.HasValue())
    {
        return users.Error();
    }

    for (const auto& user : users.Value())
    {
        OsConfigLogInfo(context.GetLogHandle(), "User: %s, UID: %d, shell: %s, min: %d", user.pw_name, user.pw_uid, user.pw_shell, minUID.Value());
        if (user.pw_uid >= minUID.Value())
        {
            continue;
        }

        OsConfigLogInfo(context.GetLogHandle(), "User: %s, UID: %d, shell: %s", user.pw_name, user.pw_uid, user.pw_shell);
        if (allowlistedAccounts.end() != allowlistedAccounts.find(user.pw_name))
        {
            // Skip allowlisted account
            OsConfigLogDebug(context.GetLogHandle(), "Skipping allowlisted account '%s'", user.pw_name);
            continue;
        }

        OsConfigLogInfo(context.GetLogHandle(), "User: %s, UID: %d, shell: %s", user.pw_name, user.pw_uid, user.pw_shell);
        const auto shell = string(user.pw_shell);
        const auto it = validShells->find(shell);
        if (it != validShells->end())
        {
            OsConfigLogInfo(context.GetLogHandle(), "System user %d has a valid login shell '%s'", user.pw_uid, user.pw_shell);
            return indicators.NonCompliant(string("System user ") + std::to_string(user.pw_uid) + " has a valid login shell");
        }

        OsConfigLogInfo(context.GetLogHandle(), "User: %s, UID: %d, shell: %s", user.pw_name, user.pw_uid, user.pw_shell);
        OsConfigLogDebug(context.GetLogHandle(), "System user %d does not have a valid login shell: '%s'", user.pw_uid, user.pw_shell);
        indicators.Compliant(string("System user ") + std::to_string(user.pw_uid) + " does not have a valid login shell");
    }

    return Status::Compliant;
}
} // namespace ComplianceEngine
