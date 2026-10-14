// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <CommonContext.h>
#include <Users.h>
#include <cerrno>
#include <parsers/LoginDefs.h>

namespace ComplianceEngine
{
Result<uid_t> GetUidMin(ContextInterface& context)
{
    return GetUidMin(context, context.GetFileContents("/etc/login.defs"));
}

Result<uid_t> GetUidMin(ContextInterface& context, const Result<std::string>& loginDefsResult)
{
    if (!loginDefsResult.HasValue())
    {
        OsConfigLogWarning(context.GetLogHandle(), "Failed to read /etc/login.defs: %s", loginDefsResult.Error().message.c_str());
        return loginDefsResult.Error();
    }
    if (loginDefsResult.Value().empty())
    {
        OsConfigLogWarning(context.GetLogHandle(), "Failed to read /etc/login.defs");
        return Error("Failed to read /etc/login.defs");
    }
    const auto parsed = LoginDefs::Parse(loginDefsResult.Value(), "/etc/login.defs", context.GetLogHandle());
    if (!parsed.HasValue())
    {
        OsConfigLogWarning(context.GetLogHandle(), "Invalid /etc/login.defs: %s", parsed.Error().message.c_str());
        return parsed.Error();
    }
    if (!parsed.Value().uidMin.HasValue())
    {
        return Error("Could not get UID_MIN find value");
    }
    return parsed.Value().uidMin.Value();
}
} // namespace ComplianceEngine
