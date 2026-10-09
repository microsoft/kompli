// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <CommonContext.h>
#include <StringTools.h>
#include <Users.h>
#include <parsers/LoginDefs.h>

namespace ComplianceEngine
{
Result<unsigned int> GetUidMin(ContextInterface& context)
{
    auto loginDefsResult = context.GetFileContents("/etc/login.defs");
    if (!loginDefsResult.HasValue() || loginDefsResult.Value().empty())
    {
        OsConfigLogWarning(context.GetLogHandle(), "Failed to read /etc/login.defs");
        return Error("Failed to read /etc/login.defs");
    }
    const auto parsed = LoginDefs::Parse(loginDefsResult.Value(), "/etc/login.defs");
    if (!parsed.HasValue())
    {
        OsConfigLogWarning(context.GetLogHandle(), "Invalid /etc/login.defs: %s", parsed.Error().message.c_str());
        return parsed.Error();
    }
    const auto* record = parsed.Value().FindFirst("UID_MIN");
    if (nullptr == record)
    {
        return Error("Could not get UID_MIN find value");
    }
    if (parsed.Value().HasEmbeddedNul(*record))
    {
        OsConfigLogWarning(context.GetLogHandle(), "Invalid UID_MIN value in /etc/login.defs: embedded NUL");
        return Error("Invalid UID_MIN value: embedded NUL", EINVAL);
    }
    const auto value = TrimWhiteSpaces(parsed.Value().Text(record->valueSpan));
    auto result = TryStringToUint(value);
    if (!result.HasValue())
    {
        OsConfigLogWarning(context.GetLogHandle(), "Invalid UID_MIN value in /etc/login.defs %s", result.Error().message.c_str());
    }
    return result;
}
} // namespace ComplianceEngine
