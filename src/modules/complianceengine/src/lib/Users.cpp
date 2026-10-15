// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <CommonContext.h>
#include <StringTools.h>
#include <Users.h>
#include <sstream>

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
    std::stringstream ss(loginDefsResult.Value());
    std::string line;
    while (std::getline(ss, line))
    {
        line = TrimWhiteSpaces(StripComment(line));
        std::istringstream lineStream(line);
        std::string key;
        lineStream >> key;
        if (key == "UID_MIN")
        {
            std::string value;
            std::getline(lineStream, value);
            value = TrimWhiteSpaces(value);
            auto result = TryStringToUint(value);
            if (!result.HasValue())
            {
                OsConfigLogWarning(context.GetLogHandle(), "Invalid UID_MIN value in /etc/login.defs %s", result.Error().message.c_str());
            }
            return result;
        }
    }
    return Error("Could not get UID_MIN find value");
}
} // namespace ComplianceEngine
