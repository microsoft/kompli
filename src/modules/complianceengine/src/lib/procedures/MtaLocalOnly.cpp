// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "NetworkTools.h"

#include <Evaluator.h>
#include <MtaLocalOnly.h>
#include <Regex.h>

namespace ComplianceEngine
{
Result<Status> AuditMtaLocalOnly(const MtaLocalOnlyParams& params, IndicatorsTree& indicators, ContextInterface& context)
{
    const auto version = params.configurationVersion.Value();
    auto result = GetOpenPorts(context);
    if (!result.HasValue())
    {
        return result.Error();
    }
    const auto& openPorts = result.Value();
    for (const auto& port : openPorts)
    {
        if (!port.IsLocal() && ((port.port == 25) || (port.port == 587) || (port.port == 465)))
        {
            return indicators.NonCompliant("MTA is listening on port " + std::to_string(port.port) + " on non-local interface");
        }
    }
    if (version != MtaConfigurationVersion::None)
    {
        std::string command =
            "interfaces=$(if command -v postconf >/dev/null 2>&1; then postconf -n inet_interfaces; "
            "elif command -v exim >/dev/null 2>&1; then exim -bP local_interfaces; ";
        if (version == MtaConfigurationVersion::Version3)
        {
            command +=
                "elif command -v sendmail >/dev/null 2>&1; then "
                "awk 'tolower($0) ~ /o daemonportoptions=/ && match($0, /Addr=[^,+]+/) "
                "{ address = substr($0, RSTART + 5, RLENGTH - 5); if (address != \"127.0.0.1\") print address }' "
                "/etc/mail/sendmail.cf; ";
        }
        command += "fi 2>/dev/null); printf '%s' \"$interfaces\"";
        const auto configuration = context.ExecuteCommand(command);
        if (!configuration.HasValue())
        {
            return configuration.Error();
        }
        const auto& interfaces = configuration.Value();
        const regex allInterfaces(R"(\ball\b)", std::regex_constants::icase);
        const regex localInterfaces(version == MtaConfigurationVersion::Version1 ? R"(0\.0\.0\.0|::1|loopback-only)" : R"(0\.0\.0\.0|::1|loopback-only|localhost)",
            std::regex_constants::icase);
        if (regex_search(interfaces, allInterfaces) || (!interfaces.empty() && !regex_search(interfaces, localInterfaces)))
        {
            return indicators.NonCompliant("MTA is configured to bind to a non-local interface: " + interfaces);
        }
    }
    return indicators.Compliant("No open MTA ports found on non-local interfaces");
}

} // namespace ComplianceEngine
