// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "NetworkTools.h"

#include <Evaluator.h>
#include <MtaLocalOnly.h>
#include <regex>
#include <sstream>

namespace Kompli
{
namespace
{
Result<Status> AuditMtaLocalOnlyV4(IndicatorsTree& indicators, ContextInterface& context)
{
    // v4 treats missing ss as failure, but otherwise evaluates stdout even when a probe exits nonzero.
    const auto sockets = context.ExecuteCommand(
        "if command -v ss >/dev/null 2>&1; then ss -plntu 2>/dev/null || true; "
        "else printf '%s\\n' 'ss unavailable'; fi");
    if (!sockets.HasValue())
    {
        return sockets.Error();
    }
    if (sockets.Value() == "ss unavailable\n")
    {
        return indicators.NonCompliant("ss not found; MTA listening sockets could not be determined");
    }
    for (const auto port : {25, 465, 587})
    {
        const auto portString = std::to_string(port);
        const std::regex mailPort(":" + portString + "[ \\t]");
        const std::regex loopback("[ \\t]+(127\\.0\\.0\\.1|\\[?::1\\]?):" + portString + "\\b");
        std::istringstream lines(sockets.Value());
        std::string line;
        while (std::getline(lines, line))
        {
            // Match whole socket lines, including v4's exact loopback set and port boundary.
            if (std::regex_search(line, mailPort) && !std::regex_search(line, loopback))
            {
                return indicators.NonCompliant("MTA is listening on port " + portString + " on non-local interface");
            }
        }
    }
    const auto configuration = context.ExecuteCommand(
        "interfaces=$(if command -v postconf >/dev/null 2>&1; then postconf -h inet_interfaces; "
        "elif command -v exim >/dev/null 2>&1; then "
        "value=$(exim -bP local_interfaces 2>/dev/null || true); value=${value#*=}; "
        "printf '%s\\n' \"$value\" | sed -E 's/^[[:space:]]*<.[[:space:]]*//'; "
        "elif command -v sendmail >/dev/null 2>&1; then "
        "grep -i 'O DaemonPortOptions=' /etc/mail/sendmail.cf | "
        "grep -oP '(?<=Addr=)[^,+ ]+' | paste -sd, -; "
        "fi 2>/dev/null); printf '%s' \"$interfaces\"");
    if (!configuration.HasValue())
    {
        return configuration.Error();
    }
    std::istringstream lines(configuration.Value());
    std::string firstLine;
    std::getline(lines, firstLine);
    for (auto& character : firstLine)
    {
        if (character == ',' || character == ';')
        {
            character = ' ';
        }
    }
    // Bash read -ra consumes only the first line; preserve its token grammar, not IP-address validation.
    const std::regex localInterface(R"(^(loopback-only|localhost|::1|\[::1\]|127(\.[0-9]{1,3}){3})$)", std::regex_constants::icase);
    const std::regex tokenPattern("[^ \\t]+");
    for (auto token = std::sregex_iterator(firstLine.begin(), firstLine.end(), tokenPattern); token != std::sregex_iterator(); ++token)
    {
        if (!std::regex_match(token->str(), localInterface))
        {
            return indicators.NonCompliant("MTA is configured to bind to a non-local interface: " + configuration.Value());
        }
    }
    if (firstLine.find_first_not_of(" \t") == std::string::npos)
    {
        return indicators.Compliant("No non-local MTA sockets; interface configuration absent or undetermined (source audit N/A)");
    }
    return indicators.Compliant("No non-local MTA sockets; all configured interface tokens are loopback");
}
} // namespace

Result<Status> AuditMtaLocalOnly(const MtaLocalOnlyParams& params, IndicatorsTree& indicators, ContextInterface& context)
{
    const auto version = params.configurationVersion.Value();
    if (version == MtaConfigurationVersion::Version4)
    {
        return AuditMtaLocalOnlyV4(indicators, context);
    }
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
        const std::regex allInterfaces(R"(\ball\b)", std::regex_constants::icase);
        const std::regex localInterfaces(version == MtaConfigurationVersion::Version1 ? R"(0\.0\.0\.0|::1|loopback-only)" : R"(0\.0\.0\.0|::1|loopback-only|localhost)",
            std::regex_constants::icase);
        if (std::regex_search(interfaces, allInterfaces) || (!interfaces.empty() && !std::regex_search(interfaces, localInterfaces)))
        {
            return indicators.NonCompliant("MTA is configured to bind to a non-local interface: " + interfaces);
        }
    }
    return indicators.Compliant("No open MTA ports found on non-local interfaces");
}

} // namespace Kompli
