// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <CommandOutputMatch.h>
#include <ProcedureMap.h> // Used for to_string(enum)
#include <StringTools.h>
#include <TemporaryDirectory.h>
#include <set>
#include <string>

namespace ComplianceEngine
{

static const std::set<std::string> allowedCommands = {"nft list ruleset", "nft list chain", "nft list tables", "ip6tables -L -n",
    "ip6tables -L INPUT -v -n", "ip6tables -L OUTPUT -v -n", "iptables -L -n", "iptables -L INPUT -v -n", "iptables -L OUTPUT -v -n", "uname", "ps -ef",
    "ps -eZ", "sestatus", "journalctl", "arch", "grubby --info=ALL", "pam-config --query --pwhistory", "getenforce", "dmsetup table"};

Result<Status> AuditCommandOutputMatch(const CommandOutputMatchParams& params, IndicatorsTree& indicators, ContextInterface& context)
{
    assert(params.type.HasValue());
    if (allowedCommands.find(params.command) == allowedCommands.end())
    {
        return Error("Command " + params.command + " is not allowed");
    }

    auto temporary = TemporaryDirectory::Make("CommandOutputMatch");
    if (!temporary.HasValue())
    {
        return temporary.Error();
    }

    const std::string outputPath = temporary.Value().Path() + "/output";
    // Keep producer and filter exit codes separate from grep's ordinary no-match exit code.
    auto commandOutput = context.ExecuteCommand(params.command + " > \"" + EscapeForShell(outputPath) + "\"");
    if (!commandOutput.HasValue())
    {
        return Error("Failed to execute command '" + params.command + "': " + commandOutput.Error().message, commandOutput.Error().code);
    }

    std::string matchPath = outputPath;
    if (params.awk.HasValue() && !params.awk.Value().empty())
    {
        matchPath = temporary.Value().Path() + "/transformed";
        const auto transformed = context.ExecuteCommand("awk -S \"" + EscapeForShell(params.awk.Value()) + "\" \"" + EscapeForShell(outputPath) +
                                                        "\" > \"" + EscapeForShell(matchPath) + "\"");
        if (!transformed.HasValue())
        {
            return Error("Failed to transform output of command '" + params.command + "': " + transformed.Error().message, transformed.Error().code);
        }
    }

    const auto matched = context.ExecuteCommand("grep -" + std::to_string(params.type.Value()) + " -- \"" + EscapeForShell(params.pattern) + "\" \"" +
                                                EscapeForShell(matchPath) + "\"");
    if (!matched.HasValue())
    {
        if (1 != matched.Error().code)
        {
            return Error("Failed to match output of command '" + params.command + "': " + matched.Error().message, matched.Error().code);
        }
        return indicators.NonCompliant("Output of command '" + params.command + "' does not match regex '" + params.pattern + "'");
    }

    return indicators.Compliant("Output of command '" + params.command + "' matches regex '" + params.pattern + "'");
}

} // namespace ComplianceEngine
