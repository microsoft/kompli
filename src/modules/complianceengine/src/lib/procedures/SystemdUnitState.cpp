// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <CommonUtils.h>
#include <Regex.h>
#include <StringTools.h>
#include <SystemdUnitState.h>
#include <algorithm>
#include <iostream>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>

using ComplianceEngine::Optional;

namespace ComplianceEngine
{

// Documentation for dbus {ActiveState, SubState, LoadState, UnitFileState} possible values and meaning
// https://www.freedesktop.org/wiki/Software/systemd/dbus/
// man systemd.timer /Unit=
// https://www.freedesktop.org/software/systemd/man/latest/systemd.timer.html
// Unit=  # The unit to activate when this timer elapses.
Result<Status> AuditSystemdUnitState(const SystemdUnitStateParams& params, IndicatorsTree& indicators, ContextInterface& context)
{
    struct systemdQueryParams
    {
        std::string argName;
        Optional<Pattern> pattern;
        bool observed = false;
        systemdQueryParams(const char* name)
            : argName(name),
              pattern(Optional<Pattern>())
        {
        }
    };
    systemdQueryParams queryParams[] = {"ActiveState", "SubState", "LoadState", "UnitFileState", "Unit"};
    bool argFound = false;
    auto log = context.GetLogHandle();
    std::string systemCtlCmd = "systemctl show ";

    auto setParamValue = [&](systemdQueryParams& param, Pattern pattern) {
        argFound = true;
        OsConfigLogDebug(log, "SystemdUnitState check unit name '%s' arg '%s'", params.unitName.c_str(), param.argName.c_str());
        param.pattern = std::move(pattern);
        systemCtlCmd += "-p " + param.argName + " ";
    };

    if (params.activeState.HasValue())
    {
        setParamValue(queryParams[0], params.activeState.Value());
    }
    if (params.subState.HasValue())
    {
        setParamValue(queryParams[1], params.subState.Value());
    }
    if (params.loadState.HasValue())
    {
        setParamValue(queryParams[2], params.loadState.Value());
    }
    if (params.unitFileState.HasValue())
    {
        setParamValue(queryParams[3], params.unitFileState.Value());
    }
    if (params.unit.HasValue())
    {
        setParamValue(queryParams[4], params.unit.Value());
    }
    systemCtlCmd += "\"" + EscapeForShell(params.unitName) + "\"";

    if (!argFound)
    {
        OsConfigLogError(log, "Error: EnsureSystemdUnit: none of 'activeState subState loadState unitFileState unit' parameters are present");
        return Error("None of 'activeState subState loadState unitFileState unit' parameters are present");
    }

    Result<std::string> systemCtlOutput = context.ExecuteCommand(systemCtlCmd);
    if (!systemCtlOutput.HasValue())
    {
        OsConfigLogError(log, "Failed to execute systemctl command '%s': %s (code: %d)", systemCtlCmd.c_str(), systemCtlOutput.Error().message.c_str(),
            systemCtlOutput.Error().code);
        return Error("Failed to execute systemctl command '" + systemCtlCmd + "': " + systemCtlOutput.Error().message, systemCtlOutput.Error().code);
    }
    std::string line;
    std::istringstream sysctlValues(systemCtlOutput.Value());

    while (std::getline(sysctlValues, line))
    {
        size_t eqSign = line.find('=');
        if (eqSign == std::string::npos)
        {
            OsConfigLogError(log, "Invalid systemctl output, missing '=' in '%s'", line.c_str());
            return Error("Invalid systemctl output, missing '=' in '" + line + "'");
        }
        auto name = line.substr(0, eqSign);
        auto value = line.substr(eqSign + 1);
        bool matched = false;
        for (auto& param : queryParams)
        {
            if (!param.pattern.HasValue() || (name != param.argName))
            {
                continue;
            }
            if (value.empty())
            {
                OsConfigLogError(log, "Empty systemctl property '%s' for unit '%s'", name.c_str(), params.unitName.c_str());
                return Error("Empty systemctl property '" + name + "' for unit '" + params.unitName + "'");
            }
            if (!regex_match(value, param.pattern->GetRegex()))
            {
                // OsConfigLogDebug(log, "Failed to match systemctl unit name '%s' for name '%s' for pattern '%s'  for value '%s' ",
                // params.unitName.c_str(), name.c_str(), param.value.c_str(), value.c_str());
                OsConfigLogDebug(log, "Failed to match systemctl unit name '%s' for name '%s' for pattern '%s'", params.unitName.c_str(), name.c_str(),
                    value.c_str());
                return indicators.NonCompliant("Failed to match systemctl unit name '" + params.unitName + "' field '" + name + "' value '" + value +
                                               "' with pattern '" + param.pattern->GetPattern() + "'");
            }
            else
            {
                param.observed = true;
                indicators.Compliant("Successfully matched systemctl unit name '" + params.unitName + "' field '" + name + "' value '" + value +
                                     "' with pattern '" + param.pattern->GetPattern() + "'");
            }
            matched = true;
        }
        if (matched == false)
        {
            OsConfigLogError(log, "Unexpected systemctl property '%s' for unit '%s'", name.c_str(), params.unitName.c_str());
            return Error("Unexpected systemctl property '" + name + "' for unit '" + params.unitName + "'");
        }
    }

    for (const auto& param : queryParams)
    {
        if (param.pattern.HasValue() && !param.observed)
        {
            OsConfigLogError(log, "Missing requested systemctl property '%s' for unit '%s'", param.argName.c_str(), params.unitName.c_str());
            return Error("Missing requested systemctl property '" + param.argName + "' for unit '" + params.unitName + "'");
        }
    }

    OsConfigLogDebug(log, "Success to match systemctl unit name '%s' for name all params ", params.unitName.c_str());
    return Status::Compliant;
}

} // namespace ComplianceEngine
