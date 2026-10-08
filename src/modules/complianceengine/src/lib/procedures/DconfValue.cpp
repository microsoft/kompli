// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <ProcedureMap.h>
#include <StringTools.h>
#include <TypedComparison.h>
#include <algorithm>

namespace ComplianceEngine
{
Result<Status> AuditDconfValue(const DconfValueParams& params, IndicatorsTree& indicators, ContextInterface& context)
{
    const auto key = EscapeForShell(params.key);
    if ((params.operation != DconfOperation::Eq) && (params.operation != DconfOperation::Ne))
    {
        return Error("Not supported operation", EINVAL);
    }

    Result<std::string> dconfRead = context.ExecuteCommand("dconf read \"" + key + "\"");
    if (!dconfRead.HasValue())
    {
        return Error("Failed to execute dconf read " + key + " error: " + dconfRead.Error().message, dconfRead.Error().code);
    }
    auto dconfVal = dconfRead.Value();

    // remove newline character
    if (*dconfVal.rbegin() == '\n')
    {
        dconfVal.erase(dconfVal.size() - 1);
    }

    auto comparison =
        CompareTyped(dconfVal, params.value, params.operation == DconfOperation::Eq ? TypedComparisonOperation::Equal : TypedComparisonOperation::NotEqual);
    if (!comparison.HasValue())
    {
        return comparison.Error();
    }
    if (comparison.Value())
    {
        return indicators.Compliant("Dconf read " + key + " " + std::to_string(params.operation) + " value " + params.value);
    }
    else
    {
        return indicators.NonCompliant("Dconf read " + key + " " + std::to_string(params.operation) + " value " + params.value);
    }
    return indicators.NonCompliant("Dconf read " + key + " " + std::to_string(params.operation) + " value " + params.value + " Imposible");
}

} // namespace ComplianceEngine
