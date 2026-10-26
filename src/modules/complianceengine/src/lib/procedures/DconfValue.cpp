// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <ProcedureMap.h>
#include <StringTools.h>
#include <TypedComparison.h>
#include <algorithm>

namespace ComplianceEngine
{
namespace
{
Result<TypedComparisonOperation> MapComparison(DconfOperation operation)
{
    switch (operation)
    {
        case DconfOperation::Eq:
            return TypedComparisonOperation::Equal;
        case DconfOperation::Ne:
            return TypedComparisonOperation::NotEqual;
    }
    return Error("Not supported operation " + std::to_string(static_cast<int>(operation)), EINVAL);
}
} // namespace

Result<Status> AuditDconfValue(const DconfValueParams& params, IndicatorsTree& indicators, ContextInterface& context)
{
    const auto key = EscapeForShell(params.key);
    auto mapped = MapComparison(params.operation);
    if (!mapped.HasValue())
    {
        return mapped.Error();
    }

    Result<std::string> dconfRead = context.ExecuteCommand("dconf read \"" + key + "\"");
    if (!dconfRead.HasValue())
    {
        return Error("Failed to execute dconf read " + key + " error: " + dconfRead.Error().message, dconfRead.Error().code);
    }
    auto dconfVal = dconfRead.Value();

    // remove newline character
    if (!dconfVal.empty() && *dconfVal.rbegin() == '\n')
    {
        dconfVal.erase(dconfVal.size() - 1);
    }

    auto comparison = CompareTyped(dconfVal, params.value, mapped.Value());
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
}

Result<Status> RemediateDconfValue(const DconfValueParams& params, IndicatorsTree& indicators, ContextInterface& context)
{
    if (params.operation != DconfOperation::Eq)
    {
        return Error("Cannot safely remediate a non-equality dconf operation", ENOTSUP);
    }
    if (params.key.empty() || params.value.empty() || params.key.find('\0') != std::string::npos || params.value.find('\0') != std::string::npos)
    {
        return Error("Dconf key and value must be specified", EINVAL);
    }

    auto audit = AuditDconfValue(params, indicators, context);
    if (!audit.HasValue() || audit.Value() == Status::Compliant)
    {
        return audit;
    }

    const auto key = EscapeForShell(params.key);
    const auto value = EscapeForShell(params.value);
    auto write = context.ExecuteCommand("dconf write \"" + key + "\" \"" + value + "\"");
    if (!write.HasValue())
    {
        return Error("Failed to execute dconf write " + params.key + ": " + write.Error().message, write.Error().code);
    }
    return AuditDconfValue(params, indicators, context);
}

} // namespace ComplianceEngine
