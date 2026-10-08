// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <CommonUtils.h>
#include <Evaluator.h>
#include <GsettingsValue.h>
#include <ProcedureMap.h>
#include <StringTools.h>
#include <TypedComparison.h>
#include <algorithm>
#include <cctype>
#include <cstdint>

namespace ComplianceEngine
{
namespace
{
Result<TypedComparisonOperation> MapComparison(GsettingsOperationType operation)
{
    switch (operation)
    {
        case GsettingsOperationType::LessThan:
            return TypedComparisonOperation::LessThan;
        case GsettingsOperationType::GreaterThan:
            return TypedComparisonOperation::GreaterThan;
        case GsettingsOperationType::Equal:
        case GsettingsOperationType::IsUnlocked:
            return TypedComparisonOperation::Equal;
        case GsettingsOperationType::NotEqual:
            return TypedComparisonOperation::NotEqual;
    }
    return Error("Unsupported operation", EINVAL);
}
} // namespace

Result<Status> AuditGsettingsValue(const GsettingsValueParams& params, IndicatorsTree& indicators, ContextInterface& context)
{
    auto log = context.GetLogHandle();

    const auto escapedSchema = EscapeForShell(params.schema);
    const auto escapedKey = EscapeForShell(params.key);

    auto comparison = MapComparison(params.operation);
    if (!comparison.HasValue())
    {
        return comparison.Error();
    }
    if ((params.keyType != GsettingsKeyType::Number) &&
        ((params.operation == GsettingsOperationType::LessThan) || (params.operation == GsettingsOperationType::GreaterThan)))
    {
        return Error("Unsupported operation " + std::to_string(params.operation), EINVAL);
    }
    if (params.operation == GsettingsOperationType::IsUnlocked && params.keyType != GsettingsKeyType::String)
    {
        return Error("Not supported keyType " + std::to_string(params.keyType) + " for is-unlocked operation", EINVAL);
    }

    // auto numberValue = TryStringToInt(params.value);
    //     if (!numberValue.HasValue()) {
    //         return numberValue.Error();
    //     }

    char* endptr = nullptr;
    std::int64_t numberValue = 0;
    if (params.keyType == GsettingsKeyType::Number)
    {
        numberValue = strtol(params.value.c_str(), &endptr, 10);
        if ((nullptr == endptr) || ('\0' != *endptr))
        {
            OsConfigLogError(log, "Invalid keyValue value not a number: %s", params.value.c_str());
            return Error("Invalid argument value: not a number " + params.value, EINVAL);
        }
    }

    Result<std::string> gsettingsType = context.ExecuteCommand("gsettings range \"" + escapedSchema + "\" \"" + escapedKey + "\"");
    if (!gsettingsType.HasValue() || gsettingsType.Value().empty())
    {
        return Error("Failed to execute gsettings range command " + params.key + " error: " + gsettingsType.Error().message, gsettingsType.Error().code);
    }
    auto gsettingKeyType = gsettingsType.Value();

    // remove newline character
    if (*gsettingKeyType.rbegin() == '\n')
    {
        gsettingKeyType.erase(gsettingKeyType.size() - 1);
    }
    auto supportedKeyTypes = {std::string("type u"), std::string("type i"), std::string("type s")};
    bool isKeyTypeSuported = false;
    for (auto kt : supportedKeyTypes)
    {
        if (kt == gsettingKeyType)
        {
            isKeyTypeSuported = true;
            break;
        }
    }

    if (!isKeyTypeSuported)
    {
        return Error("Unsuported  gsettings key type for schema " + params.schema + " params.key  " + params.key + " keyType: " + gsettingKeyType, EINVAL);
    }

    bool valuePrefixedByUint32 = false;
    if (gsettingKeyType == "type u")
    {
        valuePrefixedByUint32 = true;
    }
    auto gsettingsCmd = std::string("gsettings get \"") + escapedSchema + "\" \"" + escapedKey + "\"";
    if (params.operation == GsettingsOperationType::IsUnlocked)
    {
        gsettingsCmd = std::string("gsettings writable \"" + escapedSchema + "\" \"" + escapedKey + "\"");
    }

    Result<std::string> gsettingsOutput = context.ExecuteCommand(gsettingsCmd);
    if (!gsettingsOutput.HasValue() || gsettingsOutput.Value().empty())
    {
        return Error("Failed to execute gsettings get command " + params.schema + " " + params.key + " error: " + gsettingsOutput.Error().message,
            gsettingsOutput.Error().code);
    }
    auto gsettingsValue = gsettingsOutput.Value();

    // remove newline character
    if (*gsettingsValue.rbegin() == '\n')
    {
        gsettingsValue.erase(gsettingsValue.size() - 1);
    }

    if (valuePrefixedByUint32)
    {
        auto prefix = std::string("uint32");
        auto pos = gsettingsValue.find(prefix);
        if (pos == std::string::npos)
        {
            return Error("Failed to parse gsettings get command " + params.schema + " " + params.key + " output: " + gsettingsValue +
                             " expected uint32 prefix",
                EINVAL);
        }
        gsettingsValue.erase(pos, prefix.length() + 1);
    }
    std::int64_t gsettingsNumberValue = 0;
    if (gsettingKeyType == "type u" || gsettingKeyType == "type i")
    {
        endptr = nullptr;
        gsettingsNumberValue = strtol(gsettingsValue.c_str(), &endptr, 10);
        if ((nullptr == endptr) || ('\0' != *endptr))
        {
            OsConfigLogError(log, "Invalid keyValue value not a number: %s", params.value.c_str());
            return Error("Invalid operation value: not a number " + params.value, EINVAL);
        }
    }
    bool isCompliant = false;
    if (params.keyType == GsettingsKeyType::Number)
    {
        // Preserve the previous numeric comparator's int operand width.
        auto result = CompareTyped(static_cast<int>(gsettingsNumberValue), static_cast<int>(numberValue), comparison.Value());
        if (!result.HasValue())
        {
            return result.Error();
        }
        isCompliant = result.Value();
    }
    else
    {
        if (params.keyType == GsettingsKeyType::String && params.operation != GsettingsOperationType::IsUnlocked)
        {
            auto quote = *gsettingsValue.begin();
            auto endQuote = *gsettingsValue.rbegin();
            if (quote != '"' && quote != '\'' && quote != endQuote)
            {
                return indicators.NonCompliant("Gsettings key " + params.schema + " " + params.key + " " + std::to_string(params.operation) +
                                               " value " + params.value);
            }
            gsettingsValue = gsettingsValue.substr(1, gsettingsValue.length() - 2);
        }
        auto result = CompareTyped(gsettingsValue, params.value, comparison.Value());
        if (!result.HasValue())
        {
            return result.Error();
        }
        isCompliant = result.Value();
    }

    if (isCompliant)
    {
        return indicators.Compliant("Gsettings key " + params.schema + " " + params.key + " " + std::to_string(params.operation) + " value " + params.value);
    }
    else
    {
        return indicators.NonCompliant("Gsettings key " + params.schema + " " + params.key + " " + std::to_string(params.operation) + " value " + params.value);
    }

    return indicators.NonCompliant("Not supported Gsettings key operation '" + std::to_string(params.operation) + "'");
}

} // namespace ComplianceEngine
