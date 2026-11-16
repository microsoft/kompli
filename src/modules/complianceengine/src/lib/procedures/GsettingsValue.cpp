// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <CommonUtils.h>
#include <Evaluator.h>
#include <GsettingsValue.h>
#include <Pattern.h>
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
        case GsettingsOperationType::PatternMatch:
            break;
    }
    return Error("Unsupported operation " + std::to_string(static_cast<int>(operation)), EINVAL);
}

std::string GsettingsCommand(const GsettingsValueParams& params, const std::string& operation)
{
    const auto command = "gsettings " + operation + " \"" + EscapeForShell(params.schema) + "\" \"" + EscapeForShell(params.key) + "\"";
    return !params.profile || params.profile->empty() ? command : "DCONF_PROFILE=\"" + EscapeForShell(params.profile.Value()) + "\" " + command;
}
} // namespace

Result<Status> AuditGsettingsValue(const GsettingsValueParams& params, IndicatorsTree& indicators, ContextInterface& context)
{
    auto log = context.GetLogHandle();

    if (params.profile && params.profile->find('\0') != std::string::npos)
    {
        return Error("Gsettings profile must not contain NUL", EINVAL);
    }

    const bool patternMatch = params.operation == GsettingsOperationType::PatternMatch;
    Pattern pattern;
    if (patternMatch)
    {
        if (params.keyType != GsettingsKeyType::String)
        {
            return Error("Pattern matching requires string keyType", EINVAL);
        }
        auto compiled = Pattern::Make(params.value);
        if (!compiled.HasValue())
        {
            return compiled.Error();
        }
        pattern = std::move(compiled.Value());
    }
    auto comparison = MapComparison(params.operation);
    if (!patternMatch && !comparison.HasValue())
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

    Result<std::string> gsettingsType = context.ExecuteCommand(GsettingsCommand(params, "range"));
    if (!gsettingsType.HasValue())
    {
        return Error("Failed to execute gsettings range command " + params.key + " error: " + gsettingsType.Error().message, gsettingsType.Error().code);
    }
    if (gsettingsType.Value().empty())
    {
        return Error("gsettings range returned no type for " + params.schema + " " + params.key, EINVAL);
    }
    auto gsettingKeyType = gsettingsType.Value();

    // remove newline character
    if (*gsettingKeyType.rbegin() == '\n')
    {
        gsettingKeyType.erase(gsettingKeyType.size() - 1);
    }
    auto supportedKeyTypes = {std::string("type u"), std::string("type i"), std::string("type s"), std::string("type b")};
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
    if (gsettingKeyType == "type b" && params.keyType != GsettingsKeyType::String)
    {
        return Error("Boolean gsettings keys require string keyType", EINVAL);
    }

    bool valuePrefixedByUint32 = false;
    if (gsettingKeyType == "type u" && params.operation != GsettingsOperationType::IsUnlocked)
    {
        valuePrefixedByUint32 = true;
    }
    const auto gsettingsCmd = GsettingsCommand(params, params.operation == GsettingsOperationType::IsUnlocked ? "writable" : "get");

    Result<std::string> gsettingsOutput = context.ExecuteCommand(gsettingsCmd);
    if (!gsettingsOutput.HasValue())
    {
        return Error("Failed to execute gsettings get command " + params.schema + " " + params.key + " error: " + gsettingsOutput.Error().message,
            gsettingsOutput.Error().code);
    }
    if (gsettingsOutput.Value().empty())
    {
        return Error("gsettings get returned no value for " + params.schema + " " + params.key, EINVAL);
    }
    auto gsettingsValue = gsettingsOutput.Value();

    // remove newline character
    if (*gsettingsValue.rbegin() == '\n')
    {
        gsettingsValue.erase(gsettingsValue.size() - 1);
    }
    if (gsettingsValue.empty())
    {
        return Error("gsettings returned an empty value for " + params.schema + " " + params.key, EINVAL);
    }
    const auto printedValue = gsettingsValue;
    if (gsettingKeyType == "type b" || params.operation == GsettingsOperationType::IsUnlocked)
    {
        if (gsettingsValue != "true" && gsettingsValue != "false")
        {
            return Error("Invalid Boolean gsettings output for " + params.schema + " " + params.key + ": " + gsettingsValue, EINVAL);
        }
        if (!patternMatch && gsettingKeyType == "type b" && params.operation != GsettingsOperationType::IsUnlocked && params.value != "true" &&
            params.value != "false")
        {
            return Error("Invalid Boolean gsettings comparison value: " + params.value, EINVAL);
        }
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
    if ((gsettingKeyType == "type u" || gsettingKeyType == "type i") && params.operation != GsettingsOperationType::IsUnlocked)
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
    if (patternMatch)
    {
        if (gsettingKeyType == "type s" && (gsettingsValue.size() < 2 || (gsettingsValue.front() != '\'' && gsettingsValue.front() != '"') ||
                                               gsettingsValue.front() != gsettingsValue.back()))
        {
            return Error("Invalid string gsettings output for " + params.schema + " " + params.key, EINVAL);
        }
        isCompliant = std::regex_search(printedValue, pattern.GetRegex());
    }
    else if (params.keyType == GsettingsKeyType::Number)
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
        if (gsettingKeyType == "type s" && params.operation != GsettingsOperationType::IsUnlocked)
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
}

Result<Status> RemediateGsettingsValue(const GsettingsValueParams& params, IndicatorsTree& indicators, ContextInterface& context)
{
    if (params.operation != GsettingsOperationType::Equal)
    {
        return Error("Cannot safely remediate a non-equality gsettings operation", ENOTSUP);
    }
    if (params.schema.empty() || params.key.empty() || params.value.empty() || params.schema.find('\0') != std::string::npos ||
        params.key.find('\0') != std::string::npos || params.value.find('\0') != std::string::npos)
    {
        return Error("Gsettings schema, key, and value must be specified", EINVAL);
    }

    auto audit = AuditGsettingsValue(params, indicators, context);
    if (!audit.HasValue() || audit.Value() == Status::Compliant)
    {
        return audit;
    }

    const auto value = EscapeForShell(params.value);
    auto write = context.ExecuteCommand(GsettingsCommand(params, "set") + " \"" + value + "\"");
    if (!write.HasValue())
    {
        return Error("Failed to execute gsettings set " + params.schema + " " + params.key + ": " + write.Error().message, write.Error().code);
    }
    return AuditGsettingsValue(params, indicators, context);
}

} // namespace ComplianceEngine
