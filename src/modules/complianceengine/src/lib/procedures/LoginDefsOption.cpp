// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <CommonUtils.h>
#include <Evaluator.h>
#include <LoginDefsOption.h>
#include <ProcedureMap.h>
#include <StringTools.h>
#include <TypedComparison.h>
#include <sstream>
#include <string>

using std::string;

namespace ComplianceEngine
{
namespace
{
Result<TypedComparisonOperation> MapComparison(ComparisonOperation operation)
{
    switch (operation)
    {
        case ComparisonOperation::Equal:
            return TypedComparisonOperation::Equal;
        case ComparisonOperation::NotEqual:
            return TypedComparisonOperation::NotEqual;
        case ComparisonOperation::LessThan:
            return TypedComparisonOperation::LessThan;
        case ComparisonOperation::LessOrEqual:
            return TypedComparisonOperation::LessOrEqual;
        case ComparisonOperation::GreaterThan:
            return TypedComparisonOperation::GreaterThan;
        case ComparisonOperation::GreaterOrEqual:
            return TypedComparisonOperation::GreaterOrEqual;
        default:
            break;
    }
    return Error("Unsupported comparison operation " + std::to_string(static_cast<int>(operation)), EINVAL);
}

Result<bool> NumericComparison(int lhs, int rhs, ComparisonOperation operation)
{
    auto mapped = MapComparison(operation);
    if (!mapped.HasValue())
    {
        return Error("Unsupported comparison operation for numeric value: " + mapped.Error().message, mapped.Error().code);
    }
    return CompareTyped(lhs, rhs, mapped.Value());
}

Result<bool> StringComparison(const string& lhs, const string& rhs, ComparisonOperation operation)
{
    if ((operation != ComparisonOperation::Equal) && (operation != ComparisonOperation::NotEqual))
    {
        return Error("Unsupported comparison operation for string value (only eq and ne are supported)", EINVAL);
    }
    return CompareTyped(lhs, rhs, operation == ComparisonOperation::Equal ? TypedComparisonOperation::Equal : TypedComparisonOperation::NotEqual);
}

Optional<string> FindLoginDefsValue(const string& fileContents, const string& optionName, OsConfigLogHandle logHandle)
{
    std::istringstream stream(fileContents);
    string line;
    Optional<string> foundValue;

    while (std::getline(stream, line))
    {
        auto trimmedLine = TrimWhiteSpaces(line);
        if (trimmedLine.empty() || trimmedLine[0] == '#')
        {
            continue;
        }

        // Parse KEY VALUE format
        std::istringstream iss(trimmedLine);
        string key;
        string value;
        iss >> key >> value;

        if (key == optionName)
        {
            foundValue = value;
            OsConfigLogDebug(logHandle, "LoginDefsOption: found '%s' = '%s'", optionName.c_str(), value.c_str());
            // Don't break — last occurrence wins (login.defs standard behavior)
        }
    }

    return foundValue;
}
} // anonymous namespace

Result<Status> AuditLoginDefsOption(const LoginDefsOptionParams& params, IndicatorsTree& indicators, ContextInterface& context)
{
    const string filePath = context.GetSpecialFilePath("/etc/login.defs");

    OsConfigLogDebug(context.GetLogHandle(), "LoginDefsOption: checking option '%s' %s '%s' in %s", params.option.c_str(),
        std::to_string(params.comparison).c_str(), params.value.c_str(), filePath.c_str());

    auto fileContents = context.GetFileContents(filePath);
    if (!fileContents.HasValue())
    {
        return fileContents.Error();
    }

    auto foundValue = FindLoginDefsValue(fileContents.Value(), params.option, context.GetLogHandle());
    if (!foundValue.HasValue())
    {
        return indicators.NonCompliant("Option '" + params.option + "' is not set in " + filePath);
    }

    // Try numeric comparison first
    auto lhsInt = TryStringToInt(foundValue.Value());
    auto rhsInt = TryStringToInt(params.value);

    if (lhsInt.HasValue() && rhsInt.HasValue())
    {
        // Both values are numeric — use numeric comparison
        auto result = NumericComparison(lhsInt.Value(), rhsInt.Value(), params.comparison);
        if (!result.HasValue())
        {
            return result.Error();
        }

        if (result.Value())
        {
            return indicators.Compliant(params.option + " = " + foundValue.Value() + " (" + std::to_string(params.comparison) + " " + params.value +
                                        ")");
        }

        return indicators.NonCompliant(params.option + " = " + foundValue.Value() + " (expected " + std::to_string(params.comparison) + " " +
                                       params.value + ")");
    }

    // login.defs accepts ENCRYPT_METHOD names case-insensitively.
    const bool ignoreCase = params.option == "ENCRYPT_METHOD";
    const string actualValue = ignoreCase ? ToLower(foundValue.Value()) : foundValue.Value();
    const string expectedValue = ignoreCase ? ToLower(params.value) : params.value;
    auto result = StringComparison(actualValue, expectedValue, params.comparison);
    if (!result.HasValue())
    {
        return result.Error();
    }

    if (result.Value())
    {
        return indicators.Compliant(params.option + " = " + foundValue.Value() + " (" + std::to_string(params.comparison) + " " + params.value + ")");
    }

    return indicators.NonCompliant(params.option + " = " + foundValue.Value() + " (expected " + std::to_string(params.comparison) + " " + params.value +
                                   ")");
}
} // namespace ComplianceEngine
