// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <CommonUtils.h>
#include <Evaluator.h>
#include <LoginDefsOption.h>
#include <ProcedureMap.h>
#include <StringTools.h>
#include <TypedComparison.h>
#include <parsers/LoginDefs.h>
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

Optional<string> FindLoginDefsValue(const LoginDefs::Document& document, const string& optionName, OsConfigLogHandle logHandle)
{
    Optional<string> foundValue;

    for (const auto* record : document.FindAll(optionName))
    {
        std::istringstream valueStream(document.Text(record->valueSpan));
        string value;
        valueStream >> value;
        foundValue = value;
        OsConfigLogDebug(logHandle, "LoginDefsOption: found '%s' = '%s'", optionName.c_str(), value.c_str());
    }

    return foundValue;
}

bool IsNumericLoginDefsOption(const string& option)
{
    return (option == "PASS_MAX_DAYS") || (option == "PASS_MIN_DAYS") || (option == "PASS_WARN_AGE") || (option == "UID_MIN") || (option == "UID_MAX");
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

    const bool numericOption = IsNumericLoginDefsOption(params.option);
    auto rhsInt = TryStringToInt(params.value);
    if ((numericOption) && (!rhsInt.HasValue()))
    {
        return Error("Invalid " + params.option + " comparison target: " + rhsInt.Error().message, rhsInt.Error().code);
    }

    const auto parsed = LoginDefs::Parse(fileContents.Value(), filePath);
    if (!parsed.HasValue())
    {
        return parsed.Error();
    }
    const auto* selected = parsed.Value().FindLast(params.option);
    if ((nullptr != selected) && parsed.Value().HasEmbeddedNul(*selected))
    {
        return Error("Invalid " + params.option + " value: embedded NUL", EINVAL);
    }
    auto foundValue = FindLoginDefsValue(parsed.Value(), params.option, context.GetLogHandle());
    if (!foundValue.HasValue())
    {
        return indicators.NonCompliant("Option '" + params.option + "' is not set in " + filePath);
    }

    // Try numeric comparison first
    auto lhsInt = TryStringToInt(foundValue.Value());

    if (numericOption)
    {
        if (!lhsInt.HasValue())
        {
            return Error("Invalid " + params.option + " value: " + lhsInt.Error().message, lhsInt.Error().code);
        }
    }

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
