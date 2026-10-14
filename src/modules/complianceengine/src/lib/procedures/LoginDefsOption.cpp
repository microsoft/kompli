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
#include <utility>

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

const Optional<int>* NumericOption(const LoginDefs::Document& document, const string& option)
{
    if (option == "PASS_MAX_DAYS")
        return &document.passMaxDays;
    if (option == "PASS_MIN_DAYS")
        return &document.passMinDays;
    if (option == "PASS_WARN_AGE")
        return &document.passWarnAge;
    return nullptr;
}

bool IsNumericLoginDefsOption(const string& option)
{
    return (option == "PASS_MAX_DAYS") || (option == "PASS_MIN_DAYS") || (option == "PASS_WARN_AGE");
}
} // anonymous namespace

Result<Status> AuditLoginDefsOption(const LoginDefsOptionParams& params, IndicatorsTree& indicators, ContextInterface& context)
{
    if (!IsNumericLoginDefsOption(params.option) && params.option != "ENCRYPT_METHOD")
    {
        OsConfigLogError(context.GetLogHandle(), "LoginDefsOption: unsupported option '%s'", params.option.c_str());
        return Error("Unsupported login.defs option: " + params.option, EINVAL);
    }
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

    const auto parsed = LoginDefs::Parse(std::move(fileContents.Value()), filePath, context.GetLogHandle());
    if (!parsed.HasValue())
    {
        return parsed.Error();
    }
    if (numericOption)
    {
        const auto* found = NumericOption(parsed.Value(), params.option);
        if (found == nullptr || !found->HasValue())
        {
            return indicators.NonCompliant("Option '" + params.option + "' is not set in " + filePath);
        }
        const auto actual = found->Value();
        OsConfigLogDebug(context.GetLogHandle(), "LoginDefsOption: found '%s' = '%d'", params.option.c_str(), actual);
        auto result = NumericComparison(actual, rhsInt.Value(), params.comparison);
        if (!result.HasValue())
        {
            return result.Error();
        }
        if (result.Value())
        {
            return indicators.Compliant(params.option + " = " + std::to_string(actual) + " (" + std::to_string(params.comparison) + " " + params.value +
                                        ")");
        }
        return indicators.NonCompliant(params.option + " = " + std::to_string(actual) + " (expected " + std::to_string(params.comparison) + " " +
                                       params.value + ")");
    }

    if (!parsed.Value().encryptMethod.HasValue())
    {
        return indicators.NonCompliant("Option '" + params.option + "' is not set in " + filePath);
    }
    std::istringstream valueStream(parsed.Value().encryptMethod.Value());
    string value;
    valueStream >> value;
    OsConfigLogDebug(context.GetLogHandle(), "LoginDefsOption: found '%s' = '%s'", params.option.c_str(), value.c_str());
    auto lhsInt = TryStringToInt(value);
    if (lhsInt.HasValue() && rhsInt.HasValue())
    {
        auto result = NumericComparison(lhsInt.Value(), rhsInt.Value(), params.comparison);
        if (!result.HasValue())
        {
            return result.Error();
        }
        return result.Value() ?
                   indicators.Compliant(params.option + " = " + value + " (" + std::to_string(params.comparison) + " " + params.value + ")") :
                   indicators.NonCompliant(params.option + " = " + value + " (expected " + std::to_string(params.comparison) + " " + params.value + ")");
    }

    // login.defs accepts ENCRYPT_METHOD names case-insensitively.
    const bool ignoreCase = params.option == "ENCRYPT_METHOD";
    const string actualValue = ignoreCase ? ToLower(value) : value;
    const string expectedValue = ignoreCase ? ToLower(params.value) : params.value;
    auto result = StringComparison(actualValue, expectedValue, params.comparison);
    if (!result.HasValue())
    {
        return result.Error();
    }

    if (result.Value())
    {
        return indicators.Compliant(params.option + " = " + value + " (" + std::to_string(params.comparison) + " " + params.value + ")");
    }

    return indicators.NonCompliant(params.option + " = " + value + " (expected " + std::to_string(params.comparison) + " " + params.value + ")");
}
} // namespace ComplianceEngine
