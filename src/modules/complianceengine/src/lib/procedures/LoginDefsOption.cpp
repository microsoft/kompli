// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <AtomicFile.h>
#include <CommonUtils.h>
#include <Evaluator.h>
#include <LoginDefsOption.h>
#include <ProcedureMap.h>
#include <StringTools.h>
#include <TypedComparison.h>
#include <climits>
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

bool IsNumericLoginDefsOption(const string& option)
{
    return (option == "PASS_MAX_DAYS") || (option == "PASS_MIN_DAYS") || (option == "PASS_WARN_AGE") || (option == "UID_MIN") || (option == "UID_MAX");
}

Result<string> GetRemediationValue(const LoginDefsOptionParams& params)
{
    if (params.option.empty() || params.option.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_") != string::npos)
    {
        return Error("Invalid login.defs option name", EINVAL);
    }
    if (params.value.empty() || params.value.find_first_of(" \t\r\n") != string::npos)
    {
        return Error("Invalid login.defs option value", EINVAL);
    }

    if (params.comparison == ComparisonOperation::Equal || params.comparison == ComparisonOperation::LessOrEqual || params.comparison == ComparisonOperation::GreaterOrEqual)
    {
        return params.value;
    }
    if (params.comparison == ComparisonOperation::NotEqual)
    {
        return Error("Cannot safely remediate a not-equal login.defs comparison", ENOTSUP);
    }

    auto value = TryStringToInt(params.value);
    if (!value.HasValue())
    {
        return Error("Strict login.defs comparisons require an integer value", EINVAL);
    }
    if (params.comparison == ComparisonOperation::LessThan)
    {
        if (value.Value() == INT_MIN)
        {
            return Error("Cannot remediate a less-than comparison below the minimum integer", ERANGE);
        }
        return std::to_string(value.Value() - 1);
    }
    if (params.comparison == ComparisonOperation::GreaterThan)
    {
        if (value.Value() == INT_MAX)
        {
            return Error("Cannot remediate a greater-than comparison above the maximum integer", ERANGE);
        }
        return std::to_string(value.Value() + 1);
    }
    return Error("Unsupported login.defs comparison operation", ENOTSUP);
}

string ReplaceEffectiveLoginDefsValue(const string& contents, const string& option, const string& value)
{
    string result = contents;
    size_t replacementStart = string::npos;
    size_t replacementEnd = string::npos;
    size_t lineStart = 0;
    while (lineStart <= contents.size())
    {
        const size_t lineEnd = contents.find('\n', lineStart);
        const size_t end = lineEnd == string::npos ? contents.size() : lineEnd;
        size_t cursor = lineStart;
        while (cursor < end && (contents[cursor] == ' ' || contents[cursor] == '\t'))
        {
            cursor++;
        }
        if (cursor < end && contents[cursor] != '#')
        {
            const size_t keyStart = cursor;
            while (cursor < end && contents[cursor] != ' ' && contents[cursor] != '\t')
            {
                cursor++;
            }
            if (contents.compare(keyStart, cursor - keyStart, option) == 0)
            {
                while (cursor < end && (contents[cursor] == ' ' || contents[cursor] == '\t'))
                {
                    cursor++;
                }
                replacementStart = cursor;
                while (cursor < end && contents[cursor] != ' ' && contents[cursor] != '\t' && contents[cursor] != '#')
                {
                    cursor++;
                }
                replacementEnd = cursor;
            }
        }
        if (lineEnd == string::npos)
        {
            break;
        }
        lineStart = lineEnd + 1;
    }

    if (replacementStart != string::npos)
    {
        result.replace(replacementStart, replacementEnd - replacementStart, value);
        return result;
    }
    if (!result.empty() && result.back() != '\n')
    {
        result.push_back('\n');
    }
    result += option + "\t" + value + "\n";
    return result;
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

    auto foundValue = FindLoginDefsValue(fileContents.Value(), params.option, context.GetLogHandle());
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

Result<Status> RemediateLoginDefsOption(const LoginDefsOptionParams& params, IndicatorsTree& indicators, ContextInterface& context)
{
    const auto remediationValue = GetRemediationValue(params);
    if (!remediationValue.HasValue())
    {
        return remediationValue.Error();
    }

    auto audit = AuditLoginDefsOption(params, indicators, context);
    if (!audit.HasValue() || audit.Value() == Status::Compliant)
    {
        return audit;
    }

    const string filePath = context.GetSpecialFilePath("/etc/login.defs");
    auto fileContents = context.GetFileContents(filePath);
    if (!fileContents.HasValue())
    {
        return fileContents.Error();
    }
    const string updated = ReplaceEffectiveLoginDefsValue(fileContents.Value(), params.option, remediationValue.Value());
    if (updated == fileContents.Value())
    {
        return Error("login.defs remediation produced no change", EINVAL);
    }

    auto replaced = ReplaceFileContentsAtomic(filePath, updated);
    if (!replaced.HasValue())
    {
        return replaced.Error();
    }

    auto postAudit = AuditLoginDefsOption(params, indicators, context);
    if (postAudit.HasValue() && postAudit.Value() == Status::Compliant)
    {
        return postAudit;
    }

    auto rollback = ReplaceFileContentsAtomic(filePath, fileContents.Value());
    if (!rollback.HasValue())
    {
        const string reason = postAudit.HasValue() ? "login.defs remained noncompliant" : postAudit.Error().message;
        return Error(reason + "; rollback failed: " + rollback.Error().message, rollback.Error().code);
    }
    return postAudit;
}
} // namespace ComplianceEngine
