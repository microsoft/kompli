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
#include <parsers/LoginDefs.h>
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

Result<bool> EncryptionComparison(LoginDefs::EncryptionMethod lhs, LoginDefs::EncryptionMethod rhs, ComparisonOperation operation)
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

bool IsPasswordAgingOption(const string& option)
{
    return (option == "PASS_MAX_DAYS") || (option == "PASS_MIN_DAYS") || (option == "PASS_WARN_AGE");
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
    string result;
    size_t copiedEnd = 0;
    bool replaced = false;
    size_t lineStart = 0;
    while (lineStart <= contents.size())
    {
        const size_t lineEnd = contents.find('\n', lineStart);
        const size_t end = lineEnd == string::npos ? contents.size() : lineEnd;
        size_t cursor = lineStart;
        while (cursor < end && IsAsciiWhitespace(static_cast<unsigned char>(contents[cursor])))
        {
            cursor++;
        }
        if (cursor < end && contents[cursor] != '#')
        {
            const size_t keyStart = cursor;
            while (cursor < end && !IsAsciiWhitespace(static_cast<unsigned char>(contents[cursor])))
            {
                cursor++;
            }
            if (contents.compare(keyStart, cursor - keyStart, option) == 0)
            {
                while (cursor < end && IsAsciiWhitespace(static_cast<unsigned char>(contents[cursor])))
                {
                    cursor++;
                }
                size_t valueEnd = cursor + StripComment(contents.substr(cursor, end - cursor)).size();
                while (valueEnd > cursor && IsAsciiWhitespace(static_cast<unsigned char>(contents[valueEnd - 1])))
                {
                    --valueEnd;
                }
                result.append(contents, copiedEnd, cursor - copiedEnd);
                result += value;
                copiedEnd = valueEnd;
                replaced = true;
            }
        }
        if (lineEnd == string::npos)
        {
            break;
        }
        lineStart = lineEnd + 1;
    }

    result.append(contents, copiedEnd, string::npos);
    if (replaced)
    {
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
    if (!IsPasswordAgingOption(params.option) && params.option != "ENCRYPT_METHOD")
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

    const bool numericOption = IsPasswordAgingOption(params.option);
    Optional<int> numericTarget;
    Optional<LoginDefs::EncryptionMethod> methodTarget;
    if (numericOption)
    {
        const auto target = TryStringToInt(params.value);
        if (!target.HasValue())
        {
            return Error("Invalid " + params.option + " comparison target: " + target.Error().message, target.Error().code);
        }
        numericTarget = target.Value();
    }
    else
    {
        const auto target = LoginDefs::ParseEncryptionMethod(params.value);
        if (!target.HasValue())
        {
            return Error("Invalid ENCRYPT_METHOD comparison target: " + target.Error().message, target.Error().code);
        }
        methodTarget = target.Value();
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
        auto result = NumericComparison(actual, numericTarget.Value(), params.comparison);
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
    const auto method = parsed.Value().encryptMethod.Value();
    const string value = LoginDefs::EncryptionMethodName(method);
    OsConfigLogDebug(context.GetLogHandle(), "LoginDefsOption: found '%s' = '%s'", params.option.c_str(), value.c_str());
    auto result = EncryptionComparison(method, methodTarget.Value(), params.comparison);
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
