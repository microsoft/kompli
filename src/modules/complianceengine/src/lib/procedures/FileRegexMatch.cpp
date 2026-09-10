// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <Evaluator.h>
#include <FileRegexMatch.h>
#include <Optional.h>
#include <ProcedureMap.h>
#include <Regex.h>
#include <Result.h>
#include <Telemetry.h>
#include <cerrno>
#include <cstdlib>
#include <dirent.h>
#include <fstream>

namespace ComplianceEngine
{
using std::ifstream;
using std::string;
using std::regex_constants::syntax_option_type;
namespace
{

Result<long long> ParseInteger(const std::string& text)
{
    if (text.empty())
    {
        return Error("Integer value is empty", EINVAL);
    }
    const size_t firstDigit = (text[0] == '+' || text[0] == '-') ? 1 : 0;
    if (firstDigit == text.size() || text.find_first_not_of("0123456789", firstDigit) != std::string::npos)
    {
        return Error("Invalid integer syntax", EINVAL);
    }
    errno = 0;
    char* end = nullptr;
    const auto value = std::strtoll(text.c_str(), &end, 10);
    if (errno == ERANGE)
    {
        return Error("Integer value is out of range", ERANGE);
    }
    if (end != text.c_str() + text.size())
    {
        return Error("Invalid integer syntax", EINVAL);
    }
    return value;
}

// syntax Options for matchPattern and statePattern respectively
using MatchStateSyntaxOptions = std::pair<syntax_option_type, syntax_option_type>;

struct MultilineMatchResult
{
    // At least one selected value passes, or every selected value passes when allMatches is set.
    bool success;
    // At least one line matches matchPattern, regardless of its state or numeric constraints.
    bool selected;
};

// Select lines with matchPattern, then evaluate their state and numeric constraints.
Result<MultilineMatchResult> MultilineMatch(const std::string& filename, const string& matchPattern, const Optional<string>& statePattern,
    MatchStateSyntaxOptions syntaxOptions, ContextInterface& context, const Optional<long long>& minimumValue, const Optional<long long>& maximumValue, bool allMatches)
{
    // We still need to manually consume the patterns as strings as the case sensitivity is handled
    // dynamically depending on the ignoreCase field value.
    Optional<regex> matchRegex;
    Optional<regex> stateRegex;

    ifstream input(filename);
    if (!input.is_open())
    {
        return Error("Failed to open file: " + filename, errno);
    }
    try
    {
        matchRegex = regex(matchPattern, syntaxOptions.first);
        if (statePattern.HasValue())
        {
            stateRegex = regex(statePattern.Value(), syntaxOptions.second);
        }
    }
    catch (const regex_error& e)
    {
        OsConfigLogInfo(context.GetLogHandle(), "Regex error: %s", e.what());
        return Error("Regex error: " + string(e.what()), EINVAL);
    }

    int lineNumber = 0;
    bool matchingValueFound = false;
    bool selected = false;

    string line;

    // Special case for empty files, read empty line then
    while (getline(input, line) || lineNumber == 0)
    {
        lineNumber++;
        OsConfigLogDebug(context.GetLogHandle(), "Matching line %d: '%s', pattern: '%s'", lineNumber, line.c_str(), matchPattern.c_str());
        smatch match;
        if (regex_search(line, match, matchRegex.Value()))
        {
            selected = true;
            const auto capturedValue = match.size() > 1 ? match[1].str() : match[0].str();
            bool valueMatches = true;
            if (minimumValue.HasValue() || maximumValue.HasValue())
            {
                const auto numericValue = ParseInteger(capturedValue);
                valueMatches = numericValue.HasValue() && (!minimumValue.HasValue() || numericValue.Value() >= minimumValue.Value()) &&
                               (!maximumValue.HasValue() || numericValue.Value() <= maximumValue.Value());
            }
            if (!valueMatches)
            {
                if (allMatches)
                {
                    return MultilineMatchResult{false, selected};
                }
                continue;
            }
            OsConfigLogDebug(context.GetLogHandle(), "Matched line %d: %s", lineNumber, line.c_str());
            if (stateRegex.HasValue())
            {
                assert(match.ready());
                assert(match.size() > 0);
                auto valueToMatch = match.size() > 1 ? match[1].str() : match[0].str();
                OsConfigLogDebug(context.GetLogHandle(), "Value to match: %s", valueToMatch.c_str());
                if (regex_search(valueToMatch, stateRegex.Value()))
                {
                    OsConfigLogDebug(context.GetLogHandle(), "Matched line %d: %s", lineNumber, line.c_str());
                    matchingValueFound = true;
                    if (!allMatches)
                    {
                        return MultilineMatchResult{true, selected};
                    }
                }
                else if (allMatches)
                {
                    return MultilineMatchResult{false, selected};
                }
            }
            else
            {
                OsConfigLogDebug(context.GetLogHandle(), "Matched line %d: %s", lineNumber, line.c_str());
                matchingValueFound = true;
                if (!allMatches)
                {
                    return MultilineMatchResult{true, selected};
                }
            }
        }
    }
    return MultilineMatchResult{matchingValueFound, selected};
}
} // anonymous namespace

Result<Status> AuditFileRegexMatch(const FileRegexMatchParams& params, IndicatorsTree& indicators, ContextInterface& context)
{
    Optional<long long> minimumValue;
    Optional<long long> maximumValue;
    if (params.minimumValue.HasValue())
    {
        const auto bound = ParseInteger(params.minimumValue.Value());
        if (!bound.HasValue())
        {
            return Error("Invalid minimumValue: " + bound.Error().message, bound.Error().code);
        }
        minimumValue = bound.Value();
    }
    if (params.maximumValue.HasValue())
    {
        const auto bound = ParseInteger(params.maximumValue.Value());
        if (!bound.HasValue())
        {
            return Error("Invalid maximumValue: " + bound.Error().message, bound.Error().code);
        }
        maximumValue = bound.Value();
    }
    if (minimumValue.HasValue() && maximumValue.HasValue() && minimumValue.Value() > maximumValue.Value())
    {
        return Error("minimumValue exceeds maximumValue", EINVAL);
    }
    // These optional fields are guaranteed to have default values
    assert(params.matchOperation.HasValue());
    const auto matchOperation = params.matchOperation.Value();
    assert(params.stateOperation.HasValue());
    const auto stateOperation = params.stateOperation.Value();
    assert(params.behavior.HasValue());
    const auto behavior = params.behavior.Value();

    MatchStateSyntaxOptions syntaxOptions = std::make_pair(std::regex_constants::ECMAScript, std::regex_constants::ECMAScript);
    if (params.ignoreCase.HasValue())
    {
        switch (params.ignoreCase.Value())
        {
            case IgnoreCase::Both:
                syntaxOptions.first |= std::regex_constants::icase;
                syntaxOptions.second |= std::regex_constants::icase;
                break;
            case IgnoreCase::MatchPattern:
                syntaxOptions.first |= std::regex_constants::icase;
                break;
            case IgnoreCase::StatePattern:
                syntaxOptions.second |= std::regex_constants::icase;
                break;
        }
    }

    // Currently only "pattern match" is supported for both match and state operations.
    // Depending on use cases, we may want to support other operations in the future.
    if (matchOperation != Operation::Match)
    {
        return Error(string("Unsupported operation '") + std::to_string(matchOperation) + string("'"), EINVAL);
    }
    if (stateOperation != Operation::Match)
    {
        return Error(string("Unsupported operation '") + std::to_string(stateOperation) + string("'"), EINVAL);
    }

    auto* dir = opendir(params.path.c_str());
    if (dir == nullptr)
    {
        int status = errno;
        if (params.allMatches.Value())
        {
            if (status != ENOENT)
            {
                return Error("Failed to open directory '" + params.path + "'", status);
            }
            if (behavior == Behavior::AnyExist)
            {
                return indicators.Compliant("No selected settings in missing directory '" + params.path + "'");
            }
        }
        OsConfigLogInfo(context.GetLogHandle(), "Failed to open directory '%s': %s", params.path.c_str(), strerror(status));
        if (Behavior::NoneExist == behavior)
        {
            return Status::Compliant;
        }
        return indicators.NonCompliant("Failed to open directory '" + params.path + "': " + strerror(status));
    }
    auto dirCloser = std::unique_ptr<DIR, int (*)(DIR*)>(dir, closedir);

    int matchCount = 0;
    int mismatchCount = 0;
    int fileCount = 0;
    int errorCount = 0;
    int unselectedCount = 0;
    struct dirent* entry = nullptr;
    for (errno = 0, entry = readdir(dir); nullptr != entry; errno = 0, entry = readdir(dir))
    {
        if (entry->d_type != DT_REG && entry->d_type != DT_LNK)
        {
            continue;
        }

        if (entry->d_type == DT_LNK)
        {
            struct stat st;
            if (0 != stat((params.path + "/" + entry->d_name).c_str(), &st))
            {
                const int status = errno;
                OsConfigLogInfo(context.GetLogHandle(), "Failed to stat symlink target '%s/%s': %s", params.path.c_str(), entry->d_name, strerror(status));
                continue;
            }

            if (!S_ISREG(st.st_mode))
            {
                continue;
            }
        }

        if (!regex_match(entry->d_name, params.filenamePattern))
        {
            OsConfigLogDebug(context.GetLogHandle(), "Ignoring file '%s' in directory '%s'", entry->d_name, params.path.c_str());
            continue;
        }
        fileCount++;
        auto filename = params.path + "/" + entry->d_name;
        auto matchResult = MultilineMatch(filename, params.matchPattern, params.statePattern, syntaxOptions, context, minimumValue, maximumValue,
            params.allMatches.Value());
        if (!matchResult.HasValue())
        {
            OsConfigLogInfo(context.GetLogHandle(), "Failed to match file '%s': %s", filename.c_str(), matchResult.Error().message.c_str());
            errorCount++;
        }
        else if (params.allMatches.Value() && !matchResult.Value().selected)
        {
            unselectedCount++;
        }
        else if (matchResult.Value().success)
        {
            matchCount++;
        }
        else
        {
            mismatchCount++;
        }
    }

    if (errno != 0)
    {
        int status = errno;
        OsConfigLogError(context.GetLogHandle(), "Failed to read directory '%s': %s", params.path.c_str(), strerror(status));
        OSConfigTelemetryStatusTrace("readdir", status);
        return Error("Failed to read directory '" + params.path + "': " + strerror(status), status);
    }

    // This is a direct mapping of OVAL ExistenceEnumerator
    // see https://oval.mitre.org/language/version5.9/ovalsc/documentation/oval-common-schema.html#ExistenceEnumeration for details
    OsConfigLogInfo(context.GetLogHandle(), "Validating pattern matching results, behavior: '%s', matched: %d, mismatched: %d, errors: %d",
        std::to_string(behavior).c_str(), matchCount, mismatchCount, errorCount);
    if (matchCount + mismatchCount + errorCount + unselectedCount != fileCount)
    {
        return Error("Counters mismatch");
    }

    if (params.allMatches.Value() && behavior != Behavior::NoneExist)
    {
        if (errorCount > 0)
        {
            return Error("Error occurred during pattern matching", EINVAL);
        }
        if (mismatchCount > 0)
        {
            return indicators.NonCompliant("At least one selected setting failed its state constraint");
        }
    }

    if (Behavior::AllExist == behavior)
    {
        if (mismatchCount > 0)
        {
            return indicators.NonCompliant("At least one file did not match the pattern");
        }

        if (errorCount > 0)
        {
            return Error("Error occurred during pattern matching", EINVAL);
        }

        if (matchCount > 0)
        {
            return indicators.Compliant("All " + std::to_string(fileCount) + " files matched the pattern");
        }
        else
        {
            return indicators.NonCompliant("Expected all files to match, but only " + std::to_string(matchCount) + " out of " +
                                           std::to_string(fileCount) + " matched");
        }
    }
    else if (Behavior::AnyExist == behavior)
    {
        if ((matchCount == 0) && (errorCount > 0))
        {
            return Error("Error occurred during pattern matching", EINVAL);
        }
        return indicators.Compliant("Found " + std::to_string(matchCount) + " matches");
    }
    else if (Behavior::AtLeastOneExists == behavior)
    {
        if (matchCount > 0)
        {
            return indicators.Compliant("At least one file matched, found " + std::to_string(matchCount) + " matches");
        }
        if (errorCount > 0)
        {
            return Error("Error occurred during pattern matching", EINVAL);
        }
        return indicators.NonCompliant("Expected at least one file to match, but none did");
    }
    else if (Behavior::NoneExist == behavior)
    {
        if (matchCount > 0)
        {
            return indicators.NonCompliant("Expected no files to match, but " + std::to_string(matchCount) + " matched");
        }

        if (errorCount > 0)
        {
            return Error("Error occurred during pattern matching", EINVAL);
        }
        return indicators.Compliant("No files matched the pattern");
    }
    else if (Behavior::OnlyOneExists == behavior)
    {
        if (matchCount == 1 && errorCount == 0)
        {
            return indicators.Compliant("Exactly one file matched the pattern");
        }
        if (matchCount > 1)
        {
            return indicators.NonCompliant("Expected only one file to match, but " + std::to_string(matchCount) + " matched");
        }
        if (errorCount > 0)
        {
            return Error("Error occurred during pattern matching", EINVAL);
        }
        return indicators.NonCompliant("Expected exactly one file to match, but none did");
    }
    else
    {
        return Error("Unknown behavior: " + std::to_string(params.behavior), EINVAL);
    }
}
} // namespace ComplianceEngine
