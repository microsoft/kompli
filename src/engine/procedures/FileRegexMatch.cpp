// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <Evaluator.h>
#include <FileRegexMatch.h>
#include <Optional.h>
#include <ProcedureMap.h>
#include <Result.h>
#include <ResultEvidence.h>
#include <cerrno>
#include <cstdlib>
#include <dirent.h>
#include <fstream>
#include <limits>
#include <memory>
#include <regex>
#include <sys/stat.h>

namespace ComplianceEngine
{
using std::ifstream;
using std::regex;
using std::regex_error;
using std::regex_match;
using std::regex_search;
using std::smatch;
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

// The producer is below, outside the anonymous namespace, so a later
// content-acquisition caller can feed acquired content without changing
// selection or source evidence semantics.
} // anonymous namespace

Result<bool> EvaluateFileRegexContent(std::istream& input, const std::string& filename, const std::string& matchPattern, const regex& matchRegex,
    const Optional<regex>& stateRegex, ContextInterface& context, const Optional<long long>& minimumValue, const Optional<long long>& maximumValue,
    bool wholeFile, FileRegexOccurrenceSink& sink)
{
    try
    {
        size_t ordinal = 0;
        const auto evaluateMatch = [&](const smatch& match, size_t position) -> Result<SourceCheckValue> {
            const auto capturedValue = (match.size() > 1) ? match[1].str() : match[0].str();
            bool valueMatches = true;
            if (minimumValue.HasValue() || maximumValue.HasValue())
            {
                const auto numericValue = ParseInteger(capturedValue);
                valueMatches = numericValue.HasValue() && (!minimumValue.HasValue() || (numericValue.Value() >= minimumValue.Value())) &&
                               (!maximumValue.HasValue() || (numericValue.Value() <= maximumValue.Value()));
            }
            if (valueMatches && stateRegex.HasValue())
            {
                valueMatches = regex_search(capturedValue, stateRegex.Value());
            }
            const FileRegexOccurrence occurrence{ordinal++, position, capturedValue, valueMatches ? SourceCheckValue::True : SourceCheckValue::False};
            const auto consumed = sink.Consume(occurrence);
            if (!consumed.HasValue())
                return consumed.Error();
            return occurrence.state;
        };
        const auto readFailure = [&]() -> Result<bool> {
            OsConfigLogError(context.GetLogHandle(), "Failed to read file '%s'", filename.c_str());
            return Error("Failed to read file: " + filename, EIO);
        };
        // A pre-failed stream has not supplied a complete content source.
        if (!input.good())
            return readFailure();
        if (wholeFile)
        {
            string contents;
            char buffer[8192];
            do
            {
                // A short final read throws at normal EOF under failbit masks.
                try
                {
                    input.read(buffer, sizeof(buffer));
                }
                catch (const std::ios_base::failure&)
                {
                    if (input.bad() || !input.eof())
                        return readFailure();
                }
                catch (const std::bad_alloc&)
                {
                    throw; // The outer allocation boundary reports ENOMEM.
                }
                catch (...)
                {
                    return readFailure(); // A streambuf may rethrow its original exception.
                }
                contents.append(buffer, static_cast<size_t>(input.gcount()));
                if (input.bad() || (!input && !input.eof()))
                    return readFailure();
            } while (input);
            if (input.bad() || !input.eof())
            {
                return readFailure();
            }
            if ((!matchPattern.empty()) && ('^' == matchPattern[0]))
            {
                for (size_t offset = 0; offset <= contents.size();)
                {
                    smatch match;
                    const auto begin = contents.cbegin() + offset;
                    if (regex_search(begin, contents.cend(), match, matchRegex, std::regex_constants::match_continuous))
                    {
                        const auto consumed = evaluateMatch(match, offset + static_cast<size_t>(match.position(0)));
                        if (!consumed.HasValue())
                            return consumed.Error();
                        offset += std::max<size_t>(match.length(0), 1);
                        continue;
                    }
                    const auto newline = contents.find('\n', offset);
                    if (string::npos == newline)
                    {
                        break;
                    }
                    offset = newline + 1;
                }
            }
            else
            {
                auto begin = contents.cbegin();
                auto flags = std::regex_constants::match_default;
                smatch match;
                while (regex_search(begin, contents.cend(), match, matchRegex, flags))
                {
                    const auto consumed = evaluateMatch(match, static_cast<size_t>(begin - contents.cbegin()) + static_cast<size_t>(match.position(0)));
                    if (!consumed.HasValue())
                        return consumed.Error();
                    begin += match.position(0) + match.length(0);
                    if (0 == match.length(0))
                    {
                        if (begin == contents.cend())
                        {
                            break;
                        }
                        flags = (begin == contents.cbegin()) ? std::regex_constants::match_default : std::regex_constants::match_prev_avail;
                        if (regex_search(begin, contents.cend(), match, matchRegex, flags | std::regex_constants::match_not_null | std::regex_constants::match_continuous))
                        {
                            const auto emptyMatchConsumed = evaluateMatch(match, static_cast<size_t>(begin - contents.cbegin()));
                            if (!emptyMatchConsumed.HasValue())
                                return emptyMatchConsumed.Error();
                            begin += match.length(0);
                        }
                        else
                        {
                            ++begin;
                        }
                    }
                    flags = std::regex_constants::match_prev_avail;
                }
            }
            return true;
        }

        size_t lineNumber = 0;
        string line;
        // As before, an empty file is one empty line for line-mode matching.
        while (true)
        {
            bool hasLine = false;
            try
            {
                hasLine = static_cast<bool>(getline(input, line));
            }
            catch (const std::ios_base::failure&)
            {
                if (input.bad() || !input.eof())
                    return readFailure();
                // EOF can throw after extracting an unterminated final line.
                hasLine = !input.fail();
            }
            catch (const std::bad_alloc&)
            {
                throw; // The outer allocation boundary reports ENOMEM.
            }
            catch (...)
            {
                return readFailure(); // A streambuf may rethrow its original exception.
            }
            if (input.bad() || (!hasLine && !input.eof()))
                return readFailure();
            if (!hasLine && !((0 == lineNumber) && input.eof()))
                break;
            ++lineNumber;
            OsConfigLogDebug(context.GetLogHandle(), "Matching line %zu: '%s', pattern: '%s'", lineNumber, line.c_str(), matchPattern.c_str());
            smatch match;
            if (regex_search(line, match, matchRegex))
            {
                const auto consumed = evaluateMatch(match, lineNumber);
                if (!consumed.HasValue())
                    return consumed.Error();
                if (SourceCheckValue::True == consumed.Value())
                {
                    OsConfigLogDebug(context.GetLogHandle(), "Matched line %zu: %s", lineNumber, line.c_str());
                }
            }
        }
        if (input.bad() || !input.eof())
        {
            return readFailure();
        }
        return true;
    }
    catch (const std::bad_alloc&)
    {
        return Error("Failed to allocate file regex evidence", ENOMEM);
    }
    catch (const regex_error& e)
    {
        return Error("Failed to evaluate file regex: " + string(e.what()), EINVAL);
    }
}

Result<bool> EvaluateFileRegexContentAndFinalize(std::istream& input, const std::string& filename, const std::string& matchPattern,
    const regex& matchRegex, const Optional<regex>& stateRegex, ContextInterface& context, const Optional<long long>& minimumValue,
    const Optional<long long>& maximumValue, bool wholeFile, FileRegexOccurrenceSink& sink, const std::function<Result<bool>()>& finalize)
{
    const auto content = EvaluateFileRegexContent(input, filename, matchPattern, matchRegex, stateRegex, context, minimumValue, maximumValue, wholeFile, sink);
    Result<bool> closed = true;
    try
    {
        closed = finalize();
    }
    catch (const std::ios_base::failure&)
    {
        closed = Error("Failed to close file: " + filename, EIO);
    }
    catch (const std::bad_alloc&)
    {
        closed = Error("Failed to allocate file regex finalization evidence", ENOMEM);
    }
    catch (const std::bad_function_call&)
    {
        closed = Error("Missing file finalizer: " + filename, EINVAL);
    }
    catch (...)
    {
        closed = Error("Failed to close file: " + filename, EIO);
    }
    if (!content.HasValue())
        return content.Error();
    return closed;
}

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
    if (params.allMatches.Value() && params.noneMatches.Value())
    {
        return Error("allMatches and noneMatches cannot both be true", EINVAL);
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

    regex matchRegex;
    Optional<regex> stateRegex;
    try
    {
        matchRegex = regex(params.matchPattern, syntaxOptions.first);
        if (params.statePattern.HasValue())
        {
            stateRegex = regex(params.statePattern.Value(), syntaxOptions.second);
        }
    }
    catch (const regex_error& e)
    {
        OsConfigLogInfo(context.GetLogHandle(), "Regex error: %s", e.what());
        return Error("Regex error: " + string(e.what()), EINVAL);
    }

    auto* dir = opendir(params.path.c_str());
    if (dir == nullptr)
    {
        const int status = errno;
        if (status != ENOENT)
        {
            OsConfigLogError(context.GetLogHandle(), "Failed to open directory '%s': %s", params.path.c_str(), strerror(status));
            return Error("Failed to open directory '" + params.path + "': " + strerror(status), status);
        }
        if (params.allMatches.Value() || params.noneMatches.Value())
        {
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

    size_t matchCount = 0;
    size_t mismatchCount = 0;
    size_t fileCount = 0;
    size_t unselectedCount = 0;
    SourceCheckEvidence fileStates;
    SourceExistenceEvidence passingFiles;
    Optional<Error> firstFailure;
    const auto increment = [](size_t& count) {
        if (count < std::numeric_limits<size_t>::max())
        {
            ++count;
        }
    };
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

        const bool filenameMatches =
            params.filenameSearch.Value() ? regex_search(entry->d_name, params.filenamePattern) : regex_match(entry->d_name, params.filenamePattern);
        if (!filenameMatches)
        {
            OsConfigLogDebug(context.GetLogHandle(), "Ignoring file '%s' in directory '%s'", entry->d_name, params.path.c_str());
            continue;
        }
        increment(fileCount);
        const auto filename = params.path + "/" + entry->d_name;
        ifstream input(filename);
        if (!input.is_open())
        {
            const Error failure("Failed to open file: " + filename, errno);
            OsConfigLogInfo(context.GetLogHandle(), "Failed to match file '%s': %s", filename.c_str(), failure.message.c_str());
            if (!firstFailure.HasValue())
                firstFailure = failure;
            continue;
        }
        // Only bounded summaries survive each occurrence; content items remain
        // individually observable at the producer/sink boundary.
        struct SummarySink : FileRegexOccurrenceSink
        {
            SourceCheckEvidence states;
            SourceExistenceEvidence selected;
            Result<bool> Consume(const FileRegexOccurrence& occurrence) override
            {
                selected.Add(SourceExistenceValue::Exists);
                states.Add(occurrence.state);
                return true;
            }
        } summary;
        const auto evidence = EvaluateFileRegexContentAndFinalize(input, filename, params.matchPattern, matchRegex, stateRegex, context, minimumValue,
            maximumValue, params.wholeFile.Value(), summary, [&]() -> Result<bool> {
                // The completed read leaves EOF/failbit set. Clear only these
                // stale read flags before checking the new close result.
                input.clear();
                input.close();
                if (input.fail())
                {
                    const int status = errno;
                    return Error("Failed to close file: " + filename, status ? status : EIO);
                }
                return true;
            });
        if (!evidence.HasValue())
        {
            OsConfigLogInfo(context.GetLogHandle(), "Failed to match file %s: %s", filename.c_str(), evidence.Error().message.c_str());
            if (!firstFailure.HasValue())
                firstFailure = evidence.Error();
            continue;
        }
        const auto& states = summary.states;
        const auto& selected = summary.selected;
        const auto exists = selected.Evaluate(SourceExistencePolicy::AtLeastOneExists);
        if (!exists.HasValue())
            return exists.Error();
        const bool hasSelection = (SourceCheckValue::True == exists.Value());
        if ((!hasSelection) && (params.allMatches.Value() || params.noneMatches.Value()))
        {
            increment(unselectedCount);
            continue;
        }
        SourceCheckValue group = SourceCheckValue::False;
        if (hasSelection)
        {
            SourceCheckPolicy policy = SourceCheckPolicy::AtLeastOne;
            if (params.allMatches.Value())
                policy = SourceCheckPolicy::All;
            if (params.noneMatches.Value())
                policy = SourceCheckPolicy::NoneSatisfy;
            const auto checked = states.Evaluate(policy);
            if (!checked.HasValue())
                return checked.Error();
            group = checked.Value();
        }
        // A source Error would require an explicit projection contract; this
        // scalar producer emits only T/F. Operational errors never enter states.
        if (SourceCheckValue::Error == group)
        {
            return Error("Unsupported source Error in legacy file group", EINVAL);
        }
        fileStates.Add(group);
        if (SourceCheckValue::True == group)
        {
            increment(matchCount);
            passingFiles.Add(SourceExistenceValue::Exists);
        }
        else
        {
            increment(mismatchCount);
        }
    }
    const int enumerationError = errno;
    const int closeResult = closedir(dirCloser.release());
    const int closeError = (0 == closeResult) ? 0 : errno;
    if (0 != enumerationError)
    {
        OsConfigLogError(context.GetLogHandle(), "Failed to read directory '%s': %s", params.path.c_str(), strerror(enumerationError));
        if (!firstFailure.HasValue())
            firstFailure = Error("Failed to read directory '" + params.path + "': " + strerror(enumerationError), enumerationError);
    }
    if ((0 != closeError) && (!firstFailure.HasValue()))
    {
        firstFailure = Error("Failed to close directory '" + params.path + "': " + strerror(closeError), closeError);
    }
    if (firstFailure.HasValue())
        return firstFailure.Value();

    OsConfigLogInfo(context.GetLogHandle(), "Validating pattern matching results, behavior: '%s', matched: %zu, mismatched: %zu, unselected: %zu",
        std::to_string(behavior).c_str(), matchCount, mismatchCount, unselectedCount);
    if ((params.allMatches.Value() || params.noneMatches.Value()) && (Behavior::NoneExist != behavior) && (0 != mismatchCount))
    {
        return indicators.NonCompliant("At least one selected setting failed its state constraint");
    }
    // This is a legacy compatibility mapping of derived file groups, not an
    // OVAL test. The empty group cases are handled here before Check (whose
    // source chart has no empty row). AnyExist uses the source existence row.
    if (Behavior::AnyExist == behavior)
    {
        const auto any = passingFiles.Evaluate(SourceExistencePolicy::AnyExist);
        if (!any.HasValue())
            return any.Error();
        return indicators.Compliant("Found " + std::to_string(matchCount) + " matches");
    }
    if (Behavior::AllExist == behavior)
    {
        if ((0 != matchCount) || (0 != mismatchCount))
        {
            const auto all = fileStates.Evaluate(SourceCheckPolicy::All);
            if (!all.HasValue())
                return all.Error();
            if (SourceCheckValue::False == all.Value())
                return indicators.NonCompliant("At least one file did not match the pattern");
        }
        if (0 == matchCount)
        {
            return indicators.NonCompliant("Expected all files to match, but only " + std::to_string(matchCount) + " out of " +
                                           std::to_string(fileCount) + " matched");
        }
        return indicators.Compliant("All " + std::to_string(fileCount) + " files matched the pattern");
    }
    if (Behavior::AtLeastOneExists == behavior)
    {
        if ((0 == matchCount) && (0 == mismatchCount))
            return indicators.NonCompliant("Expected at least one file to match, but none did");
        const auto any = fileStates.Evaluate(SourceCheckPolicy::AtLeastOne);
        if (!any.HasValue())
            return any.Error();
        if (SourceCheckValue::True == any.Value())
            return indicators.Compliant("At least one file matched, found " + std::to_string(matchCount) + " matches");
        return indicators.NonCompliant("Expected at least one file to match, but none did");
    }
    if (Behavior::NoneExist == behavior)
    {
        if ((0 == matchCount) && (0 == mismatchCount))
            return indicators.Compliant("No files matched the pattern");
        const auto none = fileStates.Evaluate(SourceCheckPolicy::NoneSatisfy);
        if (!none.HasValue())
            return none.Error();
        if (SourceCheckValue::False == none.Value())
            return indicators.NonCompliant("Expected no files to match, but " + std::to_string(matchCount) + " matched");
        return indicators.Compliant("No files matched the pattern");
    }
    if (Behavior::OnlyOneExists == behavior)
    {
        if ((0 == matchCount) && (0 == mismatchCount))
            return indicators.NonCompliant("Expected exactly one file to match, but none did");
        const auto one = fileStates.Evaluate(SourceCheckPolicy::OnlyOne);
        if (!one.HasValue())
            return one.Error();
        if (SourceCheckValue::True == one.Value())
            return indicators.Compliant("Exactly one file matched the pattern");
        return indicators.NonCompliant((matchCount > 1) ? "Expected only one file to match, but " + std::to_string(matchCount) + " matched" :
                                                          "Expected exactly one file to match, but none did");
    }
    return Error("Unknown behavior: " + std::to_string(params.behavior), EINVAL);
}
} // namespace ComplianceEngine
