// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <AtomicFile.h>
#include <CommonUtils.h>
#include <Evaluator.h>
#include <PasswordEntriesIterator.h>
#include <Regex.h>
#include <ScopeGuard.h>
#include <StringTools.h>
#include <array>
#include <dirent.h>
#include <filesystem/FileReader.hpp>
#include <fstream>
#include <iterator>
#include <pwd.h>
#include <shadow.h>
#include <sys/stat.h>
#include <vector>

using std::ifstream;
using std::map;
using std::string;
using std::vector;

namespace ComplianceEngine
{
namespace
{
Result<regex> CompileRegex(const std::string& pattern, const ContextInterface& context)
{
    try
    {
        return regex(pattern, std::regex_constants::ECMAScript);
    }
    catch (const regex_error& e)
    {
        OsConfigLogInfo(context.GetLogHandle(), "Regex error: %s", e.what());
        return Error("Regex error: " + string(e.what()), EINVAL);
    }
}

struct MatchResult
{
    bool found = false;
    bool multiple = false;
    bool correct = false;
    bool readonly = false;
    bool exported = false;
};

Result<MatchResult> MultilineMatch(const std::string& filename, const regex& valuePattern, const regex& readonlyPattern, const regex& exportPattern,
    ContextInterface& context)
{
    auto opened = FileReader::Lines(context, filename);
    if (!opened.HasValue())
    {
        OsConfigLogError(context.GetLogHandle(), "Failed to open %s: %s", filename.c_str(), opened.Error().message.c_str());
        return std::move(opened).Error();
    }

    auto& range = opened.Value();
    int lineNumber = 0;
    MatchResult result;
    for (const auto& item : range)
    {
        if (!item.HasValue())
        {
            OsConfigLogError(context.GetLogHandle(), "Failed to read %s: %s", filename.c_str(), item.Error().message.c_str());
            return item.Error();
        }

        const string& line = item.Value();
        lineNumber++;
        smatch match;

        if (regex_search(line, match, valuePattern))
        {
            OsConfigLogDebug(context.GetLogHandle(), "Matched line %d: %s", lineNumber, line.c_str());
            assert(match.ready());

            if (result.found)
            {
                result.multiple = true;
                // A duplicate is sufficient; Close must still be checked without draining the tail.
                break;
            }
            result.found = true;

            if (match.size() != 3)
            {
                return Error("Invalid size of regex capture list", EINVAL);
            }

            auto value = TryStringToInt(match[2].str());
            if (!value.HasValue())
            {
                return value.Error();
            }

            if (value.Value() <= 900)
            {
                result.correct = true;
            }
        }

        if (regex_search(line, readonlyPattern))
        {
            OsConfigLogDebug(context.GetLogHandle(), "Matched line %d: %s", lineNumber, line.c_str());
            result.readonly = true;
        }

        if (regex_search(line, exportPattern))
        {
            OsConfigLogDebug(context.GetLogHandle(), "Matched line %d: %s", lineNumber, line.c_str());
            result.exported = true;
        }
    }

    auto closed = range.Close();
    if (!closed.HasValue())
    {
        return std::move(closed).Error();
    }
    return result;
}

Result<vector<string>> GetShellConfigLocations(ContextInterface& context)
{
    vector<string> locations = {
        context.GetSpecialFilePath("/etc/bashrc"),
        context.GetSpecialFilePath("/etc/bash.bashrc"),
        context.GetSpecialFilePath("/etc/profile"),
    };

    const auto& profiledPath = context.GetSpecialFilePath("/etc/profile.d/");
    auto* dir = opendir(profiledPath.c_str());
    ScopeGuard guard([dir]() {
        if (dir)
        {
            closedir(dir);
        }
    });
    if (!dir)
    {
        const int status = errno;
        if (ENOENT != status)
        {
            OsConfigLogError(context.GetLogHandle(), "Failed to open directory '%s': %s", profiledPath.c_str(), strerror(status));
            return Error(string("Failed to open directory '") + profiledPath + "': " + strerror(status), status);
        }
        return locations;
    }

    for (dirent* entry = readdir(dir); entry != nullptr; entry = readdir(dir))
    {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
        {
            continue;
        }

        const auto separator = !profiledPath.empty() && profiledPath.back() == '/' ? "" : "/";
        auto filePath = profiledPath + separator + entry->d_name;
        if (filePath.size() >= 3 && filePath.rfind(".sh") == filePath.size() - 3)
        {
            locations.push_back(filePath);
        }
    }
    return locations;
}

Result<string> ReadFile(const string& path)
{
    std::ifstream input(path);
    if (!input.is_open())
    {
        return Error("Failed to open file: " + path, errno);
    }
    return string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

struct TimeoutAssignment
{
    string path;
    string contents;
    size_t start;
    size_t end;
    string replacement;
};

Result<Optional<TimeoutAssignment>> FindTimeoutAssignment(const vector<string>& locations)
{
    static const regex auditAssignment(R"(^[ \t]*([^#\n\r]+[ \t]+)?TMOUT=([[:alnum:]]+)\b)");
    static const regex safeAssignment(R"(^([ \t]*)(export[ \t]+)?TMOUT=[[:alnum:]]+\b[ \t]*(#.*)?$)");
    static const regex readonlyPattern(R"(^[ \t]*([^#\n]+[ \t]+)?readonly[ \t]+TMOUT\b)");
    static const regex exportPattern(R"(^([ \t]*|[ \t]*[^#\n]+[ \t]*;[ \t]*)export[ \t]+TMOUT\b)");
    Optional<TimeoutAssignment> found;

    for (const auto& location : locations)
    {
        struct stat metadata;
        if (lstat(location.c_str(), &metadata) != 0)
        {
            if (errno == ENOENT)
            {
                continue;
            }
            return Error("Failed to inspect " + location + ": " + strerror(errno), errno);
        }

        auto contents = ReadFile(location);
        if (!contents.HasValue())
        {
            return contents.Error();
        }

        bool readonlyFound = false;
        bool exportFound = false;
        size_t lineStart = 0;
        while (lineStart <= contents->size())
        {
            const size_t newline = contents->find('\n', lineStart);
            const size_t lineEnd = newline == string::npos ? contents->size() : newline;
            const string line = contents->substr(lineStart, lineEnd - lineStart);
            if (regex_search(line, readonlyPattern))
            {
                readonlyFound = true;
            }
            if (regex_search(line, exportPattern))
            {
                exportFound = true;
            }
            if (regex_search(line, auditAssignment))
            {
                if (found.HasValue())
                {
                    return Error("Cannot safely remediate multiple TMOUT definitions", ENOTSUP);
                }
                if (readonlyFound)
                {
                    return Error("Cannot remediate TMOUT after it has been made readonly in " + location, ENOTSUP);
                }
                smatch match;
                if (!regex_match(line, match, safeAssignment))
                {
                    return Error("Cannot safely rewrite complex TMOUT definition in " + location, ENOTSUP);
                }
                const string comment = match[3].matched ? " " + match[3].str() : "";
                const string exportPrefix = match[2].matched ? "export " : "";
                found = TimeoutAssignment{location, contents.Value(), lineStart, lineEnd, match[1].str() + exportPrefix + "TMOUT=900" + comment};
            }
            if (newline == string::npos)
            {
                break;
            }
            lineStart = newline + 1;
        }

        if (found.HasValue() && found->path == location)
        {
            if (!readonlyFound)
            {
                found->replacement += "\nreadonly TMOUT";
            }
            if (!exportFound)
            {
                found->replacement += "\nexport TMOUT";
            }
        }
    }
    return found;
}
} // anonymous namespace

Result<Status> AuditShellTimeout(IndicatorsTree& indicators, ContextInterface& context)
{
    static const auto valuePattern = R"(^[ \\t]*([^#\n\r]+[ \\t]+)?TMOUT=([[:alnum:]]+)\b)";
    static const auto readonlyPattern = R"(^[ \\t]*([^#\n]+[ \\t]+)?readonly[ \\t]+TMOUT\b)";
    static const auto exportPattern = R"(^([ \\t]*|[ \\t]*[^#\n]+[ \\t]*;[ \\t]*)export[ \\t]+TMOUT\b)";

    static const auto valueRegex = CompileRegex(valuePattern, context);
    if (!valueRegex.HasValue())
    {
        return valueRegex.Error();
    }

    static const auto readonlyRegex = CompileRegex(readonlyPattern, context);
    if (!readonlyRegex.HasValue())
    {
        return readonlyRegex.Error();
    }

    static const auto exportRegex = CompileRegex(exportPattern, context);
    if (!exportRegex.HasValue())
    {
        return exportRegex.Error();
    }

    auto locations = GetShellConfigLocations(context);
    if (!locations.HasValue())
    {
        return locations.Error();
    }

    bool found = false;
    for (const auto& location : locations.Value())
    {
        struct stat st;
        if (0 != stat(location.c_str(), &st))
        {
            int status = errno;
            if (ENOENT == status)
            {
                continue;
            }

            return Error(string("Failed to stat ") + location + ": " + strerror(status), status);
        }

        auto result = MultilineMatch(location, valueRegex.Value(), readonlyRegex.Value(), exportRegex.Value(), context);
        if (!result.HasValue())
        {
            return result.Error();
        }

        if (result->found)
        {
            if (result->correct)
            {
                indicators.Compliant(string("TMOUT is set to a correct value in ") + location);
            }
            else
            {
                return indicators.NonCompliant(string("TMOUT is set to an incorrect value in ") + location);
            }

            if (result->multiple)
            {
                return indicators.NonCompliant(string("TMOUT is set multiple times in ") + location);
            }

            if (result->readonly)
            {
                indicators.Compliant(string("TMOUT is set readonly in ") + location);
            }
            else
            {
                return indicators.NonCompliant(string("TMOUT is not readonly in ") + location);
            }

            if (result->exported)
            {
                indicators.Compliant(string("TMOUT is exported in ") + location);
            }
            else
            {
                return indicators.NonCompliant(string("TMOUT is not exported in ") + location);
            }

            if (found)
            {
                return indicators.NonCompliant("TMOUT is set in multiple locations");
            }
            found = true;
        }
    }

    if (!found)
    {
        return indicators.NonCompliant("TMOUT is not set");
    }

    return indicators.Compliant("TMOUT variable is properly defined");
}

Result<Status> RemediateShellTimeout(IndicatorsTree& indicators, ContextInterface& context)
{
    auto audit = AuditShellTimeout(indicators, context);
    if (!audit.HasValue() || audit.Value() == Status::Compliant)
    {
        return audit;
    }

    auto locations = GetShellConfigLocations(context);
    if (!locations.HasValue())
    {
        return locations.Error();
    }
    auto assignment = FindTimeoutAssignment(locations.Value());
    if (!assignment.HasValue())
    {
        return assignment.Error();
    }

    TimeoutAssignment change;
    string original;
    if (assignment->HasValue())
    {
        original = assignment->Value().contents;
        change = std::move(assignment->Value());
        change.contents.replace(change.start, change.end - change.start, change.replacement);
    }
    else
    {
        const string profile = context.GetSpecialFilePath("/etc/profile");
        auto contents = ReadFile(profile);
        if (!contents.HasValue())
        {
            return Error("TMOUT is not set and no writable profile is available: " + contents.Error().message, contents.Error().code);
        }
        string updated = contents.Value();
        if (!updated.empty() && updated.back() != '\n')
        {
            updated.push_back('\n');
        }
        updated += "TMOUT=900\nreadonly TMOUT\nexport TMOUT\n";
        original = contents.Value();
        change = TimeoutAssignment{profile, contents.Value(), 0, 0, std::move(updated)};
        change.contents = change.replacement;
    }

    auto replaced = ReplaceFileContentsAtomic(change.path, change.contents);
    if (!replaced.HasValue())
    {
        return replaced.Error();
    }

    auto postAudit = AuditShellTimeout(indicators, context);
    if (postAudit.HasValue() && postAudit.Value() == Status::Compliant)
    {
        return postAudit;
    }

    auto restored = ReplaceFileContentsAtomic(change.path, original);
    if (!restored.HasValue())
    {
        return Error("Shell timeout validation failed; rollback failed: " + restored.Error().message, restored.Error().code);
    }
    return postAudit;
}
} // namespace ComplianceEngine
