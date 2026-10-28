// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <AtomicFile.h>
#include <CommonUtils.h>
#include <Evaluator.h>
#include <PasswordEntriesIterator.h>
#include <Regex.h>
#include <ScopeGuard.h>
#include <StringTools.h>
#include <algorithm>
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
        return regex(pattern, std::regex_constants::ECMAScript | std::regex_constants::icase);
    }
    catch (const regex_error& e)
    {
        OsConfigLogInfo(context.GetLogHandle(), "Regex error: %s", e.what());
        return Error("Regex error: " + string(e.what()), EINVAL);
    }
}

enum class MatchResult
{
    Correct,
    Incorrect,
    NotFound
};

mode_t ParseSymbolicValue(const std::string& user, const std::string& group, const std::string& other)
{
    mode_t value = 0;
    if (user.find("r") != string::npos)
    {
        value |= S_IRUSR;
    }
    if (user.find("w") != string::npos)
    {
        value |= S_IWUSR;
    }
    if (user.find("x") != string::npos)
    {
        value |= S_IXUSR;
    }

    if (group.find("r") != string::npos)
    {
        value |= S_IRGRP;
    }
    if (group.find("w") != string::npos)
    {
        value |= S_IWGRP;
    }
    if (group.find("x") != string::npos)
    {
        value |= S_IXGRP;
    }

    if (other.find("r") != string::npos)
    {
        value |= S_IROTH;
    }
    if (other.find("w") != string::npos)
    {
        value |= S_IWOTH;
    }
    if (other.find("x") != string::npos)
    {
        value |= S_IXOTH;
    }

    return ~value;
}

Result<MatchResult> MultilineMatch(const std::string& filename, const regex& valuePattern, const regex& pamPattern, ContextInterface& context)
{
    auto opened = Filesystem::FileReader::Lines(context, filename);
    if (!opened.HasValue())
    {
        OsConfigLogError(context.GetLogHandle(), "Failed to open %s: %s", filename.c_str(), opened.Error().message.c_str());
        return std::move(opened).Error();
    }

    auto& range = opened.Value();
    int lineNumber = 0;
    MatchResult result = MatchResult::NotFound;
    // The first matching assignment decides this file; Close still precedes publication.
    for (const auto& item : range)
    {
        if (!item.HasValue())
        {
            OsConfigLogError(context.GetLogHandle(), "Failed to read %s: %s", filename.c_str(), item.Error().message.c_str());
            return item.Error();
        }

        const string& line = item.Value();
        const mode_t expected = 027;
        lineNumber++;
        smatch match;

        if (regex_search(line, match, valuePattern))
        {
            OsConfigLogDebug(context.GetLogHandle(), "Matched line %d: %s", lineNumber, line.c_str());
            assert(match.ready());

            if (match.size() != 7)
            {
                return Error("Unexpected capture list size", EINVAL);
            }

            auto mask = match[2].str();
            if (!mask.empty())
            {
                auto octal = TryStringToInt(mask, 8);
                if (!octal.HasValue())
                {
                    // We expect an octal number as it's been sucessfully matched by the regex
                    return octal.Error();
                }

                if ((expected & octal.Value()) != expected)
                {
                    result = MatchResult::Incorrect;
                }
                else
                {
                    result = MatchResult::Correct;
                }
                break;
            }

            // We have a match, but not on the numeric result - we need to parse the symbolic mask
            auto symbolic = ParseSymbolicValue(match[3].str(), match[4].str(), match[5].str());
            if ((expected & symbolic) != expected)
            {
                result = MatchResult::Incorrect;
            }
            else
            {
                result = MatchResult::Correct;
            }
            break;
        }

        if (regex_search(line, match, pamPattern))
        {
            OsConfigLogDebug(context.GetLogHandle(), "Matched line %d: %s", lineNumber, line.c_str());

            if (match.size() != 4)
            {
                return Error("Unexpected capture list size", EINVAL);
            }

            auto octal = TryStringToInt(match[3].str(), 8);
            if (!octal.HasValue())
            {
                // We expect an octal number as it's been sucessfully matched by the regex
                return octal.Error();
            }

            if ((expected & octal.Value()) != expected)
            {
                result = MatchResult::Incorrect;
            }
            else
            {
                result = MatchResult::Correct;
            }
            break;
        }
    }

    auto closed = range.Close();
    if (!closed.HasValue())
    {
        return std::move(closed).Error();
    }
    return result;
}

Result<vector<string>> GetUmaskLocations(ContextInterface& context)
{
    vector<string> locations;
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
    }
    else
    {
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
    }

    const std::array<string, 6> standardLocations = {
        "/etc/profile", "/etc/bashrc", "/etc/bash.bashrc", "/etc/pam.d/postlogin", "/etc/login.defs", "/etc/default/login"};
    std::transform(standardLocations.begin(), standardLocations.end(), std::back_inserter(locations),
        [&context](const string& path) { return context.GetSpecialFilePath(path); });
    return locations;
}

struct UmaskChange
{
    string path;
    string original;
    string updated;
};

Result<Optional<UmaskChange>> FindUmaskChange(const vector<string>& locations, const regex& valuePattern, const regex& pamPattern)
{
    for (const auto& location : locations)
    {
        struct stat metadata;
        if (lstat(location.c_str(), &metadata) != 0)
        {
            if (errno == ENOENT)
            {
                continue;
            }
            const int status = errno;
            return Error("Failed to inspect " + location + ": " + strerror(status), status);
        }

        std::ifstream input(location);
        if (!input.is_open())
        {
            return Error("Failed to open file: " + location, errno);
        }
        const string original((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
        size_t lineStart = 0;
        while (lineStart <= original.size())
        {
            const size_t newline = original.find('\n', lineStart);
            const size_t lineEnd = newline == string::npos ? original.size() : newline;
            const string line = original.substr(lineStart, lineEnd - lineStart);
            smatch match;
            size_t valueStart = string::npos;
            size_t valueLength = 0;
            if (regex_search(line, match, valuePattern))
            {
                valueStart = lineStart + static_cast<size_t>(match.position(1));
                valueLength = static_cast<size_t>(match.length(1));
            }
            else if (regex_search(line, match, pamPattern))
            {
                valueStart = lineStart + static_cast<size_t>(match.position(3));
                valueLength = static_cast<size_t>(match.length(3));
            }
            if (valueStart != string::npos)
            {
                string updated = original;
                updated.replace(valueStart, valueLength, "027");
                return Optional<UmaskChange>(UmaskChange{location, original, std::move(updated)});
            }
            if (newline == string::npos)
            {
                break;
            }
            lineStart = newline + 1;
        }
    }
    return Optional<UmaskChange>();
}
} // anonymous namespace

Result<Status> AuditDefaultUmask(IndicatorsTree& indicators, ContextInterface& context)
{
    static const auto fileUmaskPattern = R"(^[ \t]*umask[ \t]+(([0-7]{3,4})|u=([rwx]{0,3}),g=([rwx]{0,3}),o=([rwx]{0,3}))([ \t]*#.*)?$)";
    static const auto pamPattern = R"(^[ \t]*session[ \t]+([^#\n\r]+[ \t]+)?pam_umask\.so[ \t]+([^#\n\r]+[ \t]+)?umask=([0-7]{3,4})\b)";

    static const auto valueRegex = CompileRegex(fileUmaskPattern, context);
    if (!valueRegex.HasValue())
    {
        return valueRegex.Error();
    }

    static const auto pamRegex = CompileRegex(pamPattern, context);
    if (!pamRegex.HasValue())
    {
        return pamRegex.Error();
    }

    auto umaskLocations = GetUmaskLocations(context);
    if (!umaskLocations.HasValue())
    {
        return umaskLocations.Error();
    }

    bool found = false;
    for (const auto& location : umaskLocations.Value())
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

        auto result = MultilineMatch(location, valueRegex.Value(), pamRegex.Value(), context);
        if (!result.HasValue())
        {
            return result.Error();
        }

        if (result.Value() == MatchResult::NotFound)
        {
            continue;
        }
        found = true;

        if (result.Value() == MatchResult::Correct)
        {
            return indicators.Compliant("umask is correctly set in " + location);
        }

        if (result.Value() == MatchResult::Incorrect)
        {
            // We follow CIS guidance here and don't break early on incompmliance
            // to keep consistence with precedence.
            indicators.NonCompliant("umask is incorrectly set in " + location);
        }
    }

    if (!found)
    {
        // At least one umask setting must be found
        return indicators.NonCompliant("umask is not set");
    }

    // When this line is reached, it means we have already found umask setting(s),
    // but all of them were incompliant. This is true because we break early
    // on Compliant status.
    assert(!indicators.Back().indicators.empty());
    assert(indicators.Back().indicators.back().status == Status::NonCompliant);
    return Status::NonCompliant;
}

Result<Status> RemediateDefaultUmask(IndicatorsTree& indicators, ContextInterface& context)
{
    auto audit = AuditDefaultUmask(indicators, context);
    if (!audit.HasValue() || audit.Value() == Status::Compliant)
    {
        return audit;
    }

    static const regex valuePattern(R"(^[ \t]*umask[ \t]+(([0-7]{3,4})|u=([rwx]{0,3}),g=([rwx]{0,3}),o=([rwx]{0,3}))([ \t]*#.*)?$)",
        std::regex_constants::ECMAScript | std::regex_constants::icase);
    static const regex pamPattern(R"(^[ \t]*session[ \t]+([^#\n\r]+[ \t]+)?pam_umask\.so[ \t]+([^#\n\r]+[ \t]+)?umask=([0-7]{3,4})\b)",
        std::regex_constants::ECMAScript | std::regex_constants::icase);
    auto locations = GetUmaskLocations(context);
    if (!locations.HasValue())
    {
        return locations.Error();
    }
    auto change = FindUmaskChange(locations.Value(), valuePattern, pamPattern);
    if (!change.HasValue())
    {
        return change.Error();
    }

    UmaskChange selected;
    if (change->HasValue())
    {
        selected = std::move(change->Value());
    }
    else
    {
        const string profile = context.GetSpecialFilePath("/etc/profile");
        std::ifstream input(profile);
        if (!input.is_open())
        {
            return Error("umask is not set and no writable profile is available", errno);
        }
        const string original((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
        string updated = original;
        if (!updated.empty() && updated.back() != '\n')
        {
            updated.push_back('\n');
        }
        updated += "umask 027\n";
        selected = UmaskChange{profile, original, std::move(updated)};
    }

    auto replaced = ReplaceFileContentsAtomic(selected.path, selected.updated);
    if (!replaced.HasValue())
    {
        return replaced.Error();
    }
    auto postAudit = AuditDefaultUmask(indicators, context);
    if (postAudit.HasValue() && postAudit.Value() == Status::Compliant)
    {
        return postAudit;
    }

    auto rollback = ReplaceFileContentsAtomic(selected.path, selected.original);
    if (!rollback.HasValue())
    {
        return Error("Default umask validation failed; rollback failed: " + rollback.Error().message, rollback.Error().code);
    }
    return postAudit;
}
} // namespace ComplianceEngine
