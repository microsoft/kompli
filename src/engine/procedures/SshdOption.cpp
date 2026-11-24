// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "StringTools.h"

#include <AtomicFile.h>
#include <ProcedureMap.h> // Adds std::to_string() for enum classes
#include <SshdOption.h>
#include <TypedComparison.h>
#include <cerrno>
#include <cstdlib>
#include <fnmatch.h>
#include <fts.h>
#include <functional>
#include <glob.h>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <vector>

namespace Kompli
{
namespace
{

Result<std::vector<std::string>> GetAllMatches(ContextInterface& context)
{
    std::deque<std::string> configFiles;
    configFiles.push_back("/etc/ssh/sshd_config");
    std::vector<std::string> allMatches;

    while (!configFiles.empty())
    {
        std::string currentFile = configFiles.front();
        configFiles.pop_front();

        auto fileContent = context.GetFileContents(currentFile);
        if (!fileContent.HasValue())
        {
            continue;
        }

        std::istringstream fileStream(fileContent.Value());
        std::string line;

        while (std::getline(fileStream, line))
        {
            line.erase(0, line.find_first_not_of(" \t"));

            if (line.empty() || line[0] == '#')
            {
                continue;
            }

            std::istringstream lineStream(line);
            std::string directive;
            lineStream >> directive;

            directive = ToLower(directive);

            if (directive == "include")
            {
                std::string includeFile;
                lineStream >> includeFile;
                if (!includeFile.empty())
                {
                    size_t lastSlash = includeFile.find_last_of('/');
                    if (lastSlash != std::string::npos && includeFile.find('*', lastSlash) != std::string::npos)
                    {
                        std::string directory = includeFile.substr(0, lastSlash);
                        std::string pattern = includeFile.substr(lastSlash + 1);

                        char* paths[] = {const_cast<char*>(directory.c_str()), nullptr};
                        FTS* ftsp = fts_open(paths, FTS_LOGICAL | FTS_NOCHDIR, nullptr);
                        if (ftsp != nullptr)
                        {
                            FTSENT* entry = nullptr;
                            while ((entry = fts_read(ftsp)) != nullptr)
                            {
                                if ((FTS_F == entry->fts_info) && (fnmatch(pattern.c_str(), entry->fts_name, 0) == 0))
                                {
                                    configFiles.push_back(entry->fts_path);
                                }
                            }
                            fts_close(ftsp);
                        }
                    }
                    else
                    {
                        configFiles.push_back(includeFile);
                    }
                }
            }
            else if (directive == "match")
            {
                std::string type, value;
                lineStream >> type >> value;
                type = ToLower(type);
                value = ToLower(value);
                if ((type == "user") || (type == "group") || (type == "host") || (type == "port") || (type == "address") || (type == "localaddress"))
                {
                    // The Match criteria value may be a comma-separated pattern list, e.g.
                    // "Match User *@*,<uuid>" (as appended by the aadsshlogin installer). In
                    // sshd_config a comma is an OR separator between patterns, but `sshd -T -C`
                    // treats commas as separators between distinct connection-spec items. Feeding
                    // the raw comma list into `-C user=...` makes sshd misparse the trailing
                    // patterns as bogus spec keys and abort with "Invalid test mode specification".
                    // Emit one match context per pattern so each Match block a pattern could
                    // activate is simulated independently.
                    std::istringstream valueStream(value);
                    std::string pattern;
                    while (std::getline(valueStream, pattern, ','))
                    {
                        if (pattern.empty())
                        {
                            continue;
                        }
                        if ((type == "address") || (type == "localaddress"))
                        {
                            pattern = pattern.substr(0, pattern.find_first_of('/'));
                        }
                        allMatches.push_back(type + "=" + pattern);
                    }
                }
            }
        }
    }

    return allMatches;
}
Result<std::map<std::string, std::string>> GetSshdOptions(ContextInterface& context, const std::string& extraConfig, const std::string& matchContext)
{
    std::string sshdCommand = "sshd -T";
    if (!extraConfig.empty())
    {
        sshdCommand = sshdCommand + " " + extraConfig;
    }

    if (!matchContext.empty())
    {
        sshdCommand = sshdCommand + " -C " + matchContext;
    }
    else
    {
        auto sshdTestOutput = context.ExecuteCommand(sshdCommand + " 2>&1");
        if (!sshdTestOutput.HasValue())
        {
            return Error("Failed to execute sshd -T command: " + sshdTestOutput.Error().message, sshdTestOutput.Error().code);
        }
        if (sshdTestOutput.Value().find("match group") != std::string::npos || sshdTestOutput.Value().find("Match group") != std::string::npos)
        {
            auto hostname = context.ExecuteCommand("hostname");
            if (!hostname.HasValue())
            {
                return Error("Failed to execute hostname command: " + hostname.Error().message, hostname.Error().code);
            }

            auto hostAddress = context.ExecuteCommand("hostname -I | cut -d ' ' -f1");
            if (!hostAddress.HasValue())
            {
                return Error("Failed to get host address: " + hostAddress.Error().message, hostAddress.Error().code);
            }
            auto hostnameStr = hostname.Value();
            auto hostAddrStr = hostAddress.Value();
            hostnameStr.erase(hostnameStr.find_last_not_of(" \n\r\t") + 1);
            hostAddrStr.erase(hostAddrStr.find_last_not_of(" \n\r\t") + 1);

            sshdCommand = sshdCommand + " -C user=root -C host=" + EscapeForShell(hostnameStr) + " -C addr=" + EscapeForShell(hostAddrStr);
        }
    }

    auto output = context.ExecuteCommand(sshdCommand);
    if (!output.HasValue())
    {
        return Error("Failed to execute " + sshdCommand + ": " + output.Error().message, output.Error().code);
    }

    auto configOutput = output.Value();
    std::istringstream configStream(configOutput);
    std::string line;
    std::map<std::string, std::string> options;

    while (std::getline(configStream, line))
    {
        std::istringstream lineStream(line);
        std::string currentOption;

        if (lineStream >> currentOption)
        {
            std::string optionValue;
            std::getline(lineStream, optionValue);
            optionValue = TrimWhiteSpaces(optionValue);
            currentOption = ToLower(currentOption);
            optionValue = ToLower(optionValue);
            options[currentOption] = optionValue;
        }
    }
    return options;
}

// Helper for evaluating delimited numeric limits such as MaxStartups style values.
// The ctx string qualifies indicator messages with the Match context (empty when not in all_matches mode),
// mirroring EvaluateSshdOption() so results from different Match contexts stay distinguishable.
static Result<Status> EvaluateDelimitedNumericLimits(const std::string& option, const std::string& value, const std::string& realValue,
    const char delimiter, size_t numFields, const std::string& ctx, IndicatorsTree& indicators)
{
    // Parse realValue using provided delimiter, value always uses ':' per specification.
    std::vector<long long> realParts(numFields, 0);
    std::vector<long long> limitParts(numFields, 0);
    const auto parseToken = [](const std::string& token) -> Result<long long> {
        errno = 0;
        char* end = nullptr;
        const auto parsed = std::strtoll(token.c_str(), &end, 10);
        if (errno == ERANGE || end == token.c_str())
        {
            // Preserve the error detail previously returned by std::stoll.
            return Error("stoll", EINVAL);
        }
        if (end != token.c_str() + token.size())
        {
            return Error("Unconsumed suffix in numeric token '" + token + "'", EINVAL);
        }
        return parsed;
    };

    std::istringstream realStream(realValue);
    std::string token;
    size_t idx = 0;
    while ((idx < numFields) && std::getline(realStream, token, delimiter))
    {
        auto parsed = parseToken(token);
        if (!parsed.HasValue())
        {
            return Error("Failed to parse " + option + " value '" + realValue + "': " + parsed.Error().message, parsed.Error().code);
        }
        realParts[idx] = parsed.Value();
        ++idx;
    }
    if (idx == 0)
    {
        return Error("Failed to parse " + option + " value '" + realValue + "': No numeric fields", EINVAL);
    }
    if ((idx == numFields && !realStream.eof()) || (!realValue.empty() && realValue.back() == delimiter))
    {
        return Error("Failed to parse " + option + " value '" + realValue + "': Unexpected extra field or trailing delimiter", EINVAL);
    }

    std::istringstream limitStream(value);
    idx = 0;
    while ((idx < numFields) && std::getline(limitStream, token, ':'))
    {
        auto parsed = parseToken(token);
        if (!parsed.HasValue())
        {
            return Error("Failed to parse " + option + " limit '" + value + "': " + parsed.Error().message, parsed.Error().code);
        }
        limitParts[idx] = parsed.Value();
        ++idx;
    }
    if ((idx == numFields && !limitStream.eof()) || (!value.empty() && value.back() == ':'))
    {
        return Error("Failed to parse " + option + " limit '" + value + "': Unexpected extra field or trailing delimiter", EINVAL);
    }

    for (size_t i = 0; i < numFields; ++i)
    {
        if (realParts[i] > limitParts[i])
        {
            return indicators.NonCompliant("Option '" + option + "' has value '" + realValue + "' which exceeds limits '" + value + "'" + ctx);
        }
    }
    return indicators.Compliant("Option '" + option + "' has a value '" + realValue + "' compliant with limits '" + value + "'" + ctx);
}

// Helper that evaluates a single sshd option against the provided operation/value.
// valueRegexes are only used (and must be valid) when op is regex, match, or not_match.
static Result<Status> EvaluateSshdOption(const std::map<std::string, std::string>& sshdConfig, const std::string& option, const std::string& value,
    const std::string& op, const std::vector<std::regex>& valueRegexes, const Optional<std::string>& matchContext, IndicatorsTree& indicators)
{
    // When evaluating a specific Match block (all_matches mode), qualify every message with the
    // connection context (e.g. "user=*@*") so results from different Match contexts are
    // distinguishable in the indicator tree.
    const std::string ctx = matchContext.HasValue() ? " (Match context '" + matchContext.Value() + "')" : "";
    auto itOptions = sshdConfig.find(option);
    if (itOptions == sshdConfig.end())
    {
        // For not_match semantics, absence means the forbidden pattern is not present -> compliant
        if (op == "not_match")
        {
            return indicators.Compliant("Option '" + option + "' not found." + ctx);
        }
        return indicators.NonCompliant("Option '" + option + "' not found in SSH daemon configuration" + ctx);
    }

    auto realValue = itOptions->second;

    if (("maxstartups" == option) && ("match" == op))
    {
        return EvaluateDelimitedNumericLimits(option, value, realValue, ':', 3, ctx, indicators);
    }

    if (("rekeylimit" == option) && ("match" == op))
    {
        return EvaluateDelimitedNumericLimits(option, value, realValue, ' ', 2, ctx, indicators);
    }

    if (op == "match" || op == "regex") // The only difference is in the valueRegexes preparation
    {
        if (valueRegexes.empty())
        {
            return Error("Internal error: regex not prepared for match op", EINVAL);
        }
        for (const auto& valueRegex : valueRegexes)
        {
            if (std::regex_search(realValue, valueRegex))
            {
                return indicators.Compliant("Option '" + option + "' has a compliant value '" + realValue + "'" + ctx);
            }
        }
        return indicators.NonCompliant("Option '" + option + "' has value '" + realValue + "' which does not match required pattern '" + value + "'" + ctx);
    }
    else if (op == "not_match")
    {
        if (valueRegexes.empty())
        {
            return Error("Internal error: regex not prepared for not_match op", EINVAL);
        }
        for (const auto& valueRegex : valueRegexes)
        {
            if (std::regex_search(realValue, valueRegex))
            {
                return indicators.NonCompliant("Option '" + option + "' has value '" + realValue + "' which matches forbidden pattern '" + value + "'" + ctx);
            }
        }
        return indicators.Compliant("Option '" + option + "' has a compliant value '" + realValue + "'" + ctx);
    }
    else if (op == "lt" || op == "le" || op == "gt" || op == "ge")
    {
        auto realIntRes = TryStringToInt(realValue);
        auto wantedIntRes = TryStringToInt(value);
        if (!realIntRes.HasValue() || !wantedIntRes.HasValue())
        {
            return indicators.NonCompliant("Option '" + option + "' has non-numeric value '" + realValue + "' or comparison target '" + value +
                                           "' (cannot apply numeric operation '" + op + "')" + ctx);
        }
        long long realInt = realIntRes.Value();
        long long wantedInt = wantedIntRes.Value();

        TypedComparisonOperation typedOp = TypedComparisonOperation::LessThan;
        std::string expectation;
        if (op == "lt")
        {
            expectation = "less than";
        }
        else if (op == "le")
        {
            typedOp = TypedComparisonOperation::LessOrEqual;
            expectation = "less than or equal to";
        }
        else if (op == "gt")
        {
            typedOp = TypedComparisonOperation::GreaterThan;
            expectation = "greater than";
        }
        else if (op == "ge")
        {
            typedOp = TypedComparisonOperation::GreaterOrEqual;
            expectation = "greater than or equal to";
        }

        auto result = CompareTyped(realInt, wantedInt, typedOp);
        if (!result.HasValue())
        {
            return result.Error();
        }
        if (result.Value())
        {
            return indicators.Compliant("Option '" + option + "' has a compliant numeric value '" + realValue + "' (" + expectation + " '" + value +
                                        "')" + ctx);
        }
        return indicators.NonCompliant("Option '" + option + "' has numeric value '" + realValue + "' which is not " + expectation + " '" + value + "'" + ctx);
    }
    else
    {
        return Error("Unsupported op '" + op + "'", EINVAL);
    }
}
} // namespace

Result<Status> AuditSshdOption(const SshdOptionParams& params, IndicatorsTree& indicators, ContextInterface& context)
{
    auto log = context.GetLogHandle();
    std::vector<std::string> options = params.option.items;
    if (options.size() == 0)
    {
        return Error("Missing 'option' parameter", EINVAL);
    }
    if (params.value == "")
    {
        return Error("Missing 'value' parameter", EINVAL);
    }
    for (auto& option : options)
    {
        option = ToLower(option);
    }

    std::vector<std::regex> valueRegexes;
    auto op = params.op.Value();
    if (op == SshdOptionOperation::Regex)
    {
        try
        {
            // CIS patterns use ECMAScript escapes such as \b for word boundaries.
            valueRegexes.push_back(std::regex(params.value, std::regex_constants::icase));
        }
        catch (const std::regex_error& e)
        {
            OsConfigLogError(log, "Regex error: %s", e.what());
            return Error("Failed to compile regex error: " + std::string(e.what()), EINVAL);
        }
    }
    if (op == SshdOptionOperation::Match || op == SshdOptionOperation::NotMatch)
    {
        std::istringstream valueStream(params.value);
        std::string valuePart;
        while (std::getline(valueStream, valuePart, ','))
        {
            try
            {
                valueRegexes.push_back(std::regex(valuePart, std::regex_constants::icase));
            }
            catch (const std::regex_error& e)
            {
                OsConfigLogError(log, "Regex error: %s", e.what());
                return Error("Failed to compile regex '" + valuePart + "' error: " + e.what(), EINVAL);
            }
        }
    }

    std::vector<Optional<std::string>> matchModes;
    auto mode = params.mode.Value();
    if (mode == SshdOptionMode::AllMatches)
    {
        auto allMatches = GetAllMatches(context);
        if (!allMatches.HasValue())
        {
            return allMatches.Error();
        }
        if (allMatches.Value().empty())
        {
            return indicators.Compliant("No Match blocks in SSH daemon configuration, skipping Match evaluation");
        }
        for (auto& match : allMatches.Value())
        {
            matchModes.emplace_back(std::move(match));
        }
    }
    else
    {
        matchModes.emplace_back(); // regular (no Match context)
    }

    std::string extraConfig;
    if (params.readExtraConfigs.HasValue() && params.readExtraConfigs.Value())
    {
        auto result = context.ExecuteCommand("source /etc/sysconfig/sshd 2>/dev/null && echo -n $OPTIONS");
        if (result.HasValue() && result.Value() != "")
        {
            extraConfig += result.Value();
        }
        result = context.ExecuteCommand("source /etc/crypto-policies/back-ends/opensshserver.config 2>/dev/null && echo -n $CRYPTO_POLICY");
        if (result.HasValue() && result.Value() != "")
        {
            extraConfig += " " + result.Value();
        }
    }

    for (auto const& matchMode : matchModes)
    {
        auto sshdConfig = GetSshdOptions(context, extraConfig, matchMode.ValueOr(""));
        if (!sshdConfig.HasValue())
        {
            // A failure to *evaluate* the sshd configuration (e.g. sshd -T could not run, or a
            // Match context could not be simulated) is an engine error, not evidence that the
            // system is non-compliant. Reporting it as NonCompliant produces a false negative;
            // propagate it as an Error so it is surfaced as "could not evaluate" and honored by
            // kompli's --continue-on-error handling.
            return Error("Failed to get sshd options: " + sshdConfig.Error().message, sshdConfig.Error().code);
        }
        for (auto const& option : options)
        {
            OsConfigLogInfo(log, "Evaluating SSH daemon option '%s' in mode '%s' with op '%s' against value '%s'", option.c_str(),
                matchMode.HasValue() ? matchMode.Value().c_str() : "regular", std::to_string(op).c_str(), params.value.c_str());
            auto result = EvaluateSshdOption(sshdConfig.Value(), option, params.value, std::to_string(op), valueRegexes, matchMode, indicators);
            if (!result.HasValue())
            {
                return result.Error();
            }
            if (result.Value() == Status::NonCompliant)
            {
                return result.Value();
            }
        }
    }
    return indicators.Compliant("All options are compliant");
}

namespace
{
Result<bool> CheckSshdSources(const std::string& path, ContextInterface& context, std::map<std::string, std::string>& sources)
{
    if (sources.size() >= 64 || sources.count(path))
    {
        return Error("SSH configuration includes are recursive or exceed 64 files; no changes made", ENOTSUP);
    }
    auto contents = context.GetFileContents(path);
    if (!contents.HasValue())
    {
        return contents.Error();
    }
    if (contents.Value().size() > 1024 * 1024)
    {
        return Error("SSH configuration source exceeds 1 MiB; no changes made", ENOTSUP);
    }
    sources.emplace(path, contents.Value());
    std::istringstream lines(contents.Value());
    std::string line;
    while (std::getline(lines, line))
    {
        line = TrimWhiteSpaces(line.substr(0, line.find('#')));
        if (line.empty())
        {
            continue;
        }
        if (line.back() == '\\' || line.find('\0') != std::string::npos)
        {
            return Error("Unsupported SSH configuration line; no changes made", ENOTSUP);
        }
        const auto separator = line.find_first_of(" \t=");
        const auto directive = ToLower(line.substr(0, separator));
        if (directive == "match")
        {
            return Error("Conditional SSH Match configurations require review; no changes made", ENOTSUP);
        }
        if (directive != "include")
        {
            continue;
        }
        const auto arguments = line.find_first_not_of(" \t=", separator);
        if (arguments == std::string::npos)
        {
            return Error("SSH Include requires a path; no changes made", EINVAL);
        }
        std::istringstream words(line.substr(arguments));
        std::string pattern;
        while (words >> pattern)
        {
            if (pattern.find_first_of("'\"\\") != std::string::npos)
            {
                return Error("Quoted SSH Include paths require review; no changes made", ENOTSUP);
            }
            if (pattern.front() != '/')
            {
                pattern = "/etc/ssh/" + pattern;
            }
            pattern = context.GetSpecialFilePath(pattern);
            glob_t matches{};
            // Like sshd, a missing Include directory matches nothing; other read errors abort.
            const auto code = glob(
                pattern.c_str(), 0, [](const char*, int error) { return (error == ENOENT || error == ENOTDIR) ? 0 : 1; }, &matches);
            if (code != 0 && code != GLOB_NOMATCH)
            {
                globfree(&matches);
                return Error("Cannot enumerate SSH Include: " + pattern, EIO);
            }
            for (size_t i = 0; i < matches.gl_pathc; ++i)
            {
                auto checked = CheckSshdSources(matches.gl_pathv[i], context, sources);
                if (!checked.HasValue())
                {
                    globfree(&matches);
                    return checked.Error();
                }
            }
            globfree(&matches);
        }
    }
    return true;
}

std::string DeclaredSshdValue(const std::string& line, size_t keywordEnd)
{
    if (keywordEnd == std::string::npos)
    {
        return "";
    }
    auto value = line.substr(keywordEnd, line.find('#', keywordEnd) - keywordEnd);
    const auto start = value.find_first_not_of(" \t=");
    value = start == std::string::npos ? "" : TrimWhiteSpaces(value.substr(start));
    if (value.size() >= 2 && value.front() == '"' && value.back() == '"')
    {
        value = value.substr(1, value.size() - 2);
    }
    return ToLower(value);
}

Result<std::string> UpdateSshdGlobals(const std::string& contents, const SshdOptionParams& params, const std::function<Result<bool>(const std::string&)>& satisfiesAudit)
{
    std::string updated;
    size_t start = 0;
    while (start < contents.size())
    {
        const auto newline = contents.find('\n', start);
        auto line = contents.substr(start, newline == std::string::npos ? newline : newline - start);
        const auto first = line.find_first_not_of(" \t");
        if (first != std::string::npos)
        {
            const auto end = line.find_first_of(" \t=", first);
            const auto keyword = line.substr(first, end == std::string::npos ? end : end - first);
            if (ToLower(keyword) == params.option.items.front())
            {
                // Declarations that already satisfy the audit are never rewritten.
                auto satisfied = satisfiesAudit(DeclaredSshdValue(line, end));
                if (!satisfied.HasValue())
                {
                    return satisfied.Error();
                }
                if (!satisfied.Value())
                {
                    const auto comment = line.find('#', first);
                    line = line.substr(0, first) + keyword + " " + params.remediationValue.Value() +
                           (comment == std::string::npos ? "" : " " + line.substr(comment));
                }
            }
        }
        updated += line;
        if (newline == std::string::npos)
        {
            break;
        }
        updated += '\n';
        start = newline + 1;
    }
    return updated;
}

Result<std::string> SshdReloadService(ContextInterface& context)
{
    for (const auto& file : {"/etc/default/ssh", "/etc/sysconfig/sshd"})
    {
        const auto path = context.GetSpecialFilePath(file);
        struct stat metadata;
        if (lstat(path.c_str(), &metadata) != 0)
        {
            if (errno == ENOENT)
            {
                continue;
            }
            return Error("Cannot inspect SSH environment file: " + path, errno);
        }
        auto contents = context.GetFileContents(path);
        if (!contents.HasValue())
        {
            return contents.Error();
        }
        std::istringstream lines(contents.Value());
        std::string line;
        while (std::getline(lines, line))
        {
            line = TrimWhiteSpaces(line.substr(0, line.find('#')));
            if (line.find("SSHD_OPTS") == std::string::npos && line.find("OPTIONS") == std::string::npos)
            {
                continue;
            }
            const auto equals = line.find('=');
            const auto name = TrimWhiteSpaces(line.substr(0, equals));
            const auto value = equals == std::string::npos ? line : TrimWhiteSpaces(line.substr(equals + 1));
            if ((name != "SSHD_OPTS" && name != "OPTIONS") || (value != "" && value != "\"\"" && value != "''"))
            {
                return Error("Custom SSH startup options require review; no changes made", ENOTSUP);
            }
        }
    }
    for (const std::string service : {"sshd.service", "ssh.service"})
    {
        auto state = context.ExecuteCommand("systemctl show " + service + " --property=LoadState --property=ActiveState");
        if (!state.HasValue())
        {
            return state.Error();
        }
        if (state.Value().find("LoadState=loaded\n") == std::string::npos || state.Value().find("ActiveState=active\n") == std::string::npos)
        {
            continue;
        }
        auto startup = context.ExecuteCommand("systemctl show " + service + " --property=ExecStart --value");
        if (!startup.HasValue())
        {
            return startup.Error();
        }
        const auto argvStart = startup.Value().find("argv[]=");
        const auto argv =
            argvStart == std::string::npos ? "" : TrimWhiteSpaces(startup.Value().substr(argvStart + 7, startup.Value().find(';', argvStart) - argvStart - 7));
        const std::set<std::string> standardArguments = {
            "/usr/sbin/sshd -D", "/usr/sbin/sshd -D $SSHD_OPTS", "/usr/sbin/sshd -D $OPTIONS", "/usr/sbin/sshd -D $OPTIONS $CRYPTO_POLICY"};
        if (startup.Value().find("path=/usr/sbin/sshd ;") == std::string::npos || !standardArguments.count(argv))
        {
            return Error("Nonstandard SSH service startup requires review; no changes made", ENOTSUP);
        }
        return service;
    }
    return Error("No active standard SSH service found; no changes made", ENOTSUP);
}

Result<std::vector<std::regex>> CompileSshdAuditPatterns(const SshdOptionParams& params)
{
    std::vector<std::regex> patterns;
    if (params.op.Value() == SshdOptionOperation::Regex || params.op.Value() == SshdOptionOperation::Match || params.op.Value() == SshdOptionOperation::NotMatch)
    {
        std::istringstream values(params.value);
        std::string value;
        try
        {
            if (params.op.Value() == SshdOptionOperation::Regex)
            {
                patterns.emplace_back(params.value, std::regex_constants::icase);
            }
            else
            {
                while (std::getline(values, value, ','))
                {
                    patterns.emplace_back(value, std::regex_constants::icase);
                }
            }
        }
        catch (const std::regex_error& error)
        {
            return Error("Invalid SSH audit pattern: " + std::string(error.what()), EINVAL);
        }
    }
    return patterns;
}

// Evaluates a single literal value against the configured audit without
// recording indicators for the rule.
Result<bool> SatisfiesSshdAudit(const SshdOptionParams& params, const std::vector<std::regex>& patterns, const std::string& value)
{
    IndicatorsTree scratch;
    scratch.Push("SshdOption");
    const auto& option = params.option.items.front();
    auto result = EvaluateSshdOption({{option, value}}, option, params.value, std::to_string(params.op.Value()), patterns, {}, scratch);
    if (!result.HasValue())
    {
        return result.Error();
    }
    return result.Value() == Status::Compliant;
}

Result<bool> ValidateSshdTarget(const SshdOptionParams& params)
{
    if (params.option.items.size() != 1)
    {
        return Error("SSH remediation requires exactly one option", EINVAL);
    }
    const auto& option = params.option.items.front();
    const auto& target = params.remediationValue.Value();
    const std::set<std::string> booleans = {"disableforwarding", "permitrootlogin", "gssapiauthentication"};
    const std::map<std::string, unsigned long> limits = {{"maxauthtries", 64}, {"logingracetime", 600}, {"clientaliveinterval", 3600}, {"clientalivecountmax", 10}};
    if (booleans.count(option))
    {
        if (target != (option == "disableforwarding" ? "yes" : "no"))
        {
            return Error("Unsupported SSH boolean remediation target", EINVAL);
        }
    }
    else if (limits.count(option))
    {
        if (!std::regex_match(target, std::regex("[1-9][0-9]{0,3}")) || std::stoul(target) > limits.at(option))
        {
            return Error("SSH numeric remediation target is outside the supported range", EINVAL);
        }
    }
    else if (option != "maxstartups" || target != "10:30:60")
    {
        return Error("Unsupported SSH option or explicit target", ENOTSUP);
    }
    auto patterns = CompileSshdAuditPatterns(params);
    if (!patterns.HasValue())
    {
        return patterns.Error();
    }
    auto accepted = SatisfiesSshdAudit(params, patterns.Value(), target);
    if (!accepted.HasValue())
    {
        return accepted.Error();
    }
    if (!accepted.Value())
    {
        return Error("Explicit SSH remediation target does not satisfy the configured audit; no changes made", ENOTSUP);
    }
    return true;
}
} // namespace

Result<Status> RemediateSshdOption(const SshdOptionParams& params, IndicatorsTree& indicators, ContextInterface& context)
{
    if (!params.remediationValue.HasValue() || params.mode.Value() != SshdOptionMode::Regular)
    {
        return AuditSshdOption(params, indicators, context);
    }
    auto valid = ValidateSshdTarget(params);
    if (!valid.HasValue())
    {
        return valid.Error();
    }
    auto patterns = CompileSshdAuditPatterns(params);
    if (!patterns.HasValue())
    {
        return patterns.Error();
    }
    const auto satisfiesAudit = [&](const std::string& value) { return SatisfiesSshdAudit(params, patterns.Value(), value); };
    auto before = AuditSshdOption(params, indicators, context);
    if (!before.HasValue())
    {
        return before;
    }
    const auto& option = params.option.items.front();
    if (before.Value() == Status::Compliant && option != "permitrootlogin" && option != "gssapiauthentication" && option != "disableforwarding")
    {
        return before;
    }
    const auto path = context.GetSpecialFilePath("/etc/ssh/sshd_config");
    struct stat metadata;
    if (lstat(path.c_str(), &metadata) != 0)
    {
        return Error("Cannot inspect SSH configuration: " + path, errno);
    }
    if (!S_ISREG(metadata.st_mode) || metadata.st_nlink != 1)
    {
        return Error("SSH configuration must be regular and non-hardlinked", EINVAL);
    }
    std::map<std::string, std::string> sources;
    auto inspected = CheckSshdSources(path, context, sources);
    if (!inspected.HasValue())
    {
        return inspected.Error();
    }
    struct Change
    {
        std::string path;
        std::string original;
        std::string updated;
    };
    std::vector<Change> changes;
    for (const auto& source : sources)
    {
        auto globals = UpdateSshdGlobals(source.second, params, satisfiesAudit);
        if (!globals.HasValue())
        {
            return globals.Error();
        }
        auto updated = globals.Value();
        if (source.first == path && before.Value() != Status::Compliant)
        {
            updated = "# kompli: explicit global SSH option\n" + params.option.items.front() + " " + params.remediationValue.Value() + "\n" + updated;
        }
        if (updated != source.second)
        {
            if (lstat(source.first.c_str(), &metadata) != 0)
            {
                return Error("Cannot inspect SSH configuration source: " + source.first, errno);
            }
            if (!S_ISREG(metadata.st_mode) || metadata.st_nlink != 1)
            {
                return Error("Changed SSH sources must be regular and non-hardlinked: " + source.first, EINVAL);
            }
            changes.push_back({source.first, source.second, std::move(updated)});
        }
    }
    if (changes.empty() && before.Value() == Status::Compliant)
    {
        return indicators.Compliant("SSH effective value and global declarations already satisfy the explicit target");
    }
    auto service = SshdReloadService(context);
    if (!service.HasValue())
    {
        return service.Error();
    }
    auto syntax = context.ExecuteCommand("sshd -t");
    if (!syntax.HasValue())
    {
        return syntax.Error();
    }
    bool reloadAttempted = false;
    size_t attempted = 0;
    const auto rollback = [&](const Error& failure) -> Result<Status> {
        std::string rollbackErrors;
        for (size_t i = attempted; i > 0; --i)
        {
            const auto& change = changes[i - 1];
            auto latest = context.GetFileContents(change.path);
            if (!latest.HasValue() || (latest.Value() != change.updated && latest.Value() != change.original))
            {
                rollbackErrors += "; rollback refused: SSH configuration changed concurrently: " + change.path;
                continue;
            }
            if (latest.Value() == change.original)
            {
                continue;
            }
            auto restored = ReplaceFileContentsAtomic(change.path, change.original);
            if (!restored.HasValue())
            {
                rollbackErrors += "; SSH configuration rollback failed: " + restored.Error().message;
            }
        }
        if (!rollbackErrors.empty())
        {
            return Error(failure.message + rollbackErrors, EIO);
        }
        if (reloadAttempted)
        {
            auto checked = context.ExecuteCommand("sshd -t");
            if (!checked.HasValue())
            {
                return Error(failure.message + "; restored SSH configuration validation failed: " + checked.Error().message, checked.Error().code);
            }
            auto recovered = context.ExecuteCommand("systemctl reload " + service.Value());
            if (!recovered.HasValue())
            {
                return Error(failure.message + "; SSH reload recovery failed: " + recovered.Error().message, recovered.Error().code);
            }
        }
        return failure;
    };
    for (const auto& change : changes)
    {
        auto current = context.GetFileContents(change.path);
        if (!current.HasValue())
        {
            return rollback(current.Error());
        }
        if (current.Value() != change.original)
        {
            return rollback(Error("SSH configuration changed concurrently before write: " + change.path, EBUSY));
        }
        ++attempted;
        auto written = ReplaceFileContentsAtomic(change.path, change.updated);
        if (!written.HasValue())
        {
            return rollback(written.Error());
        }
    }
    syntax = context.ExecuteCommand("sshd -t");
    if (!syntax.HasValue())
    {
        return rollback(syntax.Error());
    }
    auto verified = AuditSshdOption(params, indicators, context);
    if (!verified.HasValue())
    {
        return rollback(verified.Error());
    }
    if (verified.Value() != Status::Compliant)
    {
        return rollback(Error("Effective SSH configuration did not satisfy the audit", EIO));
    }
    reloadAttempted = true;
    auto reloaded = context.ExecuteCommand("systemctl reload " + service.Value());
    if (!reloaded.HasValue())
    {
        return rollback(reloaded.Error());
    }
    return indicators.Compliant("Validated and reloaded the explicit global SSH option; existing sessions are retained");
}

} // namespace Kompli
