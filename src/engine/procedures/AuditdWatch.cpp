// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <AtomicFile.h>
#include <AuditdWatch.h>
#include <StringTools.h>
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <memory>
#include <regex>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace ComplianceEngine
{
namespace
{
const std::string watchKey = "kompli_watch";
const std::string loaderCommand = "systemctl show auditd.service --property=ExecStartPost --value";

Result<bool> ValidateWatch(const AuditdWatchParams& params)
{
    static const std::regex pathPattern("^/([A-Za-z0-9_-]+[A-Za-z0-9_.-]*/)*[A-Za-z0-9_-]+[A-Za-z0-9_.-]*/?$");
    static const std::regex permissionsPattern("^r?w?x?a?$");
    if (params.path.size() > 96 || !std::regex_match(params.path, pathPattern))
    {
        return Error("Audit watch requires a literal absolute path of at most 96 characters, without traversal or shell syntax", EINVAL);
    }
    if (params.permissions.empty() || !std::regex_match(params.permissions, permissionsPattern))
    {
        return Error("Audit watch permissions must be a nonempty subset in rwxa order", EINVAL);
    }
    return true;
}

std::string ManagedPath(const AuditdWatchParams& params, ContextInterface& context)
{
    const char* digits = "0123456789abcdef";
    std::string encoded;
    for (unsigned char character : params.path)
    {
        encoded += digits[character >> 4];
        encoded += digits[character & 15];
    }
    return context.GetSpecialFilePath("/etc/audit/rules.d") + "/70-kompli-watch-" + encoded + "-" + params.permissions + ".rules";
}

std::vector<std::string> Tokens(const std::string& line)
{
    std::istringstream input(line.substr(0, line.find('#')));
    std::vector<std::string> tokens;
    std::string token;
    while (input >> token)
    {
        tokens.push_back(token);
    }
    return tokens;
}

bool SamePath(const std::string& left, const std::string& right)
{
    return left.substr(0, left.size() - (left.back() == '/')) == right.substr(0, right.size() - (right.back() == '/'));
}

bool MentionsTarget(const std::vector<std::string>& tokens, const std::string& path)
{
    for (const auto& token : tokens)
    {
        for (const auto& prefix : {"", "path=", "dir="})
        {
            const std::string start = prefix;
            if (token.compare(0, start.size(), start) == 0 && token.size() > start.size() && SamePath(token.substr(start.size()), path))
            {
                return true;
            }
        }
    }
    return false;
}

bool MatchesWatch(const std::vector<std::string>& tokens, const AuditdWatchParams& params, bool requireOwned)
{
    if (tokens.size() != 4 && tokens.size() != 6)
    {
        return false;
    }
    if (tokens[0] != "-w" || !SamePath(tokens[1], params.path) || tokens[2] != "-p" || tokens[3] != params.permissions)
    {
        return false;
    }
    if (tokens.size() == 6 && (tokens[4] != "-k" || tokens[5].empty()))
    {
        return false;
    }
    return !requireOwned || (tokens.size() == 6 && tokens[5] == watchKey);
}

Result<std::vector<std::string>> RunningRules(ContextInterface& context)
{
    auto output = context.ExecuteCommand("auditctl -l");
    if (!output.HasValue())
    {
        return output.Error();
    }
    std::vector<std::string> lines;
    std::istringstream input(output.Value());
    std::string line;
    while (std::getline(input, line))
    {
        if (!Tokens(line).empty() && TrimWhiteSpaces(line) != "No rules")
        {
            lines.push_back(line);
        }
    }
    return lines;
}

Result<std::vector<std::string>> PersistentRules(ContextInterface& context)
{
    const auto directory = context.GetSpecialFilePath("/etc/audit/rules.d");
    std::unique_ptr<DIR, int (*)(DIR*)> entries(opendir(directory.c_str()), closedir);
    if (!entries)
    {
        return Error("Cannot open audit rules directory: " + std::string(strerror(errno)), errno);
    }
    std::vector<std::string> lines;
    while (true)
    {
        errno = 0;
        const auto entry = readdir(entries.get());
        if (!entry)
        {
            if (errno != 0)
            {
                return Error("Cannot enumerate audit rules directory", errno);
            }
            break;
        }
        const std::string name = entry->d_name;
        if (name.size() < 6 || name.substr(name.size() - 6) != ".rules")
        {
            continue;
        }
        const auto path = directory + "/" + name;
        struct stat metadata;
        if (lstat(path.c_str(), &metadata) != 0)
        {
            return Error("Cannot inspect audit rule source: " + path, errno);
        }
        if (!S_ISREG(metadata.st_mode) || metadata.st_nlink != 1)
        {
            return Error("Audit rule sources must be regular and non-hardlinked: " + path, ENOTSUP);
        }
        auto contents = context.GetFileContents(path);
        if (!contents.HasValue())
        {
            return contents.Error();
        }
        std::istringstream input(contents.Value());
        std::string line;
        while (std::getline(input, line))
        {
            if (!Tokens(line).empty())
            {
                lines.push_back(line);
            }
        }
    }
    return lines;
}

bool HasWatch(const std::vector<std::string>& lines, const AuditdWatchParams& params, bool requireOwned = false)
{
    return std::any_of(lines.begin(), lines.end(), [&](const std::string& line) { return MatchesWatch(Tokens(line), params, requireOwned); });
}

Result<bool> CheckConflicts(const std::vector<std::string>& lines, const AuditdWatchParams& params)
{
    for (const auto& line : lines)
    {
        const auto tokens = Tokens(line);
        if ((std::find(tokens.begin(), tokens.end(), "never,task") != tokens.end()) || (std::find(tokens.begin(), tokens.end(), "task,never") != tokens.end()) ||
            (std::find(tokens.begin(), tokens.end(), "never,exit") != tokens.end()) || (std::find(tokens.begin(), tokens.end(), "exit,never") != tokens.end()) ||
            (tokens.size() > 1 && tokens[0] == "-D") || (tokens.size() == 2 && tokens[0] == "-e" && tokens[1] == "0"))
        {
            return Error("Audit suppression or disabled-audit rules require administrator review", ENOTSUP);
        }
        if (MentionsTarget(tokens, params.path) && !MatchesWatch(tokens, params, false))
        {
            return Error("Conflicting or unsupported existing audit rule for " + params.path, ENOTSUP);
        }
    }
    return true;
}

Result<bool> CheckAuditStatus(ContextInterface& context, bool writable)
{
    auto status = context.ExecuteCommand("auditctl -s");
    if (!status.HasValue())
    {
        return status.Error();
    }
    std::istringstream input(status.Value());
    std::string line;
    bool enabled = false;
    bool daemon = false;
    while (std::getline(input, line))
    {
        const auto tokens = Tokens(line);
        if (tokens.size() == 2 && tokens[0] == "enabled")
        {
            if (tokens[1] != "1" && (writable || tokens[1] != "2"))
            {
                return Error("Audit must be enabled and mutable; immutable/disabled audit state is not changed automatically", EPERM);
            }
            enabled = true;
        }
        if (tokens.size() == 2 && tokens[0] == "pid")
        {
            auto pid = TryStringToInt(tokens[1]);
            daemon = pid.HasValue() && pid.Value() > 0;
        }
    }
    if (!enabled || !daemon)
    {
        return Error("Unable to confirm enabled auditing and a running audit daemon", ENOTSUP);
    }
    return true;
}

Result<bool> CheckLoader(ContextInterface& context)
{
    auto loader = context.ExecuteCommand(loaderCommand);
    if (!loader.HasValue())
    {
        return loader.Error();
    }
    static const std::regex supportedLoader(R"(^\{[ \t]*path=/(usr/)?sbin/augenrules[ \t]*;[ \t]*argv\[\]=/(usr/)?sbin/augenrules --load[ \t]*;[^{}]*\}[ \t]*$)");
    const auto command = TrimWhiteSpaces(loader.Value());
    if (std::regex_match(command, supportedLoader))
    {
        return true;
    }
    if (!command.empty())
    {
        return Error("Persistent audit watches require an effective auditd ExecStartPost using augenrules --load", ENOTSUP);
    }

    auto dependencies = context.ExecuteCommand("systemctl show auditd.service --property=Requires --property=Wants --value");
    if (!dependencies.HasValue())
    {
        return dependencies.Error();
    }
    std::istringstream input(dependencies.Value());
    std::string token;
    std::string unit;
    while (input >> token)
    {
        if (token == "augenrules.service" || token == "audit-rules.service")
        {
            if (!unit.empty() && unit != token)
            {
                return Error("Multiple audit rule-loader dependencies require administrator review", ENOTSUP);
            }
            unit = token;
        }
    }
    if (unit.empty())
    {
        return Error("Persistent audit watches require an auditd startup loader using augenrules --load", ENOTSUP);
    }
    for (const auto& property : {"LoadState", "Type", "After", "ExecStart"})
    {
        auto value = context.ExecuteCommand("systemctl show " + unit + " --property=" + property + " --value");
        if (!value.HasValue())
        {
            return value.Error();
        }
        const auto normalized = TrimWhiteSpaces(value.Value());
        bool valid = false;
        if (std::string(property) == "LoadState")
        {
            valid = normalized == "loaded";
        }
        else if (std::string(property) == "Type")
        {
            valid = normalized == "oneshot";
        }
        else if (std::string(property) == "After")
        {
            const auto orderedAfter = Tokens(normalized);
            valid = std::find(orderedAfter.begin(), orderedAfter.end(), "auditd.service") != orderedAfter.end();
        }
        else
        {
            valid = std::regex_match(normalized, supportedLoader);
        }
        if (!valid)
        {
            return Error("Unsupported audit rule-loader " + unit + " property " + property + ": " + normalized, ENOTSUP);
        }
    }
    return true;
}

std::string WatchCommand(const AuditdWatchParams& params, bool remove)
{
    return "auditctl " + std::string(remove ? "-W '" : "-w '") + params.path + "' -p " + params.permissions + " -k " + watchKey;
}
} // namespace

Result<Status> AuditAuditdWatch(const AuditdWatchParams& params, IndicatorsTree& indicators, ContextInterface& context)
{
    auto valid = ValidateWatch(params);
    if (!valid.HasValue())
    {
        return valid.Error();
    }
    auto status = CheckAuditStatus(context, false);
    if (!status.HasValue())
    {
        return status.Error();
    }
    auto loader = CheckLoader(context);
    if (!loader.HasValue())
    {
        return loader.Error();
    }
    auto running = RunningRules(context);
    if (!running.HasValue())
    {
        return running.Error();
    }
    auto persistent = PersistentRules(context);
    if (!persistent.HasValue())
    {
        return persistent.Error();
    }
    for (const auto& lines : {running.Value(), persistent.Value()})
    {
        auto conflict = CheckConflicts(lines, params);
        if (!conflict.HasValue())
        {
            return conflict.Error();
        }
        if (!HasWatch(lines, params))
        {
            return indicators.NonCompliant("Literal audit watch missing from runtime or persistent sources: " + params.path);
        }
    }
    return indicators.Compliant("Literal audit watch exists in runtime and persistent sources: " + params.path);
}

Result<Status> RemediateAuditdWatch(const AuditdWatchParams& params, IndicatorsTree& indicators, ContextInterface& context)
{
    auto audit = AuditAuditdWatch(params, indicators, context);
    if (!audit.HasValue() || audit.Value() == Status::Compliant)
    {
        return audit;
    }
    auto writable = CheckAuditStatus(context, true);
    if (!writable.HasValue())
    {
        return writable.Error();
    }
    struct stat target;
    if (stat(context.GetSpecialFilePath(params.path).c_str(), &target) != 0)
    {
        return Error("Audit watch target must already exist: " + params.path, errno);
    }
    if (!S_ISREG(target.st_mode) && !S_ISDIR(target.st_mode))
    {
        return Error("Audit watch target must be a regular file or directory", ENOTSUP);
    }
    auto running = RunningRules(context);
    if (!running.HasValue())
    {
        return running.Error();
    }
    auto persistent = PersistentRules(context);
    if (!persistent.HasValue())
    {
        return persistent.Error();
    }
    for (const auto& lines : {running.Value(), persistent.Value()})
    {
        auto conflict = CheckConflicts(lines, params);
        if (!conflict.HasValue())
        {
            return conflict.Error();
        }
    }
    const bool create = !HasWatch(persistent.Value(), params);
    const bool add = !HasWatch(running.Value(), params);
    const auto path = ManagedPath(params, context);
    const auto managedContents = "# Managed by kompli\n-w " + params.path + " -p " + params.permissions + " -k " + watchKey + "\n";
    struct stat created = {};
    if (create)
    {
        auto written = CreateFileContentsAtomic(path, managedContents, 0600, &created);
        if (!written.HasValue())
        {
            return written.Error();
        }
    }
    bool attempted = false;
    auto apply = [&]() -> Result<Status> {
        if (add)
        {
            attempted = true;
            auto result = context.ExecuteCommand(WatchCommand(params, false));
            if (!result.HasValue())
            {
                return result.Error();
            }
        }
        return AuditAuditdWatch(params, indicators, context);
    };
    auto postAudit = apply();
    if (postAudit.HasValue() && postAudit.Value() == Status::Compliant)
    {
        return postAudit;
    }
    std::string rollbackErrors;
    if (attempted)
    {
        auto current = RunningRules(context);
        if (!current.HasValue())
        {
            rollbackErrors += "cannot inspect runtime watch before rollback: " + current.Error().message;
        }
        else if (HasWatch(current.Value(), params, true))
        {
            auto removed = context.ExecuteCommand(WatchCommand(params, true));
            if (!removed.HasValue())
            {
                rollbackErrors += "runtime watch removal: " + removed.Error().message;
            }
            else
            {
                auto remaining = RunningRules(context);
                if (!remaining.HasValue() || HasWatch(remaining.Value(), params, true))
                {
                    rollbackErrors += "runtime watch removal could not be verified";
                }
            }
        }
        else
        {
            for (const auto& line : current.Value())
            {
                const auto tokens = Tokens(line);
                if (MentionsTarget(tokens, params.path) && std::find(tokens.begin(), tokens.end(), watchKey) != tokens.end())
                {
                    rollbackErrors += "owned runtime watch changed before rollback";
                    break;
                }
            }
        }
    }
    if (create)
    {
        struct stat current;
        auto contents = context.GetFileContents(path);
        if (lstat(path.c_str(), &current) != 0 || current.st_ino != created.st_ino || current.st_dev != created.st_dev || current.st_nlink != 1 ||
            !contents.HasValue() || contents.Value() != managedContents)
        {
            rollbackErrors += "; managed audit source changed before rollback";
        }
        else if (unlink(path.c_str()) != 0)
        {
            rollbackErrors += "; cannot remove managed audit source: " + std::string(strerror(errno));
        }
    }
    if (!rollbackErrors.empty())
    {
        return Error("Audit watch verification/application failed; rollback failed: " + rollbackErrors, EIO);
    }
    return postAudit;
}
} // namespace ComplianceEngine
