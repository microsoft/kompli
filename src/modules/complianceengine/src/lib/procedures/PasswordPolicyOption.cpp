// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <AtomicFile.h>
#include <DistributionInfo.h>
#include <PasswordPolicyOption.h>
#include <StringTools.h>
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <iterator>
#include <map>
#include <memory>
#include <regex>
#include <set>
#include <sstream>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <vector>

namespace ComplianceEngine
{
namespace
{
struct OptionRange
{
    int minimum;
    int maximum;
};

Result<bool> Validate(const PasswordPolicyOptionParams& params)
{
    static const std::map<std::string, std::map<std::string, OptionRange>> ranges = {
        {"pwquality", {{"minlen", {6, 1024}}, {"difok", {1, 1024}}, {"maxrepeat", {1, 1024}}, {"maxsequence", {1, 1024}}, {"enforce_for_root", {0, 0}}}},
        {"faillock", {{"deny", {1, 65535}}, {"unlock_time", {0, 604800}}, {"root_unlock_time", {1, 604800}}, {"even_deny_root", {0, 0}}}},
        {"pwhistory", {{"remember", {1, 400}}, {"enforce_for_root", {0, 0}}}},
    };
    const auto policy = ranges.find(params.policy);
    if (policy == ranges.end())
    {
        return Error("Unsupported password policy: " + params.policy, EINVAL);
    }
    const auto option = policy->second.find(params.option);
    if (option == policy->second.end())
    {
        return Error("Unsupported " + params.policy + " option: " + params.option, ENOTSUP);
    }
    if (option->second.maximum == 0)
    {
        if (params.value != "true")
        {
            return Error("Password policy flags require the explicit value 'true'", EINVAL);
        }
    }
    else
    {
        auto value = TryStringToInt(params.value);
        if (!value.HasValue() || value.Value() < option->second.minimum || value.Value() > option->second.maximum ||
            std::to_string(value.Value()) != params.value)
        {
            return Error("Password policy target must be a canonical integer within the supported option range", EINVAL);
        }
    }
    return true;
}

bool IsFlag(const PasswordPolicyOptionParams& params)
{
    return params.option == "enforce_for_root" || params.option == "even_deny_root";
}

std::string ActiveLine(const std::string& line)
{
    return TrimWhiteSpaces(line.substr(0, line.find('#')));
}

std::string OptionName(const std::string& line)
{
    const auto active = ActiveLine(line);
    return active.substr(0, active.find_first_of("= \t\r"));
}

Result<std::vector<std::string>> PamLines(const std::string& contents)
{
    std::vector<std::string> result;
    std::string assembled;
    size_t start = 0;
    bool continued = false;
    while (start < contents.size())
    {
        const auto newline = contents.find('\n', start);
        const auto end = newline == std::string::npos ? contents.size() : newline + 1;
        auto line = contents.substr(start, end - start);
        if (line.find('\0') != std::string::npos)
        {
            return Error("NUL in PAM configuration", EINVAL);
        }
        // Linux-PAM strips spaces, tabs and LF (not CR) before checking the last
        // backslash, even at EOF. A comment terminates continuation on that line.
        const auto last = line.find_last_not_of(" \t\n");
        continued = last != std::string::npos && line[last] == '\\' && line.find('#') == std::string::npos;
        if (last != std::string::npos && line[last] == '\\')
        {
            line = line.substr(0, last) + " ";
        }
        const auto first = line.find_first_not_of(" \t");
        if (first != std::string::npos)
        {
            line.erase(0, first);
        }
        line = line.substr(0, line.find('#'));
        assembled += line;
        if (!continued)
        {
            if (!TrimWhiteSpaces(assembled).empty())
            {
                result.push_back(TrimWhiteSpaces(assembled));
            }
            assembled.clear();
        }
        start = end;
    }
    if (continued)
    {
        return Error("Incomplete continued PAM configuration at EOF", EINVAL);
    }
    return result;
}

Result<bool> InspectPamFile(const std::string& path, const PasswordPolicyOptionParams& params, ContextInterface& context)
{
    auto contents = context.GetFileContents(path);
    if (!contents.HasValue())
    {
        return contents.Error();
    }
    auto logical = PamLines(contents.Value());
    if (!logical.HasValue())
    {
        return logical.Error();
    }
    bool found = false;
    const auto module = "pam_" + params.policy + ".so";
    for (const auto& line : logical.Value())
    {
        std::istringstream tokens(ActiveLine(line));
        std::string token;
        bool selected = false;
        while (tokens >> token)
        {
            if (!selected)
            {
                if (token.substr(token.find_last_of('/') + 1) == module)
                {
                    selected = true;
                    found = true;
                }

                continue;
            }
            if (token.compare(0, 5, "conf=") == 0 || token.compare(0, 7, "config=") == 0)
            {
                return Error("Custom PAM configuration path in " + path + "; refusing to modify the default configuration", ENOTSUP);
            }
            if (token == params.option || token.compare(0, params.option.size() + 1, params.option + "=") == 0)
            {
                const auto expected = IsFlag(params) ? params.option : params.option + "=" + params.value;
                if (token != expected)
                {
                    return Error("Conflicting inline PAM option '" + params.option + "' in " + path + "; authentication stacks are not rewritten", ENOTSUP);
                }
            }
        }
    }
    return found;
}

bool HasWord(const std::string& text, const std::string& word)
{
    std::istringstream words(text);
    std::string token;
    while (words >> token)
    {
        if (token == word)
        {
            return true;
        }
    }
    return false;
}

Result<bool> CheckModuleConfiguration(const PasswordPolicyOptionParams& params, ContextInterface& context, const std::string& modulePath = "",
    bool configurationRequired = true)
{
    const auto module = "pam_" + params.policy + ".so";
    std::vector<std::string> paths;
    if (!modulePath.empty() && modulePath.front() == '/')
    {
        paths.push_back(context.GetSpecialFilePath(modulePath));
    }
    else
    {
        for (const auto& directory :
            {"/usr/lib64/security/", "/lib64/security/", "/usr/lib/security/", "/lib/security/", "/usr/lib/x86_64-linux-gnu/security/",
                "/lib/x86_64-linux-gnu/security/", "/usr/lib/aarch64-linux-gnu/security/", "/lib/aarch64-linux-gnu/security/"})
        {
            paths.push_back(context.GetSpecialFilePath(std::string(directory) + module));
        }
    }
    for (const auto& path : paths)
    {
        struct stat metadata;
        if (stat(path.c_str(), &metadata) != 0)
        {
            if (errno != ENOENT)
            {
                return Error("Cannot inspect installed PAM module " + path, errno);
            }
            continue;
        }
        if (!S_ISREG(metadata.st_mode))
        {
            return Error("Installed PAM module is not a regular file: " + path, EINVAL);
        }
        std::ifstream stream(path, std::ios::binary);
        if (!stream)
        {
            return Error("Cannot read installed PAM module " + path, errno);
        }
        const std::string contents{std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>()};
        if (stream.bad())
        {
            return Error("Cannot completely read installed PAM module " + path, EIO);
        }
        if (contents.compare(0, 4, "\177ELF") != 0)
        {
            return Error("Installed PAM module is not an ELF object: " + path, EINVAL);
        }
        // Configuration-only integration requires evidence of a local reader.
        // Managed inline policy does not depend on configuration-file support.
        if (configurationRequired && params.policy != "pwquality" && contents.find(params.policy + ".conf") == std::string::npos)
        {
            return Error("Installed " + module + " has no configuration-file support; use a supported vendor inline policy integration", ENOTSUP);
        }
        return true;
    }
    return Error("Installed " + module + " required; install the distribution prerequisite package before PAM integration", ENOENT);
}

// Activation is deliberately limited to existing authselect profiles. Other
// vendors need installed, vendor-supported integration, not guessed PAM hooks.
struct PamActivation
{
    std::string command;
    std::string backup;
    std::string originalSelection;
};

Result<bool> RestorePam(const PamActivation& activation, ContextInterface& context);

Result<PamActivation> ActivatePam(const PasswordPolicyOptionParams& params, ContextInterface& context)
{
    PamActivation activation;
    auto distribution = DistributionInfo::ParseEtcOsRelease(context.GetSpecialFilePath("/etc/os-release"));
    if (!distribution.HasValue())
    {
        return distribution.Error();
    }
    switch (distribution->distribution)
    {
        case LinuxDistribution::RHEL:
        case LinuxDistribution::OracleLinux:
        case LinuxDistribution::AlmaLinux:
        case LinuxDistribution::RockyLinux:
            break;
        default:
            return Error(
                "This distribution has no supported installed vendor activation for the requested PAM policy; "
                "pam-config/pam-auth-update integration requires an appropriate installed vendor profile, not guessed hooks",
                ENOTSUP);
    }
    const auto executable = context.GetSpecialFilePath("/usr/bin/authselect");
    if (access(executable.c_str(), X_OK) != 0)
    {
        return Error(
            "PAM activation requires an existing authselect profile with the requested feature. "
            "pam-config/pam-auth-update or unmanaged stacks require vendor-supported integration; no hooks were inserted",
            ENOTSUP);
    }
    activation.command = "\"" + executable + "\"";
    auto current = context.ExecuteCommand(activation.command + " current --raw");
    if (!current.HasValue() || TrimWhiteSpaces(current.Value()).empty())
    {
        return Error("No existing authselect selection; refusing to choose an authentication provider", ENOTSUP);
    }
    activation.originalSelection = TrimWhiteSpaces(current.Value());
    const auto profile = activation.originalSelection.substr(0, activation.originalSelection.find_first_of(" \t\r\n"));
    if (profile.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-/") != std::string::npos || profile.find("..") != std::string::npos)
    {
        return Error("Invalid authselect profile identifier", EINVAL);
    }
    auto checked = context.ExecuteCommand(activation.command + " check");
    if (!checked.HasValue())
    {
        return Error("Existing PAM configuration does not pass authselect check; refusing to overwrite local changes", ENOTSUP);
    }
    const auto feature = "with-" + params.policy;
    if (params.policy == "pwquality")
    {
        return Error("Selected authselect profile has no active pwquality stack; refusing to change providers", ENOTSUP);
    }
    if (HasWord(activation.originalSelection, feature))
    {
        return Error("Authselect feature is enabled but PAM policy is not usable; repair the selected profile", ENOTSUP);
    }
    auto features = context.ExecuteCommand(activation.command + " list-features \"" + profile + "\"");
    if (!features.HasValue() || !HasWord(features.Value(), feature))
    {
        return Error("Selected authselect profile does not support " + feature, ENOTSUP);
    }
    auto installed = CheckModuleConfiguration(params, context);
    if (!installed.HasValue())
    {
        return installed.Error();
    }
    activation.backup = "kompli-password-" + std::to_string(getpid()) + "-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    // apply-changes creates a vendor backup before enable-feature is attempted.
    auto backup = context.ExecuteCommand(activation.command + " apply-changes --backup=" + activation.backup);
    if (!backup.HasValue())
    {
        auto restored = RestorePam(activation, context);
        return restored.HasValue() ? backup.Error() : Error("Authselect backup/apply failed; rollback failed: " + restored.Error().message, EIO);
    }
    auto enabled = context.ExecuteCommand(activation.command + " enable-feature " + feature);
    auto selection = context.ExecuteCommand(activation.command + " current --raw");
    auto validation = context.ExecuteCommand(activation.command + " check");
    const auto selectedProfile =
        selection.HasValue() ? TrimWhiteSpaces(selection.Value()).substr(0, TrimWhiteSpaces(selection.Value()).find_first_of(" \t\r\n")) : "";
    bool preserved = selectedProfile == profile && selection.HasValue() && HasWord(selection.Value(), feature);
    std::istringstream previous(activation.originalSelection);
    std::string token;
    while (previous >> token)
    {
        preserved = preserved && selection.HasValue() && HasWord(selection.Value(), token);
    }
    if (selection.HasValue())
    {
        std::istringstream selected(selection.Value());
        while (selected >> token)
        {
            preserved = preserved && (token == feature || HasWord(activation.originalSelection, token));
        }
    }
    if (!enabled.HasValue() || !validation.HasValue() || !preserved)
    {
        auto restored = context.ExecuteCommand(activation.command + " backup-restore " + activation.backup);
        auto state = context.ExecuteCommand(activation.command + " current --raw");
        auto check = context.ExecuteCommand(activation.command + " check");
        if (!restored.HasValue() || !state.HasValue() || TrimWhiteSpaces(state.Value()) != activation.originalSelection || !check.HasValue())
        {
            return Error("PAM activation failed; authselect rollback failed", EIO);
        }
        return Error("PAM activation failed validation; prior authselect profile and features restored", EIO);
    }
    return activation;
}

Result<bool> RestorePam(const PamActivation& activation, ContextInterface& context)
{
    if (activation.backup.empty())
    {
        return true;
    }
    auto restored = context.ExecuteCommand(activation.command + " backup-restore " + activation.backup);
    auto state = context.ExecuteCommand(activation.command + " current --raw");
    auto check = context.ExecuteCommand(activation.command + " check");
    if (!restored.HasValue() || !state.HasValue() || TrimWhiteSpaces(state.Value()) != activation.originalSelection || !check.HasValue())
    {
        return Error("Authselect rollback failed to restore prior profile and features", EIO);
    }
    return true;
}
struct PamEntry
{
    std::string type;
    std::string control;
    std::string module;
    std::string modulePath;
    std::string arguments;
};

Result<std::vector<PamEntry>> PamEntries(const std::string& contents)
{
    auto lines = PamLines(contents);
    if (!lines.HasValue())
    {
        return lines.Error();
    }
    std::vector<PamEntry> entries;
    for (const auto& line : lines.Value())
    {
        std::istringstream tokens(line);
        PamEntry entry;
        tokens >> entry.type >> entry.control;
        if (!entry.control.empty() && entry.control.front() == '[' && entry.control.back() != ']')
        {
            std::string token;
            while (tokens >> token)
            {
                entry.control += " " + token;
                if (token.back() == ']')
                {
                    break;
                }
            }
        }
        tokens >> entry.modulePath;
        std::getline(tokens, entry.arguments);
        entry.arguments = TrimWhiteSpaces(entry.arguments);
        entry.module = entry.modulePath.substr(entry.modulePath.find_last_of('/') + 1);
        if (entry.module.empty() || (!entry.control.empty() && entry.control.front() == '[' && entry.control.back() != ']'))
        {
            return Error("Malformed managed PAM stack", EINVAL);
        }
        entries.push_back(entry);
    }
    return entries;
}

Result<bool> ValidateIntegration(const PasswordPolicyOptionParams& params, ContextInterface& context, const std::map<std::string, std::string>* generated = nullptr)
{
    // These are authselect's two entry stacks. Do not infer effectiveness from a
    // reference in an unused service or a sufficient/optional policy module.
    std::vector<std::string> stacks = {"system-auth", "password-auth"};
    auto distribution = DistributionInfo::ParseEtcOsRelease(context.GetSpecialFilePath("/etc/os-release"));
    if (!distribution.HasValue())
    {
        return distribution.Error();
    }
    if (distribution->distribution == LinuxDistribution::AzureLinux || distribution->distribution == LinuxDistribution::Mariner)
    {
        return Error("Unmanaged Azure Linux PAM stack has no supported vendor policy integration; refusing guessed authentication hooks", ENOTSUP);
    }
    if (distribution->distribution == LinuxDistribution::Debian || distribution->distribution == LinuxDistribution::Ubuntu ||
        distribution->distribution == LinuxDistribution::SUSE)
    {
        if (params.policy == "faillock")
        {
            return Error("No supported vendor faillock control-flow for common-* PAM stacks; refusing guessed authentication hooks", ENOTSUP);
        }
        stacks = {"common-password"};
    }
    for (const auto& name : stacks)
    {
        auto contents = generated ? Result<std::string>(generated->at(name)) :
                                    context.GetFileContents(context.GetSpecialFilePath(std::string("/etc/pam.d/") + name));
        if (!contents.HasValue())
        {
            return contents.Error();
        }
        auto entries = PamEntries(contents.Value());
        if (!entries.HasValue())
        {
            return entries.Error();
        }
        bool policy = false;
        bool provider = false;
        bool failure = false;
        bool denied = false;
        bool account = false;
        for (size_t index = 0; index < entries->size(); ++index)
        {
            const auto& entry = entries.Value()[index];
            if (entry.module == "pam_" + params.policy + ".so")
            {
                const bool inlineValue = IsFlag(params) ? HasWord(entry.arguments, params.option) : entry.arguments.find(params.option + "=") != std::string::npos;
                auto installed = CheckModuleConfiguration(params, context, entry.modulePath, !inlineValue);
                if (!installed.HasValue())
                {
                    return installed.Error();
                }
            }
            if (params.policy != "faillock" && entry.type == "password")
            {
                if (entry.module == "pam_" + params.policy + ".so")
                {
                    if (policy || provider || (entry.control != "required" && entry.control != "requisite") ||
                        (params.policy == "pwhistory" && !HasWord(entry.arguments, "use_authtok")))
                    {
                        return Error("Password policy can be bypassed or does not share the password token in " + name, ENOTSUP);
                    }
                    policy = true;
                }
                else if (entry.module == "pam_unix.so" || entry.module == "pam_sss.so")
                {
                    if (!policy || !HasWord(entry.arguments, "use_authtok"))
                    {
                        return Error("Password provider precedes policy or does not consume its token in " + name, ENOTSUP);
                    }
                    provider = true;
                }
                else if (entry.control == "sufficient" || (!entry.control.empty() && entry.control.front() == '['))
                {
                    const bool localHistoryGate = params.policy == "pwhistory" && entry.module == "pam_localuser.so" &&
                                                  entry.control == "[default=1 ignore=ignore success=ok]" && index + 1 < entries->size() &&
                                                  entries.Value()[index + 1].type == "password" &&
                                                  entries.Value()[index + 1].module == "pam_pwhistory.so";
                    const bool localProviderGate = policy && provider && entry.module == "pam_localuser.so" &&
                                                   entry.control == "[success=1 default=ignore]" && index + 1 < entries->size() &&
                                                   entries.Value()[index + 1].type == "password" && entries.Value()[index + 1].module == "pam_sss.so";
                    if (!localHistoryGate && !localProviderGate)
                    {
                        return Error("Unsupported password control-flow in " + name, ENOTSUP);
                    }
                }
            }
            if (params.policy == "faillock")
            {
                if (entry.type == "auth" && entry.module == "pam_faillock.so")
                {
                    if (HasWord(entry.arguments, "preauth") && !policy && !provider && entry.control == "required")
                    {
                        policy = true;
                    }
                    else if (HasWord(entry.arguments, "authfail") && policy && provider && !failure && (entry.control == "[default=die]" || entry.control == "required"))
                    {
                        failure = true;
                    }
                    else
                    {
                        return Error("Unsupported faillock authentication control-flow in " + name, ENOTSUP);
                    }
                }
                else if (entry.type == "auth" && entry.module == "pam_deny.so" && failure && (entry.control == "required" || entry.control == "requisite"))
                {
                    denied = true;
                }
                else if (entry.type == "auth" && (entry.module == "pam_unix.so" || entry.module == "pam_sss.so"))
                {
                    if (!policy || failure || entry.control != "sufficient")
                    {
                        return Error("Authentication provider can bypass lockout in " + name, ENOTSUP);
                    }
                    provider = true;
                }
                else if (entry.type == "auth" && entry.control == "sufficient")
                {
                    return Error("Unsupported bypass of faillock in " + name, ENOTSUP);
                }
                else if (entry.type == "auth" && !entry.control.empty() && entry.control.front() == '[')
                {
                    if (!policy)
                    {
                        return Error("Authentication branch precedes lockout in " + name, ENOTSUP);
                    }
                    std::istringstream actions(entry.control.substr(1, entry.control.size() - 2));
                    std::string action;
                    while (actions >> action)
                    {
                        const auto equals = action.find('=');
                        if (equals == std::string::npos)
                        {
                            return Error("Malformed PAM action in " + name, EINVAL);
                        }
                        const auto value = action.substr(equals + 1);
                        if (value == "done" || value == "reset")
                        {
                            return Error("Unsupported early authentication return in " + name, ENOTSUP);
                        }
                        auto jump = TryStringToInt(value);
                        if (jump.HasValue() && jump.Value() > 0)
                        {
                            int remaining = jump.Value();
                            for (size_t target = index + 1; target < entries->size() && remaining > 0; ++target)
                            {
                                const auto& skipped = entries.Value()[target];
                                if (skipped.type != "auth")
                                {
                                    continue;
                                }
                                if (skipped.module == "pam_faillock.so")
                                {
                                    return Error("Authentication branch bypasses faillock in " + name, ENOTSUP);
                                }
                                --remaining;
                            }
                            if (remaining != 0)
                            {
                                return Error("Out-of-stack authentication jump in " + name, ENOTSUP);
                            }
                        }
                    }
                }
                if (entry.type == "account" && entry.module == "pam_faillock.so" && entry.control == "required")
                {
                    account = true;
                }
                else if (entry.type == "account" && !account && (entry.control == "sufficient" || (!entry.control.empty() && entry.control.front() == '[')))
                {
                    return Error("Account control-flow bypasses faillock reset in " + name, ENOTSUP);
                }
            }
        }
        if (!policy || !provider || (params.policy == "faillock" && (!failure || !denied || !account)))
        {
            return Error("Incomplete effective PAM policy in " + name, ENOTSUP);
        }
    }
    return true;
}

Result<bool> CheckPam(const PasswordPolicyOptionParams& params, ContextInterface& context)
{
    const auto directory = context.GetSpecialFilePath("/etc/pam.d");
    std::unique_ptr<DIR, int (*)(DIR*)> entries(opendir(directory.c_str()), closedir);
    if (!entries)
    {
        return Error("Cannot open PAM configuration directory: " + std::string(strerror(errno)), errno);
    }
    std::vector<std::string> paths;
    while (true)
    {
        errno = 0;
        const auto entry = readdir(entries.get());
        if (!entry)
        {
            if (errno != 0)
            {
                return Error("Cannot enumerate PAM configuration directory", errno);
            }
            break;
        }
        const std::string name = entry->d_name;
        if (name == "." || name == "..")
        {
            continue;
        }
        const auto path = directory + "/" + name;
        struct stat metadata;
        if (stat(path.c_str(), &metadata) != 0)
        {
            return Error("Cannot inspect PAM configuration " + path, errno);
        }
        if (!S_ISREG(metadata.st_mode))
        {
            return Error("Unexpected nonregular PAM configuration " + path, ENOTSUP);
        }
        paths.push_back(path);
    }
    const auto pamConf = context.GetSpecialFilePath("/etc/pam.conf");
    struct stat metadata;
    if (stat(pamConf.c_str(), &metadata) == 0)
    {
        if (!S_ISREG(metadata.st_mode))
        {
            return Error("Unexpected nonregular PAM configuration " + pamConf, ENOTSUP);
        }
        paths.push_back(pamConf);
    }
    else if (errno != ENOENT)
    {
        return Error("Cannot inspect PAM configuration " + pamConf, errno);
    }
    std::sort(paths.begin(), paths.end());
    bool found = false;
    for (const auto& path : paths)
    {
        auto inspected = InspectPamFile(path, params, context);
        if (!inspected.HasValue())
        {
            return inspected.Error();
        }
        found = found || inspected.Value();
    }
    if (!found)
    {
        return Error("No pam_" + params.policy + ".so reference found; configuring a file cannot enable a PAM module", ENOTSUP);
    }
    return true;
}

std::string ConfigPath(const PasswordPolicyOptionParams& params, ContextInterface& context)
{
    return context.GetSpecialFilePath("/etc/security/" + params.policy + ".conf");
}

Result<std::string> ReadConfig(const PasswordPolicyOptionParams& params, ContextInterface& context)
{
    const auto path = ConfigPath(params, context);
    struct stat metadata;
    if (lstat(path.c_str(), &metadata) != 0)
    {
        return Error("Existing password configuration required: " + path, errno);
    }
    if (!S_ISREG(metadata.st_mode) || metadata.st_nlink != 1)
    {
        return Error("Password configuration must be regular and non-hardlinked: " + path, EINVAL);
    }
    return context.GetFileContents(path);
}

bool MeetsTarget(const std::string& actual, const PasswordPolicyOptionParams& params)
{
    if (!params.integratePam.Value() || IsFlag(params))
        return actual == params.value;
    auto value = TryStringToInt(actual);
    auto target = TryStringToInt(params.value);
    if (!value.HasValue() || !target.HasValue() || std::to_string(value.Value()) != actual)
        return false;
    if (params.option == "unlock_time" || params.option == "root_unlock_time")
    {
        return value.Value() == 0 || value.Value() >= target.Value();
    }
    if (params.option == "deny" || params.option == "maxrepeat" || params.option == "maxsequence")
    {
        return value.Value() > 0 && value.Value() <= target.Value();
    }
    return value.Value() >= target.Value() && (params.policy != "pwhistory" || value.Value() <= 400);
}

bool Matches(const std::string& line, const PasswordPolicyOptionParams& params)
{
    const auto active = ActiveLine(line);
    if (IsFlag(params))
    {
        return active == params.option;
    }
    const auto equals = active.find('=');
    return equals != std::string::npos && MeetsTarget(TrimWhiteSpaces(active.substr(equals + 1)), params);
}

std::string UpdateConfig(const std::string& contents, const PasswordPolicyOptionParams& params)
{
    const auto setting = params.option + (IsFlag(params) ? "" : " = " + params.value);
    std::string updated;
    bool found = false;
    size_t start = 0;
    while (start < contents.size())
    {
        const auto newline = contents.find('\n', start);
        const auto end = newline == std::string::npos ? contents.size() : newline;
        auto line = contents.substr(start, end - start);
        if (OptionName(line) == params.option)
        {
            found = true;
            const auto comment = line.find('#');
            line = setting + (comment == std::string::npos ? "" : " " + line.substr(comment));
        }
        updated += line;
        if (newline == std::string::npos)
        {
            break;
        }
        updated += '\n';
        start = newline + 1;
    }
    if (!found)
    {
        if (!updated.empty() && updated.back() != '\n')
        {
            updated += '\n';
        }
        updated += setting + "\n";
    }
    return updated;
}

struct PolicyFile
{
    std::string path;
    struct stat metadata
    {
    };
    bool existed = false;
    std::string contents;
    std::string link;
    std::map<std::string, std::string> attributes;
};

Result<PolicyFile> SavePolicyFile(const std::string& path, ContextInterface& context)
{
    PolicyFile saved;
    saved.path = path;
    if (lstat(path.c_str(), &saved.metadata) != 0)
    {
        return errno == ENOENT ? Result<PolicyFile>(saved) : Result<PolicyFile>(Error("Cannot snapshot " + path, errno));
    }
    saved.existed = true;
    if (S_ISLNK(saved.metadata.st_mode))
    {
        std::vector<char> target(4096);
        const auto length = readlink(path.c_str(), target.data(), target.size());
        if (length < 0 || static_cast<size_t>(length) == target.size())
        {
            return Error("Cannot snapshot PAM symbolic link " + path, EINVAL);
        }
        saved.link.assign(target.data(), static_cast<size_t>(length));
        return saved;
    }
    if (!S_ISREG(saved.metadata.st_mode) || saved.metadata.st_nlink != 1)
    {
        return Error("PAM transaction requires regular, non-hardlinked files: " + path, EINVAL);
    }
    auto contents = context.GetFileContents(path);
    if (!contents.HasValue())
    {
        return contents.Error();
    }
    saved.contents = contents.Value();
    const auto size = listxattr(path.c_str(), nullptr, 0);
    if (size < 0 && errno != ENOTSUP)
    {
        return Error("Cannot snapshot PAM file attributes: " + path, errno);
    }
    if (size > 0)
    {
        std::vector<char> names(static_cast<size_t>(size));
        if (listxattr(path.c_str(), names.data(), names.size()) != size)
        {
            return Error("PAM file attributes changed during snapshot", EAGAIN);
        }
        for (size_t offset = 0; offset < names.size();)
        {
            const std::string name(names.data() + offset);
            offset += name.size() + 1;
            const auto length = getxattr(path.c_str(), name.c_str(), nullptr, 0);
            if (length < 0)
            {
                return Error("Cannot snapshot PAM attribute " + name, errno);
            }
            std::string value(static_cast<size_t>(length), '\0');
            if (getxattr(path.c_str(), name.c_str(), value.empty() ? nullptr : &value[0], value.size()) != length)
            {
                return Error("PAM attribute changed during snapshot", EAGAIN);
            }
            saved.attributes[name] = value;
        }
    }
    return saved;
}

Result<bool> RestorePolicyFile(const PolicyFile& saved)
{
    struct stat current
    {
    };
    const bool exists = lstat(saved.path.c_str(), &current) == 0;
    if (!saved.existed || !saved.link.empty())
    {
        if (exists && unlink(saved.path.c_str()) != 0)
        {
            return Error("Cannot remove generated PAM file " + saved.path, errno);
        }
        if (!saved.existed)
        {
            return true;
        }
        if (symlink(saved.link.c_str(), saved.path.c_str()) != 0 || lchown(saved.path.c_str(), saved.metadata.st_uid, saved.metadata.st_gid) != 0)
        {
            return Error("Cannot restore PAM symbolic link " + saved.path, errno);
        }
        const struct timespec times[] = {saved.metadata.st_atim, saved.metadata.st_mtim};
        return utimensat(AT_FDCWD, saved.path.c_str(), times, AT_SYMLINK_NOFOLLOW) == 0 ? Result<bool>(true) :
                                                                                          Result<bool>(Error("Cannot restore PAM link timestamps", errno));
    }
    if (exists && !S_ISREG(current.st_mode))
    {
        if (unlink(saved.path.c_str()) != 0)
        {
            return Error("Cannot remove generated PAM link " + saved.path, errno);
        }
    }
    auto written = exists && S_ISREG(current.st_mode) ? ReplaceFileContentsAtomic(saved.path, saved.contents) :
                                                        CreateFileContentsAtomic(saved.path, saved.contents, saved.metadata.st_mode & 07777);
    if (!written.HasValue())
    {
        return written.Error();
    }
    if (chown(saved.path.c_str(), saved.metadata.st_uid, saved.metadata.st_gid) != 0 || chmod(saved.path.c_str(), saved.metadata.st_mode & 07777) != 0)
    {
        return Error("Cannot restore PAM ownership/mode: " + saved.path, errno);
    }
    const auto size = listxattr(saved.path.c_str(), nullptr, 0);
    if (size > 0)
    {
        std::vector<char> names(static_cast<size_t>(size));
        if (listxattr(saved.path.c_str(), names.data(), names.size()) != size)
            return Error("Cannot inspect rollback attributes", EIO);
        for (size_t offset = 0; offset < names.size();)
        {
            const std::string name(names.data() + offset);
            offset += name.size() + 1;
            if (saved.attributes.count(name) == 0 && removexattr(saved.path.c_str(), name.c_str()) != 0)
            {
                return Error("Cannot remove newly generated PAM attribute", errno);
            }
        }
    }
    for (const auto& attribute : saved.attributes)
    {
        if (setxattr(saved.path.c_str(), attribute.first.c_str(), attribute.second.data(), attribute.second.size(), 0) != 0)
        {
            return Error("Cannot restore PAM attribute " + attribute.first, errno);
        }
    }
    const struct timespec times[] = {saved.metadata.st_atim, saved.metadata.st_mtim};
    return utimensat(AT_FDCWD, saved.path.c_str(), times, 0) == 0 ? Result<bool>(true) : Result<bool>(Error("Cannot restore PAM file timestamps", errno));
}

struct ManagedPolicyTransaction
{
    std::vector<PolicyFile> files;
    std::string authselect;
    std::string backup;
    std::string profileDirectory;
    std::string debian;
    std::string debianProfiles;
    std::string originalProfiles;
    std::string newlyEnabled;
    std::map<std::string, std::string> debconfState;
    std::vector<std::string> createdDirectories;
    std::map<std::string, struct stat> createdHistoryFiles;
    bool vendorAttempted = false;
};

Result<bool> SnapshotPolicy(ManagedPolicyTransaction& transaction, const std::string& path, ContextInterface& context)
{
    for (const auto& saved : transaction.files)
    {
        if (saved.path == path)
        {
            return true;
        }
    }
    auto saved = SavePolicyFile(path, context);
    if (!saved.HasValue())
    {
        return saved.Error();
    }
    transaction.files.push_back(saved.Value());
    return true;
}

std::string QuotePolicy(const std::string& value)
{
    std::string quoted = "'";
    for (const char character : value)
    {
        quoted += character == '\'' ? "'\\''" : std::string(1, character);
    }
    return quoted + "'";
}

Result<bool> RollbackManagedPolicy(ManagedPolicyTransaction& transaction, ContextInterface& context)
{
    std::string errors;
    if (transaction.vendorAttempted && (!transaction.authselect.empty() || !transaction.newlyEnabled.empty()))
    {
        const auto command = transaction.authselect.empty() ? transaction.debian + " --package --disable " + transaction.newlyEnabled :
                                                              transaction.authselect + " backup-restore " + QuotePolicy(transaction.backup);
        auto vendor = context.ExecuteCommand(command);
        if (!vendor.HasValue())
        {
            errors += vendor.Error().message + "; ";
        }
    }
    for (auto saved = transaction.files.rbegin(); saved != transaction.files.rend(); ++saved)
    {
        const auto history = transaction.createdHistoryFiles.find(saved->path);
        if (history != transaction.createdHistoryFiles.end())
        {
            struct stat current
            {
            };
            if (lstat(saved->path.c_str(), &current) == 0 && (current.st_ino != history->second.st_ino || current.st_dev != history->second.st_dev ||
                                                                 current.st_size != 0 || !S_ISREG(current.st_mode) || current.st_nlink != 1))
            {
                errors += "New history database acquired vendor/admin data and was retained; ";
                continue;
            }
        }
        auto restored = RestorePolicyFile(*saved);
        if (!restored.HasValue())
        {
            errors += restored.Error().message + "; ";
        }
    }
    if (!transaction.originalProfiles.empty())
    {
        auto restored = context.ExecuteCommand("printf '%s\\n' " + QuotePolicy("SET libpam-runtime/profiles " + transaction.originalProfiles) +
                                               " | DEBIAN_FRONTEND=noninteractive LC_ALL=C debconf-communicate libpam-runtime");
        if (!restored.HasValue() || restored->find("0 ") != 0)
        {
            errors += "Cannot restore debconf selected profiles; ";
        }
        for (const auto& setting : transaction.debconfState)
        {
            auto metadata = context.ExecuteCommand("printf '%s\\n' " + QuotePolicy(setting.first + " " + setting.second) +
                                                   " | DEBIAN_FRONTEND=noninteractive LC_ALL=C debconf-communicate libpam-runtime");
            if (!metadata.HasValue() || metadata->find("0 ") != 0)
            {
                errors += "Cannot restore debconf metadata; ";
            }
        }
    }
    for (const auto& directory : transaction.createdDirectories)
    {
        if (rmdir(directory.c_str()) != 0 && errno != ENOENT)
        {
            errors += "Cannot remove created faillock directory (existing tallies retained); ";
        }
    }
    struct stat profile
    {
    };
    if (!transaction.profileDirectory.empty() && lstat(transaction.profileDirectory.c_str(), &profile) == 0 && rmdir(transaction.profileDirectory.c_str()) != 0)
    {
        errors += "Cannot remove generated authselect profile; ";
    }
    return errors.empty() ? Result<bool>(true) : Result<bool>(Error("PAM rollback failed: " + errors, EIO));
}

Result<bool> WriteManagedPolicy(ManagedPolicyTransaction& transaction, const std::string& path, const std::string& contents, ContextInterface& context,
    mode_t mode = 0644)
{
    auto snapshot = SnapshotPolicy(transaction, path, context);
    if (!snapshot.HasValue())
    {
        return snapshot.Error();
    }
    struct stat metadata
    {
    };
    if (lstat(path.c_str(), &metadata) == 0)
    {
        return ReplaceFileContentsAtomic(path, contents);
    }
    return CreateFileContentsAtomic(path, contents, mode);
}

Result<std::string> InlinePolicy(const std::string& contents, const PasswordPolicyOptionParams& params)
{
    std::string normalized;
    size_t physical = 0;
    while (physical < contents.size())
    {
        const auto start = physical;
        bool continued = false;
        do
        {
            const auto newline = contents.find('\n', physical);
            const auto end = newline == std::string::npos ? contents.size() : newline + 1;
            const auto line = contents.substr(physical, end - physical);
            const auto last = line.find_last_not_of(" \t\n");
            continued = last != std::string::npos && line[last] == '\\' && line.find('#') == std::string::npos;
            physical = end;
        } while (continued && physical < contents.size());
        const auto record = contents.substr(start, physical - start);
        auto logical = PamLines(record);
        if (!logical.HasValue())
        {
            return logical.Error();
        }
        bool selected = false;
        if (logical->size() == 1)
        {
            auto entry = PamEntries(logical.Value()[0]);
            selected = entry.HasValue() && entry->size() == 1 && entry.Value()[0].module == "pam_" + params.policy + ".so";
        }
        if (selected && record.find('\n') < record.size() - 1)
        {
            normalized += logical.Value()[0] + "\n";
            std::istringstream comments(record);
            std::string line;
            while (std::getline(comments, line))
            {
                const auto comment = line.find('#');
                if (comment != std::string::npos)
                {
                    normalized += line.substr(comment) + "\n";
                }
            }
        }
        else
        {
            normalized += record;
        }
    }
    if (normalized != contents)
    {
        return InlinePolicy(normalized, params);
    }
    auto logical = PamLines(contents);
    if (!logical.HasValue())
    {
        return logical.Error();
    }
    std::string result;
    size_t start = 0;
    for (const auto& line : logical.Value())
    {
        const auto position = contents.find(line, start);
        auto entries = PamEntries(line);
        if (!entries.HasValue())
        {
            std::istringstream tokens(line);
            PamEntry metadata;
            tokens >> metadata.type >> metadata.modulePath;
            metadata.module = metadata.modulePath.substr(metadata.modulePath.find_last_of('/') + 1);
            metadata.control = metadata.modulePath;
            if ((metadata.type != "required" && metadata.type != "requisite") || metadata.module != "pam_" + params.policy + ".so")
            {
                continue;
            }
            entries = std::vector<PamEntry>{metadata};
        }
        auto entry = entries.Value()[0];
        if (entry.type == "required" || entry.type == "requisite" || entry.type == "sufficient" || entry.type == "optional")
        {
            entry.modulePath = entry.control;
            entry.module = entry.control.substr(entry.control.find_last_of('/') + 1);
        }
        if (entry.module != "pam_" + params.policy + ".so")
        {
            continue;
        }
        if (params.policy != "pwhistory")
        {
            std::istringstream arguments(entry.arguments);
            std::string token;
            while (arguments >> token)
            {
                if (token.find("conf=") == 0 && token.substr(5) != "/etc/security/" + params.policy + ".conf")
                {
                    return Error("Custom PAM configuration retained; refusing remediation through an ignored default file", ENOTSUP);
                }
            }
        }
        if (position == std::string::npos)
        {
            // Reconstruct continued module records, but never unrelated records.
            // The continuation parser has already checked the exact PAM semantics.
            return Error("Managed inline updates of continued policy records require vendor normalization first", ENOTSUP);
        }
        result += contents.substr(start, position - start);
        auto updated = line;
        const auto module = updated.find(entry.modulePath);
        size_t argument = module + entry.modulePath.size();
        bool found = false;
        while (argument < updated.size())
        {
            const auto begin = updated.find_first_not_of(" \t", argument);
            if (begin == std::string::npos || updated[begin] == '{')
            {
                break;
            }
            const auto end = updated.find_first_of(" \t", begin);
            const auto token = updated.substr(begin, end == std::string::npos ? end : end - begin);
            if (token == params.option || token.compare(0, params.option.size() + 1, params.option + "=") == 0)
            {
                const auto target = !IsFlag(params) && token.find('=') != std::string::npos && MeetsTarget(token.substr(token.find('=') + 1), params) ?
                                        token :
                                        params.option + (IsFlag(params) ? "" : "=" + params.value);
                updated.replace(begin, token.size(), target);
                argument = begin + target.size();
                found = true;
            }
            else
            {
                argument = end == std::string::npos ? updated.size() : end;
            }
        }
        if (!found)
        {
            const auto directive = updated.find(" {", module);
            updated.insert(directive == std::string::npos ? updated.size() : directive, " " + params.option + (IsFlag(params) ? "" : "=" + params.value));
        }
        result += updated;
        start = position + line.size();
    }
    return result + contents.substr(start);
}

Result<std::string> AdoptLocalStack(const std::string& contents, const PasswordPolicyOptionParams& params, bool asTemplate = false)
{
    auto entries = PamEntries(contents);
    if (!entries.HasValue())
    {
        return entries.Error();
    }
    bool unixAuth = false;
    bool unixPassword = false;
    bool authDeny = false;
    bool accountUnix = false;
    bool existingPolicy = false;
    for (const auto& entry : entries.Value())
    {
        existingPolicy = existingPolicy || entry.module == "pam_" + params.policy + ".so";
        if ((entry.type == "auth" || entry.type == "password" || entry.type == "account") &&
            (entry.control != "required" && entry.control != "requisite" && entry.control != "sufficient" && entry.control != "optional"))
        {
            return Error("Unselected authselect adoption requires an inspected non-branching local provider stack", ENOTSUP);
        }
        if (entry.type == "auth" && entry.control == "sufficient")
        {
            if (entry.module != "pam_unix.so" || unixAuth)
            {
                return Error("Unselected PAM provider is not the measured local-unix topology", ENOTSUP);
            }
            unixAuth = true;
        }
        unixPassword = unixPassword || (entry.type == "password" && entry.module == "pam_unix.so" && entry.control == "sufficient" &&
                                           HasWord(entry.arguments, "use_authtok"));
        authDeny = authDeny || (entry.type == "auth" && entry.module == "pam_deny.so" && entry.control == "required");
        accountUnix = accountUnix || (entry.type == "account" && entry.module == "pam_unix.so" && entry.control == "required");
    }
    if (!unixAuth || !unixPassword || !authDeny || !accountUnix)
    {
        return Error("Cannot preserve an incomplete unselected PAM provider topology", ENOTSUP);
    }
    if (existingPolicy)
    {
        return asTemplate ? Result<std::string>(contents) : InlinePolicy(contents, params);
    }
    std::string result;
    std::istringstream lines(contents);
    std::string line;
    bool preauth = false;
    bool failure = false;
    bool account = false;
    bool history = false;
    while (std::getline(lines, line))
    {
        const auto active = ActiveLine(line);
        if (params.policy == "faillock")
        {
            if (!preauth && active.find("pam_unix.so") != std::string::npos && active.find("auth") == 0)
            {
                result += asTemplate ? "auth required pam_faillock.so preauth {include if \"with-faillock\"}\n" : "auth required pam_faillock.so preauth\n";
                preauth = true;
            }
            if (!failure && active.find("pam_deny.so") != std::string::npos && active.find("auth") == 0)
            {
                result += asTemplate ? "auth required pam_faillock.so authfail {include if \"with-faillock\"}\n" : "auth required pam_faillock.so authfail\n";
                failure = true;
            }
            if (!account && active.find("account") == 0)
            {
                result += asTemplate ? "account required pam_faillock.so {include if \"with-faillock\"}\n" : "account required pam_faillock.so\n";
                account = true;
            }
        }
        if (params.policy == "pwhistory" && !history && active.find("password") == 0 && active.find("pam_unix.so") != std::string::npos)
        {
            result += asTemplate ? "password requisite pam_pwhistory.so use_authtok {include if \"with-pwhistory\"}\n" :
                                   "password requisite pam_pwhistory.so use_authtok\n";
            history = true;
        }
        result += line + "\n";
    }
    return asTemplate ? Result<std::string>(result) : InlinePolicy(result, params);
}

Result<bool> ManagedAuthselect(ManagedPolicyTransaction& transaction, const PasswordPolicyOptionParams& params, ContextInterface& context)
{
    const auto executable = context.GetSpecialFilePath("/usr/bin/authselect");
    if (access(executable.c_str(), X_OK) != 0)
    {
        return Error("Installed authselect is required for managed PAM adoption", ENOENT);
    }
    transaction.authselect = QuotePolicy(executable);
    transaction.backup = "kompli-preserved-" + std::to_string(getpid()) + "-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    auto current = context.ExecuteCommand(transaction.authselect + " current --raw");
    const auto selection = current.HasValue() ? TrimWhiteSpaces(current.Value()) : "";
    struct stat selectionMetadata
    {
    };
    if (selection.empty() && lstat(context.GetSpecialFilePath("/etc/authselect/authselect.conf").c_str(), &selectionMetadata) == 0)
    {
        return Error("Existing authselect state cannot be read; refusing forced profile adoption", ENOTSUP);
    }
    const auto base = selection.substr(0, selection.find_first_of(" \t\r\n"));
    if (base.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-/") != std::string::npos || base.find("..") != std::string::npos)
    {
        return Error("Invalid existing authselect selection", EINVAL);
    }
    if (!selection.empty())
    {
        auto check = context.ExecuteCommand(transaction.authselect + " check");
        if (!check.HasValue())
        {
            return Error("Existing authselect selection contains administrator edits; adoption refused", ENOTSUP);
        }
    }
    for (const auto& name : {"authselect.conf", "user-nsswitch.conf", "system-auth", "password-auth", "postlogin", "fingerprint-auth", "smartcard-auth",
             "nsswitch.conf", "dconf-db", "dconf-locks"})
    {
        auto saved = SnapshotPolicy(transaction, context.GetSpecialFilePath(std::string("/etc/authselect/") + name), context);
        if (!saved.HasValue())
        {
            return saved.Error();
        }
    }
    for (const auto& name : {"system-auth", "password-auth", "postlogin", "fingerprint-auth", "smartcard-auth"})
    {
        auto saved = SnapshotPolicy(transaction, context.GetSpecialFilePath(std::string("/etc/pam.d/") + name), context);
        if (!saved.HasValue())
        {
            return saved.Error();
        }
    }
    auto savedNss = SnapshotPolicy(transaction, context.GetSpecialFilePath("/etc/nsswitch.conf"), context);
    for (const auto& path : {"/etc/dconf/db/distro.d/20-authselect", "/etc/dconf/db/distro.d/locks/20-authselect", "/etc/dconf/db/distro"})
    {
        auto saved = SnapshotPolicy(transaction, context.GetSpecialFilePath(path), context);
        if (!saved.HasValue())
            return saved.Error();
    }
    auto nss = context.GetFileContents(context.GetSpecialFilePath("/etc/nsswitch.conf"));
    if (!savedNss.HasValue() || !nss.HasValue())
    {
        return Error("Cannot snapshot existing NSS provider configuration", EIO);
    }
    // A kompli-preserved selection is updated in place; copying it again would
    // accumulate custom profiles on every remediated option.
    const std::string managedPrefix = "custom/kompli-preserved-";
    const bool reuseManaged = base.compare(0, managedPrefix.size(), managedPrefix) == 0;
    const auto profile = reuseManaged ? base : "custom/" + transaction.backup;
    if (!reuseManaged)
    {
        const auto candidate = context.GetSpecialFilePath("/etc/authselect/custom") + "/" + transaction.backup;
        struct stat candidateMetadata
        {
        };
        if (lstat(candidate.c_str(), &candidateMetadata) == 0 || errno != ENOENT)
        {
            return Error("Preserved-provider profile path is not absent; existing metadata retained", EEXIST);
        }
        transaction.profileDirectory = candidate;
    }
    if (reuseManaged)
    {
        const auto directory = context.GetSpecialFilePath("/etc/authselect/custom") + "/" + base.substr(7);
        for (const auto& name : {"system-auth", "password-auth"})
        {
            const auto path = directory + "/" + name;
            auto snapshot = SavePolicyFile(path, context);
            if (!snapshot.HasValue())
            {
                return snapshot.Error();
            }
            if (!snapshot->existed || !snapshot->link.empty())
            {
                return Error("Managed authselect profile must contain independent regular templates", EINVAL);
            }
            transaction.files.push_back(snapshot.Value());
            auto updated = InlinePolicy(snapshot->contents, params);
            if (!updated.HasValue())
            {
                return updated.Error();
            }
            auto written = ReplaceFileContentsAtomic(path, updated.Value());
            if (!written.HasValue())
            {
                return written.Error();
            }
        }
    }
    else if (selection.empty())
    {
        if (mkdir(transaction.profileDirectory.c_str(), 0755) != 0)
        {
            transaction.profileDirectory.clear();
            return Error("Cannot create preserved-provider authselect profile", errno);
        }
        for (const auto& name : {"system-auth", "password-auth", "postlogin", "fingerprint-auth", "smartcard-auth"})
        {
            auto contents = context.GetFileContents(context.GetSpecialFilePath(std::string("/etc/pam.d/") + name));
            std::string value;
            if (!contents.HasValue())
            {
                if (contents.Error().code != ENOENT)
                    return contents.Error();
                if (std::string(name) == "system-auth" || std::string(name) == "password-auth")
                {
                    return contents.Error();
                }
                auto fallback = context.GetFileContents(context.GetSpecialFilePath("/etc/pam.d/other"));
                if (!fallback.HasValue())
                    return Error("Missing optional PAM service has no inspected fallback to preserve", ENOTSUP);
                value = fallback.Value();
            }
            else
            {
                value = contents.Value();
                if (std::string(name) == "system-auth" || std::string(name) == "password-auth")
                {
                    auto faillock = params;
                    faillock.policy = "faillock";
                    auto adopted = AdoptLocalStack(value, faillock, true);
                    if (!adopted.HasValue())
                    {
                        return adopted.Error();
                    }
                    auto history = params;
                    history.policy = "pwhistory";
                    auto complete = AdoptLocalStack(adopted.Value(), history, true);
                    if (!complete.HasValue())
                    {
                        return complete.Error();
                    }
                    auto inlineValue = InlinePolicy(complete.Value(), params);
                    if (!inlineValue.HasValue())
                    {
                        return inlineValue.Error();
                    }
                    value = inlineValue.Value();
                }
            }
            auto written = WriteManagedPolicy(transaction, transaction.profileDirectory + "/" + name, value, context);
            if (!written.HasValue())
            {
                return written.Error();
            }
        }
        std::map<std::string, std::string> dconf;
        for (const auto& source : std::map<std::string, std::string>{
                 {"dconf-db", "/etc/dconf/db/distro.d/20-authselect"}, {"dconf-locks", "/etc/dconf/db/distro.d/locks/20-authselect"}})
        {
            auto contents = context.GetFileContents(context.GetSpecialFilePath(source.second));
            if (!contents.HasValue() && contents.Error().code != ENOENT)
                return contents.Error();
            dconf[source.first] = contents.HasValue() ? contents.Value() : "";
        }
        for (const auto& document :
            std::map<std::string, std::string>{{"nsswitch.conf", nss.Value()}, {"README", "Provider-preserving local PAM adoption by kompli.\n"},
                {"REQUIREMENTS", "The original PAM providers and NSS databases are retained.\n"}, {"dconf-db", dconf["dconf-db"]},
                {"dconf-locks", dconf["dconf-locks"]}})
        {
            auto written = WriteManagedPolicy(transaction, transaction.profileDirectory + "/" + document.first, document.second, context);
            if (!written.HasValue())
            {
                return written.Error();
            }
        }
    }
    else
    {
        auto copied = context.ExecuteCommand(transaction.authselect + " create-profile " + QuotePolicy(transaction.backup) + " --base-on " + QuotePolicy(base));
        std::unique_ptr<DIR, int (*)(DIR*)> directory(opendir(transaction.profileDirectory.c_str()), closedir);
        if (!directory)
        {
            return copied.HasValue() ? Error("Vendor did not create the copied authselect profile", EIO) : copied.Error();
        }
        while (const auto entry = readdir(directory.get()))
        {
            const std::string name = entry->d_name;
            if (name == "." || name == "..")
            {
                continue;
            }
            const auto path = transaction.profileDirectory + "/" + name;
            auto snapshot = SavePolicyFile(path, context);
            if (!snapshot.HasValue())
            {
                return Error("Copied authselect profile must contain independent regular templates", EINVAL);
            }
            // These files did not exist before the vendor copy command.
            snapshot->existed = false;
            transaction.files.push_back(snapshot.Value());
            if (!snapshot->link.empty())
                return Error("Copied authselect profile must not link to mutable vendor templates", EINVAL);
            if (!copied.HasValue())
            {
                continue;
            }
            if (name == "system-auth" || name == "password-auth")
            {
                auto updated = InlinePolicy(snapshot->contents, params);
                if (!updated.HasValue())
                {
                    return updated.Error();
                }
                auto written = ReplaceFileContentsAtomic(path, updated.Value());
                if (!written.HasValue())
                {
                    return written.Error();
                }
            }
        }
        if (!copied.HasValue())
        {
            return copied.Error();
        }
    }
    const auto oldFeatures = selection.empty() ? "" : TrimWhiteSpaces(selection.substr(base.size()));
    std::istringstream featureWords(oldFeatures);
    std::string featureWord;
    while (featureWords >> featureWord)
    {
        if (featureWord.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") != std::string::npos)
        {
            return Error("Invalid existing authselect feature identifier", EINVAL);
        }
    }
    auto feature = params.policy == "pwquality" ? "" : "with-" + params.policy;
    if (!feature.empty() && !HasWord(oldFeatures, feature))
    {
        auto available = context.ExecuteCommand(transaction.authselect + " list-features " + QuotePolicy(profile));
        if (!available.HasValue() || !HasWord(available.Value(), feature))
        {
            return Error("Copied vendor profile does not support the requested PAM feature", ENOTSUP);
        }
    }
    const auto features = oldFeatures + (feature.empty() || HasWord(oldFeatures, feature) ? "" : " " + feature);
    auto generatedNss = context.ExecuteCommand(transaction.authselect + " test --nsswitch " + QuotePolicy(profile) + " " + features);
    if (!generatedNss.HasValue())
    {
        return generatedNss.Error();
    }
    auto normalizeNss = [](const std::string& text) {
        std::string result;
        std::istringstream lines(text);
        std::string line;
        while (std::getline(lines, line))
        {
            const auto active = ActiveLine(line);
            if (!active.empty() && active.find("File ") != 0)
            {
                std::istringstream words(active);
                std::string word;
                while (words >> word)
                {
                    result += word + " ";
                }
                result += "\n";
            }
        }
        return result;
    };
    if (normalizeNss(generatedNss.Value()) != normalizeNss(nss.Value()))
    {
        return Error("Vendor profile would change NSS providers or actions; adoption refused", ENOTSUP);
    }
    auto generatedPam = context.ExecuteCommand(transaction.authselect + " test --system-auth --password-auth " + QuotePolicy(profile) + " " + features);
    if (!generatedPam.HasValue())
    {
        return generatedPam.Error();
    }
    std::map<std::string, std::string> generated;
    for (const auto& name : {"system-auth", "password-auth"})
    {
        const auto header = std::string("File /etc/pam.d/") + name + ":";
        const auto begin = generatedPam->find(header);
        if (begin == std::string::npos)
        {
            return Error("Authselect did not render both authentication entry points", EIO);
        }
        const auto start = generatedPam->find('\n', begin);
        const auto end = generatedPam->find("\nFile ", start);
        generated[name] = generatedPam->substr(start + 1, end == std::string::npos ? end : end - start - 1);
    }
    auto validated = ValidateIntegration(params, context, &generated);
    if (!validated.HasValue())
    {
        return validated.Error();
    }
    transaction.vendorAttempted = true;
    auto selected = context.ExecuteCommand(transaction.authselect + " select " + QuotePolicy(profile) + " " + features +
                                           (selection.empty() ? " --force" : "") + " --backup=" + QuotePolicy(transaction.backup));
    if (!selected.HasValue())
    {
        return selected.Error();
    }
    auto check = context.ExecuteCommand(transaction.authselect + " check");
    auto postNss = context.GetFileContents(context.GetSpecialFilePath("/etc/nsswitch.conf"));
    auto postSelection = context.ExecuteCommand(transaction.authselect + " current --raw");
    if (!check.HasValue() || !postNss.HasValue() || normalizeNss(postNss.Value()) != normalizeNss(nss.Value()) || !postSelection.HasValue() ||
        !HasWord(postSelection.Value(), profile))
    {
        return Error("Preserved-provider authselect validation failed", EIO);
    }
    std::istringstream previous(oldFeatures);
    std::string token;
    while (previous >> token)
    {
        if (!HasWord(postSelection.Value(), token))
        {
            return Error("Authselect dropped an existing feature", EIO);
        }
    }
    for (const auto& saved : transaction.files)
    {
        if (saved.existed && S_ISREG(saved.metadata.st_mode) &&
            (saved.path == context.GetSpecialFilePath("/etc/nsswitch.conf") || saved.path.find(context.GetSpecialFilePath("/etc/pam.d") + "/") == 0))
        {
            if (chown(saved.path.c_str(), saved.metadata.st_uid, saved.metadata.st_gid) != 0 || chmod(saved.path.c_str(), saved.metadata.st_mode & 07777) != 0)
            {
                return Error("Cannot preserve generated PAM/NSS metadata", errno);
            }
        }
    }
    return true;
}

std::string NormalizeDebianRecord(const std::string& line)
{
    auto value = ActiveLine(line);
    const auto bracket = value.find(']');
    if (bracket != std::string::npos)
    {
        value = std::regex_replace(value.substr(0, bracket + 1), std::regex("=[0-9]+"), "=end") + value.substr(bracket + 1);
    }
    std::istringstream tokens(value);
    std::string token;
    std::string result;
    while (tokens >> token)
    {
        result += token + " ";
    }
    return TrimWhiteSpaces(result);
}

Result<bool> CheckDebianAdministration(ContextInterface& context)
{
    for (const auto& type : {"auth", "account", "password", "session", "session-noninteractive"})
    {
        auto saved = context.GetFileContents(context.GetSpecialFilePath(std::string("/var/lib/pam/") + type));
        auto current = context.GetFileContents(context.GetSpecialFilePath(std::string("/etc/pam.d/common-") + type));
        if (!saved.HasValue() || !current.HasValue())
        {
            return Error("Existing pam-auth-update state is required; unmanaged common-* files are not overwritten", ENOTSUP);
        }
        std::vector<std::string> expected;
        std::istringstream records(saved.Value());
        std::string line;
        while (std::getline(records, line))
        {
            if (line.find("Module: ") != 0 && !ActiveLine(line).empty())
            {
                expected.push_back(NormalizeDebianRecord(line));
            }
        }
        std::vector<std::string> actual;
        int state = 0;
        std::istringstream lines(current.Value());
        while (std::getline(lines, line))
        {
            if (line.find("# here are the per-package modules (the \"Primary\" block)") == 0)
            {
                state = 1;
            }
            else if (line.find("# here's the fallback if no module succeeds") == 0)
            {
                state = 2;
            }
            else if (line.find("# and here are more per-package modules (the \"Additional\" block)") == 0)
            {
                state = 3;
            }
            else if (line.find("# end of pam-auth-update config") == 0)
            {
                state = 4;
            }
            else if ((state == 1 || state == 3) && !ActiveLine(line).empty())
            {
                const auto first = line.find_first_of(" \t");
                actual.push_back(NormalizeDebianRecord(first == std::string::npos ? line : line.substr(first + 1)));
            }
            else if (!ActiveLine(line).empty())
            {
                const auto first = line.find_first_of(" \t");
                const auto record = NormalizeDebianRecord(first == std::string::npos ? line : line.substr(first + 1));
                const bool stockUmask =
                    (std::string(type) == "session" || std::string(type) == "session-noninteractive") && record == "optional pam_umask.so";
                if (state != 2 || (record != "requisite pam_deny.so" && record != "required pam_permit.so" && !stockUmask))
                {
                    return Error("Administrator PAM records outside the vendor-managed blocks; merge refused", ENOTSUP);
                }
            }
        }
        if (state != 4 || actual != expected)
        {
            return Error("Administrator edits or inconsistent pam-auth-update state in common-" + std::string(type) + "; merge refused", ENOTSUP);
        }
    }
    return true;
}

Result<std::set<std::string>> DebianSelections(const std::string& output)
{
    const auto response = TrimWhiteSpaces(output);
    if (response.find("0 ") != 0 || response.find_first_of("\r\n") != std::string::npos)
    {
        return Error("Cannot read debconf PAM profile selection", EIO);
    }
    std::set<std::string> selections;
    std::istringstream names(response.substr(2));
    std::string name;
    while (std::getline(names, name, ','))
    {
        name = TrimWhiteSpaces(name);
        if (name.empty() || name.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") != std::string::npos)
        {
            return Error("Invalid installed PAM profile identifier", EINVAL);
        }
        selections.insert(name);
    }
    return selections;
}

Result<bool> ValidateDebianFaillock(const PasswordPolicyOptionParams& params, ContextInterface& context)
{
    auto auth = context.GetFileContents(context.GetSpecialFilePath("/etc/pam.d/common-auth"));
    auto account = context.GetFileContents(context.GetSpecialFilePath("/etc/pam.d/common-account"));
    if (!auth.HasValue() || !account.HasValue())
    {
        return Error("Cannot validate generated Debian authentication/account stacks", EIO);
    }
    auto entries = PamEntries(auth.Value());
    auto accounts = PamEntries(account.Value());
    if (!entries.HasValue() || !accounts.HasValue())
    {
        return Error("Malformed generated Debian PAM stack", EINVAL);
    }
    bool preauth = false;
    bool failure = false;
    bool deny = false;
    bool provider = false;
    size_t failureIndex = entries->size();
    size_t denyIndex = entries->size();
    for (size_t index = 0; index < entries->size(); ++index)
    {
        const auto& entry = entries.Value()[index];
        if (entry.module == "pam_faillock.so" && HasWord(entry.arguments, "authfail"))
        {
            failureIndex = index;
        }
        if (entry.module == "pam_deny.so")
        {
            denyIndex = index;
        }
    }
    for (size_t index = 0; index < entries->size(); ++index)
    {
        const auto& entry = entries.Value()[index];
        if (entry.type != "auth")
        {
            return Error("Unexpected type in generated common-auth", EINVAL);
        }
        if (entry.module == "pam_faillock.so" && HasWord(entry.arguments, "preauth"))
        {
            if (provider || preauth || entry.control != "requisite")
            {
                return Error("Debian preauth does not reject lockout before providers", ENOTSUP);
            }
            preauth = true;
        }
        else if (entry.module == "pam_faillock.so" && HasWord(entry.arguments, "authfail"))
        {
            if (!preauth || !provider || entry.control != "required")
            {
                return Error("Debian authentication failures are not counted safely", ENOTSUP);
            }
            if (failure)
                return Error("Duplicate Debian authfail would count failures more than once", ENOTSUP);
            failure = true;
        }
        else if (entry.module == "pam_unix.so" || entry.module == "pam_sss.so" || entry.module == "pam_ldap.so")
        {
            const auto success = entry.control.find("success=");
            const auto end = entry.control.find(' ', success);
            auto jump = success == std::string::npos ? Result<int>(Error("Missing success action", EINVAL)) :
                                                       TryStringToInt(entry.control.substr(success + 8, end - success - 8));
            if (!preauth || failure || entry.control.find("default=ignore") == std::string::npos || !jump.HasValue() ||
                index + 1 + static_cast<size_t>(jump.Value()) <= denyIndex || index + 1 + static_cast<size_t>(jump.Value()) >= entries->size() ||
                failureIndex >= denyIndex)
            {
                return Error("Provider success/failure jumps do not preserve Debian lockout semantics", ENOTSUP);
            }
            provider = true;
        }
        else if (entry.module == "pam_deny.so" && failure && (entry.control == "required" || entry.control == "requisite"))
        {
            deny = true;
        }
        else if ((!preauth || !deny) && entry.control != "required" && entry.control != "optional")
        {
            return Error("Unsupported Debian authentication branch around faillock", ENOTSUP);
        }
    }
    bool reset = false;
    size_t resetIndex = accounts->size();
    for (size_t index = 0; index < accounts->size(); ++index)
    {
        const auto& entry = accounts.Value()[index];
        reset = reset || (entry.type == "account" && entry.module == "pam_faillock.so" && entry.control == "required");
        if (reset)
        {
            resetIndex = index;
            break;
        }
    }
    for (size_t index = 0; index < resetIndex; ++index)
    {
        const auto& entry = accounts.Value()[index];
        const auto success = entry.control.find("success=");
        if (entry.control == "sufficient" ||
            (success != std::string::npos && (entry.control.substr(success + 8, 4) == "done" || entry.control.substr(success + 8, 3) == "die")))
        {
            return Error("Account success can bypass the Debian faillock reset", ENOTSUP);
        }
        if (success != std::string::npos)
        {
            const auto end = entry.control.find_first_of(" ]", success + 8);
            auto jump = TryStringToInt(entry.control.substr(success + 8, end - success - 8));
            if (jump.HasValue() && (jump.Value() < 0 || index + 1 + static_cast<size_t>(jump.Value()) > resetIndex))
            {
                return Error("Account success jump bypasses the Debian faillock reset", ENOTSUP);
            }
        }
    }
    if (!preauth || !failure || !deny || !provider || !reset)
    {
        return Error("Incomplete generated Debian faillock threshold/reset topology", ENOTSUP);
    }
    return CheckModuleConfiguration(params, context, "", false);
}

Result<bool> ManagedDebian(ManagedPolicyTransaction& transaction, const PasswordPolicyOptionParams& params, ContextInterface& context)
{
    if (params.policy != "faillock" && params.policy != "pwquality")
    {
        return Error("No installed Debian vendor password-history profile; explicit history integration is required", ENOTSUP);
    }
    auto administration = CheckDebianAdministration(context);
    if (!administration.HasValue())
    {
        return administration.Error();
    }
    const auto executable = context.GetSpecialFilePath("/usr/sbin/pam-auth-update");
    if (access(executable.c_str(), X_OK) != 0)
    {
        return Error("Installed pam-auth-update is required", ENOENT);
    }
    transaction.debian = "DEBIAN_FRONTEND=noninteractive " + QuotePolicy(executable);
    auto current =
        context.ExecuteCommand("printf 'GET libpam-runtime/profiles\\n' | DEBIAN_FRONTEND=noninteractive LC_ALL=C debconf-communicate libpam-runtime");
    auto selections = current.HasValue() ? DebianSelections(current.Value()) : Result<std::set<std::string>>(current.Error());
    if (!selections.HasValue())
    {
        return selections.Error();
    }
    transaction.originalProfiles = TrimWhiteSpaces(current->substr(2));
    const auto retained = [&](const std::string& type) -> Result<std::vector<std::string>> {
        auto content = context.GetFileContents(context.GetSpecialFilePath("/etc/pam.d/common-" + type));
        auto entries = content.HasValue() ? PamEntries(content.Value()) : Result<std::vector<PamEntry>>(content.Error());
        if (!entries.HasValue())
            return entries.Error();
        std::vector<std::string> records;
        for (const auto& entry : entries.Value())
        {
            if ((params.policy == "faillock" && entry.module == "pam_faillock.so" && (entry.type == "auth" || entry.type == "account")) ||
                (params.policy == "pwquality" && entry.module == "pam_pwquality.so" && entry.type == "password"))
            {
                continue;
            }
            std::istringstream arguments(entry.arguments);
            std::string word, normalized;
            while (arguments >> word)
            {
                if (entry.module == "pam_unix.so" &&
                    ((entry.type == "auth" && word == "try_first_pass") ||
                        (params.policy == "pwquality" && entry.type == "password" && (word == "use_authtok" || word == "try_first_pass"))))
                    continue;
                normalized += word + " ";
            }
            records.push_back(entry.type + " " + std::regex_replace(entry.control, std::regex("success=[0-9]+"), "success=end") + " " +
                              entry.modulePath + " " + normalized);
        }
        return records;
    };
    std::map<std::string, std::vector<std::string>> originalRecords;
    for (const auto& type : {"auth", "account", "password", "session", "session-noninteractive"})
    {
        auto records = retained(type);
        if (!records.HasValue())
            return records.Error();
        originalRecords[type] = records.Value();
    }
    for (const auto& setting : std::map<std::string, std::string>{{"FGET libpam-runtime/profiles seen", "FSET libpam-runtime/profiles seen"},
             {"GET libpam-runtime/override", "SET libpam-runtime/override"}, {"FGET libpam-runtime/override seen", "FSET libpam-runtime/override seen"}})
    {
        auto value = context.ExecuteCommand("printf '%s\\n' " + QuotePolicy(setting.first) +
                                            " | DEBIAN_FRONTEND=noninteractive LC_ALL=C debconf-communicate libpam-runtime");
        if (!value.HasValue() || value->find("0 ") != 0)
        {
            return Error("Cannot snapshot pam-auth-update debconf metadata", EIO);
        }
        transaction.debconfState[setting.second] = TrimWhiteSpaces(value->substr(2));
    }
    for (const auto& type : {"auth", "account", "password", "session", "session-noninteractive"})
    {
        for (const auto& path : {std::string("/etc/pam.d/common-") + type, std::string("/var/lib/pam/") + type})
        {
            auto saved = SnapshotPolicy(transaction, context.GetSpecialFilePath(path), context);
            if (!saved.HasValue())
            {
                return saved.Error();
            }
        }
    }
    auto seen = SnapshotPolicy(transaction, context.GetSpecialFilePath("/var/lib/pam/seen"), context);
    if (!seen.HasValue())
    {
        return seen.Error();
    }
    if (params.policy == "pwquality")
    {
        auto profile = context.GetFileContents(context.GetSpecialFilePath("/usr/share/pam-configs/pwquality"));
        if (!profile.HasValue() || profile->find("pam_pwquality.so") == std::string::npos)
        {
            return Error("Installed libpam-pwquality vendor profile is required", ENOENT);
        }
        transaction.debianProfiles = "pwquality";
    }
    else
    {
        int firstPriority = -1025;
        std::string firstProfile;
        for (const auto& name : selections.Value())
        {
            auto profile = context.GetFileContents(context.GetSpecialFilePath("/usr/share/pam-configs/" + name));
            if (!profile.HasValue())
            {
                return profile.Error();
            }
            const auto priority = profile->find("Priority:");
            const auto end = profile->find('\n', priority);
            auto number = priority == std::string::npos ? Result<int>(Error("Missing profile priority", EINVAL)) :
                                                          TryStringToInt(TrimWhiteSpaces(profile->substr(priority + 9, end - priority - 9)));
            if (profile->find("Auth-Type: Primary") != std::string::npos && (!number.HasValue() || number.Value() >= 1024 || number.Value() <= -1024) &&
                name.find("kompli-faillock-") != 0)
            {
                return Error("Installed provider priority conflicts with Debian faillock boundaries", ENOTSUP);
            }
            if (profile->find("Auth-Type: Primary") != std::string::npos && number.HasValue() && number.Value() > firstPriority)
            {
                firstPriority = number.Value();
                firstProfile = profile.Value();
            }
        }
        const auto field = [&](const std::string& name) {
            std::smatch match;
            const auto text = firstProfile + "\n";
            return std::regex_search(text, match, std::regex("(?:^|\\n)" + name + ":\\n((?:[ \\t][^\\n]*\\n)+)")) ? match[1].str() : "";
        };
        const auto initial = field("Auth-Initial");
        const auto normalize = [](const std::string& body) {
            std::istringstream words(body);
            std::string word, result;
            while (words >> word)
            {
                if (word != "try_first_pass")
                    result += word + " ";
            }
            return result;
        };
        const auto regular = field("Auth");
        if (!initial.empty() && initial != regular && (initial.find("pam_unix.so") == std::string::npos || normalize(initial) != normalize(regular)))
        {
            return Error("First provider Auth-Initial token behavior cannot safely shift behind preauth; existing provider metadata retained", ENOTSUP);
        }
        const std::map<std::string, std::string> profiles = {
            {"kompli-faillock-preauth",
                "# Managed by kompli PasswordPolicyOption\nName: Kompli faillock preauth and account reset\nDefault: no\nPriority: 1024\n"
                "Auth-Type: Primary\nAuth:\n\trequisite pam_faillock.so preauth\n"},
            {"kompli-faillock-authfail",
                "# Managed by kompli PasswordPolicyOption\nName: Kompli faillock authentication failures\nDefault: no\nPriority: -1024\n"
                "Auth-Type: Primary\nAuth:\n\trequired pam_faillock.so authfail\n"},
            {"kompli-faillock-reset",
                "# Managed by kompli PasswordPolicyOption\nName: Kompli faillock successful account reset\nDefault: no\nPriority: -1048576\n"
                "Account-Type: Additional\nAccount:\n\trequired pam_faillock.so\n"}};
        for (const auto& profile : profiles)
        {
            const auto path = context.GetSpecialFilePath("/usr/share/pam-configs/" + profile.first);
            auto existing = SavePolicyFile(path, context);
            if (!existing.HasValue())
            {
                return existing.Error();
            }
            const auto original = existing->existed ? existing->contents : profile.second;
            if (existing->existed && original.find("# Managed by kompli PasswordPolicyOption\n") != 0)
            {
                return Error("Administrator-owned profile conflicts with kompli faillock metadata", ENOTSUP);
            }
            if (existing->existed && original.substr(0, original.find("\n\t")) != profile.second.substr(0, profile.second.find("\n\t")))
            {
                return Error("Administrator changed kompli profile metadata; merge refused", ENOTSUP);
            }
            auto updated = InlinePolicy(original, params);
            if (!updated.HasValue())
            {
                return updated.Error();
            }
            auto written = WriteManagedPolicy(transaction, path, updated.Value(), context);
            if (!written.HasValue())
            {
                return written.Error();
            }
        }
        transaction.debianProfiles = "kompli-faillock-preauth kompli-faillock-authfail kompli-faillock-reset";
    }
    std::istringstream requested(transaction.debianProfiles);
    std::string requestedProfile;
    while (requested >> requestedProfile)
    {
        if (selections->count(requestedProfile) == 0)
        {
            transaction.newlyEnabled += requestedProfile + " ";
        }
    }
    transaction.vendorAttempted = true;
    auto generated = context.ExecuteCommand(transaction.debian + " --package --enable " + transaction.debianProfiles);
    if (!generated.HasValue())
    {
        return generated.Error();
    }
    auto post =
        context.ExecuteCommand("printf 'GET libpam-runtime/profiles\\n' | DEBIAN_FRONTEND=noninteractive LC_ALL=C debconf-communicate libpam-runtime");
    auto postSelections = post.HasValue() ? DebianSelections(post.Value()) : Result<std::set<std::string>>(post.Error());
    auto expected = selections.Value();
    std::istringstream enabled(transaction.debianProfiles);
    std::string name;
    while (enabled >> name)
    {
        expected.insert(name);
    }
    if (!postSelections.HasValue() || postSelections.Value() != expected)
    {
        return Error("pam-auth-update changed existing providers or did not enable the requested profiles", EIO);
    }
    for (const auto& original : originalRecords)
    {
        auto records = retained(original.first);
        if (!records.HasValue() || records.Value() != original.second)
        {
            return Error("pam-auth-update changed an existing provider, argument or control; saved vendor state will be restored", ENOTSUP);
        }
    }
    return params.policy == "faillock" ? ValidateDebianFaillock(params, context) : ValidateIntegration(params, context);
}

Result<bool> ManagedSuseHistory(ManagedPolicyTransaction& transaction, const PasswordPolicyOptionParams& params, ContextInterface& context)
{
    if (params.policy != "pwhistory")
        return Error("Installed SUSE pam-config lacks inspected pwquality/faillock integration", ENOTSUP);
    const auto executable = context.GetSpecialFilePath("/usr/sbin/pam-config");
    if (access(executable.c_str(), X_OK) != 0)
        return Error("Installed pam-config is required", ENOENT);
    std::map<std::string, std::vector<PamEntry>> original;
    std::set<std::string> historyArguments;
    auto effective = params;
    for (const auto& name : {"common-auth", "common-account", "common-password", "common-session"})
    {
        const auto link = context.GetSpecialFilePath(std::string("/etc/pam.d/") + name);
        struct stat metadata
        {
        };
        if (lstat(link.c_str(), &metadata) != 0 || !S_ISLNK(metadata.st_mode))
        {
            return Error("SUSE administrator common-* override retained; vendor common-*-pc linkage is required", ENOTSUP);
        }
        std::vector<char> target(4096);
        const auto length = readlink(link.c_str(), target.data(), target.size());
        const auto expected = std::string(name) + "-pc";
        const std::string actual = length > 0 ? std::string(target.data(), static_cast<size_t>(length)) : "";
        if (actual != expected && actual != "/etc/pam.d/" + expected)
        {
            return Error("SUSE common-* does not link to the vendor state", ENOTSUP);
        }
        for (const auto& path : {link, context.GetSpecialFilePath("/etc/pam.d/" + expected)})
        {
            auto saved = SnapshotPolicy(transaction, path, context);
            if (!saved.HasValue())
                return saved.Error();
            if (path != link && !S_ISREG(transaction.files.back().metadata.st_mode))
            {
                return Error("SUSE vendor common-*-pc state must be an independent regular file", ENOTSUP);
            }
        }
        auto content = context.GetFileContents(link);
        auto entries = content.HasValue() ? PamEntries(content.Value()) : Result<std::vector<PamEntry>>(content.Error());
        if (!entries.HasValue())
            return entries.Error();
        for (const auto& entry : entries.Value())
        {
            if (entry.module != "pam_pwhistory.so")
            {
                original[name].push_back(entry);
            }
            else
            {
                std::istringstream arguments(entry.arguments);
                std::string argument;
                while (arguments >> argument)
                {
                    if (!IsFlag(params) && argument.find(params.option + "=") == 0 && MeetsTarget(argument.substr(params.option.size() + 1), effective))
                    {
                        effective.value = argument.substr(params.option.size() + 1);
                    }
                    if (argument != "use_authtok" && argument != params.option && argument.find(params.option + "=") != 0)
                    {
                        historyArguments.insert(argument);
                    }
                }
            }
        }
    }
    const auto option = "--pwhistory-" + params.option + (IsFlag(params) ? "" : "=" + effective.value);
    auto generated = context.ExecuteCommand(QuotePolicy(executable) + " --add --pwhistory --pwhistory-use_authtok " + option);
    if (!generated.HasValue())
        return generated.Error();
    for (const auto& stack : original)
    {
        auto content = context.GetFileContents(context.GetSpecialFilePath("/etc/pam.d/" + stack.first));
        auto entries = content.HasValue() ? PamEntries(content.Value()) : Result<std::vector<PamEntry>>(content.Error());
        if (!entries.HasValue())
            return entries.Error();
        size_t index = 0;
        for (const auto& entry : entries.Value())
        {
            if (entry.module == "pam_pwhistory.so")
            {
                for (const auto& argument : historyArguments)
                {
                    if (!HasWord(entry.arguments, argument))
                        return Error("pam-config changed an unrelated history argument", ENOTSUP);
                }
                continue;
            }
            if (index >= stack.second.size() || entry.type != stack.second[index].type || entry.control != stack.second[index].control ||
                entry.modulePath != stack.second[index].modulePath || entry.arguments != stack.second[index].arguments)
            {
                return Error("pam-config changed an existing provider/control/argument; vendor state will be restored", ENOTSUP);
            }
            ++index;
        }
        if (index != stack.second.size())
            return Error("pam-config removed an existing provider", ENOTSUP);
    }
    for (const auto& saved : transaction.files)
    {
        if (saved.existed && S_ISREG(saved.metadata.st_mode))
        {
            if (chown(saved.path.c_str(), saved.metadata.st_uid, saved.metadata.st_gid) != 0 || chmod(saved.path.c_str(), saved.metadata.st_mode & 07777) != 0)
            {
                return Error("Cannot preserve pam-config file ownership/mode", errno);
            }
            for (const auto& attribute : saved.attributes)
            {
                if (setxattr(saved.path.c_str(), attribute.first.c_str(), attribute.second.data(), attribute.second.size(), 0) != 0)
                {
                    return Error("Cannot preserve pam-config file attributes", errno);
                }
            }
        }
    }
    return ValidateIntegration(params, context);
}

// Walk logical ancestors so every component resolves through the context, which
// keeps alternate roots from inheriting trust decisions about their own parents.
Result<bool> CheckTrustedAncestors(const std::string& logicalPath, ContextInterface& context, const std::string& message)
{
    auto parent = logicalPath.substr(0, logicalPath.find_last_of('/'));
    while (!parent.empty())
    {
        const auto path = context.GetSpecialFilePath(parent);
        struct stat metadata
        {
        };
        if (lstat(path.c_str(), &metadata) != 0 || !S_ISDIR(metadata.st_mode) || metadata.st_uid != 0 || (metadata.st_mode & 0022) != 0)
        {
            return Error(message, EACCES);
        }
        parent = parent.substr(0, parent.find_last_of('/'));
    }
    return true;
}

Result<bool> EnsureFaillockRuntime(ManagedPolicyTransaction& transaction, const PasswordPolicyOptionParams& params, ContextInterface& context)
{
    if (params.policy != "faillock")
    {
        return true;
    }
    auto distribution = DistributionInfo::ParseEtcOsRelease(context.GetSpecialFilePath("/etc/os-release"));
    if (!distribution.HasValue())
    {
        return distribution.Error();
    }
    const bool debian = distribution->distribution == LinuxDistribution::Debian || distribution->distribution == LinuxDistribution::Ubuntu;
    std::string directory;
    const auto normalized = [](std::string value) {
        if (value.find("%t/") == 0)
            value.replace(0, 2, "/run");
        if (value.find("/var/run/") == 0)
            value.replace(0, 8, "/run");
        return value;
    };
    const auto canonical = [&](const std::string& value) { return context.GetSpecialFilePath(normalized(value)); };
    for (const auto& stack :
        (debian ? std::vector<std::string>{"common-auth", "common-account"} : std::vector<std::string>{"system-auth", "password-auth"}))
    {
        auto contents = context.GetFileContents(context.GetSpecialFilePath("/etc/pam.d/" + stack));
        auto entries = contents.HasValue() ? PamEntries(contents.Value()) : Result<std::vector<PamEntry>>(contents.Error());
        if (!entries.HasValue())
        {
            return entries.Error();
        }
        for (const auto& entry : entries.Value())
        {
            if (entry.module != "pam_faillock.so")
            {
                continue;
            }
            std::string configuration = "/etc/security/faillock.conf";
            std::string overrideDirectory;
            std::istringstream arguments(entry.arguments);
            std::string argument;
            while (arguments >> argument)
            {
                if (argument.find("conf=") == 0)
                    configuration = argument.substr(5);
                if (argument.find("dir=") == 0)
                    overrideDirectory = argument.substr(4);
            }
            std::string effective = "/var/run/faillock";
            auto config = context.GetFileContents(context.GetSpecialFilePath(configuration));
            if (!config.HasValue())
            {
                return config.Error();
            }
            std::istringstream lines(config.Value());
            std::string line;
            while (std::getline(lines, line))
            {
                line = TrimWhiteSpaces(line.substr(0, line.find('#')));
                const auto equals = line.find('=');
                if (equals != std::string::npos && TrimWhiteSpaces(line.substr(0, equals)) == "dir")
                {
                    effective = TrimWhiteSpaces(line.substr(equals + 1));
                }
            }
            if (!overrideDirectory.empty())
                effective = overrideDirectory;
            if (!directory.empty() && canonical(directory) != canonical(effective))
            {
                return Error("Faillock preauth/failure/reset use different tally directories", ENOTSUP);
            }
            directory = effective;
        }
    }
    if (directory.empty() || directory[0] != '/' || directory.find("..") != std::string::npos ||
        directory.find_first_not_of("/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-") != std::string::npos)
    {
        return Error("Faillock requires one explicit, safe absolute tally directory", ENOTSUP);
    }
    const auto path = canonical(directory);
    if (normalized(directory) == "/" || normalized(directory) == "/run" || normalized(directory) == "/var/lib" || normalized(directory) == "/etc" ||
        normalized(directory) == "/root" || normalized(directory) == "/home")
    {
        return Error("Configured faillock tally directory must not be a shared system root", ENOTSUP);
    }
    auto trusted =
        CheckTrustedAncestors(normalized(directory), context, "Faillock directory parent must already exist with trusted root-owned metadata");
    if (!trusted.HasValue())
    {
        return trusted.Error();
    }
    struct stat prior
    {
    };
    const bool existed = lstat(path.c_str(), &prior) == 0;
    if (existed && (!S_ISDIR(prior.st_mode) || prior.st_uid != 0 || (prior.st_mode & 0022) != 0))
    {
        return Error("Existing faillock directory metadata is unsafe; administrator configuration retained", EACCES);
    }
    std::map<std::string, std::string> profiles;
    for (const auto& location : {"/usr/lib/tmpfiles.d", "/run/tmpfiles.d", "/etc/tmpfiles.d"})
    {
        const auto base = context.GetSpecialFilePath(location);
        std::unique_ptr<DIR, int (*)(DIR*)> files(opendir(base.c_str()), closedir);
        if (!files)
            continue;
        while (const auto item = readdir(files.get()))
        {
            const std::string name = item->d_name;
            if (name.size() > 5 && name.substr(name.size() - 5) == ".conf")
                profiles[name] = base + "/" + name;
        }
    }
    std::string profile;
    std::string prefix = normalized(directory);
    for (const auto& item : profiles)
    {
        auto text = context.GetFileContents(item.second);
        if (!text.HasValue())
            return text.Error();
        std::istringstream lines(text.Value());
        std::string line;
        while (std::getline(lines, line))
        {
            std::istringstream fields(line);
            std::string type, target;
            fields >> type >> target;
            if (canonical(target) != canonical(directory))
                continue;
            if (type != "d" || (!profile.empty() && profile != item.second))
            {
                return Error("Conflicting or unsupported existing faillock tmpfiles metadata retained", ENOTSUP);
            }
            profile = item.second;
            prefix = normalized(target);
        }
    }
    if (profile.empty())
    {
        profile = context.GetSpecialFilePath("/etc/tmpfiles.d") + "/kompli-faillock.conf";
        auto original = SavePolicyFile(profile, context);
        if (!original.HasValue())
            return original.Error();
        if (original->existed)
        {
            return Error("Existing kompli tmpfiles metadata targets another directory; administrator file retained", ENOTSUP);
        }
        std::ostringstream mode;
        mode << std::oct << (existed ? prior.st_mode & 07777 : 0755);
        auto written = WriteManagedPolicy(transaction, profile,
            "d " + normalized(directory) + " " + mode.str() + " " + std::to_string(existed ? prior.st_uid : 0) + " " +
                std::to_string(existed ? prior.st_gid : 0) + " -\n",
            context);
        if (!written.HasValue())
            return written.Error();
    }
    if (!existed)
    {
        const auto executable = context.GetSpecialFilePath("/usr/bin/systemd-tmpfiles");
        if (access(executable.c_str(), X_OK) != 0)
            return Error("Installed systemd-tmpfiles is required for faillock boot lifecycle", ENOENT);
        transaction.createdDirectories.push_back(path);
        auto created = context.ExecuteCommand(QuotePolicy(executable) + " --create --prefix=" + QuotePolicy(prefix) + " " + QuotePolicy(profile));
        if (!created.HasValue())
            return created.Error();
        struct stat current
        {
        };
        if (lstat(path.c_str(), &current) != 0 || !S_ISDIR(current.st_mode) || current.st_uid != 0 || (current.st_mode & 0022) != 0)
        {
            return Error("Scoped systemd-tmpfiles creation did not establish a safe faillock directory", EIO);
        }
    }
    return true;
}

Result<bool> EnsureHistoryDatabase(ManagedPolicyTransaction& transaction, const PasswordPolicyOptionParams& params, ContextInterface& context, bool auditOnly = false)
{
    if (params.policy != "pwhistory")
        return true;
    auto distribution = DistributionInfo::ParseEtcOsRelease(context.GetSpecialFilePath("/etc/os-release"));
    if (!distribution.HasValue())
        return distribution.Error();
    const bool common = distribution->distribution == LinuxDistribution::SUSE || distribution->distribution == LinuxDistribution::Debian ||
                        distribution->distribution == LinuxDistribution::Ubuntu;
    std::string database;
    for (const auto& name : (common ? std::vector<std::string>{"common-password"} : std::vector<std::string>{"system-auth", "password-auth"}))
    {
        auto content = context.GetFileContents(context.GetSpecialFilePath("/etc/pam.d/" + name));
        auto entries = content.HasValue() ? PamEntries(content.Value()) : Result<std::vector<PamEntry>>(content.Error());
        if (!entries.HasValue())
            return entries.Error();
        for (const auto& entry : entries.Value())
        {
            if (entry.module != "pam_pwhistory.so")
                continue;
            std::string file = "/etc/security/opasswd", config = "/etc/security/pwhistory.conf", overrideFile;
            std::istringstream arguments(entry.arguments);
            std::string argument;
            while (arguments >> argument)
            {
                if (argument.find("conf=") == 0)
                    config = argument.substr(5);
                if (argument.find("file=") == 0)
                    overrideFile = argument.substr(5);
            }
            auto reader = CheckModuleConfiguration(params, context, entry.modulePath, true);
            if (reader.HasValue())
            {
                auto settings = context.GetFileContents(context.GetSpecialFilePath(config));
                if (!settings.HasValue() && (settings.Error().code != ENOENT || config != "/etc/security/pwhistory.conf"))
                    return settings.Error();
                std::istringstream lines(settings.HasValue() ? settings.Value() : "");
                std::string line;
                while (std::getline(lines, line))
                {
                    const auto active = ActiveLine(line);
                    const auto equals = active.find('=');
                    if (equals != std::string::npos && TrimWhiteSpaces(active.substr(0, equals)) == "file")
                        file = TrimWhiteSpaces(active.substr(equals + 1));
                }
            }
            else if (reader.Error().code != ENOTSUP)
                return reader.Error();
            if (!overrideFile.empty())
            {
                if (overrideFile != "/etc/security/opasswd")
                {
                    return Error("Custom history file= argument support is not verified by configuration-reader markers; existing arguments retained", ENOTSUP);
                }
                file = overrideFile;
            }
            if (!database.empty() && database != file)
                return Error("Password stacks use different history databases", ENOTSUP);
            database = file;
        }
    }
    if (database != "/etc/security/opasswd")
    {
        return Error("Custom history database capability requires vendor validation; configured path and database retained", ENOTSUP);
    }
    const auto path = context.GetSpecialFilePath(database);
    auto trusted = CheckTrustedAncestors(database, context, "History database parent must already have trusted vendor/admin metadata");
    if (!trusted.HasValue())
    {
        return trusted.Error();
    }
    struct stat current
    {
    };
    if (lstat(path.c_str(), &current) == 0)
    {
        return S_ISREG(current.st_mode) && current.st_nlink == 1 && current.st_uid == 0 && (current.st_mode & 0077) == 0 ?
                   Result<bool>(true) :
                   Result<bool>(Error("Existing history database metadata is unsafe; contents and metadata retained", ENOTSUP));
    }
    if (errno != ENOENT)
        return Error("Cannot inspect history database", errno);
    if (auditOnly)
        return false;
    if (geteuid() != 0)
        return Error("History database initialization requires root", EACCES);
    auto snapshot = SnapshotPolicy(transaction, path, context);
    if (!snapshot.HasValue())
        return snapshot.Error();
    auto created = CreateFileContentsAtomic(path, "", 0600, &current);
    if (!created.HasValue())
    {
        transaction.files.erase(std::remove_if(transaction.files.begin(), transaction.files.end(),
                                    [&](const PolicyFile& saved) { return saved.path == path; }),
            transaction.files.end());
        return created.Error();
    }
    transaction.createdHistoryFiles[path] = current;
    const auto descriptor = open(path.c_str(), O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (descriptor < 0)
        return Error("Cannot open initialized history database", errno);
    struct stat opened
    {
    };
    if (fstat(descriptor, &opened) != 0 || !S_ISREG(opened.st_mode) || opened.st_nlink != 1 || opened.st_dev != current.st_dev ||
        opened.st_ino != current.st_ino)
    {
        close(descriptor);
        return Error("Initialized history database changed concurrently; replacement retained", EBUSY);
    }
    const auto ownership = fchown(descriptor, 0, 0);
    const auto ownershipError = errno;
    close(descriptor);
    if (ownership != 0)
        return Error("Cannot set vendor history database ownership", ownershipError);
    if (access(context.GetSpecialFilePath("/sys/fs/selinux/enforce").c_str(), F_OK) == 0)
    {
        auto executable = context.GetSpecialFilePath("/usr/sbin/restorecon");
        if (access(executable.c_str(), X_OK) != 0)
            executable = context.GetSpecialFilePath("/sbin/restorecon");
        if (access(executable.c_str(), X_OK) != 0)
            return Error("Vendor restorecon is required to label a new history database on SELinux", ENOENT);
        auto labeled = context.ExecuteCommand(QuotePolicy(executable) + " -- " + QuotePolicy(path));
        if (!labeled.HasValue())
            return labeled.Error();
    }
    return true;
}

Result<bool> EnsurePolicyLifecycle(ManagedPolicyTransaction& transaction, const PasswordPolicyOptionParams& params, ContextInterface& context)
{
    return params.policy == "pwhistory" ? EnsureHistoryDatabase(transaction, params, context) : EnsureFaillockRuntime(transaction, params, context);
}

Result<Status> AuditInlinePolicy(const PasswordPolicyOptionParams& params, IndicatorsTree& indicators, ContextInterface& context)
{
    auto distribution = DistributionInfo::ParseEtcOsRelease(context.GetSpecialFilePath("/etc/os-release"));
    if (!distribution.HasValue())
    {
        return distribution.Error();
    }
    const bool debian = distribution->distribution == LinuxDistribution::Debian || distribution->distribution == LinuxDistribution::Ubuntu;
    auto topology = debian && params.policy == "faillock" ? ValidateDebianFaillock(params, context) : ValidateIntegration(params, context);
    if (!topology.HasValue())
    {
        return topology.Error();
    }
    std::vector<std::string> stacks =
        (debian || distribution->distribution == LinuxDistribution::SUSE) ?
            (params.policy == "faillock" ? std::vector<std::string>{"common-auth", "common-account"} : std::vector<std::string>{"common-password"}) :
            std::vector<std::string>{"system-auth", "password-auth"};
    bool found = false;
    for (const auto& stack : stacks)
    {
        auto contents = context.GetFileContents(context.GetSpecialFilePath("/etc/pam.d/" + stack));
        auto entries = contents.HasValue() ? PamEntries(contents.Value()) : Result<std::vector<PamEntry>>(contents.Error());
        if (!entries.HasValue())
        {
            return entries.Error();
        }
        for (const auto& entry : entries.Value())
        {
            if (entry.module != "pam_" + params.policy + ".so")
            {
                continue;
            }
            found = true;
            bool matches = false;
            bool conflict = false;
            std::istringstream arguments(entry.arguments);
            std::string argument;
            while (arguments >> argument)
            {
                if (argument == params.option || argument.compare(0, params.option.size() + 1, params.option + "=") == 0)
                {
                    bool match = IsFlag(params) ? argument == params.option : MeetsTarget(argument.substr(params.option.size() + 1), params);
                    matches = matches || match;
                    conflict = conflict || !match;
                }
            }
            if (!matches || conflict)
            {
                return indicators.NonCompliant("Effective inline PAM option differs from target");
            }
        }
    }
    return found ? indicators.Compliant("Effective managed PAM policy matches target") :
                   indicators.NonCompliant("Effective managed PAM policy is absent");
}

Result<Status> CompleteManagedPolicy(const PasswordPolicyOptionParams& requested, IndicatorsTree& indicators, ContextInterface& context)
{
    auto params = requested;
    if (params.policy != "pwhistory" && !IsFlag(params))
    {
        auto current = context.GetFileContents(ConfigPath(params, context));
        if (current.HasValue())
        {
            std::istringstream lines(current.Value());
            std::string line;
            while (std::getline(lines, line))
            {
                if (OptionName(line) == params.option)
                {
                    const auto active = ActiveLine(line);
                    const auto equals = active.find('=');
                    const auto actual = equals == std::string::npos ? "" : TrimWhiteSpaces(active.substr(equals + 1));
                    params.value = MeetsTarget(actual, requested) ? actual : requested.value;
                }
            }
        }
    }
    auto distribution = DistributionInfo::ParseEtcOsRelease(context.GetSpecialFilePath("/etc/os-release"));
    if (!distribution.HasValue())
    {
        return distribution.Error();
    }
    const auto os = distribution->distribution;
    const bool debian = os == LinuxDistribution::Debian || os == LinuxDistribution::Ubuntu;
    if (!debian && os != LinuxDistribution::RHEL && os != LinuxDistribution::OracleLinux && os != LinuxDistribution::AlmaLinux &&
        os != LinuxDistribution::RockyLinux && os != LinuxDistribution::SUSE)
    {
        return Error("This vendor has no inspected provider-preserving policy adoption path", ENOTSUP);
    }
    auto installed = CheckModuleConfiguration(params, context, "", false);
    if (!installed.HasValue())
    {
        return installed.Error();
    }
    ManagedPolicyTransaction transaction;
    const auto fail = [&](const Error& error) -> Result<Status> {
        auto rollback = RollbackManagedPolicy(transaction, context);
        return rollback.HasValue() ? Result<Status>(error) : Result<Status>(Error(error.message + "; " + rollback.Error().message, EIO));
    };
    auto managed = debian ? ManagedDebian(transaction, params, context) :
                            (os == LinuxDistribution::SUSE ? ManagedSuseHistory(transaction, params, context) : ManagedAuthselect(transaction, params, context));
    if (!managed.HasValue())
    {
        return fail(managed.Error());
    }
    if (params.policy != "pwhistory")
    {
        const auto path = ConfigPath(params, context);
        auto saved = SavePolicyFile(path, context);
        if (!saved.HasValue())
        {
            return fail(saved.Error());
        }
        auto written = WriteManagedPolicy(transaction, path, UpdateConfig(saved->contents, params), context);
        if (!written.HasValue())
        {
            return fail(written.Error());
        }
    }
    auto verified = AuditInlinePolicy(params, indicators, context);
    // Debian pwquality uses its unchanged vendor profile and the installed
    // libpwquality configuration reader rather than duplicating password hooks.
    if (debian && params.policy == "pwquality")
    {
        auto configurationOnly = params;
        configurationOnly.integratePam = false;
        verified = AuditPasswordPolicyOption(configurationOnly, indicators, context);
    }
    if (!verified.HasValue() || verified.Value() != Status::Compliant)
    {
        return fail(verified.HasValue() ? Error("Managed PAM policy verification was noncompliant", EIO) : verified.Error());
    }
    auto runtime = EnsurePolicyLifecycle(transaction, params, context);
    if (!runtime.HasValue())
    {
        return fail(runtime.Error());
    }
    return verified;
}
} // namespace

Result<Status> AuditPasswordPolicyOption(const PasswordPolicyOptionParams& params, IndicatorsTree& indicators, ContextInterface& context)
{
    auto valid = Validate(params);
    if (!valid.HasValue())
    {
        return valid.Error();
    }
    if (params.integratePam.Value())
    {
        auto inlineAudit = AuditInlinePolicy(params, indicators, context);
        if (!inlineAudit.HasValue() && inlineAudit.Error().code != ENOENT && inlineAudit.Error().code != ENOTSUP)
        {
            return inlineAudit.Error();
        }
        if (params.policy == "pwhistory")
        {
            if (!inlineAudit.HasValue() || inlineAudit.Value() != Status::Compliant)
            {
                return indicators.NonCompliant("Effective password-history policy requires managed integration");
            }
            ManagedPolicyTransaction readonly;
            auto database = EnsureHistoryDatabase(readonly, params, context, true);
            if (!database.HasValue())
            {
                return database.Error();
            }
            return database.Value() ? inlineAudit : Result<Status>(indicators.NonCompliant("Active history database requires vendor lifecycle initialization"));
        }
        if (!inlineAudit.HasValue())
        {
            return indicators.NonCompliant("Effective PAM control-flow requires managed integration");
        }
        if (inlineAudit.HasValue() && inlineAudit.Value() == Status::Compliant)
        {
            return inlineAudit;
        }
    }
    auto pam = CheckPam(params, context);
    if (!pam.HasValue())
    {
        return params.integratePam.Value() && (pam.Error().code == ENOTSUP || pam.Error().code == ENOENT) ?
                   Result<Status>(indicators.NonCompliant("Effective PAM policy requires managed integration")) :
                   Result<Status>(pam.Error());
    }
    auto contents = ReadConfig(params, context);
    if (!contents.HasValue())
    {
        return params.integratePam.Value() && contents.Error().code == ENOENT ?
                   Result<Status>(indicators.NonCompliant("Password policy configuration is absent")) :
                   Result<Status>(contents.Error());
    }
    bool found = false;
    std::istringstream lines(contents.Value());
    std::string line;
    while (std::getline(lines, line))
    {
        if (OptionName(line) == params.option)
        {
            found = true;
            if (!Matches(line, params))
            {
                return indicators.NonCompliant("Explicit password configuration differs from target: " + params.option);
            }
        }
    }
    return found ? indicators.Compliant("Explicit password configuration matches: " + params.option) :
                   indicators.NonCompliant("Explicit password configuration missing: " + params.option);
}

Result<Status> RemediatePasswordPolicyOption(const PasswordPolicyOptionParams& params, IndicatorsTree& indicators, ContextInterface& context)
{
    auto valid = Validate(params);
    if (!valid.HasValue())
    {
        return valid.Error();
    }
    PamActivation activation;
    ManagedPolicyTransaction runtimeTransaction;
    struct PolicyLock
    {
        int descriptor;
        ~PolicyLock()
        {
            if (descriptor >= 0)
                close(descriptor);
        }
    } lock{-1};
    if (params.integratePam.Value())
    {
        const auto lockPath = context.GetSpecialFilePath("/run/kompli-password-policy.lock");
        lock.descriptor = open(lockPath.c_str(), O_CREAT | O_WRONLY | O_CLOEXEC | O_NOFOLLOW, 0600);
        struct stat metadata
        {
        };
        if (lock.descriptor < 0 || fstat(lock.descriptor, &metadata) != 0 || !S_ISREG(metadata.st_mode) || metadata.st_nlink != 1 ||
            metadata.st_uid != geteuid() || (metadata.st_mode & 0077) != 0 || flock(lock.descriptor, LOCK_EX | LOCK_NB) != 0)
        {
            return Error("Cannot exclusively lock the managed PAM transaction", EBUSY);
        }
        if (params.policy == "pwhistory")
        {
            auto audited = AuditInlinePolicy(params, indicators, context);
            if (audited.HasValue() && audited.Value() == Status::Compliant)
            {
                auto database = EnsureHistoryDatabase(runtimeTransaction, params, context);
                if (!database.HasValue())
                {
                    auto rollback = RollbackManagedPolicy(runtimeTransaction, context);
                    return Error(database.Error().message + (rollback.HasValue() ? "" : "; " + rollback.Error().message), EIO);
                }
                return audited;
            }
            return CompleteManagedPolicy(params, indicators, context);
        }
        auto original = ReadConfig(params, context);
        if (!original.HasValue())
        {
            return CompleteManagedPolicy(params, indicators, context);
        }
        auto pam = CheckPam(params, context);
        if (!pam.HasValue())
        {
            if (pam.Error().message.find("No pam_" + params.policy + ".so reference found") != 0)
            {
                return CompleteManagedPolicy(params, indicators, context);
            }
            auto activated = ActivatePam(params, context);
            if (!activated.HasValue())
            {
                return activated.Error().code == ENOTSUP ? CompleteManagedPolicy(params, indicators, context) : Result<Status>(activated.Error());
            }
            activation = activated.Value();
        }
        auto verified = ValidateIntegration(params, context);
        if (!verified.HasValue())
        {
            auto restored = RestorePam(activation, context);
            if (!restored.HasValue())
            {
                return restored.Error();
            }
            return activation.backup.empty() ? CompleteManagedPolicy(params, indicators, context) : Result<Status>(verified.Error());
        }
    }
    auto audit = AuditPasswordPolicyOption(params, indicators, context);
    if (!audit.HasValue() || audit.Value() == Status::Compliant)
    {
        if (!audit.HasValue())
        {
            auto restored = RestorePam(activation, context);
            if (!restored.HasValue())
            {
                return restored.Error();
            }
        }
        if (audit.HasValue() && params.integratePam.Value())
        {
            auto runtime = EnsurePolicyLifecycle(runtimeTransaction, params, context);
            if (!runtime.HasValue())
            {
                auto cleanup = RollbackManagedPolicy(runtimeTransaction, context);
                auto restored = RestorePam(activation, context);
                return Error(runtime.Error().message + (cleanup.HasValue() ? "" : "; " + cleanup.Error().message) +
                                 (restored.HasValue() ? "" : "; " + restored.Error().message),
                    EIO);
            }
        }
        return audit;
    }
    auto original = ReadConfig(params, context);
    if (!original.HasValue())
    {
        auto restored = RestorePam(activation, context);
        if (!restored.HasValue())
        {
            return restored.Error();
        }
        return original.Error();
    }
    const auto path = ConfigPath(params, context);
    auto written = ReplaceFileContentsAtomic(path, UpdateConfig(original.Value(), params));
    if (!written.HasValue())
    {
        auto restored = RestorePam(activation, context);
        if (!restored.HasValue())
        {
            return restored.Error();
        }
        return written.Error();
    }
    auto postAudit = AuditPasswordPolicyOption(params, indicators, context);
    auto integration = params.integratePam.Value() ? ValidateIntegration(params, context) : Result<bool>(true);
    Result<bool> runtime = true;
    if (postAudit.HasValue() && postAudit.Value() == Status::Compliant && integration.HasValue())
    {
        runtime = params.integratePam.Value() ? EnsurePolicyLifecycle(runtimeTransaction, params, context) : Result<bool>(true);
        if (runtime.HasValue())
            return postAudit;
    }
    auto cleanup = RollbackManagedPolicy(runtimeTransaction, context);
    auto rollback = ReplaceFileContentsAtomic(path, original.Value());
    auto restored = RestorePam(activation, context);
    if (!restored.HasValue())
    {
        return Error("Password verification failed; " + restored.Error().message +
                         (rollback.HasValue() ? "" : "; configuration rollback failed: " + rollback.Error().message),
            EIO);
    }
    if (!rollback.HasValue())
    {
        return Error("Password configuration verification failed; rollback failed: " + rollback.Error().message, rollback.Error().code);
    }
    if (!cleanup.HasValue())
        return cleanup.Error();
    if (!runtime.HasValue())
        return runtime.Error();
    return integration.HasValue() ? postAudit : Result<Status>(integration.Error());
}
} // namespace ComplianceEngine
