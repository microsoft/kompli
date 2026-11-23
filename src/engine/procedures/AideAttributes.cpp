#include <AideAttributes.h>
#include <AtomicFile.h>
#include <Separated.h>
#include <StringTools.h>
#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <memory>
#include <set>
#include <sstream>

namespace ComplianceEngine
{
namespace
{
Result<std::vector<std::string>> ParseAttributes(const AideAttributesParams& params)
{
    if (params.configPath.empty() || params.filename.empty() || params.attributes.empty() || params.configPath.find('\0') != std::string::npos ||
        params.filename.find('\0') != std::string::npos)
    {
        return Error("AIDE configuration, filename and required attributes must be specified", EINVAL);
    }
    if (params.attributes.back() == '+')
    {
        return Error("Invalid trailing AIDE attribute separator", EINVAL);
    }
    auto requested = Separated<std::string, '+'>::Parse(params.attributes);
    if (!requested.HasValue())
    {
        return requested.Error();
    }
    for (const auto& requiredAttribute : requested->items)
    {
        if (requiredAttribute.empty() || !std::all_of(requiredAttribute.begin(), requiredAttribute.end(),
                                             [](unsigned char character) { return std::isalnum(character) || character == '_'; }))
        {
            return Error("Invalid AIDE attribute: " + requiredAttribute, EINVAL);
        }
    }
    return requested->items;
}

std::string EncodeAidePath(const std::string& path)
{
    static const char digits[] = "0123456789ABCDEF";
    std::string result;
    result.reserve(path.size());
    for (const unsigned char character : path)
    {
        if (std::isalnum(character) || character == '/' || character == '_' || character == '-')
        {
            result.push_back(static_cast<char>(character));
        }
        else
        {
            result.push_back('%');
            result.push_back(digits[character >> 4]);
            result.push_back(digits[character & 0x0f]);
        }
    }
    return result;
}

std::string HexEncode(const std::string& value)
{
    static const char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(value.size() * 2);
    for (const unsigned char character : value)
    {
        result.push_back(digits[character >> 4]);
        result.push_back(digits[character & 0x0f]);
    }
    return result;
}

std::string SetManagedRule(const std::string& contents, const std::string& canonicalPath, const std::string& attributes)
{
    const std::string marker = "# kompli:AideAttributes:" + HexEncode(canonicalPath);
    const std::string rule = "=" + EncodeAidePath(canonicalPath) + "$ " + attributes;
    const size_t markerPosition = contents.find(marker);
    if (markerPosition == std::string::npos)
    {
        return marker + "\n" + rule + "\n" + contents;
    }

    const size_t markerEnd = contents.find('\n', markerPosition);
    if (markerEnd == std::string::npos)
    {
        return contents.substr(0, markerPosition) + marker + "\n" + rule + "\n";
    }
    const size_t ruleStart = markerEnd + 1;
    const size_t ruleEnd = contents.find('\n', ruleStart);
    std::string result = contents;
    result.replace(ruleStart, (ruleEnd == std::string::npos ? contents.size() : ruleEnd) - ruleStart, rule);
    return result;
}
} // anonymous namespace

Result<Status> AuditAideAttributes(const AideAttributesParams& params, IndicatorsTree& indicators, ContextInterface& context)
{
    const auto requested = ParseAttributes(params);
    if (!requested.HasValue())
    {
        return requested.Error();
    }
    const auto& requiredAttributes = requested.Value();

    std::unique_ptr<char, decltype(&free)> canonical(realpath(params.filename.c_str(), nullptr), &free);
    if (!canonical)
    {
        return indicators.NonCompliant("Cannot resolve AIDE file: " + params.filename);
    }
    const std::string command = "aide --config \"" + EscapeForShell(params.configPath) + "\" -p \"f:" + EscapeForShell(canonical.get()) + "\"";
    auto output = context.ExecuteCommand(command);
    if (!output.HasValue())
    {
        return indicators.NonCompliant("AIDE attribute query failed: " + output.Error().message);
    }

    std::istringstream lines(output.Value());
    std::string line;
    std::string missingAttribute = requiredAttributes.front();
    while (std::getline(lines, line))
    {
        std::replace(line.begin(), line.end(), '+', ' ');
        std::istringstream tokens(line);
        std::set<std::string> enabled;
        std::string attribute;
        while (tokens >> attribute)
        {
            enabled.insert(attribute);
        }
        const auto missing = std::find_if_not(requiredAttributes.begin(), requiredAttributes.end(),
            [&enabled](const std::string& required) { return enabled.count(required) != 0; });
        if (missing == requiredAttributes.end())
        {
            return indicators.Compliant("AIDE attributes are configured for: " + params.filename);
        }
        missingAttribute = *missing;
    }
    return indicators.NonCompliant("Required AIDE attributes are missing for: " + params.filename + "; first missing attribute: " + missingAttribute);
}

Result<Status> RemediateAideAttributes(const AideAttributesParams& params, IndicatorsTree& indicators, ContextInterface& context)
{
    const auto requested = ParseAttributes(params);
    if (!requested.HasValue())
    {
        return requested.Error();
    }

    auto audit = AuditAideAttributes(params, indicators, context);
    if (!audit.HasValue() || audit.Value() == Status::Compliant)
    {
        return audit;
    }

    std::unique_ptr<char, decltype(&free)> canonical(realpath(params.filename.c_str(), nullptr), &free);
    if (!canonical)
    {
        return indicators.NonCompliant("Cannot resolve AIDE file: " + params.filename);
    }
    const std::string canonicalPath(canonical.get());
    if (canonicalPath.find_first_of("\r\n") != std::string::npos)
    {
        return Error("AIDE file path cannot contain a newline", EINVAL);
    }

    auto config = context.GetFileContents(params.configPath);
    if (!config.HasValue())
    {
        return config.Error();
    }
    const std::string updated = SetManagedRule(config.Value(), canonicalPath, params.attributes);
    if (updated == config.Value())
    {
        return Error("AIDE remediation produced no configuration change", EINVAL);
    }

    auto replaced = ReplaceFileContentsAtomic(params.configPath, updated);
    if (!replaced.HasValue())
    {
        return replaced.Error();
    }

    auto postAudit = AuditAideAttributes(params, indicators, context);
    if (postAudit.HasValue() && postAudit.Value() == Status::Compliant)
    {
        return postAudit;
    }

    auto rollback = ReplaceFileContentsAtomic(params.configPath, config.Value());
    if (!rollback.HasValue())
    {
        const std::string reason = postAudit.HasValue() ? "AIDE configuration remained noncompliant" : postAudit.Error().message;
        return Error(reason + "; rollback failed: " + rollback.Error().message, rollback.Error().code);
    }
    return postAudit;
}
} // namespace ComplianceEngine
