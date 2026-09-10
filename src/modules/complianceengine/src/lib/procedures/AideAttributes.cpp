#include <AideAttributes.h>
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
Result<Status> AuditAideAttributes(const AideAttributesParams& params, IndicatorsTree& indicators, ContextInterface& context)
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
    const auto requested = Separated<std::string, '+'>::Parse(params.attributes);
    if (!requested.HasValue())
    {
        return requested.Error();
    }
    const auto& requiredAttributes = requested.Value().items;
    for (const auto& requiredAttribute : requiredAttributes)
    {
        if (requiredAttribute.empty() || !std::all_of(requiredAttribute.begin(), requiredAttribute.end(),
                                             [](unsigned char character) { return std::isalnum(character) || character == '_'; }))
        {
            return Error("Invalid AIDE attribute: " + requiredAttribute, EINVAL);
        }
    }

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
} // namespace ComplianceEngine
