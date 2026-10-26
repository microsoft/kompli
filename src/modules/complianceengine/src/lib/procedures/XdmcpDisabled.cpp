// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <AtomicFile.h>
#include <CommonUtils.h>
#include <Regex.h>
#include <XdmcpDisabled.h>
#include <fstream>
#include <string>

namespace ComplianceEngine
{
namespace
{
const std::vector<std::string> cXdmcpFiles = {"/etc/gdm3/custom.conf", "/etc/gdm3/daemon.conf", "/etc/gdm/custom.conf", "/etc/gdm/daemon.conf"};

std::string DisableXdmcp(const std::string& contents, bool& changed)
{
    static const regex section(R"(^\s*\[xdmcp\]\s*(#.*)?$)");
    static const regex setting(R"(^(\s*Enable\s*=\s*)true(\s*(#.*)?)$)");
    std::istringstream input(contents);
    std::ostringstream output;
    std::string line;
    bool inSection = false;
    bool first = true;
    while (std::getline(input, line))
    {
        if (!first)
        {
            output << '\n';
        }
        first = false;

        if (regex_match(line, section))
        {
            inSection = true;
        }
        else if (!line.empty() && line.find_first_not_of(" \t") != std::string::npos && line[line.find_first_not_of(" \t")] == '[')
        {
            inSection = false;
        }

        smatch match;
        if (inSection && regex_match(line, match, setting))
        {
            output << match[1].str() << "false" << match[2].str();
            changed = true;
        }
        else
        {
            output << line;
        }
    }
    if (!contents.empty() && contents.back() == '\n')
    {
        output << '\n';
    }
    return output.str();
}
} // anonymous namespace

Result<Status> AuditXdmcpDisabled(IndicatorsTree& indicators, ContextInterface& context)
{
    for (const auto& cfg : cXdmcpFiles)
    {
        auto file = context.GetFileContents(cfg);
        if (!file.HasValue())
        {
            if (file.Error().code != ENOENT)
            {
                return file.Error();
            }
            continue;
        }
        bool changed = false;
        DisableXdmcp(file.Value(), changed);
        if (changed)
        {
            return indicators.NonCompliant("Found xdmcp Enabled block");
        }
    }

    return indicators.Compliant("Did not found xdmcp Enabled block");
}

Result<Status> RemediateXdmcpDisabled(IndicatorsTree& indicators, ContextInterface& context)
{
    struct Change
    {
        std::string path;
        std::string original;
        std::string updated;
    };
    std::vector<Change> changes;

    for (const auto& cfg : cXdmcpFiles)
    {
        auto contents = context.GetFileContents(cfg);
        if (!contents.HasValue())
        {
            if (contents.Error().code == ENOENT)
            {
                continue;
            }
            return contents.Error();
        }
        bool changed = false;
        auto updated = DisableXdmcp(contents.Value(), changed);
        if (changed)
        {
            changes.push_back({context.GetSpecialFilePath(cfg), contents.Value(), std::move(updated)});
        }
    }

    size_t applied = 0;
    for (; applied < changes.size(); applied++)
    {
        auto result = ReplaceFileContentsAtomic(changes[applied].path, changes[applied].updated);
        if (!result.HasValue())
        {
            const auto originalError = result.Error();
            while (applied > 0)
            {
                applied--;
                auto rollback = ReplaceFileContentsAtomic(changes[applied].path, changes[applied].original);
                if (!rollback.HasValue())
                {
                    return Error(originalError.message + "; rollback failed: " + rollback.Error().message, originalError.code);
                }
            }
            return originalError;
        }
    }

    return AuditXdmcpDisabled(indicators, context);
}

} // namespace ComplianceEngine
