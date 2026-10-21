// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <ListValidShells.h>
#include <ScopeGuard.h>
#include <StringTools.h>
#include <cerrno>
#include <filesystem/FileReader.hpp>
#include <utility>

namespace ComplianceEngine
{
using std::set;
using std::string;
constexpr const char* etcShellsPath = "/etc/shells";
Result<set<string>> ListValidShells(ContextInterface& context)
{
    const auto path = context.GetSpecialFilePath(etcShellsPath);
    OsConfigLogDebug(context.GetLogHandle(), "Listing valid shells from %s", path.c_str());
    // Keep the historical open-failure contract for callers; the reader's
    // reached read, text and limit errors are reported rather than discarded.
    auto opened = FileReader::Lines(context, path);
    if (!opened.HasValue())
    {
        OsConfigLogError(context.GetLogHandle(), "Failed to open %s file", etcShellsPath);
        return Error(string("Failed to open ") + etcShellsPath + " file", EINVAL);
    }

    auto& range = opened.Value();
    ScopeGuard closeOnExit([&] {
        auto closed = range.Close();
        if (!closed.HasValue())
        {
            OsConfigLogError(context.GetLogHandle(), "Failed to close %s: %s", etcShellsPath, closed.Error().message.c_str());
        }
    });
    set<string> validShells;
    for (const auto& item : range)
    {
        if (!item.HasValue())
        {
            OsConfigLogError(context.GetLogHandle(), "Failed to read %s: %s", etcShellsPath, item.Error().message.c_str());
            return item.Error();
        }

        string line = item.Value();
        line = StripComment(line);

        auto index = line.rfind('/');
        if (index == string::npos)
        {
            index = 0;
        }
        const auto pos = line.find("nologin", index);
        if (pos != string::npos)
        {
            OsConfigLogDebug(context.GetLogHandle(), "Ignoring %s entry: %s", etcShellsPath, line.c_str());
            continue;
        }

        validShells.insert(std::move(line));
    }
    closeOnExit.Dismiss();
    auto closed = range.Close();
    if (!closed.HasValue())
    {
        OsConfigLogError(context.GetLogHandle(), "Failed to close %s: %s", etcShellsPath, closed.Error().message.c_str());
        return std::move(closed).Error();
    }
    return validShells;
}
} // namespace ComplianceEngine
