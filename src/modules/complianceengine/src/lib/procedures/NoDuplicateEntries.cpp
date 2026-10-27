// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <Evaluator.h>
#include <NoDuplicateEntries.h>
#include <Optional.h>
#include <Result.h>
#include <filesystem/FileReader.hpp>
#include <set>
#include <sstream>
#include <string>
#include <utility>

namespace ComplianceEngine
{
Result<Status> AuditNoDuplicateEntries(const NoDuplicateEntriesParams& params, IndicatorsTree& indicators, ContextInterface& context)
{
    if (params.delimiter.size() != 1)
    {
        return Error("Delimiter must be a single character", EINVAL);
    }

    if (params.column < 0)
    {
        return Error("Column must be a non-negative integer", EINVAL);
    }

    std::string entries;
    if (params.context.HasValue())
    {
        entries = params.context.Value();
    }
    else
    {
        entries = "entries";
    }

    std::set<std::string> uniqueEntries;
    std::set<std::string> duplicateEntries;
    auto opened = FileReader::Lines(context, params.filename);
    if (!opened.HasValue())
    {
        OsConfigLogError(context.GetLogHandle(), "Failed to open %s: %s", params.filename.c_str(), opened.Error().message.c_str());
        return Error("Failed to open file: " + params.filename, ENOENT);
    }

    auto& range = opened.Value();
    for (const auto& item : range)
    {
        if (!item.HasValue())
        {
            OsConfigLogError(context.GetLogHandle(), "Failed to read %s: %s", params.filename.c_str(), item.Error().message.c_str());
            return item.Error();
        }

        std::istringstream iss(item.Value());
        std::string token;
        for (int i = 0; i <= params.column; i++)
        {
            if (!std::getline(iss, token, params.delimiter[0]))
            {
                return Error("Column index out of bounds", EINVAL);
            }
        }

        if (uniqueEntries.find(token) != uniqueEntries.end())
        {
            duplicateEntries.insert(std::move(token));
        }
        else
        {
            uniqueEntries.insert(std::move(token));
        }
    }

    auto closed = range.Close();
    if (!closed.HasValue())
    {
        return std::move(closed).Error();
    }

    if (!duplicateEntries.empty())
    {
        for (const auto& entry : duplicateEntries)
        {
            indicators.NonCompliant("Duplicate entry: '" + entry + "'");
        }
        return Status::NonCompliant;
    }

    return indicators.Compliant(std::string("No duplicate ") + entries + " found in " + params.filename);
}
} // namespace ComplianceEngine
