// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "RuleResult.hpp"

#include <cerrno>
#include <parson.h>

namespace ComplianceEngine
{
namespace BenchmarkIO
{
using std::string;

Result<JsonWrapper> BuildRuleResultJson(
    const Resource& entry, const Status status, const string& indicatorsPayload, const std::map<string, string>& parameters)
{
    auto resultWrapper = JsonWrapper::MakeObject();
    if (!resultWrapper.HasValue())
    {
        return Error("Failed to initialize JSON object", ENOMEM);
    }
    auto result = std::move(resultWrapper.Value());
    auto* object = json_value_get_object(result.get());
    if (nullptr == object)
    {
        return Error("Failed to get JSON object", ENOMEM);
    }

    auto* indicatorsValue = json_parse_string(indicatorsPayload.c_str());
    if (nullptr == indicatorsValue)
    {
        return Error("Failed to parse JSON payload", ENOMEM);
    }
    if (json_value_get_type(indicatorsValue) != JSONArray)
    {
        json_value_free(indicatorsValue);
        return Error("Invalid JSON payload", EINVAL);
    }
    if (JSONSuccess != json_object_set_value(object, "indicators", indicatorsValue))
    {
        json_value_free(indicatorsValue);
        return Error("Failed to set JSON payload", ENOMEM);
    }

    if (JSONSuccess != json_object_set_string(object, "title", entry.resourceID.c_str()))
    {
        return Error("Failed to set JSON title", ENOMEM);
    }
    if (JSONSuccess != json_object_set_string(object, "id", entry.id.c_str()))
    {
        return Error("Failed to set JSON id", ENOMEM);
    }
    if (JSONSuccess != json_object_set_string(object, "ruleName", entry.ruleName.c_str()))
    {
        return Error("Failed to set JSON ruleName", ENOMEM);
    }
    if (JSONSuccess != json_object_set_string(object, "status", std::to_string(status).c_str()))
    {
        return Error("Failed to set JSON status", ENOMEM);
    }

    // Surface the effective parameters (payload defaults merged with any user
    // overrides) so callers can show them without decoding the procedure blob.
    auto* parametersValue = json_value_init_object();
    if (nullptr == parametersValue)
    {
        return Error("Failed to initialize parameters JSON object", ENOMEM);
    }
    auto* parametersObject = json_value_get_object(parametersValue);
    if (nullptr == parametersObject)
    {
        json_value_free(parametersValue);
        return Error("Failed to get parameters JSON object", ENOMEM);
    }
    for (const auto& parameter : parameters)
    {
        if (JSONSuccess != json_object_set_string(parametersObject, parameter.first.c_str(), parameter.second.c_str()))
        {
            json_value_free(parametersValue);
            return Error("Failed to set parameter value", ENOMEM);
        }
    }
    if (JSONSuccess != json_object_set_value(object, "parameters", parametersValue))
    {
        json_value_free(parametersValue);
        return Error("Failed to set parameters", ENOMEM);
    }

    return result;
}

} // namespace BenchmarkIO
} // namespace ComplianceEngine
