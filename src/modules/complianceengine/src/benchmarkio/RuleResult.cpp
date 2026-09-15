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

namespace
{
// Fills every rule-result field that doesn't depend on whether/how the rule
// was executed (title/id/ruleName/tags/metadata/parameters), shared by the
// executed and Skipped builders below.
Optional<Error> FillCommonRuleFields(JSON_Object* object, const Resource& entry, const std::map<string, string>& parameters)
{
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

    auto* tagsValue = json_value_init_array();
    if (nullptr == tagsValue)
    {
        return Error("Failed to initialize tags JSON array", ENOMEM);
    }
    auto* tagsArray = json_value_get_array(tagsValue);
    for (const auto& tag : entry.tags)
    {
        if (JSONSuccess != json_array_append_string(tagsArray, tag.c_str()))
        {
            json_value_free(tagsValue);
            return Error("Failed to append tag value", ENOMEM);
        }
    }
    if (JSONSuccess != json_object_set_value(object, "tags", tagsValue))
    {
        json_value_free(tagsValue);
        return Error("Failed to set tags", ENOMEM);
    }

    auto* metadataValue = json_value_init_object();
    if (nullptr == metadataValue)
    {
        return Error("Failed to initialize metadata JSON object", ENOMEM);
    }
    auto* metadataObject = json_value_get_object(metadataValue);
    if (nullptr == metadataObject || JSONSuccess != json_object_set_string(metadataObject, "description", entry.metadata.description.c_str()) ||
        JSONSuccess != json_object_set_string(metadataObject, "rationale", entry.metadata.rationale.c_str()) ||
        JSONSuccess != json_object_set_string(metadataObject, "fixtext", entry.metadata.fixtext.c_str()) ||
        JSONSuccess != json_object_set_string(metadataObject, "severity", entry.metadata.severity.c_str()) ||
        JSONSuccess != json_object_set_string(metadataObject, "references", entry.metadata.references.c_str()))
    {
        json_value_free(metadataValue);
        return Error("Failed to set metadata fields", ENOMEM);
    }
    if (JSONSuccess != json_object_set_value(object, "metadata", metadataValue))
    {
        json_value_free(metadataValue);
        return Error("Failed to set metadata", ENOMEM);
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

    return Optional<Error>();
}
} // namespace

Result<JsonWrapper> BuildRuleResultJson(
    const Resource& entry, const Status status, const string& indicatorsPayload, const std::map<string, string>& parameters, const Action action)
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

    if (JSONSuccess != json_object_set_string(object, "status", std::to_string(status).c_str()))
    {
        return Error("Failed to set JSON status", ENOMEM);
    }
    if (JSONSuccess != json_object_set_string(object, "action", Action::Audit == action ? "Audit" : "Remediation"))
    {
        return Error("Failed to set JSON action", ENOMEM);
    }

    auto fillError = FillCommonRuleFields(object, entry, parameters);
    if (fillError)
    {
        return fillError.Value();
    }

    return result;
}

Result<JsonWrapper> BuildSkippedRuleResultJson(const Resource& entry, const std::map<string, string>& parameters)
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

    // Nothing ran, so there are no indicators - an empty array rather than
    // omitting the (required) field.
    auto* indicatorsValue = json_value_init_array();
    if (nullptr == indicatorsValue)
    {
        return Error("Failed to initialize indicators JSON array", ENOMEM);
    }
    if (JSONSuccess != json_object_set_value(object, "indicators", indicatorsValue))
    {
        json_value_free(indicatorsValue);
        return Error("Failed to set JSON payload", ENOMEM);
    }

    if (JSONSuccess != json_object_set_string(object, "status", "Skipped"))
    {
        return Error("Failed to set JSON status", ENOMEM);
    }
    // No "action": the rule was never executed, so no operation applies.

    auto fillError = FillCommonRuleFields(object, entry, parameters);
    if (fillError)
    {
        return fillError.Value();
    }

    return result;
}

} // namespace BenchmarkIO
} // namespace ComplianceEngine
