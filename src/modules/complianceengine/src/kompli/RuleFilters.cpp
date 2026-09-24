// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "RuleFilters.hpp"

#include <JsonWrapper.h>
#include <algorithm>
#include <cerrno>
#include <fnmatch.h>
#include <parson.h>
#include <utility>

namespace ComplianceEngine
{
namespace Kompli
{

namespace
{
bool ContainsAny(const std::vector<std::string>& values, const std::vector<std::string>& candidates)
{
    for (const auto& candidate : candidates)
    {
        if (values.end() != std::find(values.begin(), values.end(), candidate))
        {
            return true;
        }
    }
    return false;
}

bool MatchesAnyGlob(const std::string& value, const std::vector<std::string>& patterns)
{
    for (const auto& pattern : patterns)
    {
        if (0 == fnmatch(pattern.c_str(), value.c_str(), 0))
        {
            return true;
        }
    }
    return false;
}
} // anonymous namespace

bool RuleFilters::Empty() const
{
    return tags.empty() && sections.empty() && excludedTags.empty() && excludedSections.empty();
}

bool RuleFilters::Matches(const std::string& id, const std::vector<std::string>& ruleTags) const
{
    return (tags.empty() || ContainsAny(ruleTags, tags)) && (sections.empty() || MatchesAnyGlob(id, sections)) &&
        !ContainsAny(ruleTags, excludedTags) && !MatchesAnyGlob(id, excludedSections);
}

Result<std::string> FilterResultRules(const std::string& json, const RuleFilters& filters)
{
    if (filters.Empty())
    {
        return json;
    }

    auto documentResult = JsonWrapper::FromString(json);
    if (!documentResult.HasValue())
    {
        return Error("Failed to parse canonical result JSON", EINVAL);
    }
    auto document = std::move(documentResult.Value());
    auto* root = json_value_get_object(document.get());
    if (nullptr == root)
    {
        return Error("Canonical result JSON is not an object", EINVAL);
    }
    auto* rules = json_object_get_array(root, "rules");
    if (nullptr == rules)
    {
        return Error("Canonical result JSON has no 'rules' array", EINVAL);
    }

    for (std::size_t i = json_array_get_count(rules); i > 0; --i)
    {
        const std::size_t index = i - 1;
        const auto* rule = json_array_get_object(rules, index);
        if (nullptr == rule)
        {
            return Error("Canonical result rule is not an object", EINVAL);
        }
        const char* id = json_object_get_string(rule, "id");
        if (nullptr == id)
        {
            return Error("Canonical result rule has no string 'id'", EINVAL);
        }

        std::vector<std::string> ruleTags;
        const auto* tagsValue = json_object_get_value(rule, "tags");
        if (nullptr != tagsValue)
        {
            const auto* tags = json_value_get_array(tagsValue);
            if (nullptr == tags)
            {
                return Error("Canonical result rule '" + std::string(id) + "' has a non-array 'tags' field", EINVAL);
            }
            const std::size_t tagCount = json_array_get_count(tags);
            ruleTags.reserve(tagCount);
            for (std::size_t tagIndex = 0; tagIndex < tagCount; ++tagIndex)
            {
                const char* tag = json_array_get_string(tags, tagIndex);
                if (nullptr == tag)
                {
                    return Error("Canonical result rule '" + std::string(id) + "' has a non-string tag", EINVAL);
                }
                ruleTags.push_back(tag);
            }
        }

        if (!filters.Matches(id, ruleTags) && JSONSuccess != json_array_remove(rules, index))
        {
            return Error("Failed to remove a filtered canonical result rule", ENOMEM);
        }
    }

    if (0 == json_array_get_count(rules))
    {
        return Error("Rule filters matched no result rules", EINVAL);
    }

    char* serialized = json_serialize_to_string(document.get());
    if (nullptr == serialized)
    {
        return Error("Failed to serialize filtered canonical result JSON", ENOMEM);
    }
    std::string result(serialized);
    json_free_serialized_string(serialized);
    return result;
}

} // namespace Kompli
} // namespace ComplianceEngine
