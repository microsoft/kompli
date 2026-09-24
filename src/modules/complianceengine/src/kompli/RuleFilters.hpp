// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#ifndef COMPLIANCE_ENGINE_KOMPLI_RULE_FILTERS_HPP
#define COMPLIANCE_ENGINE_KOMPLI_RULE_FILTERS_HPP

#include <Result.h>
#include <string>
#include <vector>

namespace ComplianceEngine
{
namespace Kompli
{

struct RuleFilters
{
    std::vector<std::string> tags;
    std::vector<std::string> sections;
    std::vector<std::string> excludedTags;
    std::vector<std::string> excludedSections;

    bool Empty() const;
    bool Matches(const std::string& id, const std::vector<std::string>& ruleTags) const;
};

// Projects a canonical result to the rules selected by `filters`. The source
// result's run-wide fields are retained unchanged.
Result<std::string> FilterResultRules(const std::string& json, const RuleFilters& filters);

} // namespace Kompli
} // namespace ComplianceEngine

#endif // COMPLIANCE_ENGINE_KOMPLI_RULE_FILTERS_HPP
