// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <FileObjectCollector.h>
#include <NameserverCount.h>
#include <ResultEvidence.h>
#include <TypedComparison.h>
#include <VariableResolver.h>
#include <cassert>
#include <ranges/Count.hpp>
#include <ranges/Unique.hpp>

namespace ComplianceEngine
{

Result<Status> AuditNameserverCount(const NameserverCountParams& params, IndicatorsTree& indicators, ContextInterface& context)
{
    assert(params.path.HasValue());
    const auto collection = CollectNameserverObject(context, context.GetSpecialFilePath(params.path.Value()));
    if (!collection.HasValue())
    {
        return collection.Error();
    }
    const auto count = Ranges::Count(Ranges::Unique(VariableResolution::ObjectFieldRange(collection.Value(), "nameserver", "subexpression")));
    if (!count.HasValue())
    {
        return count.Error();
    }
    const auto compared = CompareTyped(count.Value(), std::size_t{2}, TypedComparisonOperation::GreaterOrEqual);
    Result<StateSatisfaction> assessment = !compared.HasValue() ?
                                               Result<StateSatisfaction>(compared.Error()) :
                                               Result<StateSatisfaction>(compared.Value() ? StateSatisfaction::Satisfied : StateSatisfaction::NotSatisfied);

    SelectedItemsEvidence evidence;
    evidence.AddItem(assessment);
    const auto state = evidence.AllSelectedItemsSatisfied();
    if (!state.HasValue())
    {
        return state.Error();
    }
    if (!evidence.HasSelectedItems())
    {
        return indicators.NonCompliant("No nameserver count assessment was produced");
    }
    if (state.Value() == StateSatisfaction::Satisfied)
    {
        return indicators.Compliant("At least two distinct nameserver entries are configured");
    }
    return indicators.NonCompliant("Fewer than two distinct nameserver entries are configured");
}
} // namespace ComplianceEngine
