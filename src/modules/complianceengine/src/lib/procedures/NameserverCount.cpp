// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <ExactFileObjectCollector.h>
#include <NameserverCount.h>
#include <ResultEvidence.h>
#include <TypedComparison.h>
#include <VariableResolver.h>

namespace ComplianceEngine
{

Result<Status> AuditNameserverCount(const NameserverCountParams& params, IndicatorsTree& indicators, ContextInterface& context)
{
    if (params.path != "/etc/resolv.conf")
    {
        return Error("NameserverCount supports only /etc/resolv.conf", EINVAL);
    }
    const auto collection = CollectNameserverObject(context.GetSpecialFilePath(params.path));
    if (!collection.HasValue())
    {
        return collection.Error();
    }
    const auto values = VariableResolution::ExtractObjectFields(collection.Value(), "nameserver", "subexpression");
    if (!values.HasValue())
    {
        return values.Error();
    }
    const auto unique = VariableResolution::Unique(values.Value());
    const auto count = VariableResolution::Count(unique);
    if (!count.HasValue())
    {
        return count.Error();
    }
    const auto compared = CompareTyped(count.Value(), 2LL, TypedComparisonOperation::GreaterOrEqual);
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
