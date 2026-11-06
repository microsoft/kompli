// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <BenchmarkSettings.h>

namespace ComplianceEngine
{
Result<Status> AuditSetBenchmarkSettings(const std::map<std::string, std::string>& settings, IndicatorsTree& indicators, ContextInterface& context)
{
    context.SetBenchmarkSettings(settings);
    return indicators.Compliant("Benchmark settings updated");
}
} // namespace ComplianceEngine
