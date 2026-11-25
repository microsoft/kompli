// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef KOMPLI_PROCEDURES_BENCHMARK_SETTINGS_H
#define KOMPLI_PROCEDURES_BENCHMARK_SETTINGS_H

#include <Evaluator.h>

namespace Kompli
{
Result<Status> AuditSetBenchmarkSettings(const std::map<std::string, std::string>& settings, IndicatorsTree& indicators, ContextInterface& context);
} // namespace Kompli
#endif // KOMPLI_PROCEDURES_BENCHMARK_SETTINGS_H
