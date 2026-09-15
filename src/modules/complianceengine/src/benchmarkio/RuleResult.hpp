// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCE_ENGINE_BENCHMARKIO_RULE_RESULT_HPP
#define COMPLIANCE_ENGINE_BENCHMARKIO_RULE_RESULT_HPP

#include "Resource.hpp"

#include <Evaluator.h>
#include <JsonWrapper.h>
#include <MmiResults.h>
#include <Result.h>
#include <map>
#include <string>

namespace ComplianceEngine
{
namespace BenchmarkIO
{
// Builds one rule's canonical result JSON object - indicators/title/id/
// ruleName/status/action/tags/metadata/parameters, see
// kompli-result.schema.json's "$defs/rule" - from a Resource that has just
// been evaluated. Shared by the `kompli` CLI's BenchmarkFormatter (which
// appends it into a whole-run envelope's "rules" array) and `komplid` (which
// returns it standalone as a per-request response's "result" value), so the
// per-rule shape is defined exactly once. `action` is per-rule (not a single
// result-wide value) because one `run` invocation can mix audit/remediate
// across rules.
Result<JsonWrapper> BuildRuleResultJson(const Resource& entry, Status status, const std::string& indicatorsPayload,
    const std::map<std::string, std::string>& parameters, Action action);

// Builds a "Skipped" rule-result entry: a rule present in the benchmark file
// but never executed (e.g. absent from a `run` plan's rules map). Carries no
// `action` (none applies) and empty `indicators` (nothing ran).
Result<JsonWrapper> BuildSkippedRuleResultJson(const Resource& entry, const std::map<std::string, std::string>& parameters);

} // namespace BenchmarkIO
} // namespace ComplianceEngine
#endif // COMPLIANCE_ENGINE_BENCHMARKIO_RULE_RESULT_HPP
