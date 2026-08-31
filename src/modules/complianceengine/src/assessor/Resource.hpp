// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCE_ENGINE_ASSESSOR_RESOURCE_HPP
#define COMPLIANCE_ENGINE_ASSESSOR_RESOURCE_HPP

#include <BenchmarkInfo.h>
#include <Optional.h>
#include <string>

namespace ComplianceEngine
{
namespace Assessor
{
// A single parsed benchmark rule, as consumed by the assessor's main loop and
// output formatters. Populated by the benchmark-definition parser
// (BenchmarkDefinition) from one entry of a definition's spec.rules array.
struct Resource
{
    // Human-readable rule title (the definition's `title`, e.g. "1.1.1.1 Ensure
    // cramfs kernel module is not available"). Emitted in the canonical result
    // JSON as `title`.
    std::string resourceID;

    // Stable, benchmark-agnostic rule identifier (the definition's `ruleId`, a
    // UUID derived from the payload key by the augmentation engine). Emitted in
    // the canonical result JSON as `ruleId` so tooling can join to a rule
    // reliably rather than matching on ruleName/section.
    std::string ruleId;

    // Benchmark identity parsed from the rule's payload key. `.distribution` and
    // `.version` drive the applicability check in the main loop (Match against
    // the detected system); `.section` drives section filtering (main loop and
    // JSON formatter).
    CISBenchmarkInfo benchmarkInfo;

    // The rule payload serialized as JSON. Passed to the ComplianceEngine as the
    // procedure; the engine parses plain JSON directly (Engine::SetProcedure).
    std::string procedure;

    // Desired object value, if any. Benchmark definitions carry none, so this is
    // absent; an absent payload is modelled as an empty JSON object downstream.
    Optional<std::string> payload;

    // The ComplianceEngine rule name (the definition's `ruleName`), shared by the
    // procedure/init/audit/remediate object names the engine is driven with.
    std::string ruleName;

    // True when the rule carries an init object (always true for definitions).
    bool hasInitAudit = false;
};
} // namespace Assessor
} // namespace ComplianceEngine
#endif // COMPLIANCE_ENGINE_ASSESSOR_RESOURCE_HPP
