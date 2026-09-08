// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCE_ENGINE_BENCHMARKIO_RESOURCE_HPP
#define COMPLIANCE_ENGINE_BENCHMARKIO_RESOURCE_HPP

#include <Optional.h>
#include <string>

namespace ComplianceEngine
{
namespace BenchmarkIO
{
// A single parsed benchmark rule, as consumed by callers (the `kompli` CLI's
// main loop and output formatters today; `komplid` in the future). Populated
// by the benchmark-definition parser (BenchmarkDefinition) from one entry of a
// definition's spec.rules array.
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

    // Externally-quoted per-rule identifier (dotted CIS section, STIG
    // SV-XXXXX id, etc. - see docs/payload-key-format.md). Display/CLI-facing
    // only (section filtering, --audit=<section> toggle resolution); verbatim
    // copy of the rule's explicit `section` field, no longer required to be
    // re-derivable from payloadKey (see BenchmarkDefinition.cpp).
    std::string section;

    // The rule's payload key, opaque beyond being unique within one file (see
    // docs/payload-key-format.md \u00a72) - the identifier plan/run/the wire
    // protocol/the task registry/the audit cache key on internally. Verbatim
    // copy of the rule's `payloadKey` field; kompli never parses or transforms
    // its contents (no distro/version live here anymore - see
    // BenchmarkDefinition::BenchmarkDocument for the file-level prefix that
    // used to be repeated per rule).
    std::string payloadKey;

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

    // TODO(kompli parametrization design, see docs/CLI.md): not yet parsed or
    // retained. The rule's `parameterMetadata` (name -> {default,
    // validationRegex, mandatory, displayName}) is a plain top-level sibling
    // of `payload` in the benchmark-definition schema - NOT buried inside the
    // opaque procedure payload - so `kompli plan` can read it straight out of
    // this parser (no need to reuse Engine/Procedure's own parameter
    // handling) to pre-populate a plan's parameters with defaults and to
    // validate user-supplied overrides (name exists, value matches
    // validationRegex) before dispatch.
};
} // namespace BenchmarkIO
} // namespace ComplianceEngine
#endif // COMPLIANCE_ENGINE_BENCHMARKIO_RESOURCE_HPP
