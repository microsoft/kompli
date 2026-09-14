// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCE_ENGINE_BENCHMARKIO_RESOURCE_HPP
#define COMPLIANCE_ENGINE_BENCHMARKIO_RESOURCE_HPP

#include <Optional.h>
#include <map>
#include <string>
#include <vector>

namespace ComplianceEngine
{
namespace BenchmarkIO
{
// A rule's `metadata` object (benchmark.schema.json's `$defs/rule.metadata`):
// fixed, benchmark-agnostic descriptive fields. Framework-specific fields
// belong in `tags`, never here.
struct Metadata
{
    std::string description;
    std::string rationale;
    std::string fixtext;
    std::string severity;
    std::string references;
};

// One entry of a rule's `parameterMetadata` (docs/CLI.md "Parametrization"):
// the UI/validation contract for one tunable parameter, keyed by name in
// Resource::parameterMetadata. Mirrors benchmark.schema.json's
// `parameterMetadata` per-entry shape.
struct ParameterMetadata
{
    // Default value applied when the parameter is not overridden. Always
    // present (schema-required); `plan` pre-fills every rule's parameters
    // with this.
    std::string defaultValue;
    // Value type; currently only "string" is defined by the schema.
    std::string type;
    Optional<std::string> displayName;
    // A `--param=` override's value must match this when present (checked by
    // GeneratePlan).
    Optional<std::string> validationRegex;
    // Shown instead of a generic error when validationRegex doesn't match.
    Optional<std::string> validationFailedMessage;
    // Not enforced yet: defaults are always present, so a plan is never
    // generated with a missing mandatory parameter.
    bool mandatory = false;
};

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

    // Stable, benchmark-agnostic rule identifier (the definition's `id`).
    // Emitted in the canonical result JSON as `id`. There is no separate
    // `ruleId` field in kompli's own schema/result - this is the sole
    // per-rule identifier kompli carries.
    std::string id;

    // The rule payload serialized as JSON. Passed to the ComplianceEngine as the
    // procedure; the engine parses plain JSON directly (Engine::SetProcedure).
    std::string procedure;

    // Desired object value, if any. Benchmark definitions carry none, so this is
    // absent; an absent payload is modelled as an empty JSON object downstream.
    Optional<std::string> payload;

    // The ComplianceEngine rule name (the definition's `ruleName`), shared by the
    // procedure/init/audit/remediate object names the engine is driven with.
    std::string ruleName;

    // Flat, sparse `axis:value` tags (the definition's `tags`, e.g.
    // "level:l1", "severity:critical"). Emitted verbatim in the canonical
    // result JSON as `tags`.
    std::vector<std::string> tags;

    // The rule's `metadata` (the definition's `metadata`). Emitted in the
    // canonical result JSON as `metadata`.
    Metadata metadata;

    // True when the rule carries an init object (always true for definitions).
    bool hasInitAudit = false;

    // The rule's `parameterMetadata` (name -> {default, validationRegex,
    // mandatory, displayName}), a plain top-level sibling of `payload` in the
    // benchmark-definition schema - NOT buried inside the opaque procedure
    // payload. Empty for a rule with no tunable parameters. `kompli plan`
    // reads this directly to pre-populate a plan's parameters with defaults
    // and to validate `--param=` overrides (name exists, value matches
    // validationRegex) before dispatch.
    std::map<std::string, ParameterMetadata> parameterMetadata;
};
} // namespace BenchmarkIO
} // namespace ComplianceEngine
#endif // COMPLIANCE_ENGINE_BENCHMARKIO_RESOURCE_HPP
