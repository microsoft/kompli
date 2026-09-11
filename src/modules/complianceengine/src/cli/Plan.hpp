// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#ifndef COMPLIANCE_ENGINE_CLI_PLAN_HPP
#define COMPLIANCE_ENGINE_CLI_PLAN_HPP

#include <BenchmarkInfo.h>
#include <CliOptions.hpp>
#include <Logging.h>
#include <Optional.h>
#include <Result.h>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace ComplianceEngine
{
namespace Cli
{

// A plan rule's resolved mode and parameters (docs/CLI.md "Parametrization").
// `parameters` is pre-filled by `plan` from the rule's parameterMetadata
// defaults, then overridden per `--param=`/hand-editing; `run` threads it
// into the procedure it executes (see ApplyParameterOverrides).
//
// Both constructors are hand-written (not just brace-init) because this
// codebase targets C++11, where a default member initializer disqualifies a
// struct from aggregate initialization; the default one is kept explicit
// because ParsePlanFile default-constructs entries via std::map::operator[].
struct PlanRuleMode
{
    ToggleMode mode = ToggleMode::Audit;
    std::map<std::string, std::string> parameters;

    PlanRuleMode() = default;
    explicit PlanRuleMode(ToggleMode mode)
        : mode(mode)
    {
    }
};

// A parsed plan file's entry for one benchmark file (see docs/CLI.md's
// "plan / run" section and docs/payload-key-format.md section 7 for the on-disk
// JSON shape). Rules absent from `rules` are rules the plan author
// deliberately left out; `run` skips them. Keyed by `id` (the rule's sole
// per-rule identifier, unique within this one file) - see
// docs/payload-key-format.md section 6/12.
struct PlanBenchmark
{
    std::string file;
    std::string name;
    std::string sha256;
    std::map<std::string, PlanRuleMode> rules;
};

// A parsed plan file: one or more benchmark entries. Each is independently
// scoped (own file, own sha256, own rules map) so a single plan can mix
// rules from multiple benchmark files (e.g. CIS + STIG) without copying rule
// content - see docs/payload-key-format.md section 7. `run` hard-fails the whole
// plan if any entry's file doesn't apply to the current host (no partial
// results from a mismatched entry).
struct Plan
{
    std::vector<PlanBenchmark> benchmarks;
};

// Computes the SHA-256 of a file's contents, hex-encoded lowercase. Applies
// the same input-hardening posture as benchmark-definition reads (path
// traversal / writable-parent-dir / O_NOFOLLOW / ownership checks) before
// hashing, since this reads root-run input.
Result<std::string> HashFile(const std::string& path, OsConfigLogHandle logHandle);

// Generates a plan spanning one or more `benchmarkFiles`, in argument order
// (docs/CLI.md section 8.1): every rule in every file is seeded at `audit`,
// then `toggles` are applied in order (last write per rule wins). With
// exactly one file, a toggle's `section` is that file's unqualified `id`
// (today's contract, unchanged); with more than one, it must be qualified as
// `<file-basename>:<id>` since `id` is only unique within one file. Returns
// the plan serialized as pretty JSON, with one `benchmarks[]` entry per file.
// Fails if: `benchmarkFiles` is empty; the same file path is given twice (or
// two paths canonicalize to the same file); two files resolve to the same
// (framework, distribution, distributionVersion, benchmarkVersion) identity
// (see CheckUniqueBenchmarkIdentities); a toggle references a rule/file the
// input doesn't have; a `--param=` override references an unknown rule or
// parameter, or a value that doesn't match the parameter's validationRegex
// (fail-fast validation, see docs/CLI.md section 2/8.1).
Result<std::string> GeneratePlan(const std::vector<std::string>& benchmarkFiles, const std::vector<Toggle>& toggles,
    const std::vector<ParamOverride>& paramOverrides, OsConfigLogHandle logHandle);

// Parses a plan file from disk, applying the same input-hardening posture as
// benchmark-definition files (this is root-run input too).
Result<Plan> ParsePlanFile(const std::string& path, OsConfigLogHandle logHandle);

// Returns `procedureJson` (a Resource::procedure, i.e. a rule's serialized
// payload) with its top-level "parameters" object's entries overridden from
// `parameters` (a plan rule's resolved parameter map) - added if the
// procedure had none. Used by `run` to thread a plan's chosen parameter
// values into rule execution (docs/CLI.md "Parametrization"); `audit`/
// `remediate` don't call this; they always run a rule's own baked-in
// defaults unchanged.
Result<std::string> ApplyParameterOverrides(const std::string& procedureJson, const std::map<std::string, std::string>& parameters);

// Checks that no two entries share the same (framework, distribution,
// distributionVersion, benchmarkVersion) identity - the file-level prefix
// (BenchmarkDefinition::BenchmarkDocument::benchmarkInfo) that identifies
// *which* benchmark a file is. Two files resolving to the same tuple are
// either the same benchmark staged twice under different names, or two
// genuinely different revisions disagreeing about which one is current -
// both are ambiguous inputs, not a case to silently pick one and continue
// (see docs/CLI.md section 8.1). `run` calls this over every plan block's
// already-resolved benchmarkInfo, before evaluating any rule; the upcoming
// variadic `plan` (docs/CLI.md section 8.1) will call it the same way over
// its input files. `benchmarks` pairs each entry's file path (for the error
// message) with its already-parsed benchmarkInfo, in the order to check.
Optional<Error> CheckUniqueBenchmarkIdentities(const std::vector<std::pair<std::string, CISBenchmarkInfo>>& benchmarks);

} // namespace Cli
} // namespace ComplianceEngine
#endif // COMPLIANCE_ENGINE_CLI_PLAN_HPP
