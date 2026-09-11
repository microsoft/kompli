// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//
// kompli
//
// This tool runs as root on Linux endpoints to perform CIS benchmark audit and
// remediation. Its trust boundary, input-hardening posture, and known
// limitations are documented in THREAT_MODEL.md (in this directory). Keep that
// document in sync when the input format or the hardening changes.

#include "BenchmarkDefinition.hpp"
#include "BenchmarkFormatter.hpp"
#include "CliOptions.hpp"
#include "JUnitRenderer.hpp"
#include "Plan.hpp"
#include "TextRenderers.hpp"

#include <CliContext.h>
#include <CommonContext.h>
#include <DistributionInfo.h>
#include <Engine.h>
#include <Logging.h>
#include <Optional.h>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <utility>
#include <vector>
#include <version.h>

using ComplianceEngine::Action;
using ComplianceEngine::CISBenchmarkInfo;
using ComplianceEngine::CliContext;
using ComplianceEngine::CombineAllOf;
using ComplianceEngine::DistributionInfo;
using ComplianceEngine::Engine;
using ComplianceEngine::Error;
using ComplianceEngine::Optional;
using ComplianceEngine::PayloadFormatter;
using ComplianceEngine::Result;
using ComplianceEngine::Status;
using ComplianceEngine::BenchmarkDefinition::ParseFile;
using ComplianceEngine::BenchmarkFormatters::BenchmarkFormatter;
using ComplianceEngine::Cli::ApplyParameterOverrides;
using ComplianceEngine::Cli::CheckUniqueBenchmarkIdentities;
using ComplianceEngine::Cli::Command;
using ComplianceEngine::Cli::Format;
using ComplianceEngine::Cli::GeneratePlan;
using ComplianceEngine::Cli::Options;
using ComplianceEngine::Cli::ParseCommandLine;
using ComplianceEngine::Cli::ParsePlanFile;
using ComplianceEngine::Cli::Plan;
using ComplianceEngine::Cli::PrintHelp;
using ComplianceEngine::Cli::RenderJUnit;
using ComplianceEngine::Cli::RenderText;
using ComplianceEngine::Cli::TextStyle;
using ComplianceEngine::Cli::ToggleMode;
using std::string;

namespace
{
// Upper bound on a canonical result JSON fed to `render`. Generous (results for
// a full benchmark are well under this) but bounds memory for a hostile input.
constexpr std::size_t kMaxResultJsonBytes = static_cast<std::size_t>(256) * 1024 * 1024;

// Reads an entire stream into a string, refusing inputs larger than the cap.
Result<string> ReadAllBounded(std::istream& stream, std::size_t cap)
{
    string content;
    char buffer[64 * 1024];
    while (stream.read(buffer, sizeof(buffer)) || stream.gcount() > 0)
    {
        content.append(buffer, static_cast<std::size_t>(stream.gcount()));
        if (content.size() > cap)
        {
            return Error("Input exceeds the maximum allowed size", EFBIG);
        }
    }
    if (stream.bad())
    {
        return Error("Failed to read input", EIO);
    }
    return content;
}

// Renders a canonical result JSON (read from stdin or a file) into the format
// selected on the `render` subcommand. Runs without root and touches no system
// state, so it needs none of the definition input hardening `audit`/`remediate` apply.
int RunRender(const Options& options)
{
    Result<string> jsonResult = Error("uninitialized");
    if (options.input.empty() || options.input == "-")
    {
        jsonResult = ReadAllBounded(std::cin, kMaxResultJsonBytes);
    }
    else
    {
        std::ifstream file(options.input, std::ios::binary);
        if (!file.is_open())
        {
            std::cerr << "Error: failed to open input file '" << options.input << "'." << std::endl;
            return 1;
        }
        jsonResult = ReadAllBounded(file, kMaxResultJsonBytes);
    }
    if (!jsonResult.HasValue())
    {
        std::cerr << "Error: " << jsonResult.Error().message << std::endl;
        return 1;
    }

    const string suiteName = options.suiteName.HasValue() ? options.suiteName.Value() : string("compliance");

    // The parser defaults the format to Junit when none is supplied.
    const Format format = options.format.HasValue() ? options.format.Value() : Format::Junit;
    Result<string> rendered = Error("uninitialized");
    switch (format)
    {
        case Format::Junit:
            rendered = RenderJUnit(jsonResult.Value(), suiteName);
            break;
        case Format::NestedList:
            rendered = RenderText(jsonResult.Value(), TextStyle::NestedList);
            break;
        case Format::CompactList:
            rendered = RenderText(jsonResult.Value(), TextStyle::CompactList);
            break;
        case Format::Debug:
            rendered = RenderText(jsonResult.Value(), TextStyle::Debug);
            break;
    }
    if (!rendered.HasValue())
    {
        std::cerr << "Error: " << rendered.Error().message << std::endl;
        return 1;
    }
    std::cout << rendered.Value();
    return 0;
}

// Generates a plan (see docs/CLI.md) for `options.input` (the benchmark file)
// and writes it to `options.output` or stdout. Runs without root: it only
// reads the benchmark file and hashes it, it evaluates nothing.
int RunPlan(const Options& options)
{
    auto planResult = GeneratePlan(options.inputs, options.toggles, options.paramOverrides, nullptr);
    if (!planResult.HasValue())
    {
        std::cerr << "Error: " << planResult.Error().message << std::endl;
        return 1;
    }

    if (options.output.HasValue())
    {
        std::ofstream file(options.output.Value(), std::ios::binary | std::ios::trunc);
        if (!file.is_open())
        {
            std::cerr << "Error: failed to open output file '" << options.output.Value() << "'." << std::endl;
            return 1;
        }
        file << planResult.Value();
        if (!file)
        {
            std::cerr << "Error: failed to write output file '" << options.output.Value() << "'." << std::endl;
            return 1;
        }
    }
    else
    {
        std::cout << planResult.Value();
    }
    return 0;
}

// Enumerates `options.input`'s rules (id, title) to stdout, one per line,
// in document order (docs/CLI.md section 2). Runs without root: it only
// reads and parses the benchmark file, same posture as `plan`/`render`. The
// per-rule detail view (parameters and defaults) described in docs/CLI.md
// isn't implemented yet - it needs BenchmarkIO::Resource to parse
// parameterMetadata first (tracked as the Parametrization gap).
int RunList(const Options& options)
{
    auto docResult = ParseFile(options.input, nullptr);
    if (!docResult.HasValue())
    {
        std::cerr << "Error: " << docResult.Error().message << std::endl;
        return 1;
    }
    for (const auto& resource : docResult.Value().resources)
    {
        std::cout << resource.id << '\t' << resource.resourceID << '\n';
    }
    return 0;
}
} // anonymous namespace

int main(int argc, char* argv[])
{
    // Ensure file-creation permissions are at least as restrictive as 0077
    // without overriding a stricter inherited mask.
    ::umask(::umask(0) | S_IRWXG | S_IRWXO);

    const auto optionsResult = ParseCommandLine(argc, argv);
    if (!optionsResult.HasValue())
    {
        std::cerr << "Error: " << optionsResult.Error().message << std::endl;
        PrintHelp(argv[0]);
        return 1;
    }

    const auto& options = optionsResult.Value();
    if (Command::Help == options.command)
    {
        PrintHelp(argv[0]);
        return 0;
    }

    if (Command::Version == options.command)
    {
        std::cout << "kompli\nVersion: " << KOMPLI_VERSION << "\n";
        return 0;
    }

    // `render` is a pure, root-free transformation of a canonical result JSON;
    // it needs neither the engine nor the definition input path, so dispatch it early.
    if (Command::Render == options.command)
    {
        return RunRender(options);
    }

    // `plan` is a pure, root-free transformation of a benchmark-definition file
    // (read + hash only); it needs neither the engine nor a log file, so
    // dispatch it early, same as `render`.
    if (Command::Plan == options.command)
    {
        return RunPlan(options);
    }

    // `list` is likewise a pure, root-free read of a benchmark-definition file.
    if (Command::List == options.command)
    {
        return RunList(options);
    }

    // `run` resolves and validates its plan file before anything else needs a
    // log handle or the engine, so do that first and carry the parsed plan
    // (and the benchmark file path it points at) forward.
    Optional<Plan> plan;
    if (Command::Run == options.command)
    {
        auto planResult = ParsePlanFile(options.input, nullptr);
        if (!planResult.HasValue())
        {
            std::cerr << "Error: failed to parse plan file: " << planResult.Error().message << std::endl;
            return 1;
        }
        plan = std::move(planResult.Value());

        // Reject a plan whose blocks don't all resolve to distinct benchmark
        // identities, before evaluating any rule (fail fast) - two blocks
        // pointing at files that share a (framework, distribution,
        // distributionVersion, benchmarkVersion) tuple are ambiguous, not a
        // case to silently pick one and continue (docs/CLI.md section 8.1).
        // This re-reads each benchmark file up front (a nullptr log handle is
        // fine here, same as ParsePlanFile above); the per-block loop below
        // parses it again once log handle / applicability checks are ready.
        std::vector<std::pair<string, CISBenchmarkInfo>> identities;
        identities.reserve(plan.Value().benchmarks.size());
        for (const auto& benchmark : plan.Value().benchmarks)
        {
            auto identityDocResult = ParseFile(benchmark.file, nullptr);
            if (!identityDocResult.HasValue())
            {
                std::cerr << "Error: failed to parse benchmark definition input: " << identityDocResult.Error().message << std::endl;
                return 1;
            }
            identities.emplace_back(benchmark.file, identityDocResult.Value().benchmarkInfo);
        }
        auto duplicateIdentityError = CheckUniqueBenchmarkIdentities(identities);
        if (duplicateIdentityError.HasValue())
        {
            std::cerr << "Error: refusing to run plan: " << duplicateIdentityError.Value().message << std::endl;
            return 1;
        }
    }

    // The CLI logs to stderr unconditionally (no `--log-file`; see
    // docs/logging.md in the kompli repo for why the operator-supplied log
    // path was removed rather than hardened further). A null log handle
    // routes every OsConfigLog* call through the console sink.
    std::unique_ptr<OsConfigLog, void (*)(OsConfigLog*)> logHandle(nullptr, [](OsConfigLog* h) {
        OsConfigLogHandle tmp = h;
        CloseLog(&tmp);
    });

    if (options.verbose)
    {
        SetLoggingLevel(LoggingLevel::LoggingLevelInformational);
        OsConfigLogInfo(logHandle.get(), "Verbose logging enabled");
    }

    if (options.debug)
    {
        SetLoggingLevel(LoggingLevel::LoggingLevelDebug);
        OsConfigLogInfo(logHandle.get(), "Debug logging enabled");
    }

    auto context = std::unique_ptr<CliContext>(new CliContext(logHandle.get()));
    // The Engine takes ownership of a PayloadFormatter and uses it polymorphically
    // to render each rule's indicators. Pass the JSON one explicitly: the
    // constructor's default is a DebugFormatter, whose text output could not be
    // embedded as the canonical result's indicators array.
    Engine engine(std::move(context), std::unique_ptr<PayloadFormatter>(new ComplianceEngine::JsonFormatter()));

    // Determine the OS this tool is running on so rules that target a different
    // distribution/version can be skipped. LoadDistributionInfo prefers the
    // operator-supplied override file and falls back to /etc/os-release. If the
    // OS cannot be identified (e.g. an unmapped distribution ID and no override
    // file), abort rather than silently running rules meant for another system.
    auto distributionInfoError = engine.LoadDistributionInfo();
    if (distributionInfoError)
    {
        OsConfigLogError(logHandle.get(), "Failed to determine system distribution: %s", distributionInfoError.Value().message.c_str());
        OsConfigLogError(logHandle.get(), "To specify the OS identity explicitly, place an override in the '%s' file", DistributionInfo::cDefaultOverrideFilePath);
        return 1;
    }

    // `audit` / `remediate` / `run` always emit the canonical JSON. The benchmark
    // formatter builds the result envelope; the engine is separately given a
    // JSON payload formatter (at its construction, above) to render each rule's
    // indicators. Presentation is the `render` subcommand's job.
    //
    // `run` can mix audit/remediate per rule; the result schema doesn't have a
    // per-rule action field yet (tracked in docs/CLI.md), so the top-level
    // action is a best-effort summary: Remediation if any benchmark entry
    // remediates any rule, Audit otherwise.
    Action topLevelAction = Action::Audit;
    if (Command::Remediate == options.command)
    {
        topLevelAction = Action::Remediate;
    }
    else if (Command::Run == options.command)
    {
        for (const auto& benchmark : plan.Value().benchmarks)
        {
            for (const auto& rule : benchmark.rules)
            {
                if (ToggleMode::Remediate == rule.second.mode)
                {
                    topLevelAction = Action::Remediate;
                }
            }
        }
    }
    const auto& distributionInfo = engine.GetDistributionInfo().Value();
    auto formatterResult = BenchmarkFormatter::Begin(distributionInfo, topLevelAction);
    if (!formatterResult.HasValue())
    {
        OsConfigLogError(logHandle.get(), "Failed to begin formatted output: %s", formatterResult.Error().message.c_str());
        return 1;
    }
    auto& benchmarkFormatter = formatterResult.Value();

    auto status = Status::Compliant;
    bool hasError = false;
    // Rules that passed the section filter and were evaluated. The Compliant seed
    // is the CombineAllOf identity; when nothing runs it would misreport a
    // benchmark that checked nothing, so a terminal override maps that case to
    // NotApplicable below.
    size_t evaluatedRules = 0;

    // `audit`/`remediate` process exactly one file (options.input, the same
    // mode for every rule); `run` processes every benchmark entry in the plan
    // (docs/payload-key-format.md section 7 - a plan can mix rules from multiple
    // files, e.g. CIS + STIG), each independently hash-checked and
    // applicability-checked, accumulating into one combined result.
    const size_t benchmarkCount = (Command::Run == options.command) ? plan.Value().benchmarks.size() : 1;
    for (size_t b = 0; b < benchmarkCount; ++b)
    {
        const string& benchmarkFile = (Command::Run == options.command) ? plan.Value().benchmarks[b].file : options.input;

        // `run` re-checks each benchmark file's hash against the one recorded
        // when the plan was generated - belt-and-suspenders against drift
        // between plan generation and execution (see docs/CLI.md section 2's TOCTOU
        // note). A mismatch is a hard error: the plan's rule references were
        // only validated against the file as it existed at generation time.
        if (Command::Run == options.command)
        {
            auto hashResult = ComplianceEngine::Cli::HashFile(benchmarkFile, logHandle.get());
            if (!hashResult.HasValue())
            {
                OsConfigLogError(logHandle.get(), "Failed to hash benchmark file '%s': %s", benchmarkFile.c_str(), hashResult.Error().message.c_str());
                return 1;
            }
            if (hashResult.Value() != plan.Value().benchmarks[b].sha256)
            {
                OsConfigLogError(logHandle.get(),
                    "Refusing to run plan: benchmark file '%s' has changed since the plan was generated (sha256 mismatch).", benchmarkFile.c_str());
                return 1;
            }
        }

        // Parse the input as a benchmark-definition document. Definition input is a
        // required positional file argument (enforced in ParseCommandLine); the
        // parser encapsulates the full input-hardening posture (path-traversal
        // rejection, root-owned non-writable parent directory, O_NOFOLLOW open, and
        // regular-file/ownership/mode checks) and owns the file. stdin is
        // deliberately unsupported for definitions so those integrity checks can
        // never be bypassed by piping data in.
        auto docResult = ParseFile(benchmarkFile, logHandle.get());
        if (!docResult.HasValue())
        {
            OsConfigLogError(logHandle.get(), "Failed to parse benchmark definition input: %s", docResult.Error().message.c_str());
            return 1;
        }
        const auto& doc = docResult.Value();

        // Validate applicability once per file (docs/payload-key-format.md section 5) -
        // every rule in one file shares the same distro/version prefix, so this
        // is the only check possible now that rules no longer carry their own
        // (see BenchmarkIO::Resource). A mismatch hard-fails the whole run: for
        // `run`, mixing a mismatched benchmark entry into an otherwise-valid
        // plan is treated as an authoring mistake, not something to silently
        // skip and report a partial result for.
        if (!doc.benchmarkInfo.Match(distributionInfo))
        {
            OsConfigLogError(logHandle.get(), "Aborting on benchmark '%s': not applicable for the current distribution", benchmarkFile.c_str());
            OsConfigLogError(logHandle.get(), "Current system identification: %s", std::to_string(distributionInfo).c_str());
            auto overridden = distributionInfo;
            overridden.distribution = doc.benchmarkInfo.distribution;
            overridden.version = doc.benchmarkInfo.SanitizedVersion();
            OsConfigLogError(logHandle.get(), "To override this detection, place the following line inside the '%s' file: %s",
                DistributionInfo::cDefaultOverrideFilePath, std::to_string(overridden).c_str());
            return 1;
        }

        for (const auto& entry : doc.resources)
        {
            if (options.section.HasValue())
            {
                if (entry.id.find(options.section.Value()) != 0)
                {
                    OsConfigLogDebug(logHandle.get(), "Skipping entry %s as it does not match section %s", entry.resourceID.c_str(),
                        options.section.Value().c_str());
                    continue;
                }
            }

            // `audit`/`remediate` apply the same mode to every rule. `run`
            // looks the mode up per rule in this benchmark entry, keyed by
            // id (docs/payload-key-format.md section 6/12) - a rule the plan
            // doesn't mention is one the plan author deliberately left out,
            // skip it entirely rather than guessing a mode.
            ToggleMode mode = (Command::Remediate == options.command) ? ToggleMode::Remediate : ToggleMode::Audit;
            // `run` only: the plan's pre-filled/overridden parameter values
            // for this rule (docs/CLI.md "Parametrization"), threaded into
            // the procedure below. Empty for `audit`/`remediate`, which
            // always execute a rule's own baked-in defaults unchanged.
            std::string procedure = entry.procedure;
            if (Command::Run == options.command)
            {
                const auto& rules = plan.Value().benchmarks[b].rules;
                const auto it = rules.find(entry.id);
                if (it == rules.end())
                {
                    OsConfigLogDebug(logHandle.get(), "Skipping entry %s: not present in the plan", entry.resourceID.c_str());
                    continue;
                }
                mode = it->second.mode;
                if (!it->second.parameters.empty())
                {
                    auto overrideResult = ApplyParameterOverrides(entry.procedure, it->second.parameters);
                    if (!overrideResult.HasValue())
                    {
                        OsConfigLogError(logHandle.get(), "Failed to apply plan parameters for %s: %s", entry.resourceID.c_str(),
                            overrideResult.Error().message.c_str());
                        if (!options.continueOnError)
                        {
                            return 1;
                        }
                        hasError = true;
                        continue;
                    }
                    procedure = std::move(overrideResult.Value());
                }
            }

            // The rule is selected for evaluation (past the section filter / plan lookup).
            ++evaluatedRules;

            auto procedureResult = engine.MmiSet((string("procedure") + entry.ruleName).c_str(), procedure);
            if (!procedureResult.HasValue())
            {
                OsConfigLogError(logHandle.get(), "Failed to set procedure: %s", procedureResult.Error().message.c_str());
                if (!options.continueOnError)
                {
                    return 1;
                }
                hasError = true;
                continue;
            }

            switch (mode)
            {
                case ToggleMode::Audit: {
                    if (entry.hasInitAudit)
                    {
                        // If the producer flagged InitObject support but supplied no
                        // desired value, fall back to an empty JSON object so we
                        // don't deref an empty Optional.
                        const string initPayload = entry.payload.HasValue() ? entry.payload.Value() : string("{}");
                        auto result = engine.MmiSet((string("init") + entry.ruleName).c_str(), initPayload);
                        if (!result.HasValue())
                        {
                            OsConfigLogError(logHandle.get(), "Failed to init audit: %s", result.Error().message.c_str());
                            if (!options.continueOnError)
                            {
                                return 1;
                            }
                            hasError = true;
                            continue;
                        }
                    }

                    auto ruleName = string("audit") + entry.ruleName;
                    auto result = engine.MmiGet(ruleName.c_str());
                    if (!result.HasValue())
                    {
                        OsConfigLogError(logHandle.get(), "Failed to perform audit: %s", result.Error().message.c_str());
                        if (!options.continueOnError)
                        {
                            return 1;
                        }
                        hasError = true;
                        continue;
                    }

                    auto error = benchmarkFormatter.AddEntry(entry, result.Value().status, result.Value().payload, engine.GetParameters(entry.ruleName));
                    if (error)
                    {
                        OsConfigLogError(logHandle.get(), "Failed to add entry to JSON formatter: %s", error.Value().message.c_str());
                        if (!options.continueOnError)
                        {
                            return 1;
                        }
                        hasError = true;
                        continue;
                    }

                    // Aggregate the overall benchmark status the same way the engine
                    // aggregates an allOf (CombineAllOf): NonCompliant dominates,
                    // NotApplicable is sticky, otherwise Compliant.
                    status = CombineAllOf(status, result.Value().status);

                    break;
                }

                case ToggleMode::Remediate: {
                    // Benchmark definitions carry no desired value (modelled here as
                    // an absent payload); fall back to an empty JSON object so
                    // remediation can still run, mirroring the audit-init path above.
                    const string remediatePayload = entry.payload.HasValue() ? entry.payload.Value() : string("{}");
                    auto ruleName = string("remediate") + entry.ruleName;
                    auto result = engine.MmiSet(ruleName.c_str(), remediatePayload);
                    if (!result.HasValue())
                    {
                        OsConfigLogError(logHandle.get(), "Failed to remediate: %s", result.Error().message.c_str());
                        if (!options.continueOnError)
                        {
                            return 1;
                        }
                        hasError = true;
                        continue;
                    }

                    auto error = benchmarkFormatter.AddEntry(entry, result.Value(), "[]", engine.GetParameters(entry.ruleName));
                    if (error)
                    {
                        OsConfigLogError(logHandle.get(), "Failed to add entry to JSON formatter: %s", error.Value().message.c_str());
                        if (!options.continueOnError)
                        {
                            return 1;
                        }
                        hasError = true;
                        continue;
                    }

                    // Same allOf aggregation as the audit path.
                    status = CombineAllOf(status, result.Value());

                    break;
                }

                case ToggleMode::Enforce: {
                    // Reserved: `enforce` is accepted and recorded by `plan` (see
                    // docs/CLI.md) but nothing can execute it yet - active,
                    // kernel-level enforcement is a separate, not-yet-designed
                    // mechanism. Fail the rule rather than silently skipping or
                    // misreporting it as audited/remediated.
                    OsConfigLogError(logHandle.get(), "Rule %s is set to 'enforce', which is not implemented yet; no result was produced for it.",
                        entry.resourceID.c_str());
                    if (!options.continueOnError)
                    {
                        return 1;
                    }
                    hasError = true;
                    break;
                }
            }
        }
    }

    // A benchmark that evaluated no rules (an empty definition, or a section
    // filter that matched nothing) checked nothing; report NotApplicable rather
    // than a misleading Compliant. This is a terminal override, deliberately not
    // folded through CombineAllOf, whose NotApplicable is absorbing and would
    // otherwise poison any non-empty run if used as the seed.
    if (0 == evaluatedRules)
    {
        status = Status::NotApplicable;
    }

    auto result = std::move(benchmarkFormatter).Finish(status);
    if (!result.HasValue())
    {
        OsConfigLogError(logHandle.get(), "Failed to finish formatted output: %s", result.Error().message.c_str());
        return 1;
    }

    std::cout << result.Value() << "\n";
    return hasError ? 1 : 0;
}
