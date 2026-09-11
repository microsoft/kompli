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
#include "InputSecurity.hpp"
#include "JUnitRenderer.hpp"
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
#include <version.h>

using ComplianceEngine::Action;
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
using ComplianceEngine::BenchmarkIO::RefuseUnsafeLogFile;
using ComplianceEngine::Cli::Command;
using ComplianceEngine::Cli::Format;
using ComplianceEngine::Cli::Options;
using ComplianceEngine::Cli::ParseCommandLine;
using ComplianceEngine::Cli::PrintHelp;
using ComplianceEngine::Cli::RenderJUnit;
using ComplianceEngine::Cli::RenderText;
using ComplianceEngine::Cli::TextStyle;
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

    // Validate the log-file path before opening it. The shared logging code
    // opens the log with a symlink-following append and chmod's it while we run
    // as root, so an attacker-controlled symlink or writable parent directory
    // could redirect those writes. No log handle exists yet, so failures are
    // reported to stderr.
    if (options.logFile.HasValue())
    {
        if (options.logFile->empty() || RefuseUnsafeLogFile(options.logFile.Value(), nullptr))
        {
            std::cerr << "Error: refusing to use unsafe log file path." << std::endl;
            return 1;
        }
    }

    std::unique_ptr<OsConfigLog, void (*)(OsConfigLog*)> logHandle(options.logFile.HasValue() ? OpenLog(options.logFile->c_str(), nullptr) : nullptr,
        [](OsConfigLog* h) {
            OsConfigLogHandle tmp = h;
            CloseLog(&tmp);
        });
    if (logHandle)
    {
        SetConsoleLoggingEnabled(false);
    }

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

    // `audit` / `remediate` always emit the canonical JSON. The benchmark
    // formatter builds the result envelope; the engine is separately given a
    // JSON payload formatter (at its construction, above) to render each rule's
    // indicators. Presentation is the `render` subcommand's job.
    const auto& distributionInfo = engine.GetDistributionInfo().Value();
    auto formatterResult = BenchmarkFormatter::Begin(distributionInfo, options.command == Command::Audit ? Action::Audit : Action::Remediate);
    if (!formatterResult.HasValue())
    {
        OsConfigLogError(logHandle.get(), "Failed to begin formatted output: %s", formatterResult.Error().message.c_str());
        return 1;
    }
    auto& benchmarkFormatter = formatterResult.Value();

    // Parse the input as a benchmark-definition document. Definition input is a
    // required positional file argument (enforced in ParseCommandLine); the
    // parser encapsulates the full input-hardening posture (path-traversal
    // rejection, root-owned non-writable parent directory, O_NOFOLLOW open, and
    // regular-file/ownership/mode checks) and owns the file. stdin is
    // deliberately unsupported for definitions so those integrity checks can
    // never be bypassed by piping data in.
    auto resourcesResult = ParseFile(options.input, logHandle.get());
    if (!resourcesResult.HasValue())
    {
        OsConfigLogError(logHandle.get(), "Failed to parse benchmark definition input: %s", resourcesResult.Error().message.c_str());
        return 1;
    }
    const auto& resources = resourcesResult.Value();

    auto status = Status::Compliant;
    bool hasError = false;
    // Rules that passed the section filter and were evaluated. The Compliant seed
    // is the CombineAllOf identity; when nothing runs it would misreport a
    // benchmark that checked nothing, so a terminal override maps that case to
    // NotApplicable below.
    size_t evaluatedRules = 0;
    for (const auto& entry : resources)
    {
        // Abort as soon as we encounter a rule that does not target the detected
        // distribution/version. This mirrors ComplianceEngineCheckApplicability
        // in the module interface: the benchmark's distribution must match and
        // its version glob must match the running system's VERSION_ID. Every
        // rule in a definition belongs to the same benchmark, so a single
        // mismatch means the whole definition targets another system (or this
        // system was misdetected); running any of its rules would report
        // spurious results.
        const auto& distributionInfo = engine.GetDistributionInfo().Value();
        if (!entry.benchmarkInfo.Match(distributionInfo))
        {
            OsConfigLogError(logHandle.get(), "Aborting on entry %s: benchmark is not applicable for the current distribution", entry.resourceID.c_str());
            OsConfigLogError(logHandle.get(), "Current system identification: %s", std::to_string(distributionInfo).c_str());
            auto overridden = distributionInfo;
            overridden.distribution = entry.benchmarkInfo.distribution;
            overridden.version = entry.benchmarkInfo.SanitizedVersion();
            OsConfigLogError(logHandle.get(), "To override this detection, place the following line inside the '%s' file: %s",
                DistributionInfo::cDefaultOverrideFilePath, std::to_string(overridden).c_str());
            return 1;
        }

        if (options.section.HasValue())
        {
            if (entry.benchmarkInfo.section.find(options.section.Value()) != 0)
            {
                OsConfigLogDebug(logHandle.get(), "Skipping entry %s as it does not match section %s", entry.resourceID.c_str(), options.section.Value().c_str());
                continue;
            }
        }

        // The rule is selected for evaluation (past the section filter).
        ++evaluatedRules;

        auto procedureResult = engine.MmiSet((string("procedure") + entry.ruleName).c_str(), entry.procedure);
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

        switch (options.command)
        {
            case Command::Audit: {
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

            case Command::Remediate: {
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

            default:
                break;
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
