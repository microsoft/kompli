// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <CliOptions.hpp>
#include <algorithm>
#include <getopt.h>
#include <iostream>
#include <string>

namespace ComplianceEngine
{
namespace Cli
{

using std::string;

void PrintHelp(const std::string& programName)
{
    std::cout << "Usage: " + programName + " [options] <command> [filename]\n\n";
    std::cout << "Commands:\n";
    std::cout << "\taudit\t\tEvaluate a benchmark and emit the canonical result JSON.\n";
    std::cout << "\tremediate\tRemediate a benchmark and emit the canonical result JSON.\n";
    std::cout << "\trender\t\tRender a canonical result JSON into a presentation format.\n";
    std::cout << "\tplan\t\tGenerate a plan file selecting a mode (audit/remediate/enforce) per rule.\n";
    std::cout << "\trun\t\tExecute a plan file, emit the canonical result JSON.\n";
    std::cout << "\n";
    std::cout << "Common options:\n";
    std::cout << "\t-h, --help\tShow help and exit.\n";
    std::cout << "\t-V, --version\tShow software version and exit.\n";
    std::cout << "\t-v, --verbose\tRun in verbose mode.\n";
    std::cout << "\t-d, --debug\tRun in debug mode.\n";
    std::cout << "\n";
    std::cout << "audit / remediate / run options:\n";
    std::cout << "\t-e, --continue-on-error\tSkip rules that fail due to engine errors and continue processing. Returns 1 if any error occurred.\n";
    std::cout << "\t-l, --log-file\tSpecify a log file. Default: print log entries to standard output.\n";
    std::cout << "\t-s, --section\tProcess only specific sections. Default: process all available rules. Not valid for 'run' (the plan already selects "
                 "rules).\n";
    std::cout << "\tfilename\tProcess the specified benchmark-definition JSON file ('run': a plan file). Required: the file must be supplied on disk; "
                 "stdin ('-') is not supported for definitions.\n";
    std::cout << "\n";
    std::cout << "plan options:\n";
    std::cout << "\t    --audit=<section>\tSet <section>'s mode to audit (the default for every rule). Repeatable.\n";
    std::cout << "\t    --remediate=<section>\tSet <section>'s mode to remediate. Repeatable.\n";
    std::cout << "\t    --enforce=<section>\tSet <section>'s mode to enforce (accepted, not yet executable by 'run'). Repeatable.\n";
    std::cout << "\t-o, --output\tWrite the generated plan to this path. Default: standard output.\n";
    std::cout << "\n";
    std::cout << "render options:\n";
    std::cout << "\t-f, --format\tPresentation format. Allowed values: {junit, nested-list, compact-list, debug}. Default: junit.\n";
    std::cout << "\t    --suite-name\tName for the JUnit <testsuite>. Default: compliance.\n";
    std::cout << "\tfilename\tRead the canonical result JSON from this file. Optional: if skipped or '-', reads standard input.\n";
}

// Long-only option identifiers (no short equivalent). Values start above the
// ASCII range so they never collide with a short-option character.
enum
{
    kSuiteNameOpt = 256,
    kAuditOpt,
    kRemediateOpt,
    kEnforceOpt
};

// Command line parser using getopt_long.
//
// Resets getopt's global parser state on entry so this function can be safely
// called more than once per process (notably from unit tests). The shipping
// binary calls it exactly once, so the reset is a no-op there.
Result<Options> ParseCommandLine(const int argc, char* argv[])
{
    optind = 0;
#ifdef optreset
    optreset = 1;
    optind = 1;
#endif

    const auto* short_opts = "hVvdel:s:f:o:";
    const option long_opts[] = {{"help", no_argument, nullptr, 'h'}, {"version", no_argument, nullptr, 'V'}, {"verbose", no_argument, nullptr, 'v'},
        {"debug", no_argument, nullptr, 'd'}, {"continue-on-error", no_argument, nullptr, 'e'}, {"log-file", required_argument, nullptr, 'l'},
        {"section", required_argument, nullptr, 's'}, {"format", required_argument, nullptr, 'f'}, {"output", required_argument, nullptr, 'o'},
        {"suite-name", required_argument, nullptr, kSuiteNameOpt}, {"audit", required_argument, nullptr, kAuditOpt},
        {"remediate", required_argument, nullptr, kRemediateOpt}, {"enforce", required_argument, nullptr, kEnforceOpt}, {nullptr, 0, nullptr, 0}};

    auto result = Options{};
    int opt = getopt_long(argc, argv, short_opts, long_opts, nullptr);
    while (opt != -1)
    {
        switch (opt)
        {
            case 'h':
                result.command = Command::Help;
                return result;
            case 'V':
                result.command = Command::Version;
                return result;
            case 'v':
                result.verbose = true;
                break;
            case 'd':
                result.debug = true;
                break;
            case 'e':
                result.continueOnError = true;
                break;
            case 'l':
                if (optarg[0] == '\0')
                {
                    return Error("Log file path must not be empty.");
                }
                result.logFile = std::string(optarg);
                break;
            case 's':
                if (optarg[0] == '\0')
                {
                    return Error("Section must not be empty.");
                }
                result.section = std::string(optarg);
                break;
            case 'f': {
                if (optarg[0] == '\0')
                {
                    return Error("Format must not be empty.");
                }
                auto formatArg = std::string(optarg);
                std::transform(formatArg.begin(), formatArg.end(), formatArg.begin(), [](unsigned char c) { return static_cast<char>(::tolower(c)); });
                if (formatArg == "junit")
                {
                    result.format = Format::Junit;
                }
                else if (formatArg == "nested-list")
                {
                    result.format = Format::NestedList;
                }
                else if (formatArg == "compact-list")
                {
                    result.format = Format::CompactList;
                }
                else if (formatArg == "debug")
                {
                    result.format = Format::Debug;
                }
                else
                {
                    return Error("Invalid format: " + formatArg + ". Allowed values: {junit, nested-list, compact-list, debug}.");
                }
                break;
            }
            case kSuiteNameOpt:
                if (optarg[0] == '\0')
                {
                    return Error("Suite name must not be empty.");
                }
                result.suiteName = std::string(optarg);
                break;
            case 'o':
                if (optarg[0] == '\0')
                {
                    return Error("Output path must not be empty.");
                }
                result.output = std::string(optarg);
                break;
            case kAuditOpt:
            case kRemediateOpt:
            case kEnforceOpt: {
                if (optarg[0] == '\0')
                {
                    return Error("Section must not be empty.");
                }
                const ToggleMode mode = (opt == kAuditOpt) ? ToggleMode::Audit : (opt == kRemediateOpt) ? ToggleMode::Remediate : ToggleMode::Enforce;
                result.toggles.push_back(Toggle{std::string(optarg), mode});
                break;
            }
            default:
                return Error("Unknown option.");
        }

        opt = getopt_long(argc, argv, short_opts, long_opts, nullptr);
    }

    // After options, parse the positional arguments
    if (optind < argc)
    {
        const std::string arg = argv[optind];
        if (arg == "audit")
        {
            result.command = Command::Audit;
        }
        else if (arg == "remediate")
        {
            result.command = Command::Remediate;
        }
        else if (arg == "render")
        {
            result.command = Command::Render;
        }
        else if (arg == "plan")
        {
            result.command = Command::Plan;
        }
        else if (arg == "run")
        {
            result.command = Command::Run;
        }
        else
        {
            return Error("Invalid command: '" + arg + "'. Must be 'audit', 'remediate', 'render', 'plan' or 'run'.");
        }
        ++optind;
    }
    else
    {
        return Error("Missing required command: 'audit', 'remediate', 'render', 'plan' or 'run'.");
    }

    // Input filename
    if (optind < argc)
    {
        const std::string arg = argv[optind];
        result.input = arg;
        ++optind;
    }

    // End of positional arguments
    if (optind < argc)
    {
        return Error("Too many arguments provided.");
    }

    // Cross-option validation: keep each subcommand's flags scoped to what it
    // actually uses (audit/remediate/run's canonical-JSON surface stays free of
    // presentation flags; render stays free of scan flags; plan's toggles/output
    // stay off every other subcommand).
    if (Command::Render == result.command)
    {
        if (result.section.HasValue())
        {
            return Error("--section is not valid for the 'render' subcommand.");
        }
        // Default the renderer when none was supplied.
        if (!result.format.HasValue())
        {
            result.format = Format::Junit;
        }
    }
    else
    {
        if (result.format.HasValue())
        {
            return Error("--format is only valid for the 'render' subcommand; 'audit', 'remediate', 'plan' and 'run' don't use it.");
        }
        if (result.suiteName.HasValue())
        {
            return Error("--suite-name is only valid for the 'render' subcommand.");
        }

        if (Command::Plan == result.command)
        {
            if (result.section.HasValue())
            {
                return Error("--section is not valid for 'plan'; select rules with --audit=/--remediate=/--enforce= instead.");
            }
            if (result.continueOnError)
            {
                return Error("--continue-on-error is not valid for 'plan'; it doesn't execute anything.");
            }
            if (result.logFile.HasValue())
            {
                return Error("--log-file is not valid for 'plan'; it doesn't execute anything.");
            }
        }
        else
        {
            if (!result.toggles.empty())
            {
                return Error("--audit=/--remediate=/--enforce= are only valid for 'plan'.");
            }
            if (result.output.HasValue())
            {
                return Error("--output is only valid for 'plan'.");
            }
            if (Command::Run == result.command && result.section.HasValue())
            {
                return Error("--section is not valid for 'run'; the plan file already selects rules.");
            }
        }

        // audit/remediate/plan/run all require an on-disk file as the positional
        // argument (the benchmark definition for audit/remediate/plan, the plan
        // file for run). stdin ('-') is deliberately rejected so the
        // input-hardening checks cannot be bypassed by piping data in.
        if (result.input.empty() || result.input == "-")
        {
            return Error("A file argument is required for 'audit', 'remediate', 'plan' and 'run'; stdin ('-') is not supported.");
        }
    }

    return result;
}

} // namespace Cli
} // namespace ComplianceEngine
