#ifndef COMPLIANCE_ENGINE_CLI_CLI_OPTIONS_HPP
#define COMPLIANCE_ENGINE_CLI_CLI_OPTIONS_HPP

#include <Optional.h>
#include <Result.h>
#include <string>
#include <vector>

namespace ComplianceEngine
{
namespace Cli
{

enum class Command
{
    Help,
    Version,
    Audit,
    Remediate,
    Render,
    // Generates a plan file for a benchmark-definition file (see docs/CLI.md).
    Plan,
    // Executes a plan file (see docs/CLI.md).
    Run
};

// Presentation formats produced by the `render` subcommand. `audit` / `remediate`
// no longer select a format: they always emit the canonical JSON, which `render`
// turns into one of these.
enum class Format
{
    NestedList,
    CompactList,
    Debug,
    Junit
};

// A rule's mode inside a plan, selected by `plan`'s --audit/--remediate/--enforce
// toggles and read back by `run`. `Enforce` is accepted and recorded (kept in the
// contract, see docs/CLI.md) even though nothing can execute it yet.
enum class ToggleMode
{
    Audit,
    Remediate,
    Enforce
};

// One `--audit=<section>` / `--remediate=<section>` / `--enforce=<section>`
// occurrence, in the order it appeared on the command line. `plan` applies
// these in order, so the last one touching a given section wins.
//
// A hand-written constructor is required (not just brace-init) because this
// codebase targets C++11, where a default member initializer disqualifies a
// struct from aggregate initialization.
struct Toggle
{
    std::string section;
    ToggleMode mode;

    Toggle(std::string section, ToggleMode mode)
        : section(std::move(section)),
          mode(mode)
    {
    }
};

struct Options
{
    bool verbose = false;
    bool debug = false;
    bool continueOnError = false;
    Optional<std::string> logFile;
    Optional<Format> format;
    Command command = Command::Help;
    std::string input;
    Optional<std::string> section;
    // `render` only: the JUnit <testsuite name>. The CLI does not know which
    // benchmark package it came from, so the caller supplies this.
    Optional<std::string> suiteName;
    // `plan` only: repeatable --audit=/--remediate=/--enforce= toggles, in
    // argument order.
    std::vector<Toggle> toggles;
    // `plan` only: write the generated plan here instead of stdout.
    Optional<std::string> output;
};

void PrintHelp(const std::string& programName);

Result<Options> ParseCommandLine(int argc, char* argv[]);

} // namespace Cli
} // namespace ComplianceEngine

#endif // COMPLIANCE_ENGINE_CLI_CLI_OPTIONS_HPP
