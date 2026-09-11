// Smoke tests for the extracted CLI options library. Verifies the lib links
// and that ParseCommandLine accepts the same inputs the binary does today.
// Behavioural hardening (duplicate-flag rejection, empty-optarg rejection,
// breaking renames) lands in follow-up PRs along with their own tests.

#include <CliOptions.hpp>
#include <gtest/gtest.h>
#include <string>
#include <vector>

using ComplianceEngine::Cli::Command;
using ComplianceEngine::Cli::Format;
using ComplianceEngine::Cli::ParseCommandLine;
using ComplianceEngine::Cli::PrintHelp;
using ComplianceEngine::Cli::ToggleMode;

namespace
{
struct ArgvHelper
{
    std::vector<std::string> storage;
    std::vector<char*> pointers;

    explicit ArgvHelper(std::initializer_list<std::string> args)
        : storage(args)
    {
        pointers.reserve(storage.size() + 1);
        for (auto& s : storage)
        {
            pointers.push_back(&s[0]);
        }
        pointers.push_back(nullptr);
    }

    int Argc() const
    {
        return static_cast<int>(storage.size());
    }
    char** Argv()
    {
        return pointers.data();
    }
};
} // namespace

TEST(CliOptionsSmokeTest, HelpIsRecognised)
{
    ArgvHelper a{"prog", "-h"};
    auto result = ParseCommandLine(a.Argc(), a.Argv());
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value().command, Command::Help);
}

TEST(CliOptionsSmokeTest, AuditWithInputFilename)
{
    ArgvHelper a{"prog", "audit", "/tmp/x.json"};
    auto result = ParseCommandLine(a.Argc(), a.Argv());
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value().command, Command::Audit);
    EXPECT_EQ(result.Value().input, "/tmp/x.json");
}

TEST(CliOptionsSmokeTest, AuditWithoutFilenameIsRejected)
{
    // The definition file is a required positional argument for audit/remediate.
    ArgvHelper a{"prog", "audit"};
    auto result = ParseCommandLine(a.Argc(), a.Argv());
    EXPECT_FALSE(result.HasValue());
}

TEST(CliOptionsSmokeTest, RemediateWithDashFilenameIsRejected)
{
    // stdin ('-') is not accepted for definitions.
    ArgvHelper a{"prog", "remediate", "-"};
    auto result = ParseCommandLine(a.Argc(), a.Argv());
    EXPECT_FALSE(result.HasValue());
}

TEST(CliOptionsSmokeTest, FormatOnAuditIsRejected)
{
    // audit/remediate always emit the canonical JSON; --format is render-only.
    ArgvHelper a{"prog", "-f", "junit", "audit"};
    auto result = ParseCommandLine(a.Argc(), a.Argv());
    EXPECT_FALSE(result.HasValue());
}

TEST(CliOptionsSmokeTest, RenderSubcommandDefaultsToJunit)
{
    ArgvHelper a{"prog", "render"};
    auto result = ParseCommandLine(a.Argc(), a.Argv());
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value().command, Command::Render);
    ASSERT_TRUE(result.Value().format.HasValue());
    EXPECT_EQ(result.Value().format.Value(), Format::Junit);
}

TEST(CliOptionsSmokeTest, RenderSubcommandWithFileAndSuiteName)
{
    ArgvHelper a{"prog", "-f", "junit", "--suite-name", "cis_ubuntu", "render", "result.json"};
    auto result = ParseCommandLine(a.Argc(), a.Argv());
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value().command, Command::Render);
    EXPECT_EQ(result.Value().input, "result.json");
    ASSERT_TRUE(result.Value().suiteName.HasValue());
    EXPECT_EQ(result.Value().suiteName.Value(), "cis_ubuntu");
    ASSERT_TRUE(result.Value().format.HasValue());
    EXPECT_EQ(result.Value().format.Value(), Format::Junit);
}

TEST(CliOptionsSmokeTest, SuiteNameOnAuditIsRejected)
{
    ArgvHelper a{"prog", "--suite-name", "x", "audit"};
    auto result = ParseCommandLine(a.Argc(), a.Argv());
    EXPECT_FALSE(result.HasValue());
}

TEST(CliOptionsSmokeTest, SectionOnRenderIsRejected)
{
    ArgvHelper a{"prog", "-s", "1.1", "render"};
    auto result = ParseCommandLine(a.Argc(), a.Argv());
    EXPECT_FALSE(result.HasValue());
}

TEST(CliOptionsSmokeTest, InvalidFormatValueIsRejected)
{
    ArgvHelper a{"prog", "-f", "xml", "render"};
    auto result = ParseCommandLine(a.Argc(), a.Argv());
    EXPECT_FALSE(result.HasValue());
}

TEST(CliOptionsSmokeTest, TextFormatsAreParsed)
{
    for (const auto& pair : std::vector<std::pair<std::string, Format>>{
             {"nested-list", Format::NestedList}, {"compact-list", Format::CompactList}, {"debug", Format::Debug}, {"junit", Format::Junit}})
    {
        ArgvHelper a{"prog", "-f", pair.first, "render"};
        auto result = ParseCommandLine(a.Argc(), a.Argv());
        ASSERT_TRUE(result.HasValue()) << pair.first;
        ASSERT_TRUE(result.Value().format.HasValue());
        EXPECT_EQ(result.Value().format.Value(), pair.second) << pair.first;
    }
}

TEST(CliOptionsSmokeTest, ContinueOnErrorIsParsed)
{
    ArgvHelper a{"prog", "-e", "audit", "/tmp/x.json"};
    auto result = ParseCommandLine(a.Argc(), a.Argv());
    ASSERT_TRUE(result.HasValue());
    EXPECT_TRUE(result.Value().continueOnError);
}

TEST(CliOptionsSmokeTest, MissingCommandIsError)
{
    ArgvHelper a{"prog"};
    auto result = ParseCommandLine(a.Argc(), a.Argv());
    EXPECT_FALSE(result.HasValue());
}

TEST(CliOptionsSmokeTest, PrintHelpListsSubcommands)
{
    testing::internal::CaptureStdout();
    PrintHelp("prog");
    const std::string out = testing::internal::GetCapturedStdout();
    EXPECT_NE(out.find("Commands:"), std::string::npos);
    EXPECT_NE(out.find("audit"), std::string::npos);
    EXPECT_NE(out.find("remediate"), std::string::npos);
    EXPECT_NE(out.find("render"), std::string::npos);
    EXPECT_NE(out.find("plan"), std::string::npos);
    EXPECT_NE(out.find("run"), std::string::npos);
    EXPECT_NE(out.find("list"), std::string::npos);
}

TEST(CliOptionsSmokeTest, InvalidCommandIsError)
{
    ArgvHelper a{"prog", "bogus"};
    EXPECT_FALSE(ParseCommandLine(a.Argc(), a.Argv()).HasValue());
}

TEST(CliOptionsSmokeTest, TooManyArgumentsIsError)
{
    ArgvHelper a{"prog", "audit", "a.json", "extra"};
    EXPECT_FALSE(ParseCommandLine(a.Argc(), a.Argv()).HasValue());
}

TEST(CliOptionsSmokeTest, EmptySectionIsError)
{
    ArgvHelper a{"prog", "-s", "", "audit"};
    EXPECT_FALSE(ParseCommandLine(a.Argc(), a.Argv()).HasValue());
}

TEST(CliOptionsSmokeTest, UnknownOptionIsError)
{
    ArgvHelper a{"prog", "-z", "audit"};
    EXPECT_FALSE(ParseCommandLine(a.Argc(), a.Argv()).HasValue());
}

TEST(CliOptionsSmokeTest, PlanWithToggles)
{
    ArgvHelper a{"prog", "--audit=1.1", "--remediate=1.2", "--enforce=1.3", "plan", "bench.json"};
    auto result = ParseCommandLine(a.Argc(), a.Argv());
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value().command, Command::Plan);
    EXPECT_EQ(result.Value().input, "");
    ASSERT_EQ(result.Value().inputs.size(), 1u);
    EXPECT_EQ(result.Value().inputs[0], "bench.json");
    ASSERT_EQ(result.Value().toggles.size(), 3u);
    EXPECT_EQ(result.Value().toggles[0].section, "1.1");
    EXPECT_EQ(result.Value().toggles[0].mode, ToggleMode::Audit);
    EXPECT_EQ(result.Value().toggles[1].section, "1.2");
    EXPECT_EQ(result.Value().toggles[1].mode, ToggleMode::Remediate);
    EXPECT_EQ(result.Value().toggles[2].section, "1.3");
    EXPECT_EQ(result.Value().toggles[2].mode, ToggleMode::Enforce);
}

TEST(CliOptionsSmokeTest, PlanWithMultipleFiles)
{
    ArgvHelper a{"prog", "plan", "bench1.json", "bench2.json", "bench3.json"};
    auto result = ParseCommandLine(a.Argc(), a.Argv());
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value().command, Command::Plan);
    EXPECT_EQ(result.Value().input, "");
    ASSERT_EQ(result.Value().inputs.size(), 3u);
    EXPECT_EQ(result.Value().inputs[0], "bench1.json");
    EXPECT_EQ(result.Value().inputs[1], "bench2.json");
    EXPECT_EQ(result.Value().inputs[2], "bench3.json");
}

TEST(CliOptionsSmokeTest, PlanWithOutput)
{
    ArgvHelper a{"prog", "-o", "plan.json", "plan", "bench.json"};
    auto result = ParseCommandLine(a.Argc(), a.Argv());
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value().inputs.size(), 1u);
    EXPECT_EQ(result.Value().inputs[0], "bench.json");
    ASSERT_TRUE(result.Value().output.HasValue());
    EXPECT_EQ(result.Value().output.Value(), "plan.json");
}

TEST(CliOptionsSmokeTest, PlanWithoutFilenameIsRejected)
{
    ArgvHelper a{"prog", "plan"};
    EXPECT_FALSE(ParseCommandLine(a.Argc(), a.Argv()).HasValue());
}

TEST(CliOptionsSmokeTest, PlanWithSectionIsRejected)
{
    ArgvHelper a{"prog", "-s", "1.1", "plan", "bench.json"};
    EXPECT_FALSE(ParseCommandLine(a.Argc(), a.Argv()).HasValue());
}

TEST(CliOptionsSmokeTest, PlanWithContinueOnErrorIsRejected)
{
    ArgvHelper a{"prog", "-e", "plan", "bench.json"};
    EXPECT_FALSE(ParseCommandLine(a.Argc(), a.Argv()).HasValue());
}

TEST(CliOptionsSmokeTest, FormatOnPlanIsRejected)
{
    ArgvHelper a{"prog", "-f", "junit", "plan", "bench.json"};
    EXPECT_FALSE(ParseCommandLine(a.Argc(), a.Argv()).HasValue());
}

TEST(CliOptionsSmokeTest, FormatOnRunIsRejected)
{
    ArgvHelper a{"prog", "-f", "junit", "run", "plan.json"};
    EXPECT_FALSE(ParseCommandLine(a.Argc(), a.Argv()).HasValue());
}

TEST(CliOptionsSmokeTest, RunWithPlanFilename)
{
    ArgvHelper a{"prog", "run", "plan.json"};
    auto result = ParseCommandLine(a.Argc(), a.Argv());
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value().command, Command::Run);
    EXPECT_EQ(result.Value().input, "plan.json");
}

TEST(CliOptionsSmokeTest, RunWithToggleIsRejected)
{
    ArgvHelper a{"prog", "--audit=1.1", "run", "plan.json"};
    EXPECT_FALSE(ParseCommandLine(a.Argc(), a.Argv()).HasValue());
}

TEST(CliOptionsSmokeTest, RunWithOutputIsRejected)
{
    ArgvHelper a{"prog", "-o", "x.json", "run", "plan.json"};
    EXPECT_FALSE(ParseCommandLine(a.Argc(), a.Argv()).HasValue());
}

TEST(CliOptionsSmokeTest, RunWithSectionIsRejected)
{
    ArgvHelper a{"prog", "-s", "1.1", "run", "plan.json"};
    EXPECT_FALSE(ParseCommandLine(a.Argc(), a.Argv()).HasValue());
}

TEST(CliOptionsSmokeTest, RunWithoutFilenameIsRejected)
{
    ArgvHelper a{"prog", "run"};
    EXPECT_FALSE(ParseCommandLine(a.Argc(), a.Argv()).HasValue());
}

TEST(CliOptionsSmokeTest, RunWithDashFilenameIsRejected)
{
    ArgvHelper a{"prog", "run", "-"};
    EXPECT_FALSE(ParseCommandLine(a.Argc(), a.Argv()).HasValue());
}

TEST(CliOptionsSmokeTest, AuditWithToggleIsRejected)
{
    ArgvHelper a{"prog", "--remediate=1.1", "audit", "bench.json"};
    EXPECT_FALSE(ParseCommandLine(a.Argc(), a.Argv()).HasValue());
}

TEST(CliOptionsSmokeTest, AuditWithOutputIsRejected)
{
    ArgvHelper a{"prog", "-o", "x.json", "audit", "bench.json"};
    EXPECT_FALSE(ParseCommandLine(a.Argc(), a.Argv()).HasValue());
}

TEST(CliOptionsSmokeTest, EmptyToggleSectionIsError)
{
    ArgvHelper a{"prog", "--audit=", "plan", "bench.json"};
    EXPECT_FALSE(ParseCommandLine(a.Argc(), a.Argv()).HasValue());
}

TEST(CliOptionsSmokeTest, PlanWithParamOverride)
{
    ArgvHelper a{"prog", "--param=1.1.mountPoint=/tmp", "plan", "bench.json"};
    auto result = ParseCommandLine(a.Argc(), a.Argv());
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value().paramOverrides.size(), 1u);
    EXPECT_EQ(result.Value().paramOverrides[0].ref, "1.1");
    EXPECT_EQ(result.Value().paramOverrides[0].name, "mountPoint");
    EXPECT_EQ(result.Value().paramOverrides[0].value, "/tmp");
}

TEST(CliOptionsSmokeTest, PlanWithQualifiedParamOverride)
{
    ArgvHelper a{"prog", "--param=bench1.json:1.1.mountPoint=/var/tmp", "plan", "bench1.json", "bench2.json"};
    auto result = ParseCommandLine(a.Argc(), a.Argv());
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value().paramOverrides.size(), 1u);
    EXPECT_EQ(result.Value().paramOverrides[0].ref, "bench1.json:1.1");
    EXPECT_EQ(result.Value().paramOverrides[0].name, "mountPoint");
    EXPECT_EQ(result.Value().paramOverrides[0].value, "/var/tmp");
}

TEST(CliOptionsSmokeTest, PlanWithParamOverrideValueContainingEquals)
{
    ArgvHelper a{"prog", "--param=1.1.opts=a=b", "plan", "bench.json"};
    auto result = ParseCommandLine(a.Argc(), a.Argv());
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value().paramOverrides.size(), 1u);
    EXPECT_EQ(result.Value().paramOverrides[0].name, "opts");
    EXPECT_EQ(result.Value().paramOverrides[0].value, "a=b");
}

TEST(CliOptionsSmokeTest, ParamOverrideMissingEqualsIsRejected)
{
    ArgvHelper a{"prog", "--param=1.1.mountPoint", "plan", "bench.json"};
    EXPECT_FALSE(ParseCommandLine(a.Argc(), a.Argv()).HasValue());
}

TEST(CliOptionsSmokeTest, ParamOverrideMissingDotIsRejected)
{
    ArgvHelper a{"prog", "--param=mountPoint=/tmp", "plan", "bench.json"};
    EXPECT_FALSE(ParseCommandLine(a.Argc(), a.Argv()).HasValue());
}

TEST(CliOptionsSmokeTest, ParamOverrideEmptyValueIsRejected)
{
    ArgvHelper a{"prog", "--param=1.1.mountPoint=", "plan", "bench.json"};
    EXPECT_FALSE(ParseCommandLine(a.Argc(), a.Argv()).HasValue());
}

TEST(CliOptionsSmokeTest, ParamOverrideEmptyNameIsRejected)
{
    ArgvHelper a{"prog", "--param=1.1.=/tmp", "plan", "bench.json"};
    EXPECT_FALSE(ParseCommandLine(a.Argc(), a.Argv()).HasValue());
}

TEST(CliOptionsSmokeTest, ParamOverrideOnRunIsRejected)
{
    ArgvHelper a{"prog", "--param=1.1.mountPoint=/tmp", "run", "plan.json"};
    EXPECT_FALSE(ParseCommandLine(a.Argc(), a.Argv()).HasValue());
}

TEST(CliOptionsSmokeTest, ParamOverrideOnAuditIsRejected)
{
    ArgvHelper a{"prog", "--param=1.1.mountPoint=/tmp", "audit", "bench.json"};
    EXPECT_FALSE(ParseCommandLine(a.Argc(), a.Argv()).HasValue());
}

TEST(CliOptionsSmokeTest, ListWithInputFilename)
{
    ArgvHelper a{"prog", "list", "bench.json"};
    auto result = ParseCommandLine(a.Argc(), a.Argv());
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value().command, Command::List);
    EXPECT_EQ(result.Value().input, "bench.json");
}

TEST(CliOptionsSmokeTest, ListWithoutFilenameIsRejected)
{
    ArgvHelper a{"prog", "list"};
    EXPECT_FALSE(ParseCommandLine(a.Argc(), a.Argv()).HasValue());
}

TEST(CliOptionsSmokeTest, ListWithDashFilenameIsRejected)
{
    ArgvHelper a{"prog", "list", "-"};
    EXPECT_FALSE(ParseCommandLine(a.Argc(), a.Argv()).HasValue());
}

TEST(CliOptionsSmokeTest, ListWithSectionIsRejected)
{
    ArgvHelper a{"prog", "-s", "1.1", "list", "bench.json"};
    EXPECT_FALSE(ParseCommandLine(a.Argc(), a.Argv()).HasValue());
}

TEST(CliOptionsSmokeTest, ListWithContinueOnErrorIsRejected)
{
    ArgvHelper a{"prog", "-e", "list", "bench.json"};
    EXPECT_FALSE(ParseCommandLine(a.Argc(), a.Argv()).HasValue());
}

TEST(CliOptionsSmokeTest, ListWithToggleIsRejected)
{
    ArgvHelper a{"prog", "--audit=1.1", "list", "bench.json"};
    EXPECT_FALSE(ParseCommandLine(a.Argc(), a.Argv()).HasValue());
}

TEST(CliOptionsSmokeTest, ListWithOutputIsRejected)
{
    ArgvHelper a{"prog", "-o", "x.txt", "list", "bench.json"};
    EXPECT_FALSE(ParseCommandLine(a.Argc(), a.Argv()).HasValue());
}

TEST(CliOptionsSmokeTest, FormatOnListIsRejected)
{
    ArgvHelper a{"prog", "-f", "junit", "list", "bench.json"};
    EXPECT_FALSE(ParseCommandLine(a.Argc(), a.Argv()).HasValue());
}
