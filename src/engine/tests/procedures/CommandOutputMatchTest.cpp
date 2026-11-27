// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "MockContext.h"

#include <CommandOutputMatch.h>
#include <CommonContext.h>
#include <gtest/gtest.h>
#include <string>
#include <utility>
#include <vector>

using Kompli::AuditCommandOutputMatch;
using Kompli::CommandOutputMatchParams;
using Kompli::Error;
using Kompli::IndicatorsTree;
using Kompli::RegexType;
using Kompli::Result;
using Kompli::Status;
using ::testing::Return;

class ExecuteCommandGrepTest : public ::testing::Test
{
protected:
    MockContext mContext;
    IndicatorsTree indicators;

    void SetUp() override
    {
        indicators.Push("ExecuteCommandGrep");
    }
};

TEST_F(ExecuteCommandGrepTest, AuditInvalidCommand)
{
    CommandOutputMatchParams params;
    params.command = "invalid command";
    params.pattern = "test";

    auto result = AuditCommandOutputMatch(params, indicators, mContext);
    ASSERT_FALSE(result.HasValue());
    ASSERT_EQ(result.Error().message, "Command invalid command is not allowed");
}

TEST_F(ExecuteCommandGrepTest, AuditCommandFails)
{
    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("iptables -L -n"))).WillOnce(Return(Result<std::string>(Error("Command execution failed", -1))));

    CommandOutputMatchParams params;
    params.command = "iptables -L -n";
    params.pattern = "test";

    auto result = AuditCommandOutputMatch(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(ExecuteCommandGrepTest, AuditCommandMatches)
{
    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("iptables -L -n"))).WillOnce(Return(Result<std::string>("test output")));

    CommandOutputMatchParams params;
    params.command = "iptables -L -n";
    params.pattern = "test";

    auto result = AuditCommandOutputMatch(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(ExecuteCommandGrepTest, AuditDmsetupTableCommand)
{
    EXPECT_CALL(mContext, ExecuteCommand("dmsetup table | grep -P -- \"crypt\" || (echo -n 'No match found'; exit 1)"))
        .WillOnce(Return(Result<std::string>("crypt output")));

    CommandOutputMatchParams params;
    params.command = "dmsetup table";
    params.pattern = "crypt";

    auto result = AuditCommandOutputMatch(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(ExecuteCommandGrepTest, AuditAptConfigDump)
{
    EXPECT_CALL(mContext, ExecuteCommand("apt-config dump | grep -E -- \"^Acquire::Check-Date\" || (echo -n 'No match found'; exit 1)"))
        .WillOnce(Return(Result<std::string>("Acquire::Check-Date \"true\";")));

    CommandOutputMatchParams params;
    params.command = "apt-config dump";
    params.pattern = "^Acquire::Check-Date";
    params.type = RegexType::Extended;

    const auto result = AuditCommandOutputMatch(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(ExecuteCommandGrepTest, AuditUnapprovedAptConfigVariants)
{
    EXPECT_CALL(mContext, ExecuteCommand(::testing::_)).Times(0);
    for (const std::string command : {"apt-config", "apt-config shell value Acquire::Check-Date", "apt-config dump -o Acquire::Check-Date=true",
             "apt-config dump; id", "apt-config dump | id", "apt-config dump\nid"})
    {
        SCOPED_TRACE(command);
        CommandOutputMatchParams params;
        params.command = command;
        params.pattern = ".+";
        const auto result = AuditCommandOutputMatch(params, indicators, mContext);
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ(result.Error().message, "Command " + command + " is not allowed");
    }
}

class ExecuteCommandAptTest : public ExecuteCommandGrepTest
{
protected:
    void SetUp() override
    {
        ExecuteCommandGrepTest::SetUp();
        Kompli::CommonContext context(nullptr, mContext.GetStatePath());
        if (!context.ExecuteCommand("awk -S 'BEGIN { print \"sandbox\" }'").HasValue() || !context.ExecuteCommand("command -v apt-config").HasValue())
        {
            GTEST_SKIP() << "APT pipeline tests require apt-config and GNU awk with sandbox support";
        }
    }

    CommandOutputMatchParams ScalarParams()
    {
        CommandOutputMatchParams params;
        params.command = "apt-config dump";
        params.awk = R"(BEGIN { FS = "\"" } index($0, "Acquire::Check-Date \"") == 1 { print ($2 == "true") ? "PASS" : "FAIL"; found = 1; exit } END { if (!found) print "FAIL" })";
        params.pattern = "^PASS$";
        params.type = RegexType::Extended;
        return params;
    }

    CommandOutputMatchParams WeakDependencyParams()
    {
        CommandOutputMatchParams params;
        params.command = "apt-config dump";
        params.awk = R"(index($0, "APT::Install-Recommends \"0\";") { recommends = 1 } index($0, "APT::Install-Suggests \"0\";") { suggests = 1 } END { print (recommends && suggests) ? "PASS" : "FAIL" })";
        params.pattern = "^PASS$";
        params.type = RegexType::Extended;
        return params;
    }

    void ExpectDumpFixture(const std::string& output)
    {
        const std::string file = mContext.MakeTempfile(output);
        EXPECT_CALL(mContext, ExecuteCommand(::testing::StartsWith("apt-config dump | awk -S "))).WillOnce([this, file](const std::string& command) {
            Kompli::CommonContext context(nullptr, mContext.GetStatePath());
            return context.ExecuteCommand("cat \"" + file + "\"" + command.substr(std::string("apt-config dump").size()));
        });
    }

    void ExpectEffectiveConfig(const std::string& settings)
    {
        const std::string file = mContext.MakeTempfile("Dir::Etc::parts \"-\";\nDir::Etc::main \"-\";\n" + settings);
        EXPECT_CALL(mContext, ExecuteCommand(::testing::StartsWith("apt-config dump | awk -S "))).WillOnce([this, file](const std::string& command) {
            Kompli::CommonContext context(nullptr, mContext.GetStatePath());
            return context.ExecuteCommand("APT_CONFIG=\"" + file + "\" " + command);
        });
    }
};

TEST_F(ExecuteCommandAptTest, ScalarAwkRunsInRealCommandPipeline)
{
    const std::vector<std::pair<std::string, Status>> cases = {
        {"Acquire::Check-Date \"true\";\n", Status::Compliant},
        {"Acquire::Check-Date \"false\";\n", Status::NonCompliant},
        {"Acquire::Check-Date \"True\";\n", Status::NonCompliant},
        {"Acquire::Check-Date \"1\";\n", Status::NonCompliant},
        {"", Status::NonCompliant},
        {"Acquire::Check-DateExtra \"true\";\n", Status::NonCompliant},
        {"Acquire::Check-Date::Child \"true\";\n", Status::NonCompliant},
        {"Other::Acquire::Check-Date \"true\";\n", Status::NonCompliant},
        {"Acquire::Check-Date \"false\";\nAcquire::Check-Date \"true\";\n", Status::NonCompliant},
    };
    for (const auto& testCase : cases)
    {
        SCOPED_TRACE(testCase.first);
        ExpectDumpFixture(testCase.first);
        const auto result = AuditCommandOutputMatch(ScalarParams(), indicators, mContext);
        ASSERT_TRUE(result.HasValue());
        EXPECT_EQ(result.Value(), testCase.second);
    }
}

TEST_F(ExecuteCommandAptTest, WeakDependencyAwkRunsInRealCommandPipeline)
{
    const std::vector<std::pair<std::string, Status>> cases = {
        {"APT::Install-Recommends \"0\";\nAPT::Install-Suggests \"0\";\n", Status::Compliant},
        {"APT::Install-Suggests \"0\";\nAPT::Install-Recommends \"0\";\n", Status::Compliant},
        {"APT::Install-Recommends \"1\";\nAPT::Install-Suggests \"0\";\n", Status::NonCompliant},
        {"APT::Install-Recommends \"0\";\nAPT::Install-Suggests \"1\";\n", Status::NonCompliant},
        {"APT::Install-Recommends \"0\";\n", Status::NonCompliant},
        {"APT::Install-Suggests \"0\";\n", Status::NonCompliant},
        {"APT::Install-Recommends \"false\";\nAPT::Install-Suggests \"false\";\n", Status::NonCompliant},
        {"APT::Install-RecommendsExtra \"0\";\nAPT::Install-Suggests \"0\";\n", Status::NonCompliant},
        {"", Status::NonCompliant},
        {"Other::APT::Install-Recommends \"0\";\nAPT::Install-Suggests \"0\";\n", Status::Compliant},
    };
    for (const auto& testCase : cases)
    {
        SCOPED_TRACE(testCase.first);
        ExpectDumpFixture(testCase.first);
        const auto result = AuditCommandOutputMatch(WeakDependencyParams(), indicators, mContext);
        ASSERT_TRUE(result.HasValue());
        EXPECT_EQ(result.Value(), testCase.second);
    }
}

TEST_F(ExecuteCommandAptTest, ScalarUsesEffectiveAptConfigPrecedence)
{
    for (const auto& testCase : std::vector<std::pair<std::string, Status>>{{"Acquire::Check-Date \"false\";\nAcquire::Check-Date \"true\";\n", Status::Compliant},
             {"Acquire::Check-Date \"true\";\nAcquire::Check-Date \"false\";\n", Status::NonCompliant}, {"", Status::NonCompliant}})
    {
        SCOPED_TRACE(testCase.first);
        ExpectEffectiveConfig(testCase.first);
        const auto result = AuditCommandOutputMatch(ScalarParams(), indicators, mContext);
        ASSERT_TRUE(result.HasValue());
        EXPECT_EQ(result.Value(), testCase.second);
    }
}

TEST_F(ExecuteCommandAptTest, WeakDependenciesUseEffectiveAptConfigPrecedence)
{
    for (const auto& testCase : std::vector<std::pair<std::string, Status>>{
             {"APT::Install-Recommends \"1\";\nAPT::Install-Recommends \"0\";\nAPT::Install-Suggests \"0\";\n", Status::Compliant},
             {"APT::Install-Recommends \"0\";\nAPT::Install-Suggests \"0\";\nAPT::Install-Suggests \"1\";\n", Status::NonCompliant}})
    {
        SCOPED_TRACE(testCase.first);
        ExpectEffectiveConfig(testCase.first);
        const auto result = AuditCommandOutputMatch(WeakDependencyParams(), indicators, mContext);
        ASSERT_TRUE(result.HasValue());
        EXPECT_EQ(result.Value(), testCase.second);
    }
}

TEST_F(ExecuteCommandGrepTest, AuditSudoJournalEntry)
{
    EXPECT_CALL(mContext, ExecuteCommand("journalctl -t sudo --no-pager -q --lines=1 | grep -E -- \".+\" || (echo -n 'No match found'; exit 1)"))
        .WillOnce(Return(Result<std::string>("sudo journal entry")));

    CommandOutputMatchParams params;
    params.command = "journalctl -t sudo --no-pager -q --lines=1";
    params.pattern = ".+";
    params.type = RegexType::Extended;

    auto result = AuditCommandOutputMatch(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(ExecuteCommandGrepTest, AuditMissingSudoJournalEntry)
{
    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("journalctl -t sudo --no-pager -q --lines=1")))
        .WillOnce(Return(Result<std::string>(Error("No match found", 1))));

    CommandOutputMatchParams params;
    params.command = "journalctl -t sudo --no-pager -q --lines=1";
    params.pattern = ".+";
    params.type = RegexType::Extended;

    auto result = AuditCommandOutputMatch(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(ExecuteCommandGrepTest, AuditUnapprovedJournalVariants)
{
    const std::vector<std::string> commands = {
        "journalctl -t other --no-pager -q --lines=1",
        "journalctl -t sudo --no-pager -q --lines=1 --follow",
        "journalctl --rotate",
        "journalctl --vacuum-size=1",
        "journalctl -t sudo --no-pager -q --lines=1; id",
        "journalctl -t sudo --no-pager -q --lines=1 | id",
    };
    EXPECT_CALL(mContext, ExecuteCommand(::testing::_)).Times(0);
    for (const auto& command : commands)
    {
        SCOPED_TRACE(command);
        CommandOutputMatchParams params;
        params.command = command;
        params.pattern = ".+";
        auto result = AuditCommandOutputMatch(params, indicators, mContext);
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ(result.Error().message, "Command " + command + " is not allowed");
    }
}

TEST_F(ExecuteCommandGrepTest, AuditExtendedRegex)
{
    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("iptables -L -n"))).WillOnce(Return(Result<std::string>("test output")));

    CommandOutputMatchParams params;
    params.command = "iptables -L -n";
    params.pattern = "test";
    params.type = RegexType::Extended;

    auto result = AuditCommandOutputMatch(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(ExecuteCommandGrepTest, AuditWithAwkTransformation)
{
    EXPECT_CALL(mContext,
        ExecuteCommand(::testing::HasSubstr("iptables -L -n | awk -S \"{print \\$1}\"  | grep -P -- \"test\" || (echo -n 'No match found'; exit 1)")))
        .WillOnce(Return(Result<std::string>("test output")));

    CommandOutputMatchParams params;
    params.command = "iptables -L -n";
    params.awk = "{print $1}";
    params.pattern = "test";

    auto result = AuditCommandOutputMatch(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(ExecuteCommandGrepTest, AuditWithAwkAndExtendedRegex)
{
    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr(
                              "iptables -L -n | awk -S \"{print \\$2}\"  | grep -E -- \"test.*pattern\" || (echo -n 'No match found'; exit 1)")))
        .WillOnce(Return(Result<std::string>("test matched pattern")));

    CommandOutputMatchParams params;
    params.command = "iptables -L -n";
    params.awk = "{print $2}";
    params.pattern = "test.*pattern";
    params.type = RegexType::Extended;

    auto result = AuditCommandOutputMatch(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(ExecuteCommandGrepTest, AuditWithAwkSpecialCharactersEscaping)
{
    // Test that special characters in awk command are properly escaped
    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr(
                              "iptables -L -n | awk -S \"/^Chain/ {print \\$2}\"  | grep -P -- \"INPUT\" || (echo -n 'No match found'; exit 1)")))
        .WillOnce(Return(Result<std::string>("INPUT")));

    CommandOutputMatchParams params;
    params.command = "iptables -L -n";
    params.awk = "/^Chain/ {print $2}";
    params.pattern = "INPUT";

    auto result = AuditCommandOutputMatch(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(ExecuteCommandGrepTest, AuditWithAwkComplexTransformation)
{
    EXPECT_CALL(mContext,
        ExecuteCommand(::testing::HasSubstr("uname | awk -S \"BEGIN{FS=\\\"\\\\n\\\"} {gsub(/\\\\s+/, \\\"\\\", \\$1); print \\$1}\"  | "
                                            "grep -P -- \"Linux\" || (echo -n 'No match found'; exit 1)")))
        .WillOnce(Return(Result<std::string>("Linux")));

    CommandOutputMatchParams params;
    params.command = "uname";
    params.awk = "BEGIN{FS=\"\\n\"} {gsub(/\\s+/, \"\", $1); print $1}";
    params.pattern = "Linux";

    auto result = AuditCommandOutputMatch(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(ExecuteCommandGrepTest, AuditWithEmptyAwkParameter)
{
    // Test that empty awk parameter is handled correctly (should not add awk to pipeline)
    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("iptables -L -n | grep -P -- \"test\" || (echo -n 'No match found'; exit 1)")))
        .WillOnce(Return(Result<std::string>("test output")));

    CommandOutputMatchParams params;
    params.command = "iptables -L -n";
    params.awk = "";
    params.pattern = "test";

    auto result = AuditCommandOutputMatch(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(ExecuteCommandGrepTest, AuditWithAwkFailsAtGrep)
{
    // Test that when awk transforms output and grep doesn't match, it returns NonCompliant
    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr(
                              "iptables -L -n | awk -S \"{print \\$3}\"  | grep -P -- \"nonexistent\" || (echo -n 'No match found'; exit 1)")))
        .WillOnce(Return(Result<std::string>(Error("Command execution failed", 1))));

    CommandOutputMatchParams params;
    params.command = "iptables -L -n";
    params.awk = "{print $3}";
    params.pattern = "nonexistent";

    auto result = AuditCommandOutputMatch(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}
