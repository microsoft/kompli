// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "CommonContext.h"
#include "JsonWrapper.h"
#include "MockContext.h"

#include <CommandOutputMatch.h>
#include <cerrno>
#include <gtest/gtest.h>
#include <string>
#include <vector>

using ComplianceEngine::AuditCommandOutputMatch;
using ComplianceEngine::CommandOutputMatchParams;
using ComplianceEngine::Error;
using ComplianceEngine::IndicatorsTree;
using ComplianceEngine::RegexType;
using ComplianceEngine::Result;
using ComplianceEngine::Status;
using ::testing::_;
using ::testing::AllOf;
using ::testing::EndsWith;
using ::testing::HasSubstr;
using ::testing::InSequence;
using ::testing::Return;
using ::testing::StartsWith;

class ExecuteCommandGrepTest : public ::testing::Test
{
protected:
    ::testing::StrictMock<MockContext> mContext;
    IndicatorsTree indicators;
    ComplianceEngine::ParameterMap mParameters;

    void SetUp() override
    {
        indicators.Push("ExecuteCommandGrep");
    }

    void ExpectCollection(const std::string& command)
    {
        EXPECT_CALL(mContext, ExecuteCommand(AllOf(StartsWith(command + " > \""), EndsWith("/output\"")))).WillOnce(Return(Result<std::string>(std::string())));
    }

    void ExpectMatch(const std::string& arguments, bool match = true, const std::string& filename = "output")
    {
        EXPECT_CALL(mContext, ExecuteCommand(AllOf(StartsWith("grep " + arguments + " \""), EndsWith("/" + filename + "\""))))
            .WillOnce([match](const std::string&) -> Result<std::string> {
                if (!match)
                {
                    return Error("", 1);
                }
                return std::string("matched output\n");
            });
    }

    void UseRealShell(const std::string& outputCommand)
    {
        ON_CALL(mContext, ExecuteCommand(_)).WillByDefault([this, outputCommand](const std::string& command) {
            ComplianceEngine::CommonContext context(nullptr, mContext.GetStatePath());
            if (0 == command.find("getenforce > "))
            {
                return context.ExecuteCommand("(" + outputCommand + ")" + command.substr(std::string("getenforce").size()));
            }
            return context.ExecuteCommand(command);
        });
    }
};

TEST_F(ExecuteCommandGrepTest, AuditInvalidCommand)
{
    CommandOutputMatchParams params;
    params.command = "invalid command";
    params.pattern = "test";

    const auto result = AuditCommandOutputMatch(params, indicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().message, "Command invalid command is not allowed");
}

TEST_F(ExecuteCommandGrepTest, AuditCommandFailuresRemainErrors)
{
    for (const int code : {1, 2, 126, 127})
    {
        SCOPED_TRACE(code);
        EXPECT_CALL(mContext, ExecuteCommand(StartsWith("getenforce > \""))).WillOnce(Return(Result<std::string>(Error("collection failed", code))));

        CommandOutputMatchParams params;
        params.command = "getenforce";
        params.pattern = "Enforcing";

        const auto result = AuditCommandOutputMatch(params, indicators, mContext);
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ(result.Error().code, code);
        EXPECT_EQ(result.Error().message, "Failed to execute command 'getenforce': collection failed");
    }
}

TEST_F(ExecuteCommandGrepTest, AuditGetenforceMatches)
{
    InSequence sequence;
    ExpectCollection("getenforce");
    ExpectMatch("-P -- \"Enforcing\"");

    CommandOutputMatchParams params;
    params.command = "getenforce";
    params.pattern = "Enforcing";

    const auto result = AuditCommandOutputMatch(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(ExecuteCommandGrepTest, AuditGetenforceDoesNotMatch)
{
    InSequence sequence;
    ExpectCollection("getenforce");
    ExpectMatch("-P -- \"Enforcing\"", false);

    CommandOutputMatchParams params;
    params.command = "getenforce";
    params.pattern = "Enforcing";

    const auto result = AuditCommandOutputMatch(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(ExecuteCommandGrepTest, AuditDmsetupTableCommand)
{
    InSequence sequence;
    ExpectCollection("dmsetup table");
    ExpectMatch("-P -- \"crypt\"");

    CommandOutputMatchParams params;
    params.command = "dmsetup table";
    params.pattern = "crypt";

    const auto result = AuditCommandOutputMatch(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(ExecuteCommandGrepTest, AuditRegexModesPreserveGrepArguments)
{
    const std::vector<std::pair<RegexType, std::string>> modes = {
        {RegexType::Perl, "P"}, {RegexType::Extended, "E"}, {RegexType::PerlInverted, "Pv"}, {RegexType::ExtendedInverted, "Ev"}};
    for (const auto& mode : modes)
    {
        SCOPED_TRACE(mode.second);
        InSequence sequence;
        ExpectCollection("iptables -L -n");
        ExpectMatch("-" + mode.second + " -- \"test\"");

        CommandOutputMatchParams params;
        params.command = "iptables -L -n";
        params.pattern = "test";
        params.type = mode.first;

        const auto result = AuditCommandOutputMatch(params, indicators, mContext);
        ASSERT_TRUE(result.HasValue());
        EXPECT_EQ(result.Value(), Status::Compliant);
    }
}

TEST_F(ExecuteCommandGrepTest, AuditWithAwkTransformation)
{
    InSequence sequence;
    ExpectCollection("iptables -L -n");
    EXPECT_CALL(mContext, ExecuteCommand(AllOf(StartsWith("awk -S \"{print \\$1}\" \""), HasSubstr("/output\" > \""), EndsWith("/transformed\""))))
        .WillOnce(Return(Result<std::string>(std::string())));
    ExpectMatch("-P -- \"test\"", true, "transformed");

    CommandOutputMatchParams params;
    params.command = "iptables -L -n";
    params.awk = "{print $1}";
    params.pattern = "test";

    const auto result = AuditCommandOutputMatch(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(ExecuteCommandGrepTest, AuditWithAwkAndExtendedRegex)
{
    InSequence sequence;
    ExpectCollection("iptables -L -n");
    EXPECT_CALL(mContext, ExecuteCommand(AllOf(StartsWith("awk -S \"{print \\$2}\" \""), EndsWith("/transformed\"")))).WillOnce(Return(Result<std::string>(std::string())));
    ExpectMatch("-E -- \"test.*pattern\"", true, "transformed");

    CommandOutputMatchParams params;
    params.command = "iptables -L -n";
    params.awk = "{print $2}";
    params.pattern = "test.*pattern";
    params.type = RegexType::Extended;

    const auto result = AuditCommandOutputMatch(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(ExecuteCommandGrepTest, AuditWithAwkComplexTransformationEscaping)
{
    InSequence sequence;
    ExpectCollection("uname");
    EXPECT_CALL(mContext, ExecuteCommand(AllOf(StartsWith("awk -S \"BEGIN{FS=\\\"\\\\n\\\"} {gsub(/\\\\s+/, \\\"\\\", \\$1); print \\$1}\" \""),
                              EndsWith("/transformed\""))))
        .WillOnce(Return(Result<std::string>(std::string())));
    ExpectMatch("-P -- \"Linux\"", true, "transformed");

    CommandOutputMatchParams params;
    params.command = "uname";
    params.awk = "BEGIN{FS=\"\\n\"} {gsub(/\\s+/, \"\", $1); print $1}";
    params.pattern = "Linux";

    const auto result = AuditCommandOutputMatch(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(ExecuteCommandGrepTest, AuditWithEmptyAwkParameter)
{
    InSequence sequence;
    ExpectCollection("iptables -L -n");
    ExpectMatch("-P -- \"test\"");

    CommandOutputMatchParams params;
    params.command = "iptables -L -n";
    params.awk = "";
    params.pattern = "test";

    const auto result = AuditCommandOutputMatch(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(ExecuteCommandGrepTest, AuditAwkFailureIsNotANoMatch)
{
    for (const int code : {1, 2, 127})
    {
        SCOPED_TRACE(code);
        InSequence sequence;
        ExpectCollection("grubby --info=ALL");
        EXPECT_CALL(mContext, ExecuteCommand(StartsWith("awk -S "))).WillOnce(Return(Result<std::string>(Error("awk failed", code))));

        CommandOutputMatchParams params;
        params.command = "grubby --info=ALL";
        params.awk = "/^args=/";
        params.pattern = "audit=1";

        const auto result = AuditCommandOutputMatch(params, indicators, mContext);
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ(result.Error().code, code);
        EXPECT_EQ(result.Error().message, "Failed to transform output of command 'grubby --info=ALL': awk failed");
    }
}

TEST_F(ExecuteCommandGrepTest, AuditWithAwkNoMatchIsNonCompliant)
{
    InSequence sequence;
    ExpectCollection("grubby --info=ALL");
    EXPECT_CALL(mContext, ExecuteCommand(StartsWith("awk -S "))).WillOnce(Return(Result<std::string>(std::string())));
    ExpectMatch("-P -- \"audit=1\"", false, "transformed");

    CommandOutputMatchParams params;
    params.command = "grubby --info=ALL";
    params.awk = "/^args=/";
    params.pattern = "audit=1";

    const auto result = AuditCommandOutputMatch(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(ExecuteCommandGrepTest, AuditGrepErrorsRemainErrors)
{
    for (const int code : {2, 126, 127})
    {
        SCOPED_TRACE(code);
        InSequence sequence;
        ExpectCollection("getenforce");
        EXPECT_CALL(mContext, ExecuteCommand(StartsWith("grep -P "))).WillOnce(Return(Result<std::string>(Error("grep failed", code))));

        CommandOutputMatchParams params;
        params.command = "getenforce";
        params.pattern = "[";

        const auto result = AuditCommandOutputMatch(params, indicators, mContext);
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ(result.Error().code, code);
        EXPECT_EQ(result.Error().message, "Failed to match output of command 'getenforce': grep failed");
    }
}

TEST_F(ExecuteCommandGrepTest, NegatedCollectionFailureRemainsAnError)
{
    EXPECT_CALL(mContext, ExecuteCommand(StartsWith("getenforce > \""))).WillOnce(Return(Result<std::string>(Error("missing getenforce", 127))));
    auto json = ComplianceEngine::JsonWrapper::FromString(R"({"not":{"CommandOutputMatch":{"command":"getenforce","pattern":"Disabled"}}})");
    ASSERT_TRUE(json.HasValue());
    ComplianceEngine::Evaluator evaluator("test", json_value_get_object(json->get()), mParameters, mContext);
    ComplianceEngine::DebugFormatter formatter;

    const auto result = evaluator.ExecuteAudit(formatter);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, 127);
}

TEST_F(ExecuteCommandGrepTest, NegatedValidNoMatchIsCompliant)
{
    InSequence sequence;
    ExpectCollection("getenforce");
    ExpectMatch("-P -- \"Disabled\"", false);
    auto json = ComplianceEngine::JsonWrapper::FromString(R"({"not":{"CommandOutputMatch":{"command":"getenforce","pattern":"Disabled"}}})");
    ASSERT_TRUE(json.HasValue());
    ComplianceEngine::Evaluator evaluator("test", json_value_get_object(json->get()), mParameters, mContext);
    ComplianceEngine::DebugFormatter formatter;

    const auto result = evaluator.ExecuteAudit(formatter);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value().status, Status::Compliant);
}

TEST_F(ExecuteCommandGrepTest, RealShellPreservesMatchingAndLineInversion)
{
    UseRealShell("printf '%s\\n' Enforcing Permissive");
    EXPECT_CALL(mContext, ExecuteCommand(_)).Times(::testing::AnyNumber());
    for (const auto type : {RegexType::Perl, RegexType::Extended, RegexType::PerlInverted, RegexType::ExtendedInverted})
    {
        CommandOutputMatchParams params;
        params.command = "getenforce";
        params.pattern = "^Enforcing$";
        params.type = type;
        const auto result = AuditCommandOutputMatch(params, indicators, mContext);
        ASSERT_TRUE(result.HasValue());
        EXPECT_EQ(result.Value(), Status::Compliant);
    }
}

TEST_F(ExecuteCommandGrepTest, RealShellNoMatchIsNonCompliant)
{
    UseRealShell("printf '%s\\n' Permissive");
    EXPECT_CALL(mContext, ExecuteCommand(_)).Times(2);
    CommandOutputMatchParams params;
    params.command = "getenforce";
    params.pattern = "^Enforcing$";

    const auto result = AuditCommandOutputMatch(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(ExecuteCommandGrepTest, RealShellEmptyOutputIsNotAnInvertedMatch)
{
    UseRealShell("true");
    EXPECT_CALL(mContext, ExecuteCommand(_)).Times(2);
    CommandOutputMatchParams params;
    params.command = "getenforce";
    params.pattern = "Enforcing";
    params.type = RegexType::PerlInverted;

    const auto result = AuditCommandOutputMatch(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(ExecuteCommandGrepTest, RealShellFailureCannotBeHiddenByMatchingOutput)
{
    UseRealShell("printf '%s\\n' Enforcing; exit 1");
    EXPECT_CALL(mContext, ExecuteCommand(_)).Times(1);
    CommandOutputMatchParams params;
    params.command = "getenforce";
    params.pattern = "Enforcing";

    const auto result = AuditCommandOutputMatch(params, indicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, 1);
}

TEST_F(ExecuteCommandGrepTest, RealShellStderrCannotSatisfyPattern)
{
    UseRealShell("printf '%s\\n' Enforcing >&2; printf '%s\\n' Permissive");
    EXPECT_CALL(mContext, ExecuteCommand(_)).Times(2);
    CommandOutputMatchParams params;
    params.command = "getenforce";
    params.pattern = "^Enforcing$";

    const auto result = AuditCommandOutputMatch(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(ExecuteCommandGrepTest, RealShellInvalidRegexIsAnError)
{
    UseRealShell("printf '%s\\n' Enforcing");
    EXPECT_CALL(mContext, ExecuteCommand(_)).Times(2);
    CommandOutputMatchParams params;
    params.command = "getenforce";
    params.pattern = "[";

    const auto result = AuditCommandOutputMatch(params, indicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, 2);
}

TEST_F(ExecuteCommandGrepTest, RealShellQuotesPatternWithoutExecutingIt)
{
    UseRealShell("printf '%s\\n' '$(false)'");
    EXPECT_CALL(mContext, ExecuteCommand(_)).Times(2);
    CommandOutputMatchParams params;
    params.command = "getenforce";
    params.pattern = R"(^\$\(false\)$)";
    params.type = RegexType::Extended;

    const auto result = AuditCommandOutputMatch(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}
