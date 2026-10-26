// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "CommonUtils.h"
#include "MockContext.h"

#include <SshdOption.h>
#include <cerrno>
#include <gtest/gtest.h>
#include <string>

using ComplianceEngine::AuditSshdOption;
using ComplianceEngine::CompactListFormatter;
using ComplianceEngine::Error;
using ComplianceEngine::IndicatorsTree;
using ComplianceEngine::Optional;
using ComplianceEngine::Result;
using ComplianceEngine::Separated;
using ComplianceEngine::SshdOptionMode;
using ComplianceEngine::SshdOptionOperation;
using ComplianceEngine::SshdOptionParams;
using ComplianceEngine::Status;
using ::testing::Return;

static const char sshdInitialCommand[] = "sshd -T 2>&1";
static const char hostnameCommand[] = "hostname";
static const char hostAddressCommand[] = "hostname -I | cut -d ' ' -f1";
static const char sshdSimpleCommand[] = "sshd -T";
static const char sshdComplexCommand[] = "sshd -T -C user=root -C host=testhost -C addr=1.2.3.4";
static const char sshdSpecialOptionsOutput[] =
    "port 22\n"
    "maxstartups 10:30:60\n"
    "rekeylimit 10 123\n";

static const char sshdWithoutMatchGroupOutput[] =
    "port 22\n"
    "addressfamily any\n"
    "listenaddress 0.0.0.0\n"
    "permitrootlogin no\n"
    "maxauthtries 4\n"
    "pubkeyauthentication yes\n"
    "passwordauthentication no\n"
    "permitemptypasswords no\n"
    "kbdinteractiveauthentication no\n"
    "usepam yes\n"
    "x11forwarding no\n"
    "permituserpam no\n";

static const char sshdWithMatchGroupOutput[] =
    "port 22\n"
    "addressfamily any\n"
    "listenaddress 0.0.0.0\n"
    "match group admins\n"
    "permitrootlogin no\n"
    "maxauthtries 4\n"
    "pubkeyauthentication yes\n"
    "passwordauthentication no\n"
    "permitemptypasswords no\n"
    "kbdinteractiveauthentication no\n"
    "usepam yes\n"
    "x11forwarding no\n"
    "permituserpam no\n";

class EnsureSshdOptionTest : public ::testing::Test
{
protected:
    MockContext mContext;
    IndicatorsTree mIndicators;
    CompactListFormatter mFormatter;

    void SetUp() override
    {
        mIndicators.Push("EnsureSshdOption");
    }
};

TEST_F(EnsureSshdOptionTest, InitialCommandFails)
{
    EXPECT_CALL(mContext, ExecuteCommand(sshdInitialCommand)).WillOnce(Return(Result<std::string>(Error("Command failed", -1))));

    SshdOptionParams params;
    params.option = {{"permitrootlogin"}};
    params.value = "no";

    auto result = AuditSshdOption(params, mIndicators, mContext);
    // A failure to run sshd -T is an evaluation error, not a compliance verdict.
    ASSERT_FALSE(result.HasValue());
    ASSERT_TRUE(result.Error().message.find("Failed to execute sshd") != std::string::npos);
}

TEST_F(EnsureSshdOptionTest, SimpleConfigOptionExists)
{
    EXPECT_CALL(mContext, ExecuteCommand(sshdInitialCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));

    EXPECT_CALL(mContext, ExecuteCommand(sshdSimpleCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));

    SshdOptionParams params;
    params.option = {{"permitrootlogin"}};
    params.value = "no";

    auto result = AuditSshdOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
    ASSERT_TRUE(mFormatter.Format(mIndicators).Value().find("[Compliant]") != std::string::npos);
    ASSERT_TRUE(mFormatter.Format(mIndicators).Value().find("Option 'permitrootlogin' has a compliant value 'no'") != std::string::npos);
}

TEST_F(EnsureSshdOptionTest, SimpleConfigOptionMismatch)
{
    EXPECT_CALL(mContext, ExecuteCommand(sshdInitialCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));

    EXPECT_CALL(mContext, ExecuteCommand(sshdSimpleCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));

    SshdOptionParams params;
    params.option = {{"permitrootlogin"}};
    params.value = "yes";

    auto result = AuditSshdOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
    ASSERT_TRUE(mFormatter.Format(mIndicators).Value().find("[NonCompliant]") != std::string::npos);
    ASSERT_TRUE(mFormatter.Format(mIndicators).Value().find("which does not match required pattern") != std::string::npos);
}

TEST_F(EnsureSshdOptionTest, ConfigOptionNotFound)
{
    EXPECT_CALL(mContext, ExecuteCommand(sshdInitialCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));

    EXPECT_CALL(mContext, ExecuteCommand(sshdSimpleCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));

    SshdOptionParams params;
    params.option = {{"nonexistentoption"}};
    params.value = ".*";

    auto result = AuditSshdOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
    ASSERT_TRUE(mFormatter.Format(mIndicators).Value().find("Option 'nonexistentoption' not found") != std::string::npos);
}

TEST_F(EnsureSshdOptionTest, CommandFailure)
{
    EXPECT_CALL(mContext, ExecuteCommand(sshdInitialCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));

    EXPECT_CALL(mContext, ExecuteCommand(sshdSimpleCommand)).WillOnce(Return(Result<std::string>(Error("Command execution failed", -1))));
    SshdOptionParams params;
    params.option = {{"permitrootlogin"}};
    params.value = "no";

    auto result = AuditSshdOption(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    ASSERT_TRUE(result.Error().message.find("Failed to get sshd options:") != std::string::npos);
    ASSERT_TRUE(result.Error().message.find("Failed to execute sshd -T") != std::string::npos);
}

TEST_F(EnsureSshdOptionTest, WithMatchGroupConfig)
{
    EXPECT_CALL(mContext, ExecuteCommand(sshdInitialCommand)).WillOnce(Return(Result<std::string>(sshdWithMatchGroupOutput)));

    EXPECT_CALL(mContext, ExecuteCommand(hostnameCommand)).WillOnce(Return(Result<std::string>("testhost\n")));

    EXPECT_CALL(mContext, ExecuteCommand(hostAddressCommand)).WillOnce(Return(Result<std::string>("1.2.3.4\n")));

    EXPECT_CALL(mContext, ExecuteCommand(sshdComplexCommand)).WillOnce(Return(Result<std::string>(sshdWithMatchGroupOutput)));

    SshdOptionParams params;
    params.option = {{"permitrootlogin"}};
    params.value = "no";

    auto result = AuditSshdOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureSshdOptionTest, HostnameCommandFailure)
{
    EXPECT_CALL(mContext, ExecuteCommand(sshdInitialCommand)).WillOnce(Return(Result<std::string>(sshdWithMatchGroupOutput)));

    EXPECT_CALL(mContext, ExecuteCommand(hostnameCommand)).WillOnce(Return(Result<std::string>(Error("Hostname command failed", -1))));

    SshdOptionParams params;
    params.option = {{"permitrootlogin"}};
    params.value = "no";

    auto result = AuditSshdOption(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    ASSERT_TRUE(result.Error().message.find("Failed to get sshd options:") != std::string::npos);
    ASSERT_TRUE(result.Error().message.find("Failed to execute hostname command") != std::string::npos);
}

TEST_F(EnsureSshdOptionTest, HostAddressCommandFailure)
{
    EXPECT_CALL(mContext, ExecuteCommand(sshdInitialCommand)).WillOnce(Return(Result<std::string>(sshdWithMatchGroupOutput)));

    EXPECT_CALL(mContext, ExecuteCommand(hostnameCommand)).WillOnce(Return(Result<std::string>("testhost\n")));

    EXPECT_CALL(mContext, ExecuteCommand(hostAddressCommand)).WillOnce(Return(Result<std::string>(Error("Host address command failed", -1))));

    SshdOptionParams params;
    params.option = {{"permitrootlogin"}};
    params.value = "no";

    auto result = AuditSshdOption(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    ASSERT_TRUE(result.Error().message.find("Failed to get sshd options:") != std::string::npos);
    ASSERT_TRUE(result.Error().message.find("Failed to get host address") != std::string::npos);
}

TEST_F(EnsureSshdOptionTest, RegexMatches)
{
    EXPECT_CALL(mContext, ExecuteCommand(sshdInitialCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));

    EXPECT_CALL(mContext, ExecuteCommand(sshdSimpleCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));

    SshdOptionParams params;
    params.option = {{"maxauthtries"}};
    params.value = "[1-4]";

    auto result = AuditSshdOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureSshdOptionTest, RegexDoesNotMatch)
{
    EXPECT_CALL(mContext, ExecuteCommand(sshdInitialCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));

    EXPECT_CALL(mContext, ExecuteCommand(sshdSimpleCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));

    SshdOptionParams params;
    params.option = {{"maxauthtries"}};
    params.value = "[5-9]";

    auto result = AuditSshdOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureSshdOptionTest, ComplexRegexMatches)
{
    EXPECT_CALL(mContext, ExecuteCommand(sshdInitialCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));

    EXPECT_CALL(mContext, ExecuteCommand(sshdSimpleCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));

    SshdOptionParams params;
    params.option = {{"permitrootlogin"}};
    params.value = "^(no|prohibit-password)$";

    auto result = AuditSshdOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureSshdOptionTest, RegexWordBoundaryMatchesCompleteValue)
{
    EXPECT_CALL(mContext, ExecuteCommand(sshdInitialCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));

    EXPECT_CALL(mContext, ExecuteCommand(sshdSimpleCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));

    SshdOptionParams params;
    params.option = {{"permitrootlogin"}};
    params.value = "no\\b";

    auto result = AuditSshdOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureSshdOptionTest, OperationNotMatch_Compliant)
{
    EXPECT_CALL(mContext, ExecuteCommand(sshdInitialCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));
    EXPECT_CALL(mContext, ExecuteCommand(sshdSimpleCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));

    SshdOptionParams params;
    params.option = {{"permitrootlogin"}};
    params.value = "yes"; // forbidden
    params.op = SshdOptionOperation::NotMatch;

    auto result = AuditSshdOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureSshdOptionTest, OperationNotMatch_NonCompliant)
{
    EXPECT_CALL(mContext, ExecuteCommand(sshdInitialCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));
    EXPECT_CALL(mContext, ExecuteCommand(sshdSimpleCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));

    SshdOptionParams params;
    params.option = {{"permitrootlogin"}};
    params.value = "no"; // actual value matches forbidden pattern
    params.op = SshdOptionOperation::NotMatch;

    auto result = AuditSshdOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureSshdOptionTest, OperationNotMatch_MissingOptionIsCompliant)
{
    EXPECT_CALL(mContext, ExecuteCommand(sshdInitialCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));
    EXPECT_CALL(mContext, ExecuteCommand(sshdSimpleCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));

    SshdOptionParams params;
    params.option = {{"nonexistentoption"}}; // ensure not present
    params.value = "forbidden";              // arbitrary pattern
    params.op = SshdOptionOperation::NotMatch;

    auto result = AuditSshdOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
    auto formatted = mFormatter.Format(mIndicators).Value();
    // Current implementation returns generic missing option message without special suffix
    ASSERT_TRUE(formatted.find("Option 'nonexistentoption' not found") != std::string::npos);
}

TEST_F(EnsureSshdOptionTest, OperationNumericLt_Compliant)
{
    EXPECT_CALL(mContext, ExecuteCommand(sshdInitialCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));
    EXPECT_CALL(mContext, ExecuteCommand(sshdSimpleCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));

    SshdOptionParams params;
    params.option = {{"maxauthtries"}}; // value 4
    params.value = "5";
    params.op = SshdOptionOperation::LessThan;

    auto result = AuditSshdOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureSshdOptionTest, OperationNumericLt_NonCompliant)
{
    EXPECT_CALL(mContext, ExecuteCommand(sshdInitialCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));
    EXPECT_CALL(mContext, ExecuteCommand(sshdSimpleCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));

    SshdOptionParams params;
    params.option = {{"maxauthtries"}}; // value 4
    params.value = "3";
    params.op = SshdOptionOperation::LessThan;

    auto result = AuditSshdOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureSshdOptionTest, OperationNumericGe_Compliant)
{
    EXPECT_CALL(mContext, ExecuteCommand(sshdInitialCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));
    EXPECT_CALL(mContext, ExecuteCommand(sshdSimpleCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));

    SshdOptionParams params;
    params.option = {{"maxauthtries"}}; // value 4
    params.value = "4";
    params.op = SshdOptionOperation::GreaterOrEqual;

    auto result = AuditSshdOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureSshdOptionTest, OperationNumericGe_NonCompliant)
{
    EXPECT_CALL(mContext, ExecuteCommand(sshdInitialCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));
    EXPECT_CALL(mContext, ExecuteCommand(sshdSimpleCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));

    SshdOptionParams params;
    params.option = {{"maxauthtries"}}; // value 4
    params.value = "5";
    params.op = SshdOptionOperation::GreaterOrEqual;

    auto result = AuditSshdOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureSshdOptionTest, NumericOperationRejectsSuffixButTrimsOutputWhitespace)
{
    struct Case
    {
        std::string actual;
        std::string expected;
        Status status;
        std::string message;
    };
    const Case cases[] = {
        {"4junk", "5", Status::NonCompliant,
            "Option 'maxauthtries' has non-numeric value '4junk' or comparison target '5' (cannot apply numeric operation 'lt')"},
        {"4", "5junk", Status::NonCompliant,
            "Option 'maxauthtries' has non-numeric value '4' or comparison target '5junk' (cannot apply numeric operation 'lt')"},
        {"4  \t", "5", Status::Compliant, "Option 'maxauthtries' has a compliant numeric value '4' (less than '5')"},
    };
    for (const auto& test : cases)
    {
        const auto output = "port 22\nmaxauthtries " + test.actual + "\n";
        EXPECT_CALL(mContext, ExecuteCommand(sshdInitialCommand)).WillOnce(Return(Result<std::string>(output)));
        EXPECT_CALL(mContext, ExecuteCommand(sshdSimpleCommand)).WillOnce(Return(Result<std::string>(output)));
        SshdOptionParams params;
        params.option = {{"maxauthtries"}};
        params.value = test.expected;
        params.op = SshdOptionOperation::LessThan;
        IndicatorsTree indicators;
        indicators.Push("EnsureSshdOption");
        const auto result = AuditSshdOption(params, indicators, mContext);
        ASSERT_TRUE(result.HasValue()) << test.actual;
        EXPECT_EQ(result.Value(), test.status) << test.actual;
        ASSERT_FALSE(indicators.Back().indicators.empty());
        EXPECT_EQ(indicators.Back().indicators.front().status, test.status);
        EXPECT_EQ(indicators.Back().indicators.front().message, test.message);
    }
}

TEST_F(EnsureSshdOptionTest, NumericOperatorBoundariesAndIndicators)
{
    struct Case
    {
        std::string actual;
        std::string expected;
        SshdOptionOperation operation;
        Status status;
        std::string expectation;
    };
    const Case cases[] = {
        {"4", "4", SshdOptionOperation::LessThan, Status::NonCompliant, "less than"},
        {"4", "4", SshdOptionOperation::LessOrEqual, Status::Compliant, "less than or equal to"},
        {"4", "4", SshdOptionOperation::GreaterThan, Status::NonCompliant, "greater than"},
        {"4", "4", SshdOptionOperation::GreaterOrEqual, Status::Compliant, "greater than or equal to"},
        {"3", "4", SshdOptionOperation::LessThan, Status::Compliant, "less than"},
        {"5", "4", SshdOptionOperation::GreaterThan, Status::Compliant, "greater than"},
        {"-2147483648", "-2147483647", SshdOptionOperation::LessThan, Status::Compliant, "less than"},
        {"2147483647", "2147483646", SshdOptionOperation::GreaterThan, Status::Compliant, "greater than"},
    };
    for (const auto& test : cases)
    {
        const std::string output = "port 22\nmaxauthtries " + test.actual + "\n";
        EXPECT_CALL(mContext, ExecuteCommand(sshdInitialCommand)).WillOnce(Return(Result<std::string>(output)));
        EXPECT_CALL(mContext, ExecuteCommand(sshdSimpleCommand)).WillOnce(Return(Result<std::string>(output)));
        SshdOptionParams params;
        params.option = {{"maxauthtries"}};
        params.value = test.expected;
        params.op = test.operation;
        IndicatorsTree indicators;
        indicators.Push("EnsureSshdOption");
        auto result = AuditSshdOption(params, indicators, mContext);
        ASSERT_TRUE(result.HasValue()) << test.actual;
        EXPECT_EQ(result.Value(), test.status) << test.actual;
        ASSERT_EQ(indicators.Back().indicators.size(), test.status == Status::Compliant ? 2U : 1U);
        const auto& indicator = indicators.Back().indicators.front();
        EXPECT_EQ(indicator.status, test.status);
        EXPECT_EQ(indicator.message,
            test.status == Status::Compliant ?
                "Option 'maxauthtries' has a compliant numeric value '" + test.actual + "' (" + test.expectation + " '" + test.expected + "')" :
                "Option 'maxauthtries' has numeric value '" + test.actual + "' which is not " + test.expectation + " '" + test.expected + "'");
        if (test.status == Status::Compliant)
        {
            EXPECT_EQ(indicators.Back().indicators.back().message, "All options are compliant");
        }
    }
}

TEST_F(EnsureSshdOptionTest, NumericOperationKeepsMissingAndInvalidValuePolicies)
{
    SshdOptionParams params;
    params.option = {{"missingoption"}};
    params.value = "4";
    params.op = SshdOptionOperation::LessOrEqual;
    EXPECT_CALL(mContext, ExecuteCommand(sshdInitialCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));
    EXPECT_CALL(mContext, ExecuteCommand(sshdSimpleCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));
    IndicatorsTree missing;
    missing.Push("EnsureSshdOption");
    auto result = AuditSshdOption(params, missing, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
    ASSERT_EQ(missing.Back().indicators.size(), 1U);
    EXPECT_EQ(missing.Back().indicators.front().message, "Option 'missingoption' not found in SSH daemon configuration");

    params.option = {{"maxauthtries"}};
    params.value = "not-a-number";
    params.op = SshdOptionOperation::GreaterThan;
    EXPECT_CALL(mContext, ExecuteCommand(sshdInitialCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));
    EXPECT_CALL(mContext, ExecuteCommand(sshdSimpleCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));
    IndicatorsTree invalid;
    invalid.Push("EnsureSshdOption");
    result = AuditSshdOption(params, invalid, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
    ASSERT_EQ(invalid.Back().indicators.size(), 1U);
    EXPECT_EQ(invalid.Back().indicators.front().message,
        "Option 'maxauthtries' has non-numeric value '4' or comparison target 'not-a-number' (cannot apply numeric operation 'gt')");
}

TEST_F(EnsureSshdOptionTest, MaxStartups_Compliant)
{
    EXPECT_CALL(mContext, ExecuteCommand(sshdInitialCommand)).WillOnce(Return(Result<std::string>(sshdSpecialOptionsOutput)));
    EXPECT_CALL(mContext, ExecuteCommand(sshdSimpleCommand)).WillOnce(Return(Result<std::string>(sshdSpecialOptionsOutput)));

    SshdOptionParams params;
    params.option = {{"maxstartups"}}; // special case
    params.op = SshdOptionOperation::Match;
    // Provide thresholds higher than actual values (10 30 60)
    params.value = "15:40:70";

    auto result = AuditSshdOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
    auto formatted = mFormatter.Format(mIndicators).Value();
    ASSERT_TRUE(formatted.find("Option 'maxstartups' has a value '10:30:60' compliant with limits '15:40:70'") != std::string::npos);
}

TEST_F(EnsureSshdOptionTest, MaxStartups_NonCompliant)
{
    EXPECT_CALL(mContext, ExecuteCommand(sshdInitialCommand)).WillOnce(Return(Result<std::string>(sshdSpecialOptionsOutput)));
    EXPECT_CALL(mContext, ExecuteCommand(sshdSimpleCommand)).WillOnce(Return(Result<std::string>(sshdSpecialOptionsOutput)));

    SshdOptionParams params;
    params.option = {{"maxstartups"}};
    params.op = SshdOptionOperation::Match;
    // Set at least one threshold lower than actual (e.g., middle value 25 < 30)
    params.value = "15:25:70";

    auto result = AuditSshdOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
    auto formatted = mFormatter.Format(mIndicators).Value();
    ASSERT_TRUE(formatted.find("Option 'maxstartups' has value '10:30:60' which exceeds limits '15:25:70'") != std::string::npos);
}

TEST_F(EnsureSshdOptionTest, RekeyLimit_Compliant)
{
    EXPECT_CALL(mContext, ExecuteCommand(sshdInitialCommand)).WillOnce(Return(Result<std::string>(sshdSpecialOptionsOutput)));
    EXPECT_CALL(mContext, ExecuteCommand(sshdSimpleCommand)).WillOnce(Return(Result<std::string>(sshdSpecialOptionsOutput)));

    SshdOptionParams params;
    params.option = {{"rekeylimit"}};       // special case expects actual '10 123'
    params.op = SshdOptionOperation::Match; // special-case numeric limits comparison
    // Provide thresholds higher than actual values (10 123) using colon format
    params.value = "15:150"; // limits: first>=10 second>=123

    auto result = AuditSshdOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
    auto formatted = mFormatter.Format(mIndicators).Value();
    ASSERT_TRUE(formatted.find("Option 'rekeylimit' has a value '10 123' compliant with limits '15:150'") != std::string::npos);
}

TEST_F(EnsureSshdOptionTest, RekeyLimit_NonCompliant)
{
    EXPECT_CALL(mContext, ExecuteCommand(sshdInitialCommand)).WillOnce(Return(Result<std::string>(sshdSpecialOptionsOutput)));
    EXPECT_CALL(mContext, ExecuteCommand(sshdSimpleCommand)).WillOnce(Return(Result<std::string>(sshdSpecialOptionsOutput)));

    SshdOptionParams params;
    params.option = {{"rekeylimit"}};       // actual value '10 123'
    params.op = SshdOptionOperation::Match; // numeric limits compare
    params.value = "5:150";                 // first threshold lower than actual first value (10 > 5) triggers non-compliance

    auto result = AuditSshdOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
    auto formatted = mFormatter.Format(mIndicators).Value();
    ASSERT_TRUE(formatted.find("Option 'rekeylimit' has value '10 123' which exceeds limits '5:150'") != std::string::npos);
}

TEST_F(EnsureSshdOptionTest, DelimitedNumericLimitsRejectMalformedSuffixes)
{
    struct Case
    {
        std::string option;
        std::string actual;
        std::string limit;
        std::string errorPrefix;
    };
    const Case cases[] = {
        {"maxstartups", "10junk:30:60", "15:40:70", "Failed to parse maxstartups value '10junk:30:60':"},
        {"maxstartups", "10:30:60", "15junk:40:70", "Failed to parse maxstartups limit '15junk:40:70':"},
        {"rekeylimit", "10junk 123", "15:150", "Failed to parse rekeylimit value '10junk 123':"},
        {"rekeylimit", "10 123junk", "15:150", "Failed to parse rekeylimit value '10 123junk':"},
        {"rekeylimit", "10 123", "15:150junk", "Failed to parse rekeylimit limit '15:150junk':"},
    };
    for (const auto& test : cases)
    {
        const auto output = "port 22\n" + test.option + " " + test.actual + "\n";
        EXPECT_CALL(mContext, ExecuteCommand(sshdInitialCommand)).WillOnce(Return(Result<std::string>(output)));
        EXPECT_CALL(mContext, ExecuteCommand(sshdSimpleCommand)).WillOnce(Return(Result<std::string>(output)));
        SshdOptionParams params;
        params.option = {{test.option}};
        params.value = test.limit;
        params.op = SshdOptionOperation::Match;
        IndicatorsTree indicators;
        indicators.Push("EnsureSshdOption");

        const auto result = AuditSshdOption(params, indicators, mContext);
        ASSERT_FALSE(result.HasValue()) << test.option << " " << test.actual << " " << test.limit;
        EXPECT_EQ(result.Error().code, EINVAL);
        EXPECT_EQ(result.Error().message.find(test.errorPrefix), 0U);
        EXPECT_TRUE(indicators.Back().indicators.empty());
    }
}

TEST_F(EnsureSshdOptionTest, DelimitedNumericLimitsRejectExtraFieldsAndTrailingDelimiters)
{
    struct Case
    {
        std::string option;
        std::string actual;
        std::string limit;
        std::string error;
    };
    const Case cases[] = {
        {"maxstartups", "10:30:60:junk", "15:40:70", "Failed to parse maxstartups value '10:30:60:junk': Unexpected extra field or trailing delimiter"},
        {"maxstartups", "10:30:60:", "15:40:70", "Failed to parse maxstartups value '10:30:60:': Unexpected extra field or trailing delimiter"},
        {"maxstartups", "10:30:", "15:40:70", "Failed to parse maxstartups value '10:30:': Unexpected extra field or trailing delimiter"},
        {"maxstartups", "10:30:60", "15:40:70:junk", "Failed to parse maxstartups limit '15:40:70:junk': Unexpected extra field or trailing delimiter"},
        {"maxstartups", "10:30:60", "15:40:70:", "Failed to parse maxstartups limit '15:40:70:': Unexpected extra field or trailing delimiter"},
        {"maxstartups", "10:30:60", "15:40:", "Failed to parse maxstartups limit '15:40:': Unexpected extra field or trailing delimiter"},
        {"rekeylimit", "10 123 junk", "15:150", "Failed to parse rekeylimit value '10 123 junk': Unexpected extra field or trailing delimiter"},
        {"rekeylimit", "10 123", "15:150:junk", "Failed to parse rekeylimit limit '15:150:junk': Unexpected extra field or trailing delimiter"},
        {"rekeylimit", "10 123", "15:150:", "Failed to parse rekeylimit limit '15:150:': Unexpected extra field or trailing delimiter"},
    };
    for (const auto& test : cases)
    {
        const auto output = "port 22\n" + test.option + " " + test.actual + "\n";
        EXPECT_CALL(mContext, ExecuteCommand(sshdInitialCommand)).WillOnce(Return(Result<std::string>(output)));
        EXPECT_CALL(mContext, ExecuteCommand(sshdSimpleCommand)).WillOnce(Return(Result<std::string>(output)));
        SshdOptionParams params;
        params.option = {{test.option}};
        params.value = test.limit;
        params.op = SshdOptionOperation::Match;
        IndicatorsTree indicators;
        indicators.Push("EnsureSshdOption");

        const auto result = AuditSshdOption(params, indicators, mContext);
        ASSERT_FALSE(result.HasValue()) << test.option << " " << test.actual << " " << test.limit;
        EXPECT_EQ(result.Error().code, EINVAL);
        EXPECT_EQ(result.Error().message, test.error);
        EXPECT_TRUE(indicators.Back().indicators.empty());
    }
}

TEST_F(EnsureSshdOptionTest, DelimitedNumericLimitsRejectEmptyFields)
{
    struct Case
    {
        std::string option;
        std::string actual;
        std::string limit;
        std::string error;
    };
    const Case cases[] = {
        {"maxstartups", ":30:60", "15:40:70", "Failed to parse maxstartups value ':30:60': stoll"},
        {"maxstartups", "10::60", "15:40:70", "Failed to parse maxstartups value '10::60': stoll"},
        {"maxstartups", "", "15:40:70", "Failed to parse maxstartups value '': No numeric fields"},
        {"maxstartups", "10:30:60", ":40:70", "Failed to parse maxstartups limit ':40:70': stoll"},
        {"maxstartups", "10:0:60", "15::70", "Failed to parse maxstartups limit '15::70': stoll"},
        {"rekeylimit", "", "15:150", "Failed to parse rekeylimit value '': No numeric fields"},
        {"rekeylimit", "10 123", ":150", "Failed to parse rekeylimit limit ':150': stoll"},
    };
    for (const auto& test : cases)
    {
        const auto output = "port 22\n" + test.option + " " + test.actual + "\n";
        EXPECT_CALL(mContext, ExecuteCommand(sshdInitialCommand)).WillOnce(Return(Result<std::string>(output)));
        EXPECT_CALL(mContext, ExecuteCommand(sshdSimpleCommand)).WillOnce(Return(Result<std::string>(output)));
        SshdOptionParams params;
        params.option = {{test.option}};
        params.value = test.limit;
        params.op = SshdOptionOperation::Match;
        IndicatorsTree indicators;
        indicators.Push("EnsureSshdOption");

        const auto result = AuditSshdOption(params, indicators, mContext);
        ASSERT_FALSE(result.HasValue()) << test.option << " " << test.actual << " " << test.limit;
        EXPECT_EQ(result.Error().code, EINVAL);
        EXPECT_EQ(result.Error().message, test.error);
        EXPECT_TRUE(indicators.Back().indicators.empty());
    }
}

TEST_F(EnsureSshdOptionTest, DelimitedNumericLimitsKeepShorterValues)
{
    struct Case
    {
        std::string option;
        std::string actual;
        std::string limit;
    };
    const Case cases[] = {{"maxstartups", "10:30", "15:40"}, {"rekeylimit", "10", "15"}};
    for (const auto& test : cases)
    {
        const auto output = "port 22\n" + test.option + " " + test.actual + "\n";
        EXPECT_CALL(mContext, ExecuteCommand(sshdInitialCommand)).WillOnce(Return(Result<std::string>(output)));
        EXPECT_CALL(mContext, ExecuteCommand(sshdSimpleCommand)).WillOnce(Return(Result<std::string>(output)));
        SshdOptionParams params;
        params.option = {{test.option}};
        params.value = test.limit;
        params.op = SshdOptionOperation::Match;
        IndicatorsTree indicators;
        indicators.Push("EnsureSshdOption");

        const auto result = AuditSshdOption(params, indicators, mContext);
        ASSERT_TRUE(result.HasValue()) << test.option;
        EXPECT_EQ(result.Value(), Status::Compliant);
    }
}

TEST_F(EnsureSshdOptionTest, DelimitedNumericLimitsPreserveInvalidAndOverflowErrors)
{
    struct Case
    {
        std::string actual;
        std::string limit;
        std::string message;
    };
    const Case cases[] = {
        {"nope:30:60", "15:40:70", "Failed to parse maxstartups value 'nope:30:60': stoll"},
        {"10:30:60", "nope:40:70", "Failed to parse maxstartups limit 'nope:40:70': stoll"},
        {"999999999999999999999999:30:60", "15:40:70", "Failed to parse maxstartups value '999999999999999999999999:30:60': stoll"},
        {"10:30:60", "999999999999999999999999:40:70", "Failed to parse maxstartups limit '999999999999999999999999:40:70': stoll"},
    };
    for (const auto& test : cases)
    {
        const auto output = "port 22\nmaxstartups " + test.actual + "\n";
        EXPECT_CALL(mContext, ExecuteCommand(sshdInitialCommand)).WillOnce(Return(Result<std::string>(output)));
        EXPECT_CALL(mContext, ExecuteCommand(sshdSimpleCommand)).WillOnce(Return(Result<std::string>(output)));
        SshdOptionParams params;
        params.option = {{"maxstartups"}};
        params.value = test.limit;
        params.op = SshdOptionOperation::Match;
        IndicatorsTree indicators;
        indicators.Push("EnsureSshdOption");

        const auto result = AuditSshdOption(params, indicators, mContext);
        ASSERT_FALSE(result.HasValue()) << test.actual << " " << test.limit;
        EXPECT_EQ(result.Error().code, EINVAL);
        EXPECT_EQ(result.Error().message, test.message);
        EXPECT_TRUE(indicators.Back().indicators.empty());
    }
}

// ========================= Adapted legacy NoOption scenarios using EnsureSshdOption (op=not_match) =========================

TEST_F(EnsureSshdOptionTest, NoOption_AllOptionsAbsent_Adapted)
{
    EXPECT_CALL(mContext, ExecuteCommand(sshdInitialCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));
    EXPECT_CALL(mContext, ExecuteCommand(sshdSimpleCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));

    SshdOptionParams params;
    params.option = {{"nonexistentoption1", "nonexistentoption2"}};
    params.value = ".*";
    params.op = SshdOptionOperation::NotMatch;

    auto result = ComplianceEngine::AuditSshdOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
    auto formatted = mFormatter.Format(mIndicators).Value();
    // Expect individual missing option messages
    ASSERT_TRUE(formatted.find("Option 'nonexistentoption1' not found") != std::string::npos);
    ASSERT_TRUE(formatted.find("Option 'nonexistentoption2' not found") != std::string::npos);
}

TEST_F(EnsureSshdOptionTest, NoOption_OptionPresentWithForbiddenValue_Adapted)
{
    EXPECT_CALL(mContext, ExecuteCommand(sshdInitialCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));
    EXPECT_CALL(mContext, ExecuteCommand(sshdSimpleCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));

    // Original test expected NonCompliant when the value was present (since legacy NoOption treated presence of compliant value as violation)
    SshdOptionParams params;
    params.option = {{"permitrootlogin"}}; // actual value 'no'
    params.value = "no";                   // forbidden value pattern
    params.op = SshdOptionOperation::NotMatch;

    auto result = ComplianceEngine::AuditSshdOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
    auto formatted = mFormatter.Format(mIndicators).Value();
    ASSERT_TRUE(formatted.find("matches forbidden pattern 'no'") != std::string::npos);
}

TEST_F(EnsureSshdOptionTest, NoOption_OptionPresentWithAllowedValue_Adapted)
{
    EXPECT_CALL(mContext, ExecuteCommand(sshdInitialCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));
    EXPECT_CALL(mContext, ExecuteCommand(sshdSimpleCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));
    SshdOptionParams params;
    params.option = {{"maxauthtries"}};
    params.value = "5,6,7";
    params.op = SshdOptionOperation::NotMatch;

    auto result = ComplianceEngine::AuditSshdOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
    auto formatted = mFormatter.Format(mIndicators).Value();
    // Ensure we recorded compliant evaluation for the option; presence of explicit success phrase not guaranteed, so just ensure absence of forbidden pattern message
    ASSERT_TRUE(formatted.find("matches forbidden pattern") == std::string::npos);
}

TEST_F(EnsureSshdOptionTest, NoOption_InvalidRegex_Adapted)
{
    // Regex compilation fails before any command execution; no EXPECT_CALL on sshd
    SshdOptionParams params;
    params.option = {{"permitrootlogin"}};
    params.value = "(invalid["; // invalid regex
    params.op = SshdOptionOperation::NotMatch;
    auto result = AuditSshdOption(params, mIndicators, mContext);

    ASSERT_FALSE(result.HasValue());
    ASSERT_TRUE(result.Error().message.find("Failed to compile regex") != std::string::npos);
}

TEST_F(EnsureSshdOptionTest, NoOption_MissingOptionArgument_Adapted)
{
    SshdOptionParams params;
    params.value = "no";
    params.op = SshdOptionOperation::NotMatch;
    auto result = AuditSshdOption(params, mIndicators, mContext);

    ASSERT_FALSE(result.HasValue());
    ASSERT_EQ(result.Error().message, "Missing 'option' parameter");
}

TEST_F(EnsureSshdOptionTest, NoOption_MissingValueArgument_Adapted)
{
    SshdOptionParams params;
    params.option = {{"permitrootlogin"}};
    params.op = SshdOptionOperation::NotMatch;
    auto result = AuditSshdOption(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    ASSERT_EQ(result.Error().message, "Missing 'value' parameter");
}
// ========================= Tests for EnsureSshdOption in all_matches mode (formerly EnsureSshdOptionMatch) =========================

static const char sshdConfigWithMatches[] =
    "Port 22\n"
    "Match User alice\n"
    "Match Group admins\n"
    "Match Address 10.0.0.5/24\n"; // address truncated to 10.0.0.5

static const char sshdMatchUserAliceCommand[] = "sshd -T -C user=alice";
static const char sshdMatchGroupAdminsCommand[] = "sshd -T -C group=admins";
static const char sshdMatchAddress10005Command[] = "sshd -T -C address=10.0.0.5";

static const char sshdMatchOutputPermitRootLoginNo[] =
    "permitrootlogin no\n"
    "maxauthtries 4\n";

static const char sshdMatchOutputPermitRootLoginYes[] = "permitrootlogin yes\n";

TEST_F(EnsureSshdOptionTest, Match_MissingOptionArgument)
{
    SshdOptionParams params;
    params.value = "no";
    params.mode = SshdOptionMode::AllMatches;
    auto result = AuditSshdOption(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    ASSERT_EQ(result.Error().message, "Missing 'option' parameter");
}

TEST_F(EnsureSshdOptionTest, Match_MissingValueArgument)
{
    SshdOptionParams params;
    params.option = {{"permitrootlogin"}};
    params.mode = SshdOptionMode::AllMatches;
    auto result = AuditSshdOption(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    ASSERT_EQ(result.Error().message, "Missing 'value' parameter");
}

TEST_F(EnsureSshdOptionTest, Match_InvalidRegex)
{
    SshdOptionParams params;
    params.option = {{"permitrootlogin"}};
    params.value = "(invalid[";
    params.mode = SshdOptionMode::AllMatches;
    auto result = AuditSshdOption(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    ASSERT_TRUE(result.Error().message.find("Failed to compile regex") != std::string::npos);
}

TEST_F(EnsureSshdOptionTest, Match_AllCompliant)
{
    // GetAllMatches() file read
    EXPECT_CALL(mContext, GetFileContents("/etc/ssh/sshd_config")).WillOnce(Return(Result<std::string>(sshdConfigWithMatches)));

    // For each match context we expect a compliant option value
    EXPECT_CALL(mContext, ExecuteCommand(sshdMatchUserAliceCommand)).WillOnce(Return(Result<std::string>(sshdMatchOutputPermitRootLoginNo)));
    EXPECT_CALL(mContext, ExecuteCommand(sshdMatchGroupAdminsCommand)).WillOnce(Return(Result<std::string>(sshdMatchOutputPermitRootLoginNo)));
    EXPECT_CALL(mContext, ExecuteCommand(sshdMatchAddress10005Command)).WillOnce(Return(Result<std::string>(sshdMatchOutputPermitRootLoginNo)));

    SshdOptionParams params;
    params.option = {{"permitrootlogin"}};
    params.value = "no";
    params.mode = SshdOptionMode::AllMatches;

    auto result = AuditSshdOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
    auto formatted = mFormatter.Format(mIndicators).Value();
    // Unified implementation final success message changed
    ASSERT_TRUE(formatted.find("All options are compliant") != std::string::npos);
}

TEST_F(EnsureSshdOptionTest, Match_FirstNonCompliantShortCircuits)
{
    EXPECT_CALL(mContext, GetFileContents("/etc/ssh/sshd_config")).WillOnce(Return(Result<std::string>(sshdConfigWithMatches)));
    // First match returns non-compliant (yes), subsequent commands must not be invoked
    EXPECT_CALL(mContext, ExecuteCommand(sshdMatchUserAliceCommand)).WillOnce(Return(Result<std::string>(sshdMatchOutputPermitRootLoginYes)));
    EXPECT_CALL(mContext, ExecuteCommand(sshdMatchGroupAdminsCommand)).Times(0);
    EXPECT_CALL(mContext, ExecuteCommand(sshdMatchAddress10005Command)).Times(0);

    SshdOptionParams params;
    params.option = {{"permitrootlogin"}};
    params.value = "no"; // expecting 'no'
    params.mode = SshdOptionMode::AllMatches;

    auto result = AuditSshdOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureSshdOptionTest, Match_OptionMissingInOneContext)
{
    EXPECT_CALL(mContext, GetFileContents("/etc/ssh/sshd_config")).WillOnce(Return(Result<std::string>(sshdConfigWithMatches)));
    // Return config that does not contain the option
    EXPECT_CALL(mContext, ExecuteCommand(sshdMatchUserAliceCommand)).WillOnce(Return(Result<std::string>("maxauthtries 4\n")));
    EXPECT_CALL(mContext, ExecuteCommand(sshdMatchGroupAdminsCommand)).Times(0);
    EXPECT_CALL(mContext, ExecuteCommand(sshdMatchAddress10005Command)).Times(0);

    SshdOptionParams params;
    params.option = {{"permitrootlogin"}};
    params.value = ".*";

    params.mode = SshdOptionMode::AllMatches;
    auto result = AuditSshdOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant); // option missing treated as non-compliant
}

TEST_F(EnsureSshdOptionTest, Match_NotMatchOperation_Compliant)
{
    EXPECT_CALL(mContext, GetFileContents("/etc/ssh/sshd_config")).WillOnce(Return(Result<std::string>(sshdConfigWithMatches)));
    EXPECT_CALL(mContext, ExecuteCommand(sshdMatchUserAliceCommand)).WillOnce(Return(Result<std::string>(sshdMatchOutputPermitRootLoginNo)));
    EXPECT_CALL(mContext, ExecuteCommand(sshdMatchGroupAdminsCommand)).WillOnce(Return(Result<std::string>(sshdMatchOutputPermitRootLoginNo)));
    EXPECT_CALL(mContext, ExecuteCommand(sshdMatchAddress10005Command)).WillOnce(Return(Result<std::string>(sshdMatchOutputPermitRootLoginNo)));

    SshdOptionParams params;
    params.option = {{"permitrootlogin"}};
    params.value = "yes"; // forbidden
    params.op = SshdOptionOperation::NotMatch;
    params.mode = SshdOptionMode::AllMatches;

    auto result = AuditSshdOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureSshdOptionTest, Match_NotMatchOperation_NonCompliant)
{
    EXPECT_CALL(mContext, GetFileContents("/etc/ssh/sshd_config")).WillOnce(Return(Result<std::string>(sshdConfigWithMatches)));
    EXPECT_CALL(mContext, ExecuteCommand(sshdMatchUserAliceCommand)).WillOnce(Return(Result<std::string>(sshdMatchOutputPermitRootLoginNo)));
    // Since first context already matches forbidden, short circuit; no further commands expected
    EXPECT_CALL(mContext, ExecuteCommand(sshdMatchGroupAdminsCommand)).Times(0);
    EXPECT_CALL(mContext, ExecuteCommand(sshdMatchAddress10005Command)).Times(0);

    SshdOptionParams params;
    params.option = {{"permitrootlogin"}};
    params.value = "no"; // actual value matches forbidden pattern
    params.op = SshdOptionOperation::NotMatch;
    params.mode = SshdOptionMode::AllMatches;

    auto result = AuditSshdOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureSshdOptionTest, Match_NumericLt_Compliant)
{
    EXPECT_CALL(mContext, GetFileContents("/etc/ssh/sshd_config")).WillOnce(Return(Result<std::string>(sshdConfigWithMatches)));
    const char numericConfig[] = "maxauthtries 3\n";
    EXPECT_CALL(mContext, ExecuteCommand(sshdMatchUserAliceCommand)).WillOnce(Return(Result<std::string>(numericConfig)));
    EXPECT_CALL(mContext, ExecuteCommand(sshdMatchGroupAdminsCommand)).WillOnce(Return(Result<std::string>(numericConfig)));
    EXPECT_CALL(mContext, ExecuteCommand(sshdMatchAddress10005Command)).WillOnce(Return(Result<std::string>(numericConfig)));

    SshdOptionParams params;
    params.option = {{"maxauthtries"}};
    params.value = "5";
    params.op = SshdOptionOperation::LessThan;
    params.mode = SshdOptionMode::AllMatches;

    auto result = AuditSshdOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureSshdOptionTest, Match_NumericLt_NonCompliant)
{
    EXPECT_CALL(mContext, GetFileContents("/etc/ssh/sshd_config")).WillOnce(Return(Result<std::string>(sshdConfigWithMatches)));
    const char numericConfig[] = "maxauthtries 6\n"; // 6 !< 5
    EXPECT_CALL(mContext, ExecuteCommand(sshdMatchUserAliceCommand)).WillOnce(Return(Result<std::string>(numericConfig)));
    EXPECT_CALL(mContext, ExecuteCommand(sshdMatchGroupAdminsCommand)).Times(0);
    EXPECT_CALL(mContext, ExecuteCommand(sshdMatchAddress10005Command)).Times(0);

    SshdOptionParams params;
    params.option = {{"maxauthtries"}};
    params.value = "5";
    params.op = SshdOptionOperation::LessThan;
    params.mode = SshdOptionMode::AllMatches;

    auto result = AuditSshdOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureSshdOptionTest, Match_FileReadFailure_NoMatchesReturnsCompliant)
{
    EXPECT_CALL(mContext, GetFileContents("/etc/ssh/sshd_config")).WillOnce(Return(Result<std::string>(Error("read error", -1))));

    SshdOptionParams params;
    params.option = {{"permitrootlogin"}};
    params.value = "no";
    params.mode = SshdOptionMode::AllMatches;

    auto result = AuditSshdOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    // No matches => loop skipped => Compliant per current implementation
    ASSERT_EQ(result.Value(), Status::Compliant);
}

// Reproduces the aadsshlogin failure: the installer appends
//   Match User *@*,<uuid>    # Added by aadsshlogin installer
// to sshd_config. The comma separates a *pattern list* for the Match User
// criterion. When all_matches mode feeds that value verbatim into
// `sshd -T -C user=<value>`, sshd treats the comma as the separator between
// connection-spec `key=value` pairs, so the tail after the comma is parsed as
// a bogus spec item and sshd aborts with
//   "Invalid test mode specification <uuid>".
// The connection spec must carry a single concrete user, so the pattern list
// is split into one match context per pattern: `sshd -T -C user=*@*` and
// `sshd -T -C user=<uuid>` are simulated independently.
static const char sshdConfigWithAadMatchUser[] =
    "Port 22\n"
    "Match User *@*,\?\?\?\?\?\?\?\?-\?\?\?\?-\?\?\?\?-\?\?\?\?-\?\?\?\?\?\?\?\?\?\?\?\?    # Added by aadsshlogin installer\n";

static const char sshdMatchUserAadFirstPatternCommand[] = "sshd -T -C user=*@*";
static const char sshdMatchUserAadSecondPatternCommand[] = "sshd -T -C user=\?\?\?\?\?\?\?\?-\?\?\?\?-\?\?\?\?-\?\?\?\?-\?\?\?\?\?\?\?\?\?\?\?\?";
static const char sshdMatchUserAadBrokenCommand[] = "sshd -T -C user=*@*,\?\?\?\?\?\?\?\?-\?\?\?\?-\?\?\?\?-\?\?\?\?-\?\?\?\?\?\?\?\?\?\?\?\?";

TEST_F(EnsureSshdOptionTest, Match_UserPatternListWithComma_SplitsIntoOneContextPerPattern)
{
    EXPECT_CALL(mContext, GetFileContents("/etc/ssh/sshd_config")).WillOnce(Return(Result<std::string>(sshdConfigWithAadMatchUser)));

    // The forbidden call: passing the whole comma-separated pattern list to
    // `sshd -T -C user=...` is what triggers "Invalid test mode specification".
    EXPECT_CALL(mContext, ExecuteCommand(sshdMatchUserAadBrokenCommand)).Times(0);

    // The correct behaviour: each pattern of the comma-separated list is simulated
    // as its own connection spec.
    EXPECT_CALL(mContext, ExecuteCommand(sshdMatchUserAadFirstPatternCommand)).WillOnce(Return(Result<std::string>("banner /etc/issue.net\n")));
    EXPECT_CALL(mContext, ExecuteCommand(sshdMatchUserAadSecondPatternCommand)).WillOnce(Return(Result<std::string>("banner /etc/issue.net\n")));

    SshdOptionParams params;
    params.option = {{"banner"}};
    params.value = "/etc/issue.net";
    params.op = SshdOptionOperation::Match;
    params.mode = SshdOptionMode::AllMatches;

    auto result = AuditSshdOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
    auto formatted = mFormatter.Format(mIndicators).Value();
    ASSERT_TRUE(formatted.find("All options are compliant") != std::string::npos);
    // Each per-pattern result is qualified with its own Match context so the two
    // otherwise-identical compliant messages are distinguishable.
    ASSERT_TRUE(formatted.find("(Match context 'user=*@*')") != std::string::npos);
    ASSERT_TRUE(formatted.find("(Match context 'user=\?\?\?\?\?\?\?\?-\?\?\?\?-\?\?\?\?-\?\?\?\?-\?\?\?\?\?\?\?\?\?\?\?\?')") != std::string::npos);
}
TEST_F(EnsureSshdOptionTest, ReadExtraConfigs_AppendsExtraOptionsToSshdCommand)
{
    using ::testing::InSequence;
    InSequence seq;

    // Mock sourcing of extra config files returning option flags
    EXPECT_CALL(mContext, ExecuteCommand("source /etc/sysconfig/sshd 2>/dev/null && echo -n $OPTIONS")).WillOnce(Return(Result<std::string>("-oX")));

    EXPECT_CALL(mContext, ExecuteCommand("source /etc/crypto-policies/back-ends/opensshserver.config 2>/dev/null && echo -n $CRYPTO_POLICY"))
        .WillOnce(Return(Result<std::string>("-Y")));

    // Initial probe command with 2>&1 (to detect match group logic) should include aggregated extra config flags
    EXPECT_CALL(mContext, ExecuteCommand("sshd -T -oX -Y 2>&1")).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));

    // Final command (without 2>&1) to collect options also includes flags
    EXPECT_CALL(mContext, ExecuteCommand("sshd -T -oX -Y")).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));

    SshdOptionParams params;
    params.option = {{"permitrootlogin"}};
    params.value = "no";
    params.readExtraConfigs = true;

    auto result = AuditSshdOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
    auto formatted = mFormatter.Format(mIndicators).Value();
    ASSERT_TRUE(formatted.find("Option 'permitrootlogin' has a compliant value 'no'") != std::string::npos);
    ASSERT_TRUE(formatted.find("All options are compliant") != std::string::npos);
}

TEST_F(EnsureSshdOptionTest, CaseInsensitive_UpperCaseValueRegexMatches)
{
    EXPECT_CALL(mContext, ExecuteCommand(sshdInitialCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));
    EXPECT_CALL(mContext, ExecuteCommand(sshdSimpleCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));

    SshdOptionParams params;
    params.option = {{"permitrootlogin"}};
    // Value pattern uses uppercase "No" but sshd -T output is lowercased to "no"
    params.value = "No";

    auto result = AuditSshdOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureSshdOptionTest, CaseInsensitive_MixedCaseRegexPatternMatches)
{
    EXPECT_CALL(mContext, ExecuteCommand(sshdInitialCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));
    EXPECT_CALL(mContext, ExecuteCommand(sshdSimpleCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));

    SshdOptionParams params;
    params.option = {{"permitrootlogin"}};
    // Mixed-case regex pattern must match lowercased "no"
    params.value = "^(No|Prohibit-Password)$";

    auto result = AuditSshdOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureSshdOptionTest, CaseInsensitive_FullUpperCaseRegexMatches)
{
    EXPECT_CALL(mContext, ExecuteCommand(sshdInitialCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));
    EXPECT_CALL(mContext, ExecuteCommand(sshdSimpleCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));

    SshdOptionParams params;
    params.option = {{"usepam"}};
    // "YES" in value must match the lowercased "yes" from sshd -T
    params.value = "YES";

    auto result = AuditSshdOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureSshdOptionTest, CaseInsensitive_MatchOp_MixedCaseCommaList)
{
    EXPECT_CALL(mContext, ExecuteCommand(sshdInitialCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));
    EXPECT_CALL(mContext, ExecuteCommand(sshdSimpleCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));

    SshdOptionParams params;
    params.option = {{"permitrootlogin"}};
    // Match op with comma-separated values, one uses uppercase
    params.value = "Yes,No";
    params.op = SshdOptionOperation::Match;

    auto result = AuditSshdOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    // "no" is lowercased from sshd -T, "No" pattern should match case-insensitively
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureSshdOptionTest, CaseInsensitive_NotMatchOp_UpperCaseForbiddenValue)
{
    EXPECT_CALL(mContext, ExecuteCommand(sshdInitialCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));
    EXPECT_CALL(mContext, ExecuteCommand(sshdSimpleCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));

    SshdOptionParams params;
    params.option = {{"permitrootlogin"}};
    // Forbidden pattern uses upper case "NO" — must still match the lowercased actual value "no"
    params.value = "NO";
    params.op = SshdOptionOperation::NotMatch;

    auto result = AuditSshdOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    // The value "no" matches forbidden pattern "NO" case-insensitively => NonCompliant
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureSshdOptionTest, CaseInsensitive_NotMatchOp_UpperCaseNonMatchingPattern)
{
    EXPECT_CALL(mContext, ExecuteCommand(sshdInitialCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));
    EXPECT_CALL(mContext, ExecuteCommand(sshdSimpleCommand)).WillOnce(Return(Result<std::string>(sshdWithoutMatchGroupOutput)));

    SshdOptionParams params;
    params.option = {{"permitrootlogin"}};
    // Forbidden pattern "YES" does not match actual value "no" regardless of case
    params.value = "YES";
    params.op = SshdOptionOperation::NotMatch;

    auto result = AuditSshdOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}
