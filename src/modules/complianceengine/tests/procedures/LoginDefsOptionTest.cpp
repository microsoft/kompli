// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "CommonUtils.h"
#include "MockContext.h"

#include <LoginDefsOption.h>
#include <ProcedureMap.h>

using ComplianceEngine::AuditLoginDefsOption;
using ComplianceEngine::ComparisonOperation;
using ComplianceEngine::Error;
using ComplianceEngine::IndicatorsTree;
using ComplianceEngine::LoginDefsOptionParams;
using ComplianceEngine::NestedListFormatter;
using ComplianceEngine::Result;
using ComplianceEngine::Status;
using std::string;
using testing::Return;

static const char* cLoginDefsPath = "/etc/login.defs";

class LoginDefsOptionTest : public ::testing::Test
{
protected:
    MockContext mContext;
    IndicatorsTree mIndicators;
    NestedListFormatter mFormatter;

    void SetUp() override
    {
        mIndicators.Push("LoginDefsOption");
    }

    void SetLoginDefsContent(const string& content)
    {
        EXPECT_CALL(mContext, GetFileContents(cLoginDefsPath)).WillOnce(Return(Result<string>(content)));
    }

    void SetLoginDefsError()
    {
        EXPECT_CALL(mContext, GetFileContents(cLoginDefsPath)).WillOnce(Return(Result<string>(Error("Failed to load file contents"))));
    }
};

TEST_F(LoginDefsOptionTest, PassMaxDays_LessOrEqual_Compliant)
{
    SetLoginDefsContent(
        "# This is a comment\n"
        "PASS_MAX_DAYS\t365\n"
        "PASS_MIN_DAYS\t7\n");

    LoginDefsOptionParams params;
    params.option = "PASS_MAX_DAYS";
    params.value = "365";
    params.comparison = ComparisonOperation::LessOrEqual;

    auto result = AuditLoginDefsOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(LoginDefsOptionTest, PassMaxDays_LessOrEqual_CompliantWhenLess)
{
    SetLoginDefsContent("PASS_MAX_DAYS 180\n");

    LoginDefsOptionParams params;
    params.option = "PASS_MAX_DAYS";
    params.value = "365";
    params.comparison = ComparisonOperation::LessOrEqual;

    auto result = AuditLoginDefsOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(LoginDefsOptionTest, PassMaxDays_LessOrEqual_NonCompliant)
{
    SetLoginDefsContent("PASS_MAX_DAYS 99999\n");

    LoginDefsOptionParams params;
    params.option = "PASS_MAX_DAYS";
    params.value = "365";
    params.comparison = ComparisonOperation::LessOrEqual;

    auto result = AuditLoginDefsOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(LoginDefsOptionTest, PassMaxDays_GreaterOrEqual_Compliant)
{
    SetLoginDefsContent("PASS_MAX_DAYS 365\n");

    LoginDefsOptionParams params;
    params.option = "PASS_MAX_DAYS";
    params.value = "1";
    params.comparison = ComparisonOperation::GreaterOrEqual;

    auto result = AuditLoginDefsOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(LoginDefsOptionTest, PassMaxDays_GreaterOrEqual_NonCompliant)
{
    SetLoginDefsContent("PASS_MAX_DAYS 0\n");

    LoginDefsOptionParams params;
    params.option = "PASS_MAX_DAYS";
    params.value = "1";
    params.comparison = ComparisonOperation::GreaterOrEqual;

    auto result = AuditLoginDefsOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(LoginDefsOptionTest, PassMinDays_GreaterOrEqual_Compliant)
{
    SetLoginDefsContent(
        "PASS_MAX_DAYS 365\n"
        "PASS_MIN_DAYS 7\n");

    LoginDefsOptionParams params;
    params.option = "PASS_MIN_DAYS";
    params.value = "1";
    params.comparison = ComparisonOperation::GreaterOrEqual;

    auto result = AuditLoginDefsOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(LoginDefsOptionTest, PassWarnAge_GreaterOrEqual_Compliant)
{
    SetLoginDefsContent("PASS_WARN_AGE 7\n");

    LoginDefsOptionParams params;
    params.option = "PASS_WARN_AGE";
    params.value = "7";
    params.comparison = ComparisonOperation::GreaterOrEqual;

    auto result = AuditLoginDefsOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(LoginDefsOptionTest, EncryptMethod_Equal_Compliant)
{
    SetLoginDefsContent("ENCRYPT_METHOD SHA512\n");

    LoginDefsOptionParams params;
    params.option = "ENCRYPT_METHOD";
    params.value = "SHA512";
    params.comparison = ComparisonOperation::Equal;

    auto result = AuditLoginDefsOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(LoginDefsOptionTest, EncryptMethod_Equal_IgnoresCase)
{
    SetLoginDefsContent("ENCRYPT_METHOD yescrypt\n");

    LoginDefsOptionParams params;
    params.option = "ENCRYPT_METHOD";
    params.value = "YESCRYPT";
    params.comparison = ComparisonOperation::Equal;

    auto result = AuditLoginDefsOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(LoginDefsOptionTest, EncryptMethod_CaseFoldingPreservesHighBitBytes)
{
    SetLoginDefsContent("ENCRYPT_METHOD yescrypt\x80\n");

    LoginDefsOptionParams params;
    params.option = "ENCRYPT_METHOD";
    params.value = "YESCRYPT\x80";
    params.comparison = ComparisonOperation::Equal;

    auto result = AuditLoginDefsOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(LoginDefsOptionTest, EncryptMethod_Equal_NonCompliant)
{
    SetLoginDefsContent("ENCRYPT_METHOD MD5\n");

    LoginDefsOptionParams params;
    params.option = "ENCRYPT_METHOD";
    params.value = "SHA512";
    params.comparison = ComparisonOperation::Equal;

    auto result = AuditLoginDefsOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(LoginDefsOptionTest, OptionNotFound_NonCompliant)
{
    SetLoginDefsContent(
        "# Only comments\n"
        "SOME_OTHER_OPTION 42\n");

    LoginDefsOptionParams params;
    params.option = "PASS_MAX_DAYS";
    params.value = "365";
    params.comparison = ComparisonOperation::LessOrEqual;

    auto result = AuditLoginDefsOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
    ASSERT_EQ(mIndicators.Back().indicators.size(), 1U);
    EXPECT_EQ(mIndicators.Back().indicators.front().status, Status::NonCompliant);
    EXPECT_EQ(mIndicators.Back().indicators.front().message, "Option 'PASS_MAX_DAYS' is not set in /etc/login.defs");
}

TEST_F(LoginDefsOptionTest, FileNotFound_ReturnsError)
{
    SetLoginDefsError();

    LoginDefsOptionParams params;
    params.option = "PASS_MAX_DAYS";
    params.value = "365";
    params.comparison = ComparisonOperation::LessOrEqual;

    auto result = AuditLoginDefsOption(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().message, "Failed to load file contents");
    EXPECT_TRUE(mIndicators.Back().indicators.empty());
}

TEST_F(LoginDefsOptionTest, CommentSkipped)
{
    SetLoginDefsContent(
        "# PASS_MAX_DAYS 99999\n"
        "PASS_MAX_DAYS 180\n");

    LoginDefsOptionParams params;
    params.option = "PASS_MAX_DAYS";
    params.value = "365";
    params.comparison = ComparisonOperation::LessOrEqual;

    auto result = AuditLoginDefsOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(LoginDefsOptionTest, LastOccurrenceWins)
{
    SetLoginDefsContent(
        "PASS_MAX_DAYS 99999\n"
        "PASS_MAX_DAYS 180\n");

    LoginDefsOptionParams params;
    params.option = "PASS_MAX_DAYS";
    params.value = "365";
    params.comparison = ComparisonOperation::LessOrEqual;

    auto result = AuditLoginDefsOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(LoginDefsOptionTest, TabSeparated)
{
    SetLoginDefsContent("PASS_MAX_DAYS\t\t365\n");

    LoginDefsOptionParams params;
    params.option = "PASS_MAX_DAYS";
    params.value = "365";
    params.comparison = ComparisonOperation::Equal;

    auto result = AuditLoginDefsOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(LoginDefsOptionTest, LeadingWhitespace)
{
    SetLoginDefsContent("   PASS_MAX_DAYS 365\n");

    LoginDefsOptionParams params;
    params.option = "PASS_MAX_DAYS";
    params.value = "365";
    params.comparison = ComparisonOperation::Equal;

    auto result = AuditLoginDefsOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(LoginDefsOptionTest, EmptyFile)
{
    SetLoginDefsContent("");

    LoginDefsOptionParams params;
    params.option = "PASS_MAX_DAYS";
    params.value = "365";
    params.comparison = ComparisonOperation::LessOrEqual;

    auto result = AuditLoginDefsOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(LoginDefsOptionTest, LessThan_Compliant)
{
    SetLoginDefsContent("PASS_MAX_DAYS 364\n");

    LoginDefsOptionParams params;
    params.option = "PASS_MAX_DAYS";
    params.value = "365";
    params.comparison = ComparisonOperation::LessThan;

    auto result = AuditLoginDefsOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(LoginDefsOptionTest, LessThan_NonCompliant_WhenEqual)
{
    SetLoginDefsContent("PASS_MAX_DAYS 365\n");

    LoginDefsOptionParams params;
    params.option = "PASS_MAX_DAYS";
    params.value = "365";
    params.comparison = ComparisonOperation::LessThan;

    auto result = AuditLoginDefsOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(LoginDefsOptionTest, GreaterThan_Compliant)
{
    SetLoginDefsContent("PASS_MIN_DAYS 2\n");

    LoginDefsOptionParams params;
    params.option = "PASS_MIN_DAYS";
    params.value = "1";
    params.comparison = ComparisonOperation::GreaterThan;

    auto result = AuditLoginDefsOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(LoginDefsOptionTest, NotEqual_Compliant)
{
    SetLoginDefsContent("ENCRYPT_METHOD SHA512\n");

    LoginDefsOptionParams params;
    params.option = "ENCRYPT_METHOD";
    params.value = "MD5";
    params.comparison = ComparisonOperation::NotEqual;

    auto result = AuditLoginDefsOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(LoginDefsOptionTest, RealisticLoginDefs)
{
    const string content =
        "#\n"
        "# /etc/login.defs - Configuration control definitions for the login package.\n"
        "#\n"
        "\n"
        "MAIL_DIR        /var/mail\n"
        "\n"
        "# Password aging controls:\n"
        "#\n"
        "PASS_MAX_DAYS   365\n"
        "PASS_MIN_DAYS   7\n"
        "PASS_WARN_AGE   7\n"
        "\n"
        "#\n"
        "# Min/max values for automatic uid selection in useradd\n"
        "#\n"
        "UID_MIN                  1000\n"
        "UID_MAX                 60000\n"
        "\n"
        "ENCRYPT_METHOD SHA512\n";

    // Check PASS_MAX_DAYS <= 365
    {
        EXPECT_CALL(mContext, GetFileContents(cLoginDefsPath)).WillOnce(Return(Result<string>(content)));

        LoginDefsOptionParams params;
        params.option = "PASS_MAX_DAYS";
        params.value = "365";
        params.comparison = ComparisonOperation::LessOrEqual;

        auto result = AuditLoginDefsOption(params, mIndicators, mContext);
        ASSERT_TRUE(result.HasValue());
        EXPECT_EQ(result.Value(), Status::Compliant);
    }

    // Check PASS_MAX_DAYS >= 1
    {
        EXPECT_CALL(mContext, GetFileContents(cLoginDefsPath)).WillOnce(Return(Result<string>(content)));

        LoginDefsOptionParams params;
        params.option = "PASS_MAX_DAYS";
        params.value = "1";
        params.comparison = ComparisonOperation::GreaterOrEqual;

        auto result = AuditLoginDefsOption(params, mIndicators, mContext);
        ASSERT_TRUE(result.HasValue());
        EXPECT_EQ(result.Value(), Status::Compliant);
    }

    // Check ENCRYPT_METHOD == SHA512
    {
        EXPECT_CALL(mContext, GetFileContents(cLoginDefsPath)).WillOnce(Return(Result<string>(content)));

        LoginDefsOptionParams params;
        params.option = "ENCRYPT_METHOD";
        params.value = "SHA512";
        params.comparison = ComparisonOperation::Equal;

        auto result = AuditLoginDefsOption(params, mIndicators, mContext);
        ASSERT_TRUE(result.HasValue());
        EXPECT_EQ(result.Value(), Status::Compliant);
    }
}

TEST_F(LoginDefsOptionTest, NumericComparisonPreservesAllOperatorsAndIndicators)
{
    struct Case
    {
        ComparisonOperation operation;
        string actual;
        Status expected;
    };
    const Case cases[] = {
        {ComparisonOperation::Equal, "5", Status::Compliant},
        {ComparisonOperation::Equal, "4", Status::NonCompliant},
        {ComparisonOperation::NotEqual, "4", Status::Compliant},
        {ComparisonOperation::NotEqual, "5", Status::NonCompliant},
        {ComparisonOperation::LessThan, "4", Status::Compliant},
        {ComparisonOperation::LessThan, "5", Status::NonCompliant},
        {ComparisonOperation::LessOrEqual, "5", Status::Compliant},
        {ComparisonOperation::LessOrEqual, "6", Status::NonCompliant},
        {ComparisonOperation::GreaterThan, "6", Status::Compliant},
        {ComparisonOperation::GreaterThan, "5", Status::NonCompliant},
        {ComparisonOperation::GreaterOrEqual, "5", Status::Compliant},
        {ComparisonOperation::GreaterOrEqual, "4", Status::NonCompliant},
        {ComparisonOperation::LessThan, "-2147483648", Status::Compliant},
        {ComparisonOperation::GreaterThan, "2147483647", Status::Compliant},
    };

    for (const auto& test : cases)
    {
        SetLoginDefsContent("PASS_MAX_DAYS " + test.actual + "\n");
        LoginDefsOptionParams params;
        params.option = "PASS_MAX_DAYS";
        params.value = "5";
        params.comparison = test.operation;
        IndicatorsTree indicators;
        indicators.Push("LoginDefsOption");
        auto result = AuditLoginDefsOption(params, indicators, mContext);
        ASSERT_TRUE(result.HasValue()) << test.actual;
        EXPECT_EQ(result.Value(), test.expected) << test.actual;
        auto formatted = mFormatter.Format(indicators);
        ASSERT_TRUE(formatted.HasValue());
        ASSERT_EQ(indicators.Back().indicators.size(), 1U);
        const auto& indicator = indicators.Back().indicators.front();
        EXPECT_EQ(indicator.status, test.expected);
        const string message =
            "PASS_MAX_DAYS = " + test.actual + (test.expected == Status::Compliant ? " (" : " (expected ") + std::to_string(test.operation) + " 5)";
        EXPECT_EQ(indicator.message, message);
    }
}

TEST_F(LoginDefsOptionTest, StringComparisonPreservesCasePolicyAndUnsupportedOrdering)
{
    struct Case
    {
        string option;
        string actual;
        string expected;
        ComparisonOperation operation;
        Status status;
    };
    const Case cases[] = {
        {"ENCRYPT_METHOD", "YESCRYPT", "yescrypt", ComparisonOperation::Equal, Status::Compliant},
        {"ENCRYPT_METHOD", "YESCRYPT", "md5", ComparisonOperation::NotEqual, Status::Compliant},
        {"OTHER", "YESCRYPT", "yescrypt", ComparisonOperation::Equal, Status::NonCompliant},
        {"OTHER", "YESCRYPT", "yescrypt", ComparisonOperation::NotEqual, Status::Compliant},
    };
    for (const auto& test : cases)
    {
        SetLoginDefsContent(test.option + " " + test.actual + "\n");
        LoginDefsOptionParams params;
        params.option = test.option;
        params.value = test.expected;
        params.comparison = test.operation;
        IndicatorsTree indicators;
        indicators.Push("LoginDefsOption");
        auto result = AuditLoginDefsOption(params, indicators, mContext);
        ASSERT_TRUE(result.HasValue());
        EXPECT_EQ(result.Value(), test.status);
        ASSERT_EQ(indicators.Back().indicators.size(), 1U);
        EXPECT_EQ(indicators.Back().indicators.front().status, test.status);
        EXPECT_EQ(indicators.Back().indicators.front().message, test.option + " = " + test.actual + (test.status == Status::Compliant ? " (" : " (expected ") +
                                                                    std::to_string(test.operation) + " " + test.expected + ")");
    }

    SetLoginDefsContent("OTHER yescrypt\n");
    LoginDefsOptionParams params;
    params.option = "OTHER";
    params.value = "yescrypt";
    params.comparison = ComparisonOperation::LessThan;
    auto result = AuditLoginDefsOption(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, EINVAL);
    EXPECT_EQ(result.Error().message, "Unsupported comparison operation for string value (only eq and ne are supported)");
}

TEST_F(LoginDefsOptionTest, NumericEndpointsPreserveBothOperandDirections)
{
    struct Case
    {
        string actual;
        string expected;
        ComparisonOperation operation;
        Status status;
    };
    const Case cases[] = {
        {"-2147483648", "-2147483648", ComparisonOperation::Equal, Status::Compliant},
        {"-2147483648", "-2147483648", ComparisonOperation::LessThan, Status::NonCompliant},
        {"-2147483648", "-2147483648", ComparisonOperation::LessOrEqual, Status::Compliant},
        {"-2147483648", "-2147483647", ComparisonOperation::LessThan, Status::Compliant},
        {"0", "-2147483648", ComparisonOperation::GreaterThan, Status::Compliant},
        {"2147483647", "2147483647", ComparisonOperation::Equal, Status::Compliant},
        {"2147483647", "2147483647", ComparisonOperation::GreaterThan, Status::NonCompliant},
        {"2147483647", "2147483647", ComparisonOperation::GreaterOrEqual, Status::Compliant},
        {"2147483647", "2147483646", ComparisonOperation::GreaterThan, Status::Compliant},
    };
    for (const auto& test : cases)
    {
        SetLoginDefsContent("PASS_MAX_DAYS " + test.actual + "\n");
        LoginDefsOptionParams params;
        params.option = "PASS_MAX_DAYS";
        params.value = test.expected;
        params.comparison = test.operation;
        IndicatorsTree indicators;
        indicators.Push("LoginDefsOption");
        auto result = AuditLoginDefsOption(params, indicators, mContext);
        ASSERT_TRUE(result.HasValue());
        EXPECT_EQ(result.Value(), test.status);
        ASSERT_EQ(indicators.Back().indicators.size(), 1U);
        EXPECT_EQ(indicators.Back().indicators.front().status, test.status);
        EXPECT_EQ(indicators.Back().indicators.front().message, "PASS_MAX_DAYS = " + test.actual + (test.status == Status::Compliant ? " (" : " (expected ") +
                                                                    std::to_string(test.operation) + " " + test.expected + ")");
    }
}

TEST_F(LoginDefsOptionTest, OverflowFallsBackToStringComparison)
{
    SetLoginDefsContent("PASS_MAX_DAYS 2147483648\n");
    LoginDefsOptionParams params;
    params.option = "PASS_MAX_DAYS";
    params.value = "02147483648";
    params.comparison = ComparisonOperation::Equal;
    auto result = AuditLoginDefsOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);

    SetLoginDefsContent("PASS_MAX_DAYS 2147483648\n");
    params.comparison = ComparisonOperation::LessThan;
    result = AuditLoginDefsOption(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, EINVAL);
    EXPECT_EQ(result.Error().message, "Unsupported comparison operation for string value (only eq and ne are supported)");
}

TEST_F(LoginDefsOptionTest, PartialNumericParsePreservesCurrentSelection)
{
    SetLoginDefsContent("PASS_MAX_DAYS 5junk\n");
    LoginDefsOptionParams params;
    params.option = "PASS_MAX_DAYS";
    params.value = "5";
    params.comparison = ComparisonOperation::Equal;
    auto result = AuditLoginDefsOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(LoginDefsOptionTest, UnsupportedNumericOperatorReturnsErrorWithoutIndicator)
{
    SetLoginDefsContent("PASS_MAX_DAYS 5\n");
    LoginDefsOptionParams params;
    params.option = "PASS_MAX_DAYS";
    params.value = "5";
    params.comparison = ComparisonOperation::PatternMatch;
    auto result = AuditLoginDefsOption(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, EINVAL);
    EXPECT_EQ(result.Error().message, "Unsupported comparison operation for numeric value");
    EXPECT_TRUE(mIndicators.Back().indicators.empty());
}
