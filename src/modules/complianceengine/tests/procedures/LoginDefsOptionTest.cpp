// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "CommonUtils.h"
#include "MockContext.h"

#include <LoginDefsOption.h>
#include <ProcedureMap.h>
#include <cerrno>
#include <fstream>
#include <iterator>
#include <sys/stat.h>
#include <sys/xattr.h>

using ComplianceEngine::AuditLoginDefsOption;
using ComplianceEngine::ComparisonOperation;
using ComplianceEngine::Error;
using ComplianceEngine::IndicatorsTree;
using ComplianceEngine::LoginDefsOptionParams;
using ComplianceEngine::NestedListFormatter;
using ComplianceEngine::RemediateLoginDefsOption;
using ComplianceEngine::Result;
using ComplianceEngine::Status;
using std::string;
using testing::Return;

namespace
{
Result<string> ReadFile(const string& path)
{
    std::ifstream input(path);
    if (!input.is_open())
    {
        return Error("Failed to read test file", errno);
    }
    return string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}
} // namespace

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

TEST_F(LoginDefsOptionTest, PassMinDays_TrailingCisCommentDoesNotBlockAudit)
{
    SetLoginDefsContent("UID_MIN 1000\nPASS_MIN_DAYS 1  # Updated by CIS Build Kit\n");

    LoginDefsOptionParams params;
    params.option = "PASS_MIN_DAYS";
    params.value = "1";
    params.comparison = ComparisonOperation::GreaterOrEqual;

    const auto result = AuditLoginDefsOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());
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

TEST_F(LoginDefsOptionTest, EncryptMethod_RejectsUndocumentedHighBitBytes)
{
    SetLoginDefsContent("ENCRYPT_METHOD yescrypt\x80\n");

    LoginDefsOptionParams params;
    params.option = "ENCRYPT_METHOD";
    params.value = "YESCRYPT";
    params.comparison = ComparisonOperation::Equal;

    auto result = AuditLoginDefsOption(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EBADMSG, result.Error().code);
    EXPECT_TRUE(mIndicators.Back().indicators.empty());
}

TEST_F(LoginDefsOptionTest, EncryptMethod_RejectsUndocumentedComparisonTarget)
{
    SetLoginDefsContent("ENCRYPT_METHOD SHA512\n");
    LoginDefsOptionParams params;
    params.option = "ENCRYPT_METHOD";
    params.value = "SHA-512";
    params.comparison = ComparisonOperation::Equal;

    const auto result = AuditLoginDefsOption(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EINVAL, result.Error().code);
    EXPECT_EQ("Invalid ENCRYPT_METHOD comparison target: Unsupported encryption method: SHA-512", result.Error().message);
    EXPECT_TRUE(mIndicators.Back().indicators.empty());
}

TEST_F(LoginDefsOptionTest, InvalidUnselectedEncryptionMethodRejectsDocument)
{
    SetLoginDefsContent("PASS_MAX_DAYS 365\nENCRYPT_METHOD SHA-512\n");
    LoginDefsOptionParams params;
    params.option = "PASS_MAX_DAYS";
    params.value = "365";
    params.comparison = ComparisonOperation::LessOrEqual;

    const auto result = AuditLoginDefsOption(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EBADMSG, result.Error().code);
    EXPECT_EQ("/etc/login.defs:2:16: invalid ENCRYPT_METHOD value: Unsupported encryption method: SHA-512", result.Error().message);
    EXPECT_TRUE(mIndicators.Back().indicators.empty());
}

TEST_F(LoginDefsOptionTest, EncryptMethod_NormalizesDocumentedNames)
{
    SetLoginDefsContent("ENCRYPT_METHOD bcrypt\n");
    LoginDefsOptionParams params;
    params.option = "ENCRYPT_METHOD";
    params.value = "BCRYPT";
    params.comparison = ComparisonOperation::Equal;

    const auto result = AuditLoginDefsOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());
    ASSERT_EQ(1U, mIndicators.Back().indicators.size());
    EXPECT_NE(string::npos, mIndicators.Back().indicators.front().message.find("ENCRYPT_METHOD = BCRYPT"));
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

TEST_F(LoginDefsOptionTest, ConflictingDuplicateFailsWithoutIndicatorAndLogsWarning)
{
    SetLoginDefsContent(
        "PASS_MAX_DAYS 99999\n"
        "PASS_MAX_DAYS 180\n"
        "UNKNOWN yes\n"
        "UNKNOWN no\n");

    LoginDefsOptionParams params;
    params.option = "PASS_MAX_DAYS";
    params.value = "365";
    params.comparison = ComparisonOperation::LessOrEqual;

    const string logPath = mContext.GetTempdirPath() + "/duplicates.log";
    OsConfigLogHandle logHandle = OpenLog(logPath.c_str(), nullptr);
    ASSERT_NE(nullptr, logHandle);
    mContext.SetLogHandle(logHandle);
    auto result = AuditLoginDefsOption(params, mIndicators, mContext);
    CloseLog(&logHandle);
    mContext.SetLogHandle(nullptr);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EBADMSG, result.Error().code);
    EXPECT_EQ("/etc/login.defs:2:15: conflicting duplicate PASS_MAX_DAYS value", result.Error().message);
    EXPECT_TRUE(mIndicators.Back().indicators.empty());
    std::ifstream log(logPath);
    ASSERT_TRUE(log.is_open());
    const string text((std::istreambuf_iterator<char>(log)), std::istreambuf_iterator<char>());
    EXPECT_NE(string::npos, text.find("Duplicate PASS_MAX_DAYS in /etc/login.defs at line 2"));
    EXPECT_NE(string::npos, text.find("WARNING"));
}

TEST_F(LoginDefsOptionTest, EquivalentDuplicatesRemainAuditableAndLogWarnings)
{
    SetLoginDefsContent("PASS_MAX_DAYS 0180\nUNKNOWN yes\nUNKNOWN no\nPASS_MAX_DAYS 180\n");

    LoginDefsOptionParams params;
    params.option = "PASS_MAX_DAYS";
    params.value = "365";
    params.comparison = ComparisonOperation::LessOrEqual;

    const string logPath = mContext.GetTempdirPath() + "/equivalent-duplicates.log";
    OsConfigLogHandle logHandle = OpenLog(logPath.c_str(), nullptr);
    ASSERT_NE(nullptr, logHandle);
    mContext.SetLogHandle(logHandle);
    const auto result = AuditLoginDefsOption(params, mIndicators, mContext);
    CloseLog(&logHandle);
    mContext.SetLogHandle(nullptr);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());
    std::ifstream log(logPath);
    ASSERT_TRUE(log.is_open());
    const string text((std::istreambuf_iterator<char>(log)), std::istreambuf_iterator<char>());
    EXPECT_NE(string::npos, text.find("Duplicate UNKNOWN in /etc/login.defs at line 3"));
    EXPECT_NE(string::npos, text.find("Duplicate PASS_MAX_DAYS in /etc/login.defs at line 4"));
}

TEST_F(LoginDefsOptionTest, ConflictingUnselectedSettingFailsWithoutIndicator)
{
    SetLoginDefsContent("PASS_MAX_DAYS 180\nPASS_MIN_DAYS 1\nPASS_MIN_DAYS 2\n");

    LoginDefsOptionParams params;
    params.option = "PASS_MAX_DAYS";
    params.value = "365";
    params.comparison = ComparisonOperation::LessOrEqual;

    const auto result = AuditLoginDefsOption(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EBADMSG, result.Error().code);
    EXPECT_EQ("/etc/login.defs:3:15: conflicting duplicate PASS_MIN_DAYS value", result.Error().message);
    EXPECT_TRUE(mIndicators.Back().indicators.empty());
}

TEST_F(LoginDefsOptionTest, MalformedLastOccurrenceCannotFallBackToEarlierValue)
{
    SetLoginDefsContent("PASS_MAX_DAYS 180\nPASS_MAX_DAYS\n");

    LoginDefsOptionParams params;
    params.option = "PASS_MAX_DAYS";
    params.value = "365";
    params.comparison = ComparisonOperation::LessOrEqual;

    const string logPath = mContext.GetTempdirPath() + "/malformed-duplicate.log";
    OsConfigLogHandle logHandle = OpenLog(logPath.c_str(), nullptr);
    ASSERT_NE(nullptr, logHandle);
    mContext.SetLogHandle(logHandle);
    const auto result = AuditLoginDefsOption(params, mIndicators, mContext);
    CloseLog(&logHandle);
    mContext.SetLogHandle(nullptr);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EBADMSG, result.Error().code);
    EXPECT_TRUE(mIndicators.Back().indicators.empty());
    std::ifstream log(logPath);
    ASSERT_TRUE(log.is_open());
    const string text((std::istreambuf_iterator<char>(log)), std::istreambuf_iterator<char>());
    EXPECT_NE(string::npos, text.find("Duplicate PASS_MAX_DAYS in /etc/login.defs at line 2"));
}

TEST_F(LoginDefsOptionTest, CorruptedLastKeyCannotExposeEarlierPassingValue)
{
    const char contents[] = "PASS_MAX_DAYS 180\nPASS_MAX_DAYS\0 99999\n";
    SetLoginDefsContent(string(contents, sizeof(contents) - 1));

    LoginDefsOptionParams params;
    params.option = "PASS_MAX_DAYS";
    params.value = "365";
    params.comparison = ComparisonOperation::LessOrEqual;

    const auto result = AuditLoginDefsOption(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EBADMSG, result.Error().code);
    EXPECT_TRUE(mIndicators.Back().indicators.empty());
}

TEST_F(LoginDefsOptionTest, EarlierCorruptedKeyRejectsWholeDocument)
{
    const char contents[] = "PASS_MAX_DAYS\0 99999\nPASS_MAX_DAYS 180\n";
    SetLoginDefsContent(string(contents, sizeof(contents) - 1));

    LoginDefsOptionParams params;
    params.option = "PASS_MAX_DAYS";
    params.value = "365";
    params.comparison = ComparisonOperation::LessOrEqual;

    const auto result = AuditLoginDefsOption(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EBADMSG, result.Error().code);
    EXPECT_TRUE(mIndicators.Back().indicators.empty());
}

TEST_F(LoginDefsOptionTest, UnrelatedMissingValueRejectsWholeDocument)
{
    SetLoginDefsContent("PASS_MAX_DAYS 180\nOTHER\n");

    LoginDefsOptionParams params;
    params.option = "PASS_MAX_DAYS";
    params.value = "365";
    params.comparison = ComparisonOperation::LessOrEqual;

    const auto result = AuditLoginDefsOption(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EBADMSG, result.Error().code);
    EXPECT_TRUE(mIndicators.Back().indicators.empty());
}

TEST_F(LoginDefsOptionTest, SelectedEmbeddedNulCannotProduceIndicator)
{
    SetLoginDefsContent(string("PASS_MAX_DAYS 180 \0ignored\n", 27));

    LoginDefsOptionParams params;
    params.option = "PASS_MAX_DAYS";
    params.value = "365";
    params.comparison = ComparisonOperation::LessOrEqual;

    const auto result = AuditLoginDefsOption(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EBADMSG, result.Error().code);
    EXPECT_TRUE(mIndicators.Back().indicators.empty());
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

TEST_F(LoginDefsOptionTest, NumericOverflowReturnsErrorWithoutIndicator)
{
    SetLoginDefsContent("PASS_MAX_DAYS 2147483648\n");
    LoginDefsOptionParams params;
    params.option = "PASS_MAX_DAYS";
    params.value = "5";
    params.comparison = ComparisonOperation::Equal;
    auto result = AuditLoginDefsOption(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, EBADMSG);
    EXPECT_EQ(result.Error().message, "/etc/login.defs:1:15: invalid PASS_MAX_DAYS value: Integer value out of range: 2147483648");
    EXPECT_TRUE(mIndicators.Back().indicators.empty());
}

TEST_F(LoginDefsOptionTest, NumericTargetOverflowReturnsErrorWithoutIndicator)
{
    SetLoginDefsContent("PASS_MAX_DAYS 5\n");
    LoginDefsOptionParams params;
    params.option = "PASS_MAX_DAYS";
    params.value = "02147483648";
    params.comparison = ComparisonOperation::Equal;
    const auto result = AuditLoginDefsOption(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, ERANGE);
    EXPECT_EQ(result.Error().message, "Invalid PASS_MAX_DAYS comparison target: Integer value out of range: 02147483648");
    EXPECT_TRUE(mIndicators.Back().indicators.empty());
}

TEST_F(LoginDefsOptionTest, MalformedNumericTargetReturnsError)
{
    SetLoginDefsContent("PASS_MAX_DAYS 5\n");
    LoginDefsOptionParams params;
    params.option = "PASS_MAX_DAYS";
    params.value = "5junk";
    params.comparison = ComparisonOperation::Equal;
    auto result = AuditLoginDefsOption(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, EINVAL);
    EXPECT_EQ(result.Error().message, "Invalid PASS_MAX_DAYS comparison target: Invalid integer value: 5junk");
    EXPECT_TRUE(mIndicators.Back().indicators.empty());
}

TEST_F(LoginDefsOptionTest, MissingNumericOptionStillRejectsMalformedTarget)
{
    SetLoginDefsContent("ENCRYPT_METHOD SHA512\n");
    LoginDefsOptionParams params;
    params.option = "PASS_MAX_DAYS";
    params.value = "5junk";
    params.comparison = ComparisonOperation::Equal;
    const auto result = AuditLoginDefsOption(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, EINVAL);
    EXPECT_EQ(result.Error().message, "Invalid PASS_MAX_DAYS comparison target: Invalid integer value: 5junk");
    EXPECT_TRUE(mIndicators.Back().indicators.empty());
}

TEST_F(LoginDefsOptionTest, MalformedNumericValueReturnsError)
{
    SetLoginDefsContent("PASS_MAX_DAYS 5junk\n");
    LoginDefsOptionParams params;
    params.option = "PASS_MAX_DAYS";
    params.value = "5";
    params.comparison = ComparisonOperation::Equal;
    const auto result = AuditLoginDefsOption(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, EBADMSG);
    EXPECT_EQ(result.Error().message, "/etc/login.defs:1:15: invalid PASS_MAX_DAYS value: Invalid integer value: 5junk");
    EXPECT_TRUE(mIndicators.Back().indicators.empty());
}

TEST_F(LoginDefsOptionTest, EqualMalformedNumericValuesCannotPass)
{
    for (const string option : {"PASS_MAX_DAYS", "PASS_MIN_DAYS", "PASS_WARN_AGE"})
    {
        SetLoginDefsContent(option + " 5junk\n");
        LoginDefsOptionParams params;
        params.option = option;
        params.value = "5junk";
        params.comparison = ComparisonOperation::Equal;
        const auto result = AuditLoginDefsOption(params, mIndicators, mContext);
        ASSERT_FALSE(result.HasValue()) << option;
        EXPECT_EQ(result.Error().code, EINVAL) << option;
        EXPECT_TRUE(mIndicators.Back().indicators.empty()) << option;
    }
}

TEST_F(LoginDefsOptionTest, UnsupportedRequestedOptionsFailBeforeReadingFile)
{
    for (const string option : {"UID_MIN", "UID_MAX", "OTHER", ""})
    {
        LoginDefsOptionParams params;
        params.option = option;
        params.value = "5";
        params.comparison = ComparisonOperation::Equal;
        const auto result = AuditLoginDefsOption(params, mIndicators, mContext);
        ASSERT_FALSE(result.HasValue()) << option;
        EXPECT_EQ(result.Error().code, EINVAL) << option;
        EXPECT_EQ(result.Error().message, "Unsupported login.defs option: " + option);
        EXPECT_TRUE(mIndicators.Back().indicators.empty()) << option;
    }
}

TEST_F(LoginDefsOptionTest, NumericOptionsRejectOverflowingValues)
{
    for (const string option : {"PASS_MAX_DAYS", "PASS_MIN_DAYS", "PASS_WARN_AGE"})
    {
        SetLoginDefsContent(option + " 2147483648\n");
        LoginDefsOptionParams params;
        params.option = option;
        params.value = "5";
        params.comparison = ComparisonOperation::Equal;
        const auto result = AuditLoginDefsOption(params, mIndicators, mContext);
        ASSERT_FALSE(result.HasValue()) << option;
        EXPECT_EQ(result.Error().code, EBADMSG) << option;
        EXPECT_NE(result.Error().message.find("invalid " + option + " value: Integer value out of range: 2147483648"), string::npos);
        EXPECT_TRUE(mIndicators.Back().indicators.empty()) << option;
    }
}

TEST_F(LoginDefsOptionTest, UnknownFileSettingsDoNotInvalidateSupportedOption)
{
    SetLoginDefsContent("OTHER 5junk\nENCRYPT_METHOD SHA512\n");
    LoginDefsOptionParams params;
    params.option = "ENCRYPT_METHOD";
    params.value = "SHA512";
    params.comparison = ComparisonOperation::Equal;
    const auto result = AuditLoginDefsOption(params, mIndicators, mContext);
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
    EXPECT_EQ(result.Error().message, "Unsupported comparison operation for numeric value: Unsupported comparison operation 6");
    EXPECT_TRUE(mIndicators.Back().indicators.empty());
}

TEST_F(LoginDefsOptionTest, RemediateUpdatesEffectiveValueAndPreservesOtherContent)
{
    const auto path = mContext.MakeTempfile(
        "# Password policy\n"
        "PASS_MAX_DAYS 99999\n"
        "PASS_MIN_DAYS 7\n"
        "PASS_MAX_DAYS 99999\n"
        "# Other settings remain intact\n");
    mContext.SetSpecialFilePath(cLoginDefsPath, path);
    EXPECT_CALL(mContext, GetFileContents(path)).WillRepeatedly(testing::Invoke([path](const string&) { return ReadFile(path); }));

    LoginDefsOptionParams params;
    params.option = "PASS_MAX_DAYS";
    params.value = "365";
    params.comparison = ComparisonOperation::LessOrEqual;

    auto result = RemediateLoginDefsOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);

    auto contents = ReadFile(path);
    ASSERT_TRUE(contents.HasValue());
    EXPECT_EQ(contents.Value(),
        "# Password policy\n"
        "PASS_MAX_DAYS 365\n"
        "PASS_MIN_DAYS 7\n"
        "PASS_MAX_DAYS 365\n"
        "# Other settings remain intact\n");
}

TEST_F(LoginDefsOptionTest, RemediateUpdatesEqualDuplicatesWithParserWhitespace)
{
    const auto path = mContext.MakeTempfile(" \tPASS_MAX_DAYS\v099999\nPASS_MAX_DAYS 99999\n");
    mContext.SetSpecialFilePath(cLoginDefsPath, path);
    EXPECT_CALL(mContext, GetFileContents(path)).WillRepeatedly(testing::Invoke([path](const string&) { return ReadFile(path); }));

    LoginDefsOptionParams params;
    params.option = "PASS_MAX_DAYS";
    params.value = "365";
    params.comparison = ComparisonOperation::LessOrEqual;

    const auto result = RemediateLoginDefsOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());
    const auto contents = ReadFile(path);
    ASSERT_TRUE(contents.HasValue());
    EXPECT_EQ(" \tPASS_MAX_DAYS\v365\nPASS_MAX_DAYS 365\n", contents.Value());
}

TEST_F(LoginDefsOptionTest, RemediatePreservesDistinctTrailingCommentsOnEqualNumericDuplicates)
{
    const auto path = mContext.MakeTempfile(
        " \tPASS_MAX_DAYS\v099999 \t# first policy\r\n"
        "PASS_MAX_DAYS\t99999\f# second policy\n"
        "PASS_MIN_DAYS 7\n");
    mContext.SetSpecialFilePath(cLoginDefsPath, path);
    EXPECT_CALL(mContext, GetFileContents(path)).WillRepeatedly(testing::Invoke([path](const string&) { return ReadFile(path); }));

    LoginDefsOptionParams params;
    params.option = "PASS_MAX_DAYS";
    params.value = "365";
    params.comparison = ComparisonOperation::LessOrEqual;

    const auto result = RemediateLoginDefsOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());
    const auto contents = ReadFile(path);
    ASSERT_TRUE(contents.HasValue());
    EXPECT_EQ(
        " \tPASS_MAX_DAYS\v365 \t# first policy\r\n"
        "PASS_MAX_DAYS\t365\f# second policy\n"
        "PASS_MIN_DAYS 7\n",
        contents.Value());
}

TEST_F(LoginDefsOptionTest, RemediatePreservesEncryptionTrailingComment)
{
    const auto path = mContext.MakeTempfile("ENCRYPT_METHOD\tMD5  # algorithm note\r\nPASS_MIN_DAYS 7\n");
    mContext.SetSpecialFilePath(cLoginDefsPath, path);
    EXPECT_CALL(mContext, GetFileContents(path)).WillRepeatedly(testing::Invoke([path](const string&) { return ReadFile(path); }));

    LoginDefsOptionParams params;
    params.option = "ENCRYPT_METHOD";
    params.value = "SHA512";
    params.comparison = ComparisonOperation::Equal;

    const auto result = RemediateLoginDefsOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());
    const auto contents = ReadFile(path);
    ASSERT_TRUE(contents.HasValue());
    EXPECT_EQ("ENCRYPT_METHOD\tSHA512  # algorithm note\r\nPASS_MIN_DAYS 7\n", contents.Value());
}

TEST_F(LoginDefsOptionTest, RemediateRefusesConflictingDuplicatesWithoutChangingFile)
{
    const string original = "PASS_MAX_DAYS 99999\nPASS_MAX_DAYS 730\n";
    const auto path = mContext.MakeTempfile(original);
    mContext.SetSpecialFilePath(cLoginDefsPath, path);
    EXPECT_CALL(mContext, GetFileContents(path)).WillRepeatedly(testing::Invoke([path](const string&) { return ReadFile(path); }));

    LoginDefsOptionParams params;
    params.option = "PASS_MAX_DAYS";
    params.value = "365";
    params.comparison = ComparisonOperation::LessOrEqual;

    const auto result = RemediateLoginDefsOption(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EBADMSG, result.Error().code);
    EXPECT_TRUE(mIndicators.Back().indicators.empty());
    const auto contents = ReadFile(path);
    ASSERT_TRUE(contents.HasValue());
    EXPECT_EQ(original, contents.Value());
}

TEST_F(LoginDefsOptionTest, RemediatePreservesExtendedAttributes)
{
    const auto path = mContext.MakeTempfile("PASS_MAX_DAYS 99999\n");
    const string attribute = "preserved";
    ASSERT_EQ(setxattr(path.c_str(), "user.kompli-test", attribute.data(), attribute.size(), 0), 0);
    mContext.SetSpecialFilePath(cLoginDefsPath, path);
    EXPECT_CALL(mContext, GetFileContents(path)).WillRepeatedly(testing::Invoke([path](const string&) { return ReadFile(path); }));

    LoginDefsOptionParams params;
    params.option = "PASS_MAX_DAYS";
    params.value = "365";
    params.comparison = ComparisonOperation::Equal;

    auto result = RemediateLoginDefsOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);

    char value[32];
    const ssize_t size = getxattr(path.c_str(), "user.kompli-test", value, sizeof(value));
    ASSERT_EQ(size, static_cast<ssize_t>(attribute.size()));
    EXPECT_EQ(string(value, static_cast<size_t>(size)), attribute);
}

TEST_F(LoginDefsOptionTest, RemediateRollsBackWhenPostAuditFails)
{
    const string original = "PASS_MAX_DAYS 99999\n";
    const auto path = mContext.MakeTempfile(original);
    mContext.SetSpecialFilePath(cLoginDefsPath, path);
    EXPECT_CALL(mContext, GetFileContents(path))
        .WillOnce(testing::Invoke([path](const string&) { return ReadFile(path); }))
        .WillOnce(testing::Invoke([path](const string&) { return ReadFile(path); }))
        .WillOnce(Return(Result<string>(Error("Post-audit failed", EIO))));

    LoginDefsOptionParams params;
    params.option = "PASS_MAX_DAYS";
    params.value = "365";
    params.comparison = ComparisonOperation::Equal;

    auto result = RemediateLoginDefsOption(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, EIO);

    auto contents = ReadFile(path);
    ASSERT_TRUE(contents.HasValue());
    EXPECT_EQ(contents.Value(), original);
}

TEST_F(LoginDefsOptionTest, RemediateAppendsMissingOption)
{
    const auto path = mContext.MakeTempfile("# Existing settings\nPASS_MIN_DAYS 7");
    mContext.SetSpecialFilePath(cLoginDefsPath, path);
    EXPECT_CALL(mContext, GetFileContents(path)).WillRepeatedly(testing::Invoke([path](const string&) { return ReadFile(path); }));

    LoginDefsOptionParams params;
    params.option = "PASS_MAX_DAYS";
    params.value = "365";
    params.comparison = ComparisonOperation::Equal;

    auto result = RemediateLoginDefsOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);

    auto contents = ReadFile(path);
    ASSERT_TRUE(contents.HasValue());
    EXPECT_EQ(contents.Value(), "# Existing settings\nPASS_MIN_DAYS 7\nPASS_MAX_DAYS\t365\n");
}

TEST_F(LoginDefsOptionTest, RemediateStrictComparisonUsesSatisfyingValue)
{
    const auto path = mContext.MakeTempfile("PASS_MAX_DAYS 365\n");
    mContext.SetSpecialFilePath(cLoginDefsPath, path);
    EXPECT_CALL(mContext, GetFileContents(path)).WillRepeatedly(testing::Invoke([path](const string&) { return ReadFile(path); }));

    LoginDefsOptionParams params;
    params.option = "PASS_MAX_DAYS";
    params.value = "365";
    params.comparison = ComparisonOperation::LessThan;

    auto result = RemediateLoginDefsOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);

    auto contents = ReadFile(path);
    ASSERT_TRUE(contents.HasValue());
    EXPECT_EQ(contents.Value(), "PASS_MAX_DAYS 364\n");
}

TEST_F(LoginDefsOptionTest, RemediateNotEqualIsUnsupported)
{
    LoginDefsOptionParams params;
    params.option = "ENCRYPT_METHOD";
    params.value = "MD5";
    params.comparison = ComparisonOperation::NotEqual;

    auto result = RemediateLoginDefsOption(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, ENOTSUP);
}

TEST_F(LoginDefsOptionTest, RemediateCompliantFileIsNoOp)
{
    const auto path = mContext.MakeTempfile("PASS_MAX_DAYS 365\n");
    mContext.SetSpecialFilePath(cLoginDefsPath, path);
    EXPECT_CALL(mContext, GetFileContents(path)).WillOnce(testing::Invoke([path](const string&) { return ReadFile(path); }));
    struct stat before;
    ASSERT_EQ(stat(path.c_str(), &before), 0);

    LoginDefsOptionParams params;
    params.option = "PASS_MAX_DAYS";
    params.value = "365";
    params.comparison = ComparisonOperation::Equal;

    auto result = RemediateLoginDefsOption(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);

    struct stat after;
    ASSERT_EQ(stat(path.c_str(), &after), 0);
    EXPECT_EQ(before.st_ino, after.st_ino);
}

TEST_F(LoginDefsOptionTest, RemediateRejectsSymlink)
{
    const auto target = mContext.MakeTempfile("PASS_MAX_DAYS 99999\n");
    const auto link = mContext.GetTempdirPath() + "/login.defs";
    ASSERT_EQ(symlink(target.c_str(), link.c_str()), 0);
    mContext.SetSpecialFilePath(cLoginDefsPath, link);
    EXPECT_CALL(mContext, GetFileContents(link)).WillRepeatedly(testing::Invoke([target](const string&) { return ReadFile(target); }));

    LoginDefsOptionParams params;
    params.option = "PASS_MAX_DAYS";
    params.value = "365";
    params.comparison = ComparisonOperation::Equal;

    auto result = RemediateLoginDefsOption(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, EINVAL);

    auto contents = ReadFile(target);
    ASSERT_TRUE(contents.HasValue());
    EXPECT_EQ(contents.Value(), "PASS_MAX_DAYS 99999\n");
}
