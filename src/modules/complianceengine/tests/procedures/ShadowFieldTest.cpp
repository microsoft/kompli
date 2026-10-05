// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "CommonUtils.h"
#include "MockContext.h"

#include <Optional.h>
#include <ScopeGuard.h>
#include <ShadowField.h>
#include <fstream>

using ComplianceEngine::AuditShadowField;
using ComplianceEngine::ComparisonOperation;
using ComplianceEngine::Error;
using ComplianceEngine::Field;
using ComplianceEngine::IndicatorsTree;
using ComplianceEngine::NestedListFormatter;
using ComplianceEngine::Optional;
using ComplianceEngine::Result;
using ComplianceEngine::ShadowFieldParams;
using ComplianceEngine::Status;
using std::map;
using std::string;

class EnsureShadowContainsTest : public ::testing::Test
{
protected:
    MockContext mContext;
    IndicatorsTree mIndicators;
    NestedListFormatter mFormatter;
    string mTempDir;

    void SetUp() override
    {
        mIndicators.Push("ShadowContains");
        mTempDir = mContext.GetTempdirPath() + "/shadow-field";
        ASSERT_EQ(0, mkdir(mTempDir.c_str(), 0700));
    }

    string CreateTestShadowFile(string username, Optional<string> password, Optional<int> lastChange = Optional<int>(),
        Optional<int> minAge = Optional<int>(), Optional<int> maxAge = Optional<int>(), Optional<int> warnPeriod = Optional<int>(),
        Optional<int> inactivityPeriod = Optional<int>(), Optional<int> expirationDate = Optional<int>())
    {
        auto content = std::move(username);
        content += ":" + (password.HasValue() ? password.Value() : "");
        content += ":" + (lastChange.HasValue() ? std::to_string(lastChange.Value()) : "");
        content += ":" + (minAge.HasValue() ? std::to_string(minAge.Value()) : "");
        content += ":" + (maxAge.HasValue() ? std::to_string(maxAge.Value()) : "");
        content += ":" + (warnPeriod.HasValue() ? std::to_string(warnPeriod.Value()) : "");
        content += ":" + (inactivityPeriod.HasValue() ? std::to_string(inactivityPeriod.Value()) : "");
        content += ":" + (expirationDate.HasValue() ? std::to_string(expirationDate.Value()) : "");
        content += ":";

        return CreateTestShadowFile(std::move(content));
    }

    string CreateTestShadowFile(string content)
    {
        string shadowFilePath = mTempDir + "/shadow";
        std::ofstream shadowFile(shadowFilePath);
        if (!shadowFile.is_open())
        {
            OsConfigLogError(mContext.GetLogHandle(), "Failed to create test shadow file %s: %s", shadowFilePath.c_str(), strerror(errno));
            return string();
        }
        shadowFile << std::move(content);
        shadowFile.close();
        return shadowFilePath;
    }

    void RemoveTestShadowFile(const string& shadowFilePath)
    {
        if (shadowFilePath.empty())
        {
            return;
        }

        if (0 != remove(shadowFilePath.c_str()))
        {
            OsConfigLogError(mContext.GetLogHandle(), "Failed to remove test shadow file %s: %s", shadowFilePath.c_str(), strerror(errno));
        }
    }
};

TEST_F(EnsureShadowContainsTest, InvalidArguments_1)
{
    ShadowFieldParams params;
    params.field = Field::LastChange;
    params.value = "42";
    params.operation = ComparisonOperation::PatternMatch;
    // Use a non-empty password so the user is not skipped
    const auto path = CreateTestShadowFile("testuser:$6$:0::::::");
    mContext.SetSpecialFilePath("/etc/shadow", path);
    params.usernameOperation = ComparisonOperation::Equal; // unused but required by procedure
    auto result = AuditShadowField(params, mIndicators, mContext);
    RemoveTestShadowFile(path);
    ASSERT_FALSE(result.HasValue());
    ASSERT_EQ(result.Error().message, "Unsupported comparison operation for an integer type");
    ASSERT_EQ(result.Error().code, EINVAL);
}

TEST_F(EnsureShadowContainsTest, InvalidArguments_2)
{
    ShadowFieldParams params;
    params.field = Field::Username;
    params.value = "test";
    params.operation = ComparisonOperation::PatternMatch;
    const auto path = CreateTestShadowFile("testuser:$6$:0::::::");
    mContext.SetSpecialFilePath("/etc/shadow", path);
    params.usernameOperation = ComparisonOperation::Equal;
    auto result = AuditShadowField(params, mIndicators, mContext);
    RemoveTestShadowFile(path);
    ASSERT_FALSE(result.HasValue());
    ASSERT_EQ(result.Error().message, "Username field comparison is not supported");
    ASSERT_EQ(result.Error().code, EINVAL);
}

TEST_F(EnsureShadowContainsTest, InvalidArguments_3)
{
    ShadowFieldParams params;
    params.field = Field::EncryptionMethod;
    params.value = "asdf";
    params.operation = ComparisonOperation::PatternMatch;
    const auto path = CreateTestShadowFile("testuser:$6$:0::::::");
    mContext.SetSpecialFilePath("/etc/shadow", path);
    params.usernameOperation = ComparisonOperation::Equal;
    auto result = AuditShadowField(params, mIndicators, mContext);
    RemoveTestShadowFile(path);
    ASSERT_FALSE(result.HasValue());
    ASSERT_EQ(result.Error().message, "Unsupported comparison operation for encryption method");
    ASSERT_EQ(result.Error().code, EINVAL);
}

TEST_F(EnsureShadowContainsTest, InvalidArguments_4)
{
    ShadowFieldParams params;
    const auto path = CreateTestShadowFile("testuser::0::::::");
    params.field = Field::LastChange;
    params.value = "x";
    params.operation = ComparisonOperation::Equal;
    params.username = "testuser";
    params.usernameOperation = ComparisonOperation::Equal;
    mContext.SetSpecialFilePath("/etc/shadow", path);
    auto result = AuditShadowField(params, mIndicators, mContext);
    RemoveTestShadowFile(path);
    ASSERT_FALSE(result.HasValue());
    ASSERT_EQ(result.Error().message, string("invalid last password change date parameter value"));
}

TEST_F(EnsureShadowContainsTest, SpecificUser_1)
{
    ShadowFieldParams params;
    params.field = Field::Password;
    params.value = "test";
    params.operation = ComparisonOperation::PatternMatch;
    // Create controlled shadow file with password that does NOT contain 'test' so pattern fails
    const auto path = CreateTestShadowFile("testuser:$6$abc$xyz:0::::::");
    params.username = "testuser";
    params.usernameOperation = ComparisonOperation::Equal;
    mContext.SetSpecialFilePath("/etc/shadow", path);
    auto result = AuditShadowField(params, mIndicators, mContext);
    RemoveTestShadowFile(path);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureShadowContainsTest, SpecificUser_2)
{
    if (0 != getuid())
    {
        GTEST_SKIP() << "This test suite requires root privileges or fakeroot";
    }
    ShadowFieldParams params;
    params.field = Field::Password;
    params.value = "^.*$";
    params.operation = ComparisonOperation::PatternMatch;
    params.username = "root";
    auto result = AuditShadowField(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureShadowContainsTest, SpecificUser_3)
{
    if (0 != getuid())
    {
        GTEST_SKIP() << "This test suite requires root privileges or fakeroot";
    }
    ShadowFieldParams params;
    params.field = Field::Password;
    params.value = "^.*$";
    params.operation = ComparisonOperation::PatternMatch;
    params.username = "^root$";
    params.usernameOperation = ComparisonOperation::PatternMatch;
    auto result = AuditShadowField(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureShadowContainsTest, SpecificUser_4)
{
    if (0 != getuid())
    {
        GTEST_SKIP() << "This test suite requires root privileges or fakeroot";
    }
    ShadowFieldParams params;
    params.field = Field::Password;
    params.value = "^test$";
    params.operation = ComparisonOperation::PatternMatch;
    params.username = "^$";
    params.usernameOperation = ComparisonOperation::PatternMatch;
    auto result = AuditShadowField(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    // No users matched the empty string pattern so we return compliant status
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureShadowContainsTest, SpecificUser_5)
{
    if (0 != getuid())
    {
        GTEST_SKIP() << "This test suite requires root privileges or fakeroot";
    }
    ShadowFieldParams params;
    params.field = Field::Password;
    params.value = "^test$";
    params.operation = ComparisonOperation::PatternMatch;
    params.username = "^root$";
    params.usernameOperation = ComparisonOperation::Equal;
    auto result = AuditShadowField(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureShadowContainsTest, SpecificUser_6)
{
    ShadowFieldParams params;
    params.field = Field::Password;
    params.value = "^test$";
    params.operation = ComparisonOperation::PatternMatch;
    const auto path = CreateTestShadowFile("testuser:$6$abc$xyz:0::::::");
    params.username = "testuser";
    params.usernameOperation = ComparisonOperation::Equal;
    mContext.SetSpecialFilePath("/etc/shadow", path);
    auto result = AuditShadowField(params, mIndicators, mContext);
    RemoveTestShadowFile(path);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureShadowContainsTest, EncryptionMethod_1)
{
    ShadowFieldParams params;
    const auto path = CreateTestShadowFile("testuser", string("$6$rounds=5000$randomsalt$hashedpassword"));
    params.field = Field::EncryptionMethod;
    params.value = "SHA-512";
    params.operation = ComparisonOperation::Equal;
    params.username = "testuser";
    params.usernameOperation = ComparisonOperation::Equal;
    mContext.SetSpecialFilePath("/etc/shadow", path);
    auto result = AuditShadowField(params, mIndicators, mContext);
    RemoveTestShadowFile(path);
    if (!result.HasValue())
    {
        OsConfigLogError(mContext.GetLogHandle(), "AuditShadowField failed: %s", result.Error().message.c_str());
    }
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureShadowContainsTest, EncryptionMethod_2)
{
    ShadowFieldParams params;
    const auto path = CreateTestShadowFile("testuser", string(""));
    params.field = Field::EncryptionMethod;
    params.value = "SHA-512";
    params.operation = ComparisonOperation::NotEqual;
    params.username = "testuser";
    params.usernameOperation = ComparisonOperation::Equal;
    mContext.SetSpecialFilePath("/etc/shadow", path);
    auto result = AuditShadowField(params, mIndicators, mContext);
    RemoveTestShadowFile(path);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureShadowContainsTest, EncryptionMethod_3)
{
    ShadowFieldParams params;
    const auto path = CreateTestShadowFile("testuser", string("abcd"));
    params.field = Field::EncryptionMethod;
    params.value = "DES";
    params.operation = ComparisonOperation::Equal;
    params.username = "testuser";
    params.usernameOperation = ComparisonOperation::Equal;
    mContext.SetSpecialFilePath("/etc/shadow", path);
    auto result = AuditShadowField(params, mIndicators, mContext);
    RemoveTestShadowFile(path);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureShadowContainsTest, EncryptionMethod_4)
{
    ShadowFieldParams params;
    const auto path = CreateTestShadowFile("testuser", string("_abcd"));
    params.field = Field::EncryptionMethod;
    params.value = "BSDi";
    params.operation = ComparisonOperation::Equal;
    params.username = "testuser";
    params.usernameOperation = ComparisonOperation::Equal;
    mContext.SetSpecialFilePath("/etc/shadow", path);
    auto result = AuditShadowField(params, mIndicators, mContext);
    RemoveTestShadowFile(path);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureShadowContainsTest, EncryptionMethod_5)
{
    ShadowFieldParams params;
    const auto path = CreateTestShadowFile("testuser", string("!"));
    params.field = Field::EncryptionMethod;
    params.value = "None";
    params.operation = ComparisonOperation::Equal;
    params.username = "testuser";
    params.usernameOperation = ComparisonOperation::Equal;
    mContext.SetSpecialFilePath("/etc/shadow", path);
    auto result = AuditShadowField(params, mIndicators, mContext);
    RemoveTestShadowFile(path);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureShadowContainsTest, EncryptionMethod_6)
{
    ShadowFieldParams params;
    const auto path = CreateTestShadowFile("testuser", string("*"));
    params.field = Field::EncryptionMethod;
    params.value = "None";
    params.operation = ComparisonOperation::Equal;
    params.username = "testuser";
    params.usernameOperation = ComparisonOperation::Equal;
    mContext.SetSpecialFilePath("/etc/shadow", path);
    auto result = AuditShadowField(params, mIndicators, mContext);
    RemoveTestShadowFile(path);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureShadowContainsTest, EncryptionMethod_7)
{
    ShadowFieldParams params;
    const auto path = CreateTestShadowFile("testuser", string("$1$"));
    params.field = Field::EncryptionMethod;
    params.value = "MD5";
    params.operation = ComparisonOperation::Equal;
    params.username = "testuser";
    params.usernameOperation = ComparisonOperation::Equal;
    mContext.SetSpecialFilePath("/etc/shadow", path);
    auto result = AuditShadowField(params, mIndicators, mContext);
    RemoveTestShadowFile(path);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureShadowContainsTest, EncryptionMethod_8)
{
    ShadowFieldParams params;
    const auto path = CreateTestShadowFile("testuser", string("$2$"));
    params.field = Field::EncryptionMethod;
    params.value = "Blowfish";
    params.operation = ComparisonOperation::Equal;
    params.username = "testuser";
    params.usernameOperation = ComparisonOperation::Equal;
    mContext.SetSpecialFilePath("/etc/shadow", path);
    auto result = AuditShadowField(params, mIndicators, mContext);
    RemoveTestShadowFile(path);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureShadowContainsTest, EncryptionMethod_9)
{
    ShadowFieldParams params;
    const auto path = CreateTestShadowFile("testuser", string("$2a$"));
    params.field = Field::EncryptionMethod;
    params.value = "Blowfish";
    params.operation = ComparisonOperation::Equal;
    params.username = "testuser";
    params.usernameOperation = ComparisonOperation::Equal;
    mContext.SetSpecialFilePath("/etc/shadow", path);
    auto result = AuditShadowField(params, mIndicators, mContext);
    RemoveTestShadowFile(path);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureShadowContainsTest, EncryptionMethod_10)
{
    ShadowFieldParams params;
    const auto path = CreateTestShadowFile("testuser", string("$2y$"));
    params.field = Field::EncryptionMethod;
    params.value = "Blowfish";
    params.operation = ComparisonOperation::Equal;
    params.username = "testuser";
    params.usernameOperation = ComparisonOperation::Equal;
    mContext.SetSpecialFilePath("/etc/shadow", path);
    auto result = AuditShadowField(params, mIndicators, mContext);
    RemoveTestShadowFile(path);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureShadowContainsTest, EncryptionMethod_11)
{
    ShadowFieldParams params;
    const auto path = CreateTestShadowFile("testuser", string("$md5$"));
    params.field = Field::EncryptionMethod;
    params.value = "MD5";
    params.operation = ComparisonOperation::Equal;
    params.username = "testuser";
    params.usernameOperation = ComparisonOperation::Equal;
    mContext.SetSpecialFilePath("/etc/shadow", path);
    auto result = AuditShadowField(params, mIndicators, mContext);
    RemoveTestShadowFile(path);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureShadowContainsTest, EncryptionMethod_12)
{
    ShadowFieldParams params;
    const auto path = CreateTestShadowFile("testuser", string("$5$"));
    params.field = Field::EncryptionMethod;
    params.value = "SHA-256";
    params.operation = ComparisonOperation::Equal;
    params.username = "testuser";
    params.usernameOperation = ComparisonOperation::Equal;
    mContext.SetSpecialFilePath("/etc/shadow", path);
    auto result = AuditShadowField(params, mIndicators, mContext);
    RemoveTestShadowFile(path);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureShadowContainsTest, EncryptionMethod_13)
{
    ShadowFieldParams params;
    const auto path = CreateTestShadowFile("testuser", string("$y$"));
    params.field = Field::EncryptionMethod;
    params.value = "YesCrypt";
    params.operation = ComparisonOperation::Equal;
    params.username = "testuser";
    params.usernameOperation = ComparisonOperation::Equal;
    mContext.SetSpecialFilePath("/etc/shadow", path);
    auto result = AuditShadowField(params, mIndicators, mContext);
    RemoveTestShadowFile(path);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureShadowContainsTest, IntegerFields_1)
{
    ShadowFieldParams params;
    const auto path = CreateTestShadowFile("testuser", string("$y$"), 1, 2, 3, 4, 5, 6);
    params.field = Field::LastChange;
    params.value = "1";
    params.operation = ComparisonOperation::Equal;
    params.username = "testuser";
    params.usernameOperation = ComparisonOperation::Equal;
    mContext.SetSpecialFilePath("/etc/shadow", path);
    auto result = AuditShadowField(params, mIndicators, mContext);
    RemoveTestShadowFile(path);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureShadowContainsTest, IntegerFields_2)
{
    ShadowFieldParams params;
    const auto path = CreateTestShadowFile("testuser", string("$y$"), 1, 2, 3, 4, 5, 6);
    params.field = Field::MinAge;
    params.value = "2";
    params.operation = ComparisonOperation::Equal;
    params.username = "testuser";
    params.usernameOperation = ComparisonOperation::Equal;
    mContext.SetSpecialFilePath("/etc/shadow", path);
    auto result = AuditShadowField(params, mIndicators, mContext);
    RemoveTestShadowFile(path);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureShadowContainsTest, IntegerFields_3)
{
    ShadowFieldParams params;
    const auto path = CreateTestShadowFile("testuser", string("$y$"), 1, 2, 3, 4, 5, 6);
    params.field = Field::MaxAge;
    params.value = "3";
    params.operation = ComparisonOperation::Equal;
    params.username = "testuser";
    params.usernameOperation = ComparisonOperation::Equal;
    mContext.SetSpecialFilePath("/etc/shadow", path);
    auto result = AuditShadowField(params, mIndicators, mContext);
    RemoveTestShadowFile(path);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureShadowContainsTest, IntegerFields_4)
{
    ShadowFieldParams params;
    const auto path = CreateTestShadowFile("testuser", string("$y$"), 1, 2, 3, 4, 5, 6);
    params.field = Field::WarnPeriod;
    params.value = "4";
    params.operation = ComparisonOperation::Equal;
    params.username = "testuser";
    params.usernameOperation = ComparisonOperation::Equal;
    mContext.SetSpecialFilePath("/etc/shadow", path);
    auto result = AuditShadowField(params, mIndicators, mContext);
    RemoveTestShadowFile(path);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureShadowContainsTest, IntegerFields_5)
{
    ShadowFieldParams params;
    const auto path = CreateTestShadowFile("testuser", string("$y$"), 1, 2, 3, 4, 5, 6);
    params.field = Field::InactivityPeriod;
    params.value = "5";
    params.operation = ComparisonOperation::Equal;
    params.username = "testuser";
    params.usernameOperation = ComparisonOperation::Equal;
    mContext.SetSpecialFilePath("/etc/shadow", path);
    auto result = AuditShadowField(params, mIndicators, mContext);
    RemoveTestShadowFile(path);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureShadowContainsTest, IntegerFields_6)
{
    ShadowFieldParams params;
    const auto path = CreateTestShadowFile("testuser", string("$y$"), 1, 2, 3, 4, 5, 6);
    params.field = Field::ExpirationDate;
    params.value = "6";
    params.operation = ComparisonOperation::Equal;
    params.username = "testuser";
    params.usernameOperation = ComparisonOperation::Equal;
    mContext.SetSpecialFilePath("/etc/shadow", path);
    auto result = AuditShadowField(params, mIndicators, mContext);
    RemoveTestShadowFile(path);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureShadowContainsTest, FeatureFlag)
{
    ShadowFieldParams params;
    const auto path = CreateTestShadowFile("testuser", string("$y$"), 1, 2, 3, 4, 5, 6);
    params.field = Field::Reserved;
    params.value = "6";
    params.operation = ComparisonOperation::Equal;
    params.username = "testuser";
    params.usernameOperation = ComparisonOperation::Equal;
    mContext.SetSpecialFilePath("/etc/shadow", path);
    auto result = AuditShadowField(params, mIndicators, mContext);
    RemoveTestShadowFile(path);
    ASSERT_FALSE(result.HasValue());
    ASSERT_EQ(result.Error().message, string("reserved field comparison is not supported"));
}

TEST_F(EnsureShadowContainsTest, TypedIntegerComparisonsPreserveOperatorBoundaries)
{
    struct Case
    {
        ComparisonOperation operation;
        string expectedValue;
        Status expectedStatus;
    };
    const Case cases[] = {
        {ComparisonOperation::Equal, "5", Status::Compliant},
        {ComparisonOperation::Equal, "6", Status::NonCompliant},
        {ComparisonOperation::NotEqual, "6", Status::Compliant},
        {ComparisonOperation::NotEqual, "5", Status::NonCompliant},
        {ComparisonOperation::LessThan, "6", Status::Compliant},
        {ComparisonOperation::LessThan, "5", Status::NonCompliant},
        {ComparisonOperation::LessOrEqual, "5", Status::Compliant},
        {ComparisonOperation::LessOrEqual, "4", Status::NonCompliant},
        {ComparisonOperation::GreaterThan, "4", Status::Compliant},
        {ComparisonOperation::GreaterThan, "5", Status::NonCompliant},
        {ComparisonOperation::GreaterOrEqual, "5", Status::Compliant},
        {ComparisonOperation::GreaterOrEqual, "6", Status::NonCompliant},
    };
    const auto path = CreateTestShadowFile("testuser", string("$y$"), 5);
    ASSERT_FALSE(path.empty());
    ScopeGuard cleanup([&] { RemoveTestShadowFile(path); });
    mContext.SetSpecialFilePath("/etc/shadow", path);
    for (const auto& test : cases)
    {
        ShadowFieldParams params;
        params.username = "testuser";
        params.field = Field::LastChange;
        params.value = test.expectedValue;
        params.operation = test.operation;
        IndicatorsTree indicators;
        indicators.Push("ShadowContains");
        auto result = AuditShadowField(params, indicators, mContext);
        ASSERT_TRUE(result.HasValue()) << test.expectedValue;
        EXPECT_EQ(result.Value(), test.expectedStatus) << test.expectedValue;
        ASSERT_EQ(indicators.Back().indicators.size(), test.expectedStatus == Status::Compliant ? 2U : 1U);
        const auto& indicator = indicators.Back().indicators.front();
        EXPECT_EQ(indicator.status, test.expectedStatus);
        EXPECT_EQ(indicator.message, test.expectedStatus == Status::Compliant ?
                                         "last password change date matches expected value for user 'testuser'" :
                                         "last password change date does not match expected value for user 'testuser'");
    }
}

TEST_F(EnsureShadowContainsTest, StringOrderingAndInvalidIntegerKeepCallerPolicies)
{
    const auto path = CreateTestShadowFile("testuser", string("abc"), 5);
    ASSERT_FALSE(path.empty());
    ScopeGuard cleanup([&] { RemoveTestShadowFile(path); });
    mContext.SetSpecialFilePath("/etc/shadow", path);
    ShadowFieldParams params;
    params.username = "testuser";
    params.field = Field::Password;
    params.value = "abb";
    params.operation = ComparisonOperation::LessThan;
    auto result = AuditShadowField(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant); // supplied value precedes the stored password

    params.field = Field::LastChange;
    params.value = "2147483648";
    params.operation = ComparisonOperation::Equal;
    result = AuditShadowField(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, EINVAL);
    EXPECT_EQ(result.Error().message, "invalid last password change date parameter value");
}

TEST_F(EnsureShadowContainsTest, PasswordStringComparisonsPreserveOperandDirection)
{
    struct Case
    {
        ComparisonOperation operation;
        string supplied;
        Status expected;
    };
    const Case cases[] = {
        {ComparisonOperation::Equal, "abc", Status::Compliant},
        {ComparisonOperation::Equal, "abb", Status::NonCompliant},
        {ComparisonOperation::NotEqual, "abb", Status::Compliant},
        {ComparisonOperation::NotEqual, "abc", Status::NonCompliant},
        {ComparisonOperation::LessThan, "abb", Status::Compliant},
        {ComparisonOperation::LessThan, "abc", Status::NonCompliant},
        {ComparisonOperation::LessOrEqual, "abc", Status::Compliant},
        {ComparisonOperation::LessOrEqual, "abd", Status::NonCompliant},
        {ComparisonOperation::GreaterThan, "abd", Status::Compliant},
        {ComparisonOperation::GreaterThan, "abc", Status::NonCompliant},
        {ComparisonOperation::GreaterOrEqual, "abc", Status::Compliant},
        {ComparisonOperation::GreaterOrEqual, "abb", Status::NonCompliant},
    };
    const auto path = CreateTestShadowFile("testuser", string("abc"));
    ASSERT_FALSE(path.empty());
    ScopeGuard cleanup([&] { RemoveTestShadowFile(path); });
    mContext.SetSpecialFilePath("/etc/shadow", path);
    for (const auto& test : cases)
    {
        ShadowFieldParams params;
        params.username = "testuser";
        params.field = Field::Password;
        params.value = test.supplied;
        params.operation = test.operation;
        IndicatorsTree indicators;
        indicators.Push("ShadowContains");
        auto result = AuditShadowField(params, indicators, mContext);
        ASSERT_TRUE(result.HasValue());
        EXPECT_EQ(result.Value(), test.expected) << test.supplied;
        ASSERT_EQ(indicators.Back().indicators.size(), test.expected == Status::Compliant ? 2U : 1U);
        EXPECT_EQ(indicators.Back().indicators.front().status, test.expected);
    }
}

TEST_F(EnsureShadowContainsTest, UsernameSelectionAndMultipleEntriesRetainVerdict)
{
    const auto path = CreateTestShadowFile("alpha:$y$:5::::::\nbeta:$y$:4::::::\n");
    ASSERT_FALSE(path.empty());
    ScopeGuard cleanup([&] { RemoveTestShadowFile(path); });
    mContext.SetSpecialFilePath("/etc/shadow", path);
    ShadowFieldParams params;
    params.username = "alpha";
    params.usernameOperation = ComparisonOperation::LessThan;
    params.field = Field::LastChange;
    params.value = "5";
    params.operation = ComparisonOperation::Equal;
    auto result = AuditShadowField(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
    ASSERT_EQ(mIndicators.Back().indicators.size(), 1U);
    EXPECT_EQ(mIndicators.Back().indicators.front().message, "last password change date does not match expected value for user 'beta'");

    params.username = "test";
    params.usernameOperation = ComparisonOperation::Equal;
    IndicatorsTree absent;
    absent.Push("ShadowContains");
    result = AuditShadowField(params, absent, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
    ASSERT_EQ(absent.Back().indicators.size(), 1U);
    EXPECT_EQ(absent.Back().indicators.front().message, "last password change date matches expected value for all tested users");

    params.username.Reset();
    IndicatorsTree all;
    all.Push("ShadowContains");
    result = AuditShadowField(params, all, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
    ASSERT_EQ(all.Back().indicators.size(), 1U);
    EXPECT_EQ(all.Back().indicators.front().message, "last password change date does not match expected value for user 'beta'");
}

TEST_F(EnsureShadowContainsTest, LockedOnlyEntryKeepsCurrentAbsencePolicy)
{
    const auto path = CreateTestShadowFile("locked", string("!"), 5);
    ASSERT_FALSE(path.empty());
    ScopeGuard cleanup([&] { RemoveTestShadowFile(path); });
    mContext.SetSpecialFilePath("/etc/shadow", path);
    ShadowFieldParams params;
    params.username = "locked";
    params.field = Field::LastChange;
    params.value = "6";
    params.operation = ComparisonOperation::Equal;
    auto result = AuditShadowField(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
    ASSERT_EQ(mIndicators.Back().indicators.size(), 1U);
    EXPECT_EQ(mIndicators.Back().indicators.front().message, "last password change date matches expected value for all tested users");
}

TEST_F(EnsureShadowContainsTest, IntegerParsingAndUnsupportedOperationKeepErrorsLocal)
{
    const auto path = CreateTestShadowFile("testuser", string("$y$"), 5);
    ASSERT_FALSE(path.empty());
    ScopeGuard cleanup([&] { RemoveTestShadowFile(path); });
    mContext.SetSpecialFilePath("/etc/shadow", path);
    ShadowFieldParams params;
    params.username = "testuser";
    params.field = Field::LastChange;
    params.value = "5junk";
    params.operation = ComparisonOperation::Equal;
    auto result = AuditShadowField(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);

    IndicatorsTree unsupported;
    unsupported.Push("ShadowContains");
    params.operation = ComparisonOperation::PatternMatch;
    result = AuditShadowField(params, unsupported, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, EINVAL);
    EXPECT_EQ(result.Error().message, "Unsupported comparison operation for an integer type");
    EXPECT_TRUE(unsupported.Back().indicators.empty());
}
