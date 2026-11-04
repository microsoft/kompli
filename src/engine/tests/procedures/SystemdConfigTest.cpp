// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "MockContext.h"

#include <SystemdConfig.h>
#include <cerrno>
#include <fstream>
#include <gtest/gtest.h>
#include <iterator>
#include <limits>
#include <regex>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

using ComplianceEngine::AuditSystemdConfigValue;
using ComplianceEngine::Error;
using ComplianceEngine::IndicatorsTree;
using ComplianceEngine::RemediateSystemdConfigValue;
using ComplianceEngine::Result;
using ComplianceEngine::Status;
using ComplianceEngine::SystemdConfigValueOperator;
using ComplianceEngine::SystemdConfigValueParams;
using ::testing::Return;

namespace
{
Result<std::string> ReadTestFile(const std::string& path)
{
    std::ifstream input(path);
    if (!input.is_open())
    {
        return Error("Failed to read test file", errno);
    }
    return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}
} // namespace

class SystemdConfigTest : public ::testing::Test
{
protected:
    MockContext mContext;
    IndicatorsTree mIndicators;

    void SetUp() override
    {
        mIndicators.Push("SystemdParameter");
    }

    void TearDown() override
    {
    }
};

TEST_F(SystemdConfigTest, NeitherFileNorDirProvided)
{
    SystemdConfigValueParams params;
    params.parameter = "TestParam";
    params.valueRegex = std::regex(".*");

    auto result = AuditSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    ASSERT_EQ(result.Error().message, "Neither 'file' nor 'dir' argument is provided");
}

TEST_F(SystemdConfigTest, RemediateExactValueInExistingBlock)
{
    const std::string logicalPath = "/etc/systemd/system.conf";
    const auto configPath = mContext.MakeTempfile(
        "[Manager]\n"
        "DefaultLimitNOFILE=1024\n");
    mContext.SetSpecialFilePath(logicalPath, configPath);
    EXPECT_CALL(mContext, GetFileContents(configPath)).WillRepeatedly(::testing::Invoke([](const std::string& path) { return ReadTestFile(path); }));
    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("cat-config \"" + logicalPath + "\"")))
        .WillRepeatedly(::testing::Invoke([configPath, logicalPath](const std::string&) {
            auto contents = ReadTestFile(configPath);
            if (!contents.HasValue())
            {
                return contents;
            }
            return Result<std::string>("# " + logicalPath + "\n" + contents.Value());
        }));

    SystemdConfigValueParams params;
    params.parameter = "DefaultLimitNOFILE";
    params.op = SystemdConfigValueOperator::Equal;
    params.value = "65536";
    params.file = logicalPath;
    params.block = "Manager";

    auto result = RemediateSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
    auto contents = ReadTestFile(configPath);
    ASSERT_TRUE(contents.HasValue());
    EXPECT_EQ(contents.Value(), "[Manager]\nDefaultLimitNOFILE=65536\n");
}

TEST_F(SystemdConfigTest, RemediateReplacesLastValueAcrossDuplicateBlocks)
{
    const std::string logicalPath = "/etc/systemd/system.conf";
    const auto configPath = mContext.MakeTempfile(
        "[Manager]\n"
        "DefaultLimitNOFILE=1024\n"
        "[Sleep]\n"
        "AllowSuspend=yes\n"
        "[Manager]\n"
        "DefaultLimitNOFILE=2048\n");
    mContext.SetSpecialFilePath(logicalPath, configPath);
    EXPECT_CALL(mContext, GetFileContents(configPath)).WillRepeatedly(::testing::Invoke([](const std::string& path) { return ReadTestFile(path); }));
    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("cat-config \"" + logicalPath + "\"")))
        .WillRepeatedly(::testing::Invoke([configPath, logicalPath](const std::string&) {
            auto contents = ReadTestFile(configPath);
            if (!contents.HasValue())
            {
                return contents;
            }
            return Result<std::string>("# " + logicalPath + "\n" + contents.Value());
        }));

    SystemdConfigValueParams params;
    params.parameter = "DefaultLimitNOFILE";
    params.op = SystemdConfigValueOperator::Equal;
    params.value = "65536";
    params.file = logicalPath;
    params.block = "Manager";

    auto result = RemediateSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);

    auto contents = ReadTestFile(configPath);
    ASSERT_TRUE(contents.HasValue());
    EXPECT_EQ(contents.Value(),
        "[Manager]\n"
        "DefaultLimitNOFILE=1024\n"
        "[Sleep]\n"
        "AllowSuspend=yes\n"
        "[Manager]\n"
        "DefaultLimitNOFILE=65536\n");
}

TEST_F(SystemdConfigTest, RemediateAddsMissingValueToExistingBlock)
{
    const std::string logicalPath = "/etc/systemd/system.conf";
    const auto configPath = mContext.MakeTempfile(
        "[Manager]\n"
        "DefaultTimeoutStopSec=90s\n"
        "[Sleep]\n"
        "AllowSuspend=yes\n");
    mContext.SetSpecialFilePath(logicalPath, configPath);
    EXPECT_CALL(mContext, GetFileContents(configPath)).WillRepeatedly(::testing::Invoke([](const std::string& path) { return ReadTestFile(path); }));
    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("cat-config \"" + logicalPath + "\"")))
        .WillRepeatedly(::testing::Invoke([configPath, logicalPath](const std::string&) {
            auto contents = ReadTestFile(configPath);
            if (!contents.HasValue())
            {
                return contents;
            }
            return Result<std::string>("# " + logicalPath + "\n" + contents.Value());
        }));

    SystemdConfigValueParams params;
    params.parameter = "DefaultLimitNOFILE";
    params.op = SystemdConfigValueOperator::Equal;
    params.value = "65536";
    params.file = logicalPath;
    params.block = "Manager";

    auto result = RemediateSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
    auto contents = ReadTestFile(configPath);
    ASSERT_TRUE(contents.HasValue());
    EXPECT_EQ(contents.Value(),
        "[Manager]\n"
        "DefaultTimeoutStopSec=90s\n"
        "DefaultLimitNOFILE=65536\n"
        "[Sleep]\n"
        "AllowSuspend=yes\n");
}

TEST_F(SystemdConfigTest, RemediateLeavesCompliantFileUnchanged)
{
    const std::string logicalPath = "/etc/systemd/system.conf";
    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("cat-config \"" + logicalPath + "\"")))
        .WillOnce(Return(Result<std::string>("# /etc/systemd/system.conf\n"
                                             "[Manager]\n"
                                             "DefaultLimitNOFILE=65536\n")));
    EXPECT_CALL(mContext, GetFileContents(::testing::_)).Times(0);

    SystemdConfigValueParams params;
    params.parameter = "DefaultLimitNOFILE";
    params.op = SystemdConfigValueOperator::Equal;
    params.value = "65536";
    params.file = logicalPath;
    params.block = "Manager";

    auto result = RemediateSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(SystemdConfigTest, RemediateRollsBackWhenPostAuditFails)
{
    const std::string logicalPath = "/etc/systemd/system.conf";
    const std::string original =
        "[Manager]\n"
        "DefaultLimitNOFILE=1024\n";
    const auto configPath = mContext.MakeTempfile(original);
    mContext.SetSpecialFilePath(logicalPath, configPath);
    EXPECT_CALL(mContext, GetFileContents(configPath)).WillRepeatedly(::testing::Invoke([](const std::string& path) { return ReadTestFile(path); }));
    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("cat-config \"" + logicalPath + "\"")))
        .WillRepeatedly(Return(Result<std::string>("# /usr/lib/systemd/system.conf\n"
                                                   "[Manager]\n"
                                                   "DefaultLimitNOFILE=1024\n")));

    SystemdConfigValueParams params;
    params.parameter = "DefaultLimitNOFILE";
    params.op = SystemdConfigValueOperator::Equal;
    params.value = "65536";
    params.file = logicalPath;
    params.block = "Manager";

    auto result = RemediateSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
    auto contents = ReadTestFile(configPath);
    ASSERT_TRUE(contents.HasValue());
    EXPECT_EQ(contents.Value(), original);
}

TEST_F(SystemdConfigTest, RemediateRejectsIntermediateSymlink)
{
    const std::string logicalPath = "/etc/systemd/redirect/system.conf";
    const std::string outsideDirectory = mContext.GetTempdirPath() + "/outside";
    ASSERT_EQ(mkdir(outsideDirectory.c_str(), 0700), 0);
    const std::string targetPath = outsideDirectory + "/system.conf";
    {
        std::ofstream target(targetPath);
        target << "[Manager]\nDefaultLimitNOFILE=1024\n";
    }
    const std::string redirect = mContext.GetTempdirPath() + "/redirect";
    ASSERT_EQ(symlink(outsideDirectory.c_str(), redirect.c_str()), 0);
    const std::string configPath = redirect + "/system.conf";
    mContext.SetSpecialFilePath(logicalPath, configPath);

    EXPECT_CALL(mContext, GetFileContents(configPath)).WillOnce(::testing::Invoke([](const std::string& path) { return ReadTestFile(path); }));
    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("cat-config \"" + logicalPath + "\"")))
        .WillOnce(Return(Result<std::string>("# " + logicalPath +
                                             "\n"
                                             "[Manager]\n"
                                             "DefaultLimitNOFILE=1024\n")));

    SystemdConfigValueParams params;
    params.parameter = "DefaultLimitNOFILE";
    params.op = SystemdConfigValueOperator::Equal;
    params.value = "65536";
    params.file = logicalPath;
    params.block = "Manager";

    auto result = RemediateSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());

    auto contents = ReadTestFile(targetPath);
    ASSERT_TRUE(contents.HasValue());
    EXPECT_EQ(contents.Value(), "[Manager]\nDefaultLimitNOFILE=1024\n");
}

TEST_F(SystemdConfigTest, RemediateRejectsRegexAndAmbiguousTargets)
{
    SystemdConfigValueParams params;
    params.parameter = "DefaultLimitNOFILE";
    params.valueRegex = std::regex("^[0-9]+$");
    params.file = "/etc/systemd/system.conf";
    params.block = "Manager";

    auto regexResult = RemediateSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_FALSE(regexResult.HasValue());
    EXPECT_EQ(regexResult.Error().code, ENOTSUP);

    params.valueRegex.Reset();
    params.value = "65536";
    params.op = SystemdConfigValueOperator::GreaterOrEqual;
    auto rangeResult = RemediateSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_FALSE(rangeResult.HasValue());
    EXPECT_EQ(rangeResult.Error().code, ENOTSUP);

    params.op = SystemdConfigValueOperator::Equal;
    params.file = "system.conf";
    auto relativePathResult = RemediateSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_FALSE(relativePathResult.HasValue());
    EXPECT_EQ(relativePathResult.Error().code, ENOTSUP);

    params.file = "/tmp/system.conf";
    auto outsideSystemdResult = RemediateSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_FALSE(outsideSystemdResult.HasValue());
    EXPECT_EQ(outsideSystemdResult.Error().code, ENOTSUP);

    params.file = "/etc/systemd/../shadow";
    auto traversalResult = RemediateSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_FALSE(traversalResult.HasValue());
    EXPECT_EQ(traversalResult.Error().code, ENOTSUP);

    params.file = "/etc/systemd/system.conf";
    params.block.Reset();
    auto missingBlockResult = RemediateSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_FALSE(missingBlockResult.HasValue());
    EXPECT_EQ(missingBlockResult.Error().code, ENOTSUP);
}

TEST_F(SystemdConfigTest, BothFileAndDirProvided)
{
    SystemdConfigValueParams params;
    params.parameter = "TestParam";
    params.valueRegex = std::regex(".*");
    params.file = "test.conf";
    params.dir = "/etc/systemd";

    auto result = AuditSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    ASSERT_EQ(result.Error().message, "Both 'file' and 'dir' arguments are provided, only one is allowed");
}

TEST_F(SystemdConfigTest, FileCommandExecutionFails)
{
    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("/usr/bin/systemd-analyze cat-config \"test.conf\"")))
        .WillOnce(Return(Result<std::string>(Error("Command execution failed", -1))));

    SystemdConfigValueParams params;
    params.parameter = "TestParam";
    params.valueRegex = std::regex(".*");
    params.file = "test.conf";

    auto result = AuditSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    ASSERT_EQ(result.Error().message, "Command execution failed");
}

TEST_F(SystemdConfigTest, FileParameterNotFound)
{
    std::string systemdOutput =
        "# /etc/systemd/test.conf\n"
        "OtherParam=value1\n"
        "AnotherParam=value2\n";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("/usr/bin/systemd-analyze cat-config \"test.conf\""))).WillOnce(Return(Result<std::string>(systemdOutput)));

    SystemdConfigValueParams params;
    params.parameter = "TestParam";
    params.valueRegex = std::regex(".*");
    params.file = "test.conf";

    auto result = AuditSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(SystemdConfigTest, FileParameterFoundButRegexMismatch)
{
    std::string systemdOutput =
        "# /etc/systemd/test.conf\n"
        "TestParam=wrongvalue\n"
        "OtherParam=value1\n";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("/usr/bin/systemd-analyze cat-config \"test.conf\""))).WillOnce(Return(Result<std::string>(systemdOutput)));

    SystemdConfigValueParams params;
    params.parameter = "TestParam";
    params.valueRegex = std::regex("^correctvalue$");
    params.file = "test.conf";

    auto result = AuditSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(SystemdConfigTest, FileParameterFoundAndRegexMatches)
{
    std::string systemdOutput =
        "# /etc/systemd/test.conf\n"
        "TestParam=correctvalue\n"
        "OtherParam=value1\n";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("/usr/bin/systemd-analyze cat-config \"test.conf\""))).WillOnce(Return(Result<std::string>(systemdOutput)));

    SystemdConfigValueParams params;
    params.parameter = "TestParam";
    params.valueRegex = std::regex("^correctvalue$");
    params.file = "test.conf";

    auto result = AuditSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(SystemdConfigTest, FileParameterWithComplexRegex)
{
    std::string systemdOutput =
        "# /etc/systemd/system.conf\n"
        "DefaultLimitNOFILE=65536\n"
        "DefaultTimeoutStopSec=90s\n";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("/usr/bin/systemd-analyze cat-config \"system.conf\""))).WillOnce(Return(Result<std::string>(systemdOutput)));

    SystemdConfigValueParams params;
    params.parameter = "DefaultLimitNOFILE";
    params.valueRegex = std::regex("^[0-9]+$");
    params.file = "system.conf";

    auto result = AuditSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(SystemdConfigTest, FileWithMultipleConfigSections)
{
    std::string systemdOutput =
        "# /etc/systemd/system.conf\n"
        "DefaultLimitNOFILE=1024\n"
        "# /usr/lib/systemd/system.conf\n"
        "DefaultLimitNOFILE=65536\n"
        "DefaultTimeoutStopSec=90s\n";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("/usr/bin/systemd-analyze cat-config \"system.conf\""))).WillOnce(Return(Result<std::string>(systemdOutput)));

    SystemdConfigValueParams params;
    params.parameter = "DefaultLimitNOFILE";
    params.valueRegex = std::regex("^65536$");
    params.file = "system.conf";

    auto result = AuditSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(SystemdConfigTest, FileWithCommentsAndEmptyLines)
{
    std::string systemdOutput =
        "# /etc/systemd/test.conf\n"
        "\n"
        "# This is a comment\n"
        "TestParam=value123\n"
        "\n"
        "# Another comment\n"
        "OtherParam=othervalue\n";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("/usr/bin/systemd-analyze cat-config \"test.conf\""))).WillOnce(Return(Result<std::string>(systemdOutput)));

    SystemdConfigValueParams params;
    params.parameter = "TestParam";
    params.valueRegex = std::regex("value[0-9]+");
    params.file = "test.conf";

    auto result = AuditSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(SystemdConfigTest, FileWithInvalidLineFormat)
{
    std::string systemdOutput =
        "# /etc/systemd/test.conf\n"
        "TestParam=correctvalue\n"
        "InvalidLineWithoutEquals\n"
        "OtherParam=value1\n";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("/usr/bin/systemd-analyze cat-config \"test.conf\""))).WillOnce(Return(Result<std::string>(systemdOutput)));

    SystemdConfigValueParams params;
    params.parameter = "TestParam";
    params.valueRegex = std::regex("correctvalue");
    params.file = "test.conf";

    auto result = AuditSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(SystemdConfigTest, FileParameterWithAnyValueRegex)
{
    std::string systemdOutput =
        "# /etc/systemd/test.conf\n"
        "TestParam=any_value_should_match\n";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("/usr/bin/systemd-analyze cat-config \"test.conf\""))).WillOnce(Return(Result<std::string>(systemdOutput)));

    SystemdConfigValueParams params;
    params.parameter = "TestParam";
    params.valueRegex = std::regex(".*");
    params.file = "test.conf";

    auto result = AuditSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(SystemdConfigTest, FileParameterWithEmptyValue)
{
    std::string systemdOutput =
        "# /etc/systemd/test.conf\n"
        "TestParam=\n"
        "OtherParam=value1\n";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("/usr/bin/systemd-analyze cat-config \"test.conf\""))).WillOnce(Return(Result<std::string>(systemdOutput)));

    SystemdConfigValueParams params;
    params.parameter = "TestParam";
    params.valueRegex = std::regex("^$");
    params.file = "test.conf";

    auto result = AuditSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(SystemdConfigTest, FileParameterWithSpecialCharacters)
{
    std::string systemdOutput =
        "# /etc/systemd/test.conf\n"
        "TestParam=/path/to/file with spaces\n";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("/usr/bin/systemd-analyze cat-config \"test.conf\""))).WillOnce(Return(Result<std::string>(systemdOutput)));

    SystemdConfigValueParams params;
    params.parameter = "TestParam";
    params.valueRegex = std::regex("/path/to/file with spaces");
    params.file = "test.conf";

    auto result = AuditSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

// --- Tests for op + value comparisons ---

TEST_F(SystemdConfigTest, NeitherValueNorValueRegexProvided)
{
    SystemdConfigValueParams params;
    params.parameter = "TestParam";
    params.file = "test.conf";
    // Neither value nor valueRegex set

    auto result = AuditSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    ASSERT_EQ(result.Error().message, "'value' (or 'valueRegex') must be provided");
}

TEST_F(SystemdConfigTest, OpWithoutValueProvided)
{
    SystemdConfigValueParams params;
    params.parameter = "TestParam";
    params.file = "test.conf";
    params.op = SystemdConfigValueOperator::Equal;
    // Neither value nor valueRegex set

    auto result = AuditSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    ASSERT_EQ(result.Error().message, "'value' (or 'valueRegex') must be provided");
}

TEST_F(SystemdConfigTest, OpWithValueRegexNotAllowed)
{
    SystemdConfigValueParams params;
    params.parameter = "TestParam";
    params.file = "test.conf";
    params.op = SystemdConfigValueOperator::LessThan;
    params.valueRegex = std::regex("^[0-9]+$");
    // op requires value, not valueRegex

    auto result = AuditSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    ASSERT_EQ(result.Error().message, "'op' requires 'value' (not 'valueRegex')");
}

TEST_F(SystemdConfigTest, BothValueAndValueRegexProvided)
{
    SystemdConfigValueParams params;
    params.parameter = "TestParam";
    params.file = "test.conf";
    params.value = std::string("99");
    params.valueRegex = std::regex("^42$");

    auto result = AuditSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    ASSERT_EQ(result.Error().message, "Both 'value' and 'valueRegex' are provided, only one is allowed");
}

TEST_F(SystemdConfigTest, ValueWithoutOpTreatedAsRegexCompliant)
{
    std::string systemdOutput =
        "# /etc/systemd/test.conf\n"
        "TestParam=correctvalue\n";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("/usr/bin/systemd-analyze cat-config \"test.conf\""))).WillOnce(Return(Result<std::string>(systemdOutput)));

    SystemdConfigValueParams params;
    params.parameter = "TestParam";
    params.value = std::string("^correctvalue$");
    params.file = "test.conf";
    // No op, so value is treated as regex

    auto result = AuditSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(SystemdConfigTest, ValueWithoutOpTreatedAsRegexNonCompliant)
{
    std::string systemdOutput =
        "# /etc/systemd/test.conf\n"
        "TestParam=wrongvalue\n";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("/usr/bin/systemd-analyze cat-config \"test.conf\""))).WillOnce(Return(Result<std::string>(systemdOutput)));

    SystemdConfigValueParams params;
    params.parameter = "TestParam";
    params.value = std::string("^correctvalue$");
    params.file = "test.conf";
    // No op, so value is treated as regex

    auto result = AuditSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(SystemdConfigTest, ValueWithoutOpRegexPattern)
{
    std::string systemdOutput =
        "# /etc/systemd/test.conf\n"
        "TestParam=65536\n";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("/usr/bin/systemd-analyze cat-config \"test.conf\""))).WillOnce(Return(Result<std::string>(systemdOutput)));

    SystemdConfigValueParams params;
    params.parameter = "TestParam";
    params.value = std::string("^[0-9]+$");
    params.file = "test.conf";
    // No op, so value is treated as regex

    auto result = AuditSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(SystemdConfigTest, OperatorEqualCompliant)
{
    std::string systemdOutput =
        "# /etc/systemd/test.conf\n"
        "TestParam=hello\n";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("/usr/bin/systemd-analyze cat-config \"test.conf\""))).WillOnce(Return(Result<std::string>(systemdOutput)));

    SystemdConfigValueParams params;
    params.parameter = "TestParam";
    params.op = SystemdConfigValueOperator::Equal;
    params.value = std::string("hello");
    params.file = "test.conf";

    auto result = AuditSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(SystemdConfigTest, OperatorEqualNonCompliant)
{
    std::string systemdOutput =
        "# /etc/systemd/test.conf\n"
        "TestParam=world\n";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("/usr/bin/systemd-analyze cat-config \"test.conf\""))).WillOnce(Return(Result<std::string>(systemdOutput)));

    SystemdConfigValueParams params;
    params.parameter = "TestParam";
    params.op = SystemdConfigValueOperator::Equal;
    params.value = std::string("hello");
    params.file = "test.conf";

    auto result = AuditSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(SystemdConfigTest, OperatorLessThanCompliant)
{
    std::string systemdOutput =
        "# /etc/systemd/test.conf\n"
        "TestParam=5\n";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("/usr/bin/systemd-analyze cat-config \"test.conf\""))).WillOnce(Return(Result<std::string>(systemdOutput)));

    SystemdConfigValueParams params;
    params.parameter = "TestParam";
    params.op = SystemdConfigValueOperator::LessThan;
    params.value = std::string("10");
    params.file = "test.conf";

    auto result = AuditSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(SystemdConfigTest, OperatorLessThanNonCompliant)
{
    std::string systemdOutput =
        "# /etc/systemd/test.conf\n"
        "TestParam=10\n";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("/usr/bin/systemd-analyze cat-config \"test.conf\""))).WillOnce(Return(Result<std::string>(systemdOutput)));

    SystemdConfigValueParams params;
    params.parameter = "TestParam";
    params.op = SystemdConfigValueOperator::LessThan;
    params.value = std::string("10");
    params.file = "test.conf";

    auto result = AuditSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(SystemdConfigTest, OperatorLessOrEqualCompliant)
{
    std::string systemdOutput =
        "# /etc/systemd/test.conf\n"
        "TestParam=10\n";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("/usr/bin/systemd-analyze cat-config \"test.conf\""))).WillOnce(Return(Result<std::string>(systemdOutput)));

    SystemdConfigValueParams params;
    params.parameter = "TestParam";
    params.op = SystemdConfigValueOperator::LessOrEqual;
    params.value = std::string("10");
    params.file = "test.conf";

    auto result = AuditSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(SystemdConfigTest, OperatorLessOrEqualNonCompliant)
{
    std::string systemdOutput =
        "# /etc/systemd/test.conf\n"
        "TestParam=11\n";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("/usr/bin/systemd-analyze cat-config \"test.conf\""))).WillOnce(Return(Result<std::string>(systemdOutput)));

    SystemdConfigValueParams params;
    params.parameter = "TestParam";
    params.op = SystemdConfigValueOperator::LessOrEqual;
    params.value = std::string("10");
    params.file = "test.conf";

    auto result = AuditSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(SystemdConfigTest, OperatorGreaterThanCompliant)
{
    std::string systemdOutput =
        "# /etc/systemd/test.conf\n"
        "TestParam=100\n";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("/usr/bin/systemd-analyze cat-config \"test.conf\""))).WillOnce(Return(Result<std::string>(systemdOutput)));

    SystemdConfigValueParams params;
    params.parameter = "TestParam";
    params.op = SystemdConfigValueOperator::GreaterThan;
    params.value = std::string("50");
    params.file = "test.conf";

    auto result = AuditSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(SystemdConfigTest, OperatorGreaterThanNonCompliant)
{
    std::string systemdOutput =
        "# /etc/systemd/test.conf\n"
        "TestParam=50\n";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("/usr/bin/systemd-analyze cat-config \"test.conf\""))).WillOnce(Return(Result<std::string>(systemdOutput)));

    SystemdConfigValueParams params;
    params.parameter = "TestParam";
    params.op = SystemdConfigValueOperator::GreaterThan;
    params.value = std::string("50");
    params.file = "test.conf";

    auto result = AuditSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(SystemdConfigTest, OperatorGreaterOrEqualCompliant)
{
    std::string systemdOutput =
        "# /etc/systemd/test.conf\n"
        "TestParam=50\n";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("/usr/bin/systemd-analyze cat-config \"test.conf\""))).WillOnce(Return(Result<std::string>(systemdOutput)));

    SystemdConfigValueParams params;
    params.parameter = "TestParam";
    params.op = SystemdConfigValueOperator::GreaterOrEqual;
    params.value = std::string("50");
    params.file = "test.conf";

    auto result = AuditSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(SystemdConfigTest, OperatorGreaterOrEqualNonCompliant)
{
    std::string systemdOutput =
        "# /etc/systemd/test.conf\n"
        "TestParam=49\n";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("/usr/bin/systemd-analyze cat-config \"test.conf\""))).WillOnce(Return(Result<std::string>(systemdOutput)));

    SystemdConfigValueParams params;
    params.parameter = "TestParam";
    params.op = SystemdConfigValueOperator::GreaterOrEqual;
    params.value = std::string("50");
    params.file = "test.conf";

    auto result = AuditSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(SystemdConfigTest, NumericComparisonWithNonNumericActualValue)
{
    std::string systemdOutput =
        "# /etc/systemd/test.conf\n"
        "TestParam=notanumber\n";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("/usr/bin/systemd-analyze cat-config \"test.conf\""))).WillOnce(Return(Result<std::string>(systemdOutput)));

    SystemdConfigValueParams params;
    params.parameter = "TestParam";
    params.op = SystemdConfigValueOperator::LessThan;
    params.value = std::string("10");
    params.file = "test.conf";

    auto result = AuditSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_NE(result.Error().message.find("Failed to convert values to numbers"), std::string::npos);
}

TEST_F(SystemdConfigTest, NumericComparisonWithNonNumericExpectedValue)
{
    std::string systemdOutput =
        "# /etc/systemd/test.conf\n"
        "TestParam=42\n";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("/usr/bin/systemd-analyze cat-config \"test.conf\""))).WillOnce(Return(Result<std::string>(systemdOutput)));

    SystemdConfigValueParams params;
    params.parameter = "TestParam";
    params.op = SystemdConfigValueOperator::GreaterThan;
    params.value = std::string("abc");
    params.file = "test.conf";

    auto result = AuditSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_NE(result.Error().message.find("Failed to convert values to numbers"), std::string::npos);
}

TEST_F(SystemdConfigTest, OperatorEqualWithNumericStrings)
{
    std::string systemdOutput =
        "# /etc/systemd/test.conf\n"
        "TestParam=42\n";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("/usr/bin/systemd-analyze cat-config \"test.conf\""))).WillOnce(Return(Result<std::string>(systemdOutput)));

    SystemdConfigValueParams params;
    params.parameter = "TestParam";
    params.op = SystemdConfigValueOperator::Equal;
    params.value = std::string("42");
    params.file = "test.conf";

    auto result = AuditSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(SystemdConfigTest, TypedOperatorBoundariesPreserveStringEqualityAndLongOrdering)
{
    struct Case
    {
        std::string actual;
        std::string expected;
        SystemdConfigValueOperator operation;
        Status status;
    };
    const auto min = std::numeric_limits<long>::min();
    const auto max = std::numeric_limits<long>::max();
    const Case cases[] = {
        {"042", "42", SystemdConfigValueOperator::Equal, Status::NonCompliant},
        {"-1", "0", SystemdConfigValueOperator::LessThan, Status::Compliant},
        {"0", "-1", SystemdConfigValueOperator::GreaterThan, Status::Compliant},
        {std::to_string(min), std::to_string(min), SystemdConfigValueOperator::LessThan, Status::NonCompliant},
        {std::to_string(min), std::to_string(min), SystemdConfigValueOperator::LessOrEqual, Status::Compliant},
        {std::to_string(min), std::to_string(min + 1), SystemdConfigValueOperator::LessThan, Status::Compliant},
        {std::to_string(max), std::to_string(max), SystemdConfigValueOperator::GreaterThan, Status::NonCompliant},
        {std::to_string(max), std::to_string(max), SystemdConfigValueOperator::GreaterOrEqual, Status::Compliant},
        {std::to_string(max), std::to_string(max - 1), SystemdConfigValueOperator::GreaterThan, Status::Compliant},
    };
    for (const auto& test : cases)
    {
        const std::string output = "# /etc/systemd/test.conf\nTestParam=" + test.actual + "\n";
        EXPECT_CALL(mContext, ExecuteCommand("/usr/bin/systemd-analyze cat-config \"test.conf\"")).WillOnce(Return(Result<std::string>(output)));
        SystemdConfigValueParams params;
        params.parameter = "TestParam";
        params.file = "test.conf";
        params.value = test.expected;
        params.op = test.operation;
        IndicatorsTree indicators;
        indicators.Push("SystemdParameter");
        auto result = AuditSystemdConfigValue(params, indicators, mContext);
        ASSERT_TRUE(result.HasValue()) << test.actual;
        EXPECT_EQ(result.Value(), test.status) << test.actual;
        ASSERT_EQ(indicators.Back().indicators.size(), 1U);
        EXPECT_EQ(indicators.Back().indicators.front().status, test.status);
        EXPECT_EQ(indicators.Back().indicators.front().message,
            test.status == Status::Compliant ?
                "Parameter 'TestParam' found in file '/etc/systemd/test.conf' with value '" + test.actual + "'" :
                "Parameter 'TestParam' value '" + test.actual + "' in file '/etc/systemd/test.conf' does not satisfy the comparison");
    }
}

TEST_F(SystemdConfigTest, NumericOperatorKeepsMissingAndConversionPolicies)
{
    SystemdConfigValueParams params;
    params.parameter = "TestParam";
    params.file = "test.conf";
    params.op = SystemdConfigValueOperator::GreaterThan;
    params.value = "0";
    const std::string absent = "# /etc/systemd/test.conf\nOtherParam=1\n";

    EXPECT_CALL(mContext, ExecuteCommand("/usr/bin/systemd-analyze cat-config \"test.conf\"")).WillOnce(Return(Result<std::string>(absent)));
    IndicatorsTree missing;
    missing.Push("SystemdParameter");
    auto result = AuditSystemdConfigValue(params, missing, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
    ASSERT_EQ(missing.Back().indicators.size(), 1U);
    EXPECT_EQ(missing.Back().indicators.front().message, "Parameter 'TestParam' not found");

    EXPECT_CALL(mContext, ExecuteCommand("/usr/bin/systemd-analyze cat-config \"test.conf\"")).WillOnce(Return(Result<std::string>(absent)));
    params.passOnNotFound = true;
    IndicatorsTree optional;
    optional.Push("SystemdParameter");
    result = AuditSystemdConfigValue(params, optional, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
    ASSERT_EQ(optional.Back().indicators.size(), 1U);
    EXPECT_EQ(optional.Back().indicators.front().message, "Parameter 'TestParam' not found but Compliant due to passOnNotFound==true");

    EXPECT_CALL(mContext, ExecuteCommand("/usr/bin/systemd-analyze cat-config \"test.conf\""))
        .WillOnce(Return(Result<std::string>("# /etc/systemd/test.conf\nTestParam=abc\n")));
    IndicatorsTree invalid;
    invalid.Push("SystemdParameter");
    result = AuditSystemdConfigValue(params, invalid, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().message, "Failed to convert values to numbers for comparison: actual='abc', expected='0'");
    EXPECT_TRUE(invalid.Back().indicators.empty());
}

TEST_F(SystemdConfigTest, InvalidDirectNumericOperationReturnsErrorWithoutIndicator)
{
    EXPECT_CALL(mContext, ExecuteCommand("/usr/bin/systemd-analyze cat-config \"test.conf\""))
        .WillOnce(Return(Result<std::string>("# /etc/systemd/test.conf\nTestParam=1\n")));
    SystemdConfigValueParams params;
    params.parameter = "TestParam";
    params.file = "test.conf";
    params.op = static_cast<SystemdConfigValueOperator>(100);
    params.value = "0";

    auto result = AuditSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, EINVAL);
    EXPECT_EQ(result.Error().message, "Unsupported numeric comparison operation 100");
    EXPECT_TRUE(mIndicators.Back().indicators.empty());
}

// --- Tests for block parameter ---

TEST_F(SystemdConfigTest, BlockParameterFoundInCorrectBlock)
{
    std::string systemdOutput =
        "# /etc/systemd/test.conf\n"
        "[Service]\n"
        "ExecStart=/usr/bin/test\n"
        "Restart=always\n"
        "[Unit]\n"
        "Description=Test Unit\n";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("/usr/bin/systemd-analyze cat-config \"test.conf\""))).WillOnce(Return(Result<std::string>(systemdOutput)));

    SystemdConfigValueParams params;
    params.parameter = "Restart";
    params.valueRegex = std::regex("^always$");
    params.file = "test.conf";
    params.block = std::string("Service");

    auto result = AuditSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(SystemdConfigTest, BlockParameterNotFoundInWrongBlock)
{
    std::string systemdOutput =
        "# /etc/systemd/test.conf\n"
        "[Service]\n"
        "ExecStart=/usr/bin/test\n"
        "Restart=always\n"
        "[Unit]\n"
        "Description=Test Unit\n";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("/usr/bin/systemd-analyze cat-config \"test.conf\""))).WillOnce(Return(Result<std::string>(systemdOutput)));

    SystemdConfigValueParams params;
    params.parameter = "Restart";
    params.valueRegex = std::regex("^always$");
    params.file = "test.conf";
    params.block = std::string("Unit");

    auto result = AuditSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(SystemdConfigTest, BlockParameterNotFoundInNonexistentBlock)
{
    std::string systemdOutput =
        "# /etc/systemd/test.conf\n"
        "[Service]\n"
        "ExecStart=/usr/bin/test\n";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("/usr/bin/systemd-analyze cat-config \"test.conf\""))).WillOnce(Return(Result<std::string>(systemdOutput)));

    SystemdConfigValueParams params;
    params.parameter = "ExecStart";
    params.valueRegex = std::regex(".*");
    params.file = "test.conf";
    params.block = std::string("Install");

    auto result = AuditSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(SystemdConfigTest, SameParameterInDifferentBlocksWithBlockFilter)
{
    std::string systemdOutput =
        "# /etc/systemd/test.conf\n"
        "[Service]\n"
        "Type=simple\n"
        "[Socket]\n"
        "Type=stream\n";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("/usr/bin/systemd-analyze cat-config \"test.conf\""))).WillOnce(Return(Result<std::string>(systemdOutput)));

    SystemdConfigValueParams params;
    params.parameter = "Type";
    params.op = SystemdConfigValueOperator::Equal;
    params.value = std::string("stream");
    params.file = "test.conf";
    params.block = std::string("Socket");

    auto result = AuditSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(SystemdConfigTest, SameParameterInDifferentBlocksWithoutBlockFilter)
{
    std::string systemdOutput =
        "# /etc/systemd/test.conf\n"
        "[Service]\n"
        "Type=simple\n"
        "[Socket]\n"
        "Type=stream\n";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("/usr/bin/systemd-analyze cat-config \"test.conf\""))).WillOnce(Return(Result<std::string>(systemdOutput)));

    SystemdConfigValueParams params;
    params.parameter = "Type";
    params.op = SystemdConfigValueOperator::Equal;
    params.value = std::string("simple");
    params.file = "test.conf";
    // No block filter - should find the first occurrence

    auto result = AuditSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(SystemdConfigTest, BlockWithOperatorComparison)
{
    std::string systemdOutput =
        "# /etc/systemd/test.conf\n"
        "[Service]\n"
        "LimitNOFILE=65536\n"
        "[Unit]\n"
        "StartLimitBurst=5\n";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("/usr/bin/systemd-analyze cat-config \"test.conf\""))).WillOnce(Return(Result<std::string>(systemdOutput)));

    SystemdConfigValueParams params;
    params.parameter = "LimitNOFILE";
    params.op = SystemdConfigValueOperator::GreaterOrEqual;
    params.value = std::string("1024");
    params.file = "test.conf";
    params.block = std::string("Service");

    auto result = AuditSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(SystemdConfigTest, ParameterWithoutBlockHeaderFoundWithoutBlockFilter)
{
    // Parameters before any block header have an empty block
    std::string systemdOutput =
        "# /etc/systemd/test.conf\n"
        "GlobalParam=globalvalue\n"
        "[Service]\n"
        "ServiceParam=servicevalue\n";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("/usr/bin/systemd-analyze cat-config \"test.conf\""))).WillOnce(Return(Result<std::string>(systemdOutput)));

    SystemdConfigValueParams params;
    params.parameter = "GlobalParam";
    params.valueRegex = std::regex("^globalvalue$");
    params.file = "test.conf";
    // No block filter

    auto result = AuditSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(SystemdConfigTest, JournalCompressUsesPassOnNotFoundWhenOutputHasNoJournalSection)
{
    std::string systemdOutput = "# /etc/systemd/journald.conf\n";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("/usr/bin/systemd-analyze cat-config \"journald.conf\""))).WillOnce(Return(Result<std::string>(systemdOutput)));

    SystemdConfigValueParams params;
    params.parameter = "Compress";
    params.valueRegex = std::regex("^yes$");
    params.file = "journald.conf";
    params.block = std::string("Journal");
    params.passOnNotFound = true;

    auto result = AuditSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(SystemdConfigTest, JournalCompressUsesPassOnNotFoundWhenJournalSectionHasNoCompressLine)
{
    std::string systemdOutput =
        "# /etc/systemd/journald.conf\n"
        "[Journal]\n"
        "Storage=auto\n";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("/usr/bin/systemd-analyze cat-config \"journald.conf\""))).WillOnce(Return(Result<std::string>(systemdOutput)));

    SystemdConfigValueParams params;
    params.parameter = "Compress";
    params.valueRegex = std::regex("^yes$");
    params.file = "journald.conf";
    params.block = std::string("Journal");
    params.passOnNotFound = true;

    auto result = AuditSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(SystemdConfigTest, JournalCompressWinsOverPassOnNotFound)
{
    std::string systemdOutput =
        "# /etc/systemd/journald.conf\n"
        "[Journal]\n"
        "Compress=no\n";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("/usr/bin/systemd-analyze cat-config \"journald.conf\""))).WillOnce(Return(Result<std::string>(systemdOutput)));

    SystemdConfigValueParams params;
    params.parameter = "Compress";
    params.valueRegex = std::regex("^yes$");
    params.file = "journald.conf";
    params.block = std::string("Journal");
    params.passOnNotFound = true;

    auto result = AuditSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(SystemdConfigTest, FileParameterNotFoundButPassOnNotFound)
{
    std::string systemdOutput =
        "# /etc/systemd/test.conf\n"
        "OtherParam=value1\n"
        "AnotherParam=value2\n";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr("/usr/bin/systemd-analyze cat-config \"test.conf\""))).WillOnce(Return(Result<std::string>(systemdOutput)));

    SystemdConfigValueParams params;
    params.parameter = "TestParam";
    params.valueRegex = std::regex(".*");
    params.file = "test.conf";
    params.passOnNotFound = true;

    auto result = AuditSystemdConfigValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}
