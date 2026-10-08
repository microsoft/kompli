// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "Evaluator.h"
#include "MockContext.h"

#include <GsettingsValue.h>
#include <ProcedureMap.h>
#include <dirent.h>
#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include <unistd.h>

using ComplianceEngine::AuditGsettingsValue;
using ComplianceEngine::Error;
using ComplianceEngine::GsettingsKeyType;
using ComplianceEngine::GsettingsOperationType;
using ComplianceEngine::GsettingsValueParams;
using ComplianceEngine::IndicatorsTree;
using ComplianceEngine::Result;
using ComplianceEngine::Status;

class EnsureGsettings : public ::testing::Test
{
protected:
    MockContext mContext;
    IndicatorsTree mIndicators;

    const std::string gsettingsRangeCmd = "gsettings range ";
    const std::string gsettingsGetCmd = "gsettings get ";
    const std::string gsettingsWritableCmd = "gsettings writable ";
    GsettingsValueParams mParams;

    const std::string gsettingsTypeS = "type s\n";
    const std::string gsettingsTypeU = "type u\n";
    const std::string gsettingsTypeI = "type i\n";

    std::string GsettingsRangeCmd()
    {
        return gsettingsRangeCmd + "\"" + mParams.schema + "\" \"" + mParams.key + "\"";
    }

    std::string GsettingsGetCmd()
    {
        return gsettingsGetCmd + "\"" + mParams.schema + "\" \"" + mParams.key + "\"";
    }

    std::string GsettingsWritableCmd()
    {
        return gsettingsWritableCmd + "\"" + mParams.schema + "\" \"" + mParams.key + "\"";
    }

    void SetUp() override
    {
        mIndicators.Push("EnsureGsettings");
    }
};

TEST_F(EnsureGsettings, AuditSuccessStringEqual)
{
    mParams.schema = "org.gnome.desktop.interface";
    mParams.key = "cursor-theme";
    mParams.keyType = GsettingsKeyType::String;
    mParams.operation = GsettingsOperationType::Equal;
    mParams.value = "Adwaita";

    EXPECT_CALL(mContext, ExecuteCommand(GsettingsRangeCmd())).WillOnce(::testing::Return(Result<std::string>(gsettingsTypeS)));
    EXPECT_CALL(mContext, ExecuteCommand(GsettingsGetCmd())).WillOnce(::testing::Return(Result<std::string>("\"Adwaita\"")));
    auto result = AuditGsettingsValue(mParams, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureGsettings, AuditSuccessStringNotEqual)
{
    mParams.schema = "org.gnome.desktop.interface";
    mParams.key = "cursor-theme";
    mParams.keyType = GsettingsKeyType::String;
    mParams.operation = GsettingsOperationType::NotEqual;
    mParams.value = "FOOOO";

    EXPECT_CALL(mContext, ExecuteCommand(GsettingsRangeCmd())).WillOnce(::testing::Return(Result<std::string>(gsettingsTypeS)));
    EXPECT_CALL(mContext, ExecuteCommand(GsettingsGetCmd())).WillOnce(::testing::Return(Result<std::string>("\"Adwaita\"")));
    auto result = AuditGsettingsValue(mParams, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}
TEST_F(EnsureGsettings, AuditSuccessNumberTypeIEqual)
{
    mParams.schema = "org.gnome.desktop.interface";
    mParams.key = "cursor-size";
    mParams.keyType = GsettingsKeyType::Number;
    mParams.operation = GsettingsOperationType::Equal;
    mParams.value = "1";

    EXPECT_CALL(mContext, ExecuteCommand(GsettingsRangeCmd())).WillOnce(::testing::Return(Result<std::string>(gsettingsTypeI)));
    EXPECT_CALL(mContext, ExecuteCommand(GsettingsGetCmd())).WillOnce(::testing::Return(Result<std::string>("1")));
    auto result = AuditGsettingsValue(mParams, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureGsettings, AuditSuccessNumberTypeUEqual)
{

    mParams.schema = "org.gnome.desktop.interface";
    mParams.key = "cursor-size";
    mParams.keyType = GsettingsKeyType::Number;
    mParams.operation = GsettingsOperationType::Equal;
    mParams.value = "1";

    EXPECT_CALL(mContext, ExecuteCommand(GsettingsRangeCmd())).WillOnce(::testing::Return(Result<std::string>(gsettingsTypeU)));
    EXPECT_CALL(mContext, ExecuteCommand(GsettingsGetCmd())).WillOnce(::testing::Return(Result<std::string>("uint32 1\n")));
    auto result = AuditGsettingsValue(mParams, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureGsettings, AuditSuccessNumberTypeUOpreationLowerThan)
{

    mParams.schema = "org.gnome.desktop.interface";
    mParams.key = "cursor-size";
    mParams.keyType = GsettingsKeyType::Number;
    mParams.operation = GsettingsOperationType::LessThan;
    mParams.value = "10";

    EXPECT_CALL(mContext, ExecuteCommand(GsettingsRangeCmd())).WillOnce(::testing::Return(Result<std::string>(gsettingsTypeU)));
    EXPECT_CALL(mContext, ExecuteCommand(GsettingsGetCmd())).WillOnce(::testing::Return(Result<std::string>("uint32 9\n")));
    auto result = AuditGsettingsValue(mParams, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}
TEST_F(EnsureGsettings, AuditSuccessNumberTypeUOpreationGreaterThan)
{

    mParams.schema = "org.gnome.desktop.interface";
    mParams.key = "cursor-size";
    mParams.keyType = GsettingsKeyType::Number;
    mParams.operation = GsettingsOperationType::GreaterThan;
    mParams.value = "42";

    EXPECT_CALL(mContext, ExecuteCommand(GsettingsRangeCmd())).WillOnce(::testing::Return(Result<std::string>(gsettingsTypeU)));
    EXPECT_CALL(mContext, ExecuteCommand(GsettingsGetCmd())).WillOnce(::testing::Return(Result<std::string>("uint32 420\n")));
    auto result = AuditGsettingsValue(mParams, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureGsettings, AuditSuccessNumberTypeIOpreationLowerThan)
{

    mParams.schema = "org.gnome.desktop.interface";
    mParams.key = "cursor-size";
    mParams.keyType = GsettingsKeyType::Number;
    mParams.operation = GsettingsOperationType::LessThan;
    mParams.value = "1337";

    EXPECT_CALL(mContext, ExecuteCommand(GsettingsRangeCmd())).WillOnce(::testing::Return(Result<std::string>(gsettingsTypeI)));
    EXPECT_CALL(mContext, ExecuteCommand(GsettingsGetCmd())).WillOnce(::testing::Return(Result<std::string>("42\n")));
    auto result = AuditGsettingsValue(mParams, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}
TEST_F(EnsureGsettings, AuditSuccessNumberTypeUOpreationNotEqual)
{

    mParams.schema = "org.gnome.desktop.interface";
    mParams.key = "cursor-size";
    mParams.keyType = GsettingsKeyType::Number;
    mParams.operation = GsettingsOperationType::NotEqual;
    mParams.value = "42";

    EXPECT_CALL(mContext, ExecuteCommand(GsettingsRangeCmd())).WillOnce(::testing::Return(Result<std::string>(gsettingsTypeU)));
    EXPECT_CALL(mContext, ExecuteCommand(GsettingsGetCmd())).WillOnce(::testing::Return(Result<std::string>("uint32 420\n")));
    auto result = AuditGsettingsValue(mParams, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureGsettings, AuditFailureWongOperation)
{

    mParams.schema = "org.gnome.desktop.interface";
    mParams.key = "cursor-size";
    mParams.keyType = GsettingsKeyType::String;
    mParams.operation = GsettingsOperationType::GreaterThan;
    mParams.value = "fooo bar qux";

    auto result = AuditGsettingsValue(mParams, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    ASSERT_EQ(result.Error().message, "Unsupported operation gt");
}

TEST_F(EnsureGsettings, AuditFailureArgNotANumber)
{

    mParams.schema = "org.gnome.desktop.interface";
    mParams.key = "cursor-size";
    mParams.keyType = GsettingsKeyType::Number;
    mParams.operation = GsettingsOperationType::Equal;
    mParams.value = "fooo bar qux";

    auto result = AuditGsettingsValue(mParams, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    ASSERT_EQ(result.Error().message, "Invalid argument value: not a number " + mParams.value);
}

TEST_F(EnsureGsettings, AuditFailureReturnedNotNumber)
{

    mParams.schema = "org.gnome.desktop.interface";
    mParams.key = "cursor-size";
    mParams.keyType = GsettingsKeyType::Number;
    mParams.operation = GsettingsOperationType::Equal;
    mParams.value = "1337";

    EXPECT_CALL(mContext, ExecuteCommand(GsettingsRangeCmd())).WillOnce(::testing::Return(Result<std::string>(gsettingsTypeI)));
    EXPECT_CALL(mContext, ExecuteCommand(GsettingsGetCmd())).WillOnce(::testing::Return(Result<std::string>("MORE COFFEE")));
    auto result = AuditGsettingsValue(mParams, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    ASSERT_EQ(result.Error().message, "Invalid operation value: not a number " + mParams.value);
}

TEST_F(EnsureGsettings, AuditSuccessIsUnlockedTrue)
{
    mParams.schema = "org.gnome.desktop.interface";
    mParams.key = "cursor-theme";
    mParams.keyType = GsettingsKeyType::String;
    mParams.operation = GsettingsOperationType::IsUnlocked;
    mParams.value = "true";

    EXPECT_CALL(mContext, ExecuteCommand(GsettingsRangeCmd())).WillOnce(::testing::Return(Result<std::string>(gsettingsTypeS)));
    EXPECT_CALL(mContext, ExecuteCommand(GsettingsWritableCmd())).WillOnce(::testing::Return(Result<std::string>("true\n")));
    auto result = AuditGsettingsValue(mParams, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureGsettings, AuditSuccessIsUnlockedFalse)
{
    mParams.schema = "org.gnome.desktop.interface";
    mParams.key = "cursor-theme";
    mParams.keyType = GsettingsKeyType::String;
    mParams.operation = GsettingsOperationType::IsUnlocked;
    mParams.value = "false";

    EXPECT_CALL(mContext, ExecuteCommand(GsettingsRangeCmd())).WillOnce(::testing::Return(Result<std::string>(gsettingsTypeS)));
    EXPECT_CALL(mContext, ExecuteCommand(GsettingsWritableCmd())).WillOnce(::testing::Return(Result<std::string>("true\n")));
    auto result = AuditGsettingsValue(mParams, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureGsettings, AuditSuccessIsUnlockedValueChrzaszczyrzewoszyce)
{
    mParams.schema = "org.gnome.desktop.interface";
    mParams.key = "cursor-theme";
    mParams.keyType = GsettingsKeyType::String;
    mParams.operation = GsettingsOperationType::IsUnlocked;
    mParams.value = "chrzaszczyrzewoszyce";

    EXPECT_CALL(mContext, ExecuteCommand(GsettingsRangeCmd())).WillOnce(::testing::Return(Result<std::string>(gsettingsTypeS)));
    EXPECT_CALL(mContext, ExecuteCommand(GsettingsWritableCmd())).WillOnce(::testing::Return(Result<std::string>("false\n")));
    auto result = AuditGsettingsValue(mParams, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureGsettings, AuditFailureIsUnlockedKeyTypeNumberU)
{
    mParams.schema = "org.gnome.desktop.interface";
    mParams.key = "cursor-theme";
    mParams.keyType = GsettingsKeyType::Number;
    mParams.operation = GsettingsOperationType::IsUnlocked;
    mParams.value = "42";

    auto result = AuditGsettingsValue(mParams, mIndicators, mContext);
    ASSERT_TRUE(!result.HasValue());
    ASSERT_EQ(result.Error().message, "Not supported keyType number for is-unlocked operation");
}

TEST_F(EnsureGsettings, AuditFailureIsUnlockedKeyTypeNumberI)
{
    mParams.schema = "org.gnome.desktop.interface";
    mParams.key = "cursor-theme";
    mParams.keyType = GsettingsKeyType::Number;
    mParams.operation = GsettingsOperationType::IsUnlocked;
    mParams.value = "42";

    auto result = AuditGsettingsValue(mParams, mIndicators, mContext);
    ASSERT_TRUE(!result.HasValue());
    ASSERT_EQ(result.Error().message, "Not supported keyType number for is-unlocked operation");
}

TEST_F(EnsureGsettings, TypedNumberComparisonsPreserveBoundaries)
{
    struct Case
    {
        GsettingsOperationType operation;
        std::string actual;
        Status expected;
    };
    const Case cases[] = {
        {GsettingsOperationType::Equal, "5", Status::Compliant},
        {GsettingsOperationType::Equal, "4", Status::NonCompliant},
        {GsettingsOperationType::NotEqual, "4", Status::Compliant},
        {GsettingsOperationType::NotEqual, "5", Status::NonCompliant},
        {GsettingsOperationType::LessThan, "4", Status::Compliant},
        {GsettingsOperationType::LessThan, "5", Status::NonCompliant},
        {GsettingsOperationType::GreaterThan, "6", Status::Compliant},
        {GsettingsOperationType::GreaterThan, "5", Status::NonCompliant},
    };
    mParams.schema = "org.gnome.desktop.interface";
    mParams.key = "cursor-size";
    mParams.keyType = GsettingsKeyType::Number;
    mParams.value = "5";
    for (const auto& test : cases)
    {
        mParams.operation = test.operation;
        EXPECT_CALL(mContext, ExecuteCommand(GsettingsRangeCmd())).WillOnce(::testing::Return(Result<std::string>(gsettingsTypeI)));
        EXPECT_CALL(mContext, ExecuteCommand(GsettingsGetCmd())).WillOnce(::testing::Return(Result<std::string>(test.actual)));
        IndicatorsTree indicators;
        indicators.Push("EnsureGsettings");
        auto result = AuditGsettingsValue(mParams, indicators, mContext);
        ASSERT_TRUE(result.HasValue()) << test.actual;
        EXPECT_EQ(result.Value(), test.expected) << test.actual;
        ASSERT_EQ(indicators.Back().indicators.size(), 1U);
        EXPECT_EQ(indicators.Back().indicators.front().status, test.expected);
        EXPECT_EQ(indicators.Back().indicators.front().message,
            "Gsettings key org.gnome.desktop.interface cursor-size " + std::to_string(test.operation) + " value 5");
    }
}

TEST_F(EnsureGsettings, UnsignedOutputPreservesLegacyIntNarrowing)
{
    mParams.schema = "org.gnome.desktop.interface";
    mParams.key = "cursor-size";
    mParams.keyType = GsettingsKeyType::Number;
    mParams.operation = GsettingsOperationType::LessThan;
    mParams.value = "2147483648";
    EXPECT_CALL(mContext, ExecuteCommand(GsettingsRangeCmd())).WillOnce(::testing::Return(Result<std::string>(gsettingsTypeU)));
    EXPECT_CALL(mContext, ExecuteCommand(GsettingsGetCmd())).WillOnce(::testing::Return(Result<std::string>("uint32 2147483647")));
    auto result = AuditGsettingsValue(mParams, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureGsettings, QuotedStringComparisonsAndMalformedOutput)
{
    mParams.schema = "org.gnome.desktop.interface";
    mParams.key = "cursor-theme";
    mParams.keyType = GsettingsKeyType::String;
    mParams.value = "Adwaita";
    struct Case
    {
        GsettingsOperationType operation;
        std::string output;
        Status expected;
    };
    const Case cases[] = {
        {GsettingsOperationType::Equal, "'Adwaita'", Status::Compliant},
        {GsettingsOperationType::Equal, "'Other'", Status::NonCompliant},
        {GsettingsOperationType::NotEqual, "'Other'", Status::Compliant},
        {GsettingsOperationType::NotEqual, "'Adwaita'", Status::NonCompliant},
        {GsettingsOperationType::NotEqual, "Unquoted", Status::NonCompliant},
    };
    for (const auto& test : cases)
    {
        mParams.operation = test.operation;
        EXPECT_CALL(mContext, ExecuteCommand(GsettingsRangeCmd())).WillOnce(::testing::Return(Result<std::string>(gsettingsTypeS)));
        EXPECT_CALL(mContext, ExecuteCommand(GsettingsGetCmd())).WillOnce(::testing::Return(Result<std::string>(test.output)));
        IndicatorsTree indicators;
        indicators.Push("EnsureGsettings");
        auto result = AuditGsettingsValue(mParams, indicators, mContext);
        ASSERT_TRUE(result.HasValue());
        EXPECT_EQ(result.Value(), test.expected) << test.output;
        ASSERT_EQ(indicators.Back().indicators.size(), 1U);
        EXPECT_EQ(indicators.Back().indicators.front().status, test.expected);
        EXPECT_EQ(indicators.Back().indicators.front().message,
            "Gsettings key org.gnome.desktop.interface cursor-theme " + std::to_string(test.operation) + " value Adwaita");
    }
}

TEST_F(EnsureGsettings, RepresentableNumericEndpointsRetainComparison)
{
    struct Case
    {
        std::string type;
        std::string actual;
        std::string expected;
        GsettingsOperationType operation;
        Status status;
    };
    const Case cases[] = {
        {"type i\n", "-2147483648", "-2147483648", GsettingsOperationType::Equal, Status::Compliant},
        {"type i\n", "-2147483648", "-2147483648", GsettingsOperationType::LessThan, Status::NonCompliant},
        {"type i\n", "-2147483648", "-2147483647", GsettingsOperationType::LessThan, Status::Compliant},
        {"type i\n", "0", "-1", GsettingsOperationType::GreaterThan, Status::Compliant},
        {"type i\n", "2147483647", "2147483647", GsettingsOperationType::Equal, Status::Compliant},
        {"type i\n", "2147483647", "2147483647", GsettingsOperationType::GreaterThan, Status::NonCompliant},
        {"type u\n", "uint32 0", "0", GsettingsOperationType::Equal, Status::Compliant},
        {"type u\n", "uint32 2147483647", "2147483646", GsettingsOperationType::GreaterThan, Status::Compliant},
    };
    mParams.schema = "org.gnome.desktop.interface";
    mParams.key = "cursor-size";
    mParams.keyType = GsettingsKeyType::Number;
    for (const auto& test : cases)
    {
        mParams.operation = test.operation;
        mParams.value = test.expected;
        EXPECT_CALL(mContext, ExecuteCommand(GsettingsRangeCmd())).WillOnce(::testing::Return(Result<std::string>(test.type)));
        EXPECT_CALL(mContext, ExecuteCommand(GsettingsGetCmd())).WillOnce(::testing::Return(Result<std::string>(test.actual)));
        IndicatorsTree indicators;
        indicators.Push("EnsureGsettings");
        auto result = AuditGsettingsValue(mParams, indicators, mContext);
        ASSERT_TRUE(result.HasValue());
        EXPECT_EQ(result.Value(), test.status);
        ASSERT_EQ(indicators.Back().indicators.size(), 1U);
        EXPECT_EQ(indicators.Back().indicators.front().status, test.status);
        EXPECT_EQ(indicators.Back().indicators.front().message,
            "Gsettings key org.gnome.desktop.interface cursor-size " + std::to_string(test.operation) + " value " + test.expected);
    }
}

TEST_F(EnsureGsettings, StringOrderingStillFailsAndIsUnlockedKeepsOwnOperation)
{
    mParams.schema = "org.gnome.desktop.interface";
    mParams.key = "cursor-theme";
    mParams.keyType = GsettingsKeyType::String;
    mParams.value = "Adwaita";
    mParams.operation = GsettingsOperationType::LessThan;
    auto result = AuditGsettingsValue(mParams, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().message, "Unsupported operation lt");

    mParams.operation = GsettingsOperationType::IsUnlocked;
    mParams.value = "true";
    EXPECT_CALL(mContext, ExecuteCommand(GsettingsRangeCmd())).WillOnce(::testing::Return(Result<std::string>(gsettingsTypeS)));
    EXPECT_CALL(mContext, ExecuteCommand(GsettingsWritableCmd())).WillOnce(::testing::Return(Result<std::string>("true")));
    result = AuditGsettingsValue(mParams, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureGsettings, InvalidDirectOperationReturnsErrorWithoutCommandOrIndicator)
{
    mParams.operation = static_cast<GsettingsOperationType>(100);
    EXPECT_CALL(mContext, ExecuteCommand(::testing::_)).Times(0);
    const auto result = AuditGsettingsValue(mParams, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, EINVAL);
    EXPECT_EQ(result.Error().message, "Unsupported operation");
    EXPECT_TRUE(mIndicators.Back().indicators.empty());
}

TEST_F(EnsureGsettings, SignedNegativeOrderingAndUnsignedPrefixPreserveCallerPolicy)
{
    mParams.schema = "org.gnome.desktop.interface";
    mParams.key = "cursor-size";
    mParams.keyType = GsettingsKeyType::Number;
    mParams.operation = GsettingsOperationType::LessThan;
    mParams.value = "0";
    EXPECT_CALL(mContext, ExecuteCommand(GsettingsRangeCmd())).WillOnce(::testing::Return(Result<std::string>(gsettingsTypeI)));
    EXPECT_CALL(mContext, ExecuteCommand(GsettingsGetCmd())).WillOnce(::testing::Return(Result<std::string>("-1")));
    auto result = AuditGsettingsValue(mParams, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);

    mParams.operation = GsettingsOperationType::Equal;
    EXPECT_CALL(mContext, ExecuteCommand(GsettingsRangeCmd())).WillOnce(::testing::Return(Result<std::string>(gsettingsTypeU)));
    EXPECT_CALL(mContext, ExecuteCommand(GsettingsGetCmd())).WillOnce(::testing::Return(Result<std::string>("0")));
    IndicatorsTree missingPrefix;
    missingPrefix.Push("EnsureGsettings");
    result = AuditGsettingsValue(mParams, missingPrefix, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, EINVAL);
    EXPECT_NE(result.Error().message.find("expected uint32 prefix"), std::string::npos);
    EXPECT_TRUE(missingPrefix.Back().indicators.empty());
}

TEST_F(EnsureGsettings, CommandFailurePropagatesWithoutComparisonIndicator)
{
    mParams.schema = "org.gnome.desktop.interface";
    mParams.key = "cursor-size";
    mParams.keyType = GsettingsKeyType::Number;
    mParams.value = "5";
    EXPECT_CALL(mContext, ExecuteCommand(GsettingsRangeCmd())).WillOnce(::testing::Return(Result<std::string>(Error("range unavailable", EACCES))));
    auto result = AuditGsettingsValue(mParams, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, EACCES);
    EXPECT_NE(result.Error().message.find("range unavailable"), std::string::npos);
    EXPECT_TRUE(mIndicators.Back().indicators.empty());

    EXPECT_CALL(mContext, ExecuteCommand(GsettingsRangeCmd())).WillOnce(::testing::Return(Result<std::string>(gsettingsTypeI)));
    EXPECT_CALL(mContext, ExecuteCommand(GsettingsGetCmd())).WillOnce(::testing::Return(Result<std::string>(Error("get unavailable", EIO))));
    result = AuditGsettingsValue(mParams, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, EIO);
    EXPECT_NE(result.Error().message.find("get unavailable"), std::string::npos);
    EXPECT_TRUE(mIndicators.Back().indicators.empty());
}
