// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "MockContext.h"

#include <DconfValue.h>
#include <ProcedureMap.h>
#include <TypedComparison.h>
#include <gtest/gtest.h>
#include <limits>

TEST(TypedComparisonTest, EvaluatesAllOperatorsOnTypedIntegersAndStrings)
{
    using ComplianceEngine::CompareTyped;
    using ComplianceEngine::TypedComparisonOperation;
    struct Case
    {
        TypedComparisonOperation operation;
        bool less;
        bool equal;
        bool greater;
    };
    const Case cases[] = {
        {TypedComparisonOperation::Equal, false, true, false},
        {TypedComparisonOperation::NotEqual, true, false, true},
        {TypedComparisonOperation::LessThan, true, false, false},
        {TypedComparisonOperation::LessOrEqual, true, true, false},
        {TypedComparisonOperation::GreaterThan, false, false, true},
        {TypedComparisonOperation::GreaterOrEqual, false, true, true},
    };

    for (const auto& test : cases)
    {
        auto lessInt = CompareTyped(-1, 0, test.operation);
        auto equalInt = CompareTyped(0, 0, test.operation);
        auto greaterInt = CompareTyped(1, 0, test.operation);
        auto lessString = CompareTyped(std::string("A"), std::string("a"), test.operation);
        auto equalString = CompareTyped(std::string("a"), std::string("a"), test.operation);
        auto greaterString = CompareTyped(std::string("b"), std::string("a"), test.operation);
        ASSERT_TRUE(lessInt.HasValue());
        ASSERT_TRUE(equalInt.HasValue());
        ASSERT_TRUE(greaterInt.HasValue());
        ASSERT_TRUE(lessString.HasValue());
        ASSERT_TRUE(equalString.HasValue());
        ASSERT_TRUE(greaterString.HasValue());
        EXPECT_EQ(lessInt.Value(), test.less);
        EXPECT_EQ(equalInt.Value(), test.equal);
        EXPECT_EQ(greaterInt.Value(), test.greater);
        EXPECT_EQ(lessString.Value(), test.less);
        EXPECT_EQ(equalString.Value(), test.equal);
        EXPECT_EQ(greaterString.Value(), test.greater);
    }
}

TEST(TypedComparisonTest, PreservesIntegerLimitsAndRejectsUnknownOperation)
{
    using ComplianceEngine::CompareTyped;
    using ComplianceEngine::TypedComparisonOperation;
    const auto minimum = std::numeric_limits<long>::min();
    const auto maximum = std::numeric_limits<long>::max();
    auto less = CompareTyped(minimum, maximum, TypedComparisonOperation::LessThan);
    auto greater = CompareTyped(maximum, minimum, TypedComparisonOperation::GreaterThan);
    auto invalid = CompareTyped(1, 1, static_cast<TypedComparisonOperation>(100));
    ASSERT_TRUE(less.HasValue());
    ASSERT_TRUE(greater.HasValue());
    EXPECT_TRUE(less.Value());
    EXPECT_TRUE(greater.Value());
    ASSERT_FALSE(invalid.HasValue());
    EXPECT_EQ(invalid.Error().code, EINVAL);
}

using ComplianceEngine::AuditDconfValue;
using ComplianceEngine::DconfOperation;
using ComplianceEngine::DconfValueParams;
using ComplianceEngine::Error;
using ComplianceEngine::IndicatorsTree;
using ComplianceEngine::Result;
using ComplianceEngine::Status;

class EnsureDconf : public ::testing::Test
{
protected:
    MockContext mContext;
    IndicatorsTree mIndicators;

    DconfValueParams mParams;

    std::string DconfRead() const
    {
        return "dconf read \"" + mParams.key + "\"";
    }

    void SetUp() override
    {
        mIndicators.Push("EnsureGsettings");
    }
};

TEST_F(EnsureDconf, AuditNonCompliantValueNotEqual)
{
    mParams.key = "/org/gnome/login-screen/banner-message-text";
    mParams.operation = DconfOperation::Eq;
    mParams.value = "You *SHALL NOT PASS* (this login screen)";
    EXPECT_CALL(mContext, ExecuteCommand(DconfRead())).WillOnce(::testing::Return(Result<std::string>("You *SHALL* PASSS")));
    auto result = AuditDconfValue(mParams, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureDconf, AuditCompliantValueNotEqual)
{
    mParams.key = "/org/gnome/login-screen/banner-message-text";
    mParams.operation = DconfOperation::Ne;
    mParams.value = "You *SHALL NOT PASS* (this login screen)";
    EXPECT_CALL(mContext, ExecuteCommand(DconfRead())).WillOnce(::testing::Return(Result<std::string>("You *SHALL* PASSS")));
    auto result = AuditDconfValue(mParams, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureDconf, AuditCompliantValueEqual)
{
    mParams.key = "/org/gnome/login-screen/banner-message-text";
    mParams.operation = DconfOperation::Eq;
    mParams.value = "You *SHALL NOT PASS* (this login screen)";
    EXPECT_CALL(mContext, ExecuteCommand(DconfRead())).WillOnce(::testing::Return(Result<std::string>(mParams.value)));
    auto result = AuditDconfValue(mParams, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureDconf, TypedStringComparisonPreservesBothVerdicts)
{
    mParams.key = "/org/gnome/login-screen/banner-message-text";
    struct Case
    {
        DconfOperation operation;
        std::string actual;
        Status expected;
    };
    const Case cases[] = {
        {DconfOperation::Eq, "same", Status::Compliant},
        {DconfOperation::Eq, "other", Status::NonCompliant},
        {DconfOperation::Ne, "other", Status::Compliant},
        {DconfOperation::Ne, "same", Status::NonCompliant},
    };
    mParams.value = "same";
    for (const auto& test : cases)
    {
        mParams.operation = test.operation;
        EXPECT_CALL(mContext, ExecuteCommand(DconfRead())).WillOnce(::testing::Return(Result<std::string>(test.actual)));
        IndicatorsTree indicators;
        indicators.Push("EnsureGsettings");
        auto result = AuditDconfValue(mParams, indicators, mContext);
        ASSERT_TRUE(result.HasValue());
        EXPECT_EQ(result.Value(), test.expected);
        ASSERT_EQ(indicators.Back().indicators.size(), 1U);
        EXPECT_EQ(indicators.Back().indicators.front().status, test.expected);
        EXPECT_EQ(indicators.Back().indicators.front().message,
            "Dconf read /org/gnome/login-screen/banner-message-text " + std::to_string(test.operation) + " value same");
    }
}

TEST_F(EnsureDconf, TrailingNewlineAndLiteralWhitespaceStayLocal)
{
    mParams.key = "/org/gnome/login-screen/banner-message-text";
    mParams.value = "same";
    mParams.operation = DconfOperation::Eq;
    EXPECT_CALL(mContext, ExecuteCommand(DconfRead())).WillOnce(::testing::Return(Result<std::string>("same\n")));
    auto result = AuditDconfValue(mParams, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);

    EXPECT_CALL(mContext, ExecuteCommand(DconfRead())).WillOnce(::testing::Return(Result<std::string>("same ")));
    result = AuditDconfValue(mParams, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureDconf, CommandFailurePropagatesWithoutIndicator)
{
    mParams.key = "/org/gnome/login-screen/banner-message-text";
    EXPECT_CALL(mContext, ExecuteCommand(DconfRead())).WillOnce(::testing::Return(Result<std::string>(Error("unavailable", EACCES))));
    auto result = AuditDconfValue(mParams, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, EACCES);
    EXPECT_EQ(result.Error().message, "Failed to execute dconf read /org/gnome/login-screen/banner-message-text error: unavailable");
    EXPECT_TRUE(mIndicators.Back().indicators.empty());
}

TEST_F(EnsureDconf, InvalidDirectOperationReturnsErrorWithoutCommandOrIndicator)
{
    mParams.operation = static_cast<DconfOperation>(100);
    EXPECT_CALL(mContext, ExecuteCommand(::testing::_)).Times(0);
    const auto result = AuditDconfValue(mParams, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, EINVAL);
    EXPECT_EQ(result.Error().message, "Not supported operation");
    EXPECT_TRUE(mIndicators.Back().indicators.empty());
}
