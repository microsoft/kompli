// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "MockContext.h"

#include <DconfValue.h>
#include <ProcedureMap.h>
#include <gtest/gtest.h>

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
