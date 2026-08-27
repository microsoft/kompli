// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "MmiResults.h"
#include "Result.h"
#include "Telemetry.h"

#include <algorithm>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <map>
#include <utility>
#include <vector>

using ComplianceEngine::AuditResult;
using ComplianceEngine::Error;
using ComplianceEngine::Result;
using ComplianceEngine::Status;
using ComplianceEngine::TelemetryEvent;
using ComplianceEngine::TelemetryEventType;

struct CapturedEvent
{
    int64_t durationUs;
    std::chrono::system_clock::time_point createdAt;
};

class MockTelemetry : public ComplianceEngine::TelemetryInterface
{
public:
    explicit MockTelemetry() = default;

    ~MockTelemetry() noexcept = default;

    MockTelemetry(const MockTelemetry&) = delete;
    MockTelemetry& operator=(const MockTelemetry&) = delete;
    MockTelemetry(MockTelemetry&&) = delete;
    MockTelemetry& operator=(MockTelemetry&&) = delete;

    std::vector<std::pair<TelemetryEvent, CapturedEvent>> mCapturedEvents;

private:
    void LogEvent(const TelemetryEvent& event, int64_t durationUs, const std::chrono::system_clock::time_point& createdAt) noexcept override
    {
        mCapturedEvents.push_back(std::make_pair(event, CapturedEvent{durationUs, createdAt}));
    }
};

class TelemetryTest : public ::testing::Test
{
};

#ifdef BUILD_TELEMETRY

// Returns the TelemetryField with the given key, or an empty Optional if not found.
static ComplianceEngine::Optional<ComplianceEngine::TelemetryField> FindContextField(const std::vector<ComplianceEngine::TelemetryField>& context,
    const std::string& key)
{
    auto it = std::find_if(context.begin(), context.end(), [&key](const ComplianceEngine::TelemetryField& f) { return f.key == key; });
    if (it != context.end())
    {
        return ComplianceEngine::Optional<ComplianceEngine::TelemetryField>(*it);
    }
    return ComplianceEngine::Optional<ComplianceEngine::TelemetryField>();
}

TEST_F(TelemetryTest, RunInTelemetry_WithIntSuccess_NoEventLogged)
{
    MockTelemetry mockTelemetry;
    EXPECT_EQ(mockTelemetry.mCapturedEvents.size(), 0);
}

TEST_F(TelemetryTest, TelemetryEvent_RunWithTelemetry)
{
    MockTelemetry mockTelemetry;
    auto mockEvent = TelemetryEvent(TelemetryEventType::Audit, "FooBar");
    auto result = RunWithTelemetry(mockEvent, mockTelemetry, [&]() { return Result<AuditResult>(Error("System is wrong", 42)); });
    EXPECT_EQ(result.HasValue(), false);
    EXPECT_EQ(result.Error().message, std::string("System is wrong"));
    EXPECT_EQ(result.Error().code, 42);
    EXPECT_EQ(mockTelemetry.mCapturedEvents.size(), 1);
    EXPECT_EQ(mockTelemetry.mCapturedEvents[0].first.Type(), TelemetryEventType::Audit);
    // The default resultCode for Error if only Error(message) is given
    const auto& context = mockTelemetry.mCapturedEvents[0].first.Context();
    const auto resultCodeField = FindContextField(context, "resultCode");
    ASSERT_TRUE(resultCodeField.HasValue());
    EXPECT_EQ(resultCodeField.Value().numVal, 42);
}

TEST_F(TelemetryTest, TelemetryEvent_RunWithTelemetryDefautlErrorCode)
{
    MockTelemetry mockTelemetry;
    auto mockEvent = TelemetryEvent(TelemetryEventType::Audit, "FooBar");
    auto result = RunWithTelemetry(mockEvent, mockTelemetry, [&]() { return Result<AuditResult>(Error("System is wrong")); });
    EXPECT_EQ(result.HasValue(), false);
    EXPECT_EQ(result.Error().message, std::string("System is wrong"));
    // Error defaults to -1 when no code is given on Error Constructor
    EXPECT_EQ(result.Error().code, -1);
    EXPECT_EQ(mockTelemetry.mCapturedEvents.size(), 1);
    EXPECT_EQ(mockTelemetry.mCapturedEvents[0].first.Type(), TelemetryEventType::Audit);
    const auto& context = mockTelemetry.mCapturedEvents[0].first.Context();
    const auto resultCodeField = FindContextField(context, "resultCode");
    ASSERT_TRUE(resultCodeField.HasValue());
    ASSERT_EQ(resultCodeField.Value().numVal, -1);
}
TEST_F(TelemetryTest, TelemetryEvent_RunWithTelemetryNoEvents)
{
    MockTelemetry mockTelemetry;
    auto mockEvent = TelemetryEvent(TelemetryEventType::Audit, "FooBar");
    auto result = RunWithTelemetry(mockEvent, mockTelemetry, [&]() { return Result<AuditResult>(AuditResult{Status::Compliant, "Horay"}); });
    EXPECT_EQ(result.HasValue(), true);
    EXPECT_EQ(result.Value().payload, std::string("Horay"));
    EXPECT_EQ(result.Value().status, Status::Compliant);
    EXPECT_EQ(mockTelemetry.mCapturedEvents.size(), 0);
}

TEST_F(TelemetryTest, TelemetryEvent_RunWithTelemetry_StdExceptionIsRethrown)
{
    MockTelemetry mockTelemetry;
    auto mockEvent = TelemetryEvent(TelemetryEventType::Audit, "FooBar");
    bool threw = false;
    try
    {
        RunWithTelemetry(mockEvent, mockTelemetry, [&]() -> Result<AuditResult> { throw std::runtime_error("something went wrong"); });
    }
    catch (const std::exception&)
    {
        threw = true;
    }
    EXPECT_TRUE(threw);
    ASSERT_EQ(mockTelemetry.mCapturedEvents.size(), 1);
    const auto& context = mockTelemetry.mCapturedEvents[0].first.Context();
    const auto exceptionField = FindContextField(context, "exception");
    ASSERT_TRUE(exceptionField.HasValue());
    EXPECT_EQ(exceptionField.Value().strVal, std::string("something went wrong"));
}

TEST_F(TelemetryTest, TelemetryEvent_RunWithTelemetry_NonStdExceptionIsRethrown)
{
    MockTelemetry mockTelemetry;
    auto mockEvent = TelemetryEvent(TelemetryEventType::Remediation, "FooBar");
    bool threw = false;
    try
    {
        RunWithTelemetry(mockEvent, mockTelemetry, [&]() -> Result<AuditResult> { throw std::string("non-std exception payload"); });
    }
    catch (const std::string&)
    {
        threw = true;
    }
    EXPECT_TRUE(threw);
    ASSERT_EQ(mockTelemetry.mCapturedEvents.size(), 1);
    const auto& context = mockTelemetry.mCapturedEvents[0].first.Context();
    const auto exceptionField = FindContextField(context, "exception");
    ASSERT_TRUE(exceptionField.HasValue());
    EXPECT_EQ(exceptionField.Value().strVal, std::string("unknown non-std exception"));
}

#else

TEST_F(TelemetryTest, TelemetryEvent_WhenBuildNoTelemetryNoLogEventIsCalled)
{
    MockTelemetry mockTelemetry;
    auto mockEvent = TelemetryEvent(TelemetryEventType::Remediation, "FooBar");
    const auto mockCreatedAt = std::chrono::system_clock::now();
    EXPECT_EQ(mockTelemetry.mCapturedEvents.size(), 0);
    mockTelemetry.mCapturedEvents.push_back(std::make_pair(mockEvent, CapturedEvent{0, mockCreatedAt}));
    EXPECT_EQ(mockTelemetry.mCapturedEvents.size(), 1);
    auto result = RunWithTelemetry(mockEvent, mockTelemetry, [&]() { return Result<AuditResult>(Error("System is wrong", 42)); });
    EXPECT_EQ(result.HasValue(), false);
    EXPECT_EQ(result.Error().message, std::string("System is wrong"));
    EXPECT_EQ(result.Error().code, 42);
    EXPECT_EQ(mockTelemetry.mCapturedEvents.size(), 1);
}
#endif // BUILD_TELEMETRY
