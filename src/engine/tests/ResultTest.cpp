// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "Result.h"

#include "MmiResults.h"

#include <cerrno>
#include <gtest/gtest.h>

using ComplianceEngine::AuditResult;
using ComplianceEngine::Error;
using ComplianceEngine::Result;
using ComplianceEngine::Status;

class ResultTest : public ::testing::Test
{
};

namespace
{
// Reproduces the ComplianceEngineInterface.cpp "audit error -> NonCompliant
// AuditResult" reassignment idiom (below) in a single translation unit: the
// real producer, Engine::MmiGet, lives in a separate TU (Engine.cpp) from its
// ComplianceEngineInterface.cpp caller, but putting a stand-in producer here,
// next to the caller shape, lets GCC Release (-O3) inline it -- exactly the
// shape that exposed the stale-alias read below. A cross-TU call (no LTO)
// does not reproduce it.
Result<AuditResult> DispatchRuleNotFound()
{
    return Error("Rule not found", EINVAL);
}
} // namespace

// Characterizes the ComplianceEngineInterface.cpp
// "audit error -> NonCompliant AuditResult" reassignment idiom:
//   auto result = engine.MmiGet(objectName);
//   if (!result.HasValue())
//   {
//       result = ComplianceEngine::AuditResult(Status::NonCompliant, "..." + result.Error().message);
//   }
// Before the Result<T> fix, GCC Release (-O3) could inline DispatchRuleNotFound
// into this test body and miscompile the Error -> Value move-assignment so
// that result.Value().status read back as garbage bytes instead of the
// just-constructed Status::NonCompliant, while the payload string was
// correct -- i.e. a security-relevant false PASS. Debug and Clang
// configurations did not reproduce it.
TEST_F(ResultTest, ErrorToValueReassignmentPreservesStatusAndPayload)
{
    auto result = DispatchRuleNotFound();
    ASSERT_FALSE(result.HasValue());

    result = AuditResult(Status::NonCompliant, "Audit failed with a non-critical error: " + result.Error().message);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::NonCompliant, result.Value().status);
    EXPECT_EQ("Audit failed with a non-critical error: Rule not found", result.Value().payload);
}

TEST_F(ResultTest, ErrorContructor)
{
    Result<int> result(Error("error"));
    ASSERT_FALSE(result.HasValue());
    ASSERT_EQ(result.Error().message, std::string("error"));
}

TEST_F(ResultTest, ValueContructor)
{
    Result<int> result(42);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), 42);

    result = Result<int>{Error("error")};
    ASSERT_FALSE(result.HasValue());
}

TEST_F(ResultTest, CopyContructor)
{
    Result<int> result1(42);
    Result<int> result2(result1);
    ASSERT_TRUE(result1.HasValue());
    ASSERT_TRUE(result2.HasValue());
    ASSERT_EQ(result2.Value(), 42);
}

TEST_F(ResultTest, MoveContructor)
{
    Result<int> result1(42);
    Result<int> result2(std::move(result1));
#ifndef __clang_analyzer__
    ASSERT_FALSE(result1.HasValue());
#endif
    ASSERT_TRUE(result2.HasValue());
    ASSERT_EQ(result2.Value(), 42);
}

TEST_F(ResultTest, CopyAssignment)
{
    Result<int> result1(42);
    auto result2 = result1;
    ASSERT_TRUE(result1.HasValue());
    ASSERT_TRUE(result2.HasValue());
    ASSERT_EQ(result2.Value(), 42);
}

TEST_F(ResultTest, MoveAssignment)
{
    Result<int> result1(42);
    Result<int> result2 = std::move(result1);
#ifndef __clang_analyzer__
    ASSERT_FALSE(result1.HasValue());
#endif
    ASSERT_TRUE(result2.HasValue());
    ASSERT_EQ(result2.Value(), 42);
}

TEST_F(ResultTest, ValueAssignment)
{
    Result<int> result(Error("error"));
    result = 42;
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), 42);
}

TEST_F(ResultTest, ValueReference)
{
    Result<int> result(42);
    result.Value() = 43;
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), 43);
}

TEST_F(ResultTest, ErrorReference)
{
    auto result = Result<int>(Error("error"));
    result.Error().message = "ERROR";
    ASSERT_EQ(result.Error().message, "ERROR");
}

TEST_F(ResultTest, BoolConversion)
{
    Result<std::string> result(Error("error"));
    ASSERT_FALSE(result);
    result = std::string("foo");
    ASSERT_TRUE(result);
}

TEST_F(ResultTest, ValueOr)
{
    Result<int> result(Error("error"));
    ASSERT_EQ(result.ValueOr(42), 42);
    result = 43;
    ASSERT_EQ(result.ValueOr(42), 43);
}

TEST_F(ResultTest, ArrowOperator)
{
    auto result = Result<std::string>("foo");
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result->size(), 3u);
    result->append("bar");
    ASSERT_EQ(result->size(), 6u);
}
