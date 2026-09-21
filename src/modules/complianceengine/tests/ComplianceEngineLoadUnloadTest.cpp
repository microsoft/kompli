// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ComplianceEngineInterface.h"

#include <gtest/gtest.h>
#include <ostream>
#include <string>

namespace
{
struct LoadUnloadTestCase
{
    const char* name;
    bool useValidSession;
    const char* componentName;
};

void PrintTo(const LoadUnloadTestCase& testCase, std::ostream* stream)
{
    *stream << testCase.name;
}

class ComplianceEngineLoadUnloadTest : public testing::TestWithParam<LoadUnloadTestCase>
{
protected:
    static constexpr unsigned int cMaxPayloadSize = 100;
    MMI_HANDLE mHandle = nullptr;

    void SetUp() override
    {
        ComplianceEngineInitialize(nullptr);
        mHandle = ComplianceEngineMmiOpen("test", cMaxPayloadSize);
        ASSERT_NE(nullptr, mHandle);
    }

    void TearDown() override
    {
        ComplianceEngineMmiClose(mHandle);
        ComplianceEngineShutdown();
    }
};

TEST_P(ComplianceEngineLoadUnloadTest, LoadHandlesArguments)
{
    const auto& testCase = GetParam();
    auto session = testCase.useValidSession ? mHandle : nullptr;

    EXPECT_NO_THROW(ComplianceEngineLoad(session, testCase.componentName));
}

TEST_P(ComplianceEngineLoadUnloadTest, UnloadHandlesArguments)
{
    const auto& testCase = GetParam();
    auto session = testCase.useValidSession ? mHandle : nullptr;

    if (testCase.useValidSession && (nullptr != testCase.componentName) && (std::string("ComplianceEngine") == testCase.componentName))
    {
        ComplianceEngineLoad(session, testCase.componentName);
    }

    EXPECT_NO_THROW(ComplianceEngineUnload(session, testCase.componentName));
}

INSTANTIATE_TEST_SUITE_P(AllArgumentCombinations, ComplianceEngineLoadUnloadTest,
    testing::Values(LoadUnloadTestCase{"NullSessionNullComponent", false, nullptr},
        LoadUnloadTestCase{"NullSessionValidComponent", false, "ComplianceEngine"},
        LoadUnloadTestCase{"NullSessionUnsupportedComponent", false, "UnsupportedComponent"},
        LoadUnloadTestCase{"ValidSessionNullComponent", true, nullptr}, LoadUnloadTestCase{"ValidSessionValidComponent", true, "ComplianceEngine"},
        LoadUnloadTestCase{"ValidSessionUnsupportedComponent", true, "UnsupportedComponent"}),
    [](const testing::TestParamInfo<LoadUnloadTestCase>& info) { return info.param.name; });
} // namespace
