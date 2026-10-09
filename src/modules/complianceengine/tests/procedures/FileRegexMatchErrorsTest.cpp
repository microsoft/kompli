// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "MockContext.h"

#include <FileRegexMatch.h>
#include <cerrno>
#include <fstream>
#include <gtest/gtest.h>
#include <regex>
#include <string>
#include <sys/stat.h>

using ComplianceEngine::AuditFileRegexMatch;
using ComplianceEngine::Behavior;
using ComplianceEngine::FileRegexMatchParams;
using ComplianceEngine::IndicatorsTree;
using ComplianceEngine::Status;

TEST(FileRegexMatchErrorsTest, NonDirectoryRootIsNotSuccessfulAbsence)
{
    MockContext context;
    IndicatorsTree indicators;
    indicators.Push("FileRegexMatch");
    const std::string path = context.GetTempdirPath() + "/regular-file";
    std::ofstream(path) << "key=value\n";

    FileRegexMatchParams params;
    params.path = path;
    params.filenamePattern = regex(".*");
    params.matchPattern = "key";
    params.behavior = Behavior::NoneExist;

    for (const auto behavior : {Behavior::NoneExist, Behavior::AnyExist})
    {
        params.behavior = behavior;
        for (const auto selectedState : {0, 1, 2})
        {
            params.allMatches = selectedState == 1;
            params.noneMatches = selectedState == 2;
            const auto result = AuditFileRegexMatch(params, indicators, context);
            ASSERT_FALSE(result.HasValue());
            EXPECT_EQ(ENOTDIR, result.Error().code);
        }
    }
}

TEST(FileRegexMatchErrorsTest, MissingDirectoryRetainsAbsencePolicy)
{
    MockContext context;
    IndicatorsTree indicators;
    indicators.Push("FileRegexMatch");
    FileRegexMatchParams params;
    params.path = context.GetTempdirPath() + "/missing";
    params.filenamePattern = regex(".*");
    params.matchPattern = "key";
    params.behavior = Behavior::NoneExist;

    const auto noneResult = AuditFileRegexMatch(params, indicators, context);
    ASSERT_TRUE(noneResult.HasValue());
    EXPECT_EQ(Status::Compliant, noneResult.Value());

    params.behavior = Behavior::AnyExist;
    params.allMatches = true;
    const auto optionalResult = AuditFileRegexMatch(params, indicators, context);
    ASSERT_TRUE(optionalResult.HasValue());
    EXPECT_EQ(Status::Compliant, optionalResult.Value());
}

TEST(FileRegexMatchErrorsTest, InvalidPatternsFailWithoutSelectedFiles)
{
    MockContext context;
    IndicatorsTree indicators;
    indicators.Push("FileRegexMatch");
    const std::string path = context.GetTempdirPath() + "/regex-input";
    ASSERT_EQ(0, mkdir(path.c_str(), 0700));

    FileRegexMatchParams params;
    params.path = path;
    params.filenamePattern = regex("selected");
    params.matchPattern = "(";
    params.behavior = Behavior::NoneExist;

    for (const auto& inputPath : {path, context.GetTempdirPath() + "/missing"})
    {
        params.path = inputPath;
        const auto result = AuditFileRegexMatch(params, indicators, context);
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ(EINVAL, result.Error().code);
    }

    std::ofstream(path + "/unselected") << "key=value\n";
    params.path = path;
    params.matchPattern = "key";
    params.statePattern = "(";
    const auto stateResult = AuditFileRegexMatch(params, indicators, context);
    ASSERT_FALSE(stateResult.HasValue());
    EXPECT_EQ(EINVAL, stateResult.Error().code);
}

TEST(FileRegexMatchErrorsTest, EmptyAndUnterminatedInputRemainReadable)
{
    MockContext context;
    IndicatorsTree indicators;
    indicators.Push("FileRegexMatch");
    const std::string path = context.GetTempdirPath() + "/regex-input";
    ASSERT_EQ(0, mkdir(path.c_str(), 0700));
    const std::string filename = path + "/selected";
    std::ofstream(filename).close();

    FileRegexMatchParams params;
    params.path = path;
    params.filenamePattern = regex("selected");
    params.matchPattern = "^$";

    const auto emptyResult = AuditFileRegexMatch(params, indicators, context);
    ASSERT_TRUE(emptyResult.HasValue());
    EXPECT_EQ(Status::Compliant, emptyResult.Value());

    std::ofstream(filename) << "key=value";
    params.matchPattern = "^key=value$";
    for (const bool wholeFile : {false, true})
    {
        params.wholeFile = wholeFile;
        const auto result = AuditFileRegexMatch(params, indicators, context);
        ASSERT_TRUE(result.HasValue());
        EXPECT_EQ(Status::Compliant, result.Value());
    }
}
