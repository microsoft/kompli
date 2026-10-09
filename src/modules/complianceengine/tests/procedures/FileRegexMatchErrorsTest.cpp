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
