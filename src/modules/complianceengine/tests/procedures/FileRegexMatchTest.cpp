// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "MockContext.h"

#include <FileRegexMatch.h>
#include <cstdlib>
#include <dirent.h>
#include <fstream>
#include <gtest/gtest.h>
#include <linux/limits.h>
#include <string>
#include <unistd.h>

using ComplianceEngine::AuditFileRegexMatch;
using ComplianceEngine::Behavior;
using ComplianceEngine::CompactListFormatter;
using ComplianceEngine::Error;
using ComplianceEngine::FileRegexMatchParams;
using ComplianceEngine::IgnoreCase;
using ComplianceEngine::IndicatorsTree;
using ComplianceEngine::Operation;
using ComplianceEngine::Result;
using ComplianceEngine::Status;
using std::string;

class FileRegexMatchTest : public ::testing::Test
{
protected:
    char mTempdir[PATH_MAX] = "/tmp/FileRegexMatchTest.XXXXXX";
    MockContext mContext;
    IndicatorsTree mIndicators;
    std::vector<string> mTempfiles;

    void SetUp() override
    {
        mIndicators.Push("FileRegexMatch");
        ASSERT_NE(mkdtemp(mTempdir), nullptr);
    }

    void TearDown() override
    {
        for (const auto& file : mTempfiles)
        {
            remove(file.c_str());
        }
        remove(mTempdir);
    }

    void MakeTempfile(const string& content)
    {
        string filename = mTempdir;
        if (mTempfiles.empty())
        {
            filename += "/1";
            mTempfiles.push_back(filename);
        }
        else
        {
            const auto& last = mTempfiles.back();
            auto index = last.find_last_of('/');
            filename = last.substr(0, index) + "/" + std::to_string(std::stoi(last.substr(index + 1)) + 1);
            mTempfiles.push_back(filename);
        }

        std::ofstream file(filename);
        file << content;
    }
};

TEST_F(FileRegexMatchTest, NumericBoundsCheckEverySelectedLine)
{
    FileRegexMatchParams params;
    params.path = mTempdir;
    params.filenamePattern = regex("1");
    params.matchPattern = "^freq=([^ ]+)";
    params.minimumValue = "1";
    params.maximumValue = "100";
    params.allMatches = true;
    MakeTempfile("freq=1\nfreq=+00100\n");
    auto result = AuditFileRegexMatch(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
    for (const auto& invalid : {"0", "101", "-1", "1x", "999999999999999999999999"})
    {
        std::ofstream output(mTempfiles[0]);
        output << "freq=1\nfreq=" << invalid << "\n";
        output.close();
        result = AuditFileRegexMatch(params, mIndicators, mContext);
        ASSERT_TRUE(result.HasValue());
        EXPECT_EQ(result.Value(), Status::NonCompliant) << invalid;
    }
    params.maximumValue = "invalid";
    EXPECT_FALSE(AuditFileRegexMatch(params, mIndicators, mContext).HasValue());
}

TEST_F(FileRegexMatchTest, IntegerConversionBoundaries)
{
    FileRegexMatchParams params;
    params.path = mTempdir;
    params.filenamePattern = regex("1");
    params.matchPattern = "^value=(.*)$";
    params.minimumValue = "-9223372036854775808";
    params.maximumValue = "9223372036854775807";
    params.allMatches = true;
    MakeTempfile("value=-9223372036854775808\nvalue=9223372036854775807\n");
    auto result = AuditFileRegexMatch(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
    for (const auto& invalid : {"9223372036854775808", "-9223372036854775809", "", "+", "-", " 1", "1 ", "1x"})
    {
        std::ofstream output(mTempfiles[0]);
        output << "value=" << invalid << "\n";
        output.close();
        result = AuditFileRegexMatch(params, mIndicators, mContext);
        ASSERT_TRUE(result.HasValue());
        EXPECT_EQ(result.Value(), Status::NonCompliant) << invalid;
    }
}

TEST_F(FileRegexMatchTest, AllSelectedSettingsRespectOptionalExistence)
{
    FileRegexMatchParams params;
    params.path = mTempdir;
    params.filenamePattern = regex(".*");
    params.matchPattern = "^rounds=([0-9]+)$";
    params.minimumValue = "100000";
    params.allMatches = true;
    params.behavior = Behavior::AnyExist;
    MakeTempfile("unrelated=1\n");
    auto result = AuditFileRegexMatch(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
    MakeTempfile("rounds=100000\n");
    for (const auto behavior : {Behavior::AnyExist, Behavior::AtLeastOneExists, Behavior::AllExist})
    {
        params.behavior = behavior;
        result = AuditFileRegexMatch(params, mIndicators, mContext);
        ASSERT_TRUE(result.HasValue());
        EXPECT_EQ(result.Value(), Status::Compliant);
    }
    MakeTempfile("rounds=5000\n");
    for (const auto behavior : {Behavior::AnyExist, Behavior::AtLeastOneExists, Behavior::AllExist})
    {
        params.behavior = behavior;
        result = AuditFileRegexMatch(params, mIndicators, mContext);
        ASSERT_TRUE(result.HasValue());
        EXPECT_EQ(result.Value(), Status::NonCompliant);
    }
    params.path = string(mTempdir) + "/missing";
    params.behavior = Behavior::AnyExist;
    result = AuditFileRegexMatch(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
    params.path = mTempfiles[0];
    EXPECT_FALSE(AuditFileRegexMatch(params, mIndicators, mContext).HasValue());
}

TEST_F(FileRegexMatchTest, WholeFileEvaluatesEverySelectedSection)
{
    FileRegexMatchParams params;
    params.path = mTempdir;
    params.filenamePattern = regex(".*\\.repo$");
    params.matchPattern = R"(^[ \t]*\[[^\]]+\][ \t]*\n(?:[^\[]*\n)*)";
    params.statePattern = R"(\n[ \t]*gpgcheck[ \t]*=[ \t]*(True|1|yes)[ \t]*(\n|$))";
    params.allMatches = true;
    params.wholeFile = true;
    MakeTempfile("[base]\ngpgcheck=1\n\n[updates]\ngpgcheck=yes\n");
    rename(mTempfiles[0].c_str(), (string(mTempdir) + "/base.repo").c_str());
    mTempfiles[0] = string(mTempdir) + "/base.repo";

    auto result = AuditFileRegexMatch(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);

    std::ofstream output(mTempfiles[0]);
    output << "[base]\ngpgcheck=1\n\n[updates]\ngpgcheck=0\n";
    output.close();
    result = AuditFileRegexMatch(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(FileRegexMatchTest, WholeFileCanRequireNoSelectedSectionToMatch)
{
    FileRegexMatchParams params;
    params.path = mTempdir;
    params.filenamePattern = regex(".*\\.repo$");
    params.matchPattern = R"(^[ \t]*\[[^\]]+\][ \t]*\n(?:[^\[]*\n)*)";
    params.statePattern = R"(\n[ \t]*gpgcheck[ \t]*=[ \t]*(False|0|no)[ \t]*(\n|$))";
    params.wholeFile = true;
    params.noneMatches = true;
    MakeTempfile("[base]\ngpgcheck=1\n\n[updates]\ngpgcheck=yes\n");
    rename(mTempfiles[0].c_str(), (string(mTempdir) + "/base.repo").c_str());
    mTempfiles[0] = string(mTempdir) + "/base.repo";

    auto result = AuditFileRegexMatch(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);

    std::ofstream output(mTempfiles[0]);
    output << "[base]\ngpgcheck=1\n\n[updates]\ngpgcheck=0\n";
    output.close();
    result = AuditFileRegexMatch(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(FileRegexMatchTest, WholeFilePreservesSearchBoundaries)
{
    FileRegexMatchParams params;
    params.path = mTempdir;
    params.filenamePattern = regex("1");
    params.statePattern = "^b$";
    params.wholeFile = true;
    params.noneMatches = true;
    MakeTempfile("ab");
    for (const auto& pattern : {R"(a|\bb)", "a|^b"})
    {
        params.matchPattern = pattern;
        const auto result = AuditFileRegexMatch(params, mIndicators, mContext);
        ASSERT_TRUE(result.HasValue());
        EXPECT_EQ(result.Value(), Status::Compliant) << pattern;
    }
}

TEST_F(FileRegexMatchTest, WholeFileEmptyMatchesDoNotSkipNonemptyAlternatives)
{
    FileRegexMatchParams params;
    params.path = mTempdir;
    params.filenamePattern = regex("1");
    params.matchPattern = "x*|bad";
    params.statePattern = "^bad$";
    params.wholeFile = true;
    params.noneMatches = true;
    MakeTempfile("bad");
    auto result = AuditFileRegexMatch(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
    params.matchPattern = "";
    result = AuditFileRegexMatch(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(FileRegexMatchTest, WholeFileVisitsEmptyMatchAtEndOfInput)
{
    FileRegexMatchParams params;
    params.path = mTempdir;
    params.filenamePattern = regex("1");
    params.matchPattern = "value|$";
    params.statePattern = "^value$";
    params.wholeFile = true;
    params.allMatches = true;
    MakeTempfile("value");
    const auto result = AuditFileRegexMatch(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(FileRegexMatchTest, Audit_InvalidArguments_1)
{
    FileRegexMatchParams params;
    MakeTempfile("test");
    params.path = mTempdir;
    params.filenamePattern = regex("1");
    params.matchPattern = "(?i)"; // invalid regex pattern
    params.matchOperation = Operation::Match;
    auto result = AuditFileRegexMatch(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, EINVAL);
}

TEST_F(FileRegexMatchTest, Audit_EmptyFile_1)
{
    FileRegexMatchParams params;
    params.path = mTempdir;
    params.filenamePattern = regex("1");
    params.matchPattern = "test";
    params.matchOperation = Operation::Match;
    auto result = AuditFileRegexMatch(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(FileRegexMatchTest, Audit_Match_1)
{
    MakeTempfile("test");
    FileRegexMatchParams params;
    params.path = mTempdir;
    params.filenamePattern = regex("1");
    params.matchPattern = "test";
    params.matchOperation = Operation::Match;
    auto result = AuditFileRegexMatch(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(FileRegexMatchTest, Audit_Match_2)
{
    MakeTempfile("tests");
    FileRegexMatchParams params;
    params.path = mTempdir;
    params.filenamePattern = regex("1");
    params.matchPattern = "test";
    params.matchOperation = Operation::Match;
    params.behavior = Behavior::NoneExist;
    auto result = AuditFileRegexMatch(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(FileRegexMatchTest, Audit_Match_3)
{
    MakeTempfile("test");
    FileRegexMatchParams params;
    params.path = mTempdir;
    params.filenamePattern = regex("1");
    params.matchPattern = "tests";
    params.matchOperation = Operation::Match;
    auto result = AuditFileRegexMatch(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(FileRegexMatchTest, Audit_Match_4)
{
    MakeTempfile("test");
    FileRegexMatchParams params;
    params.path = mTempdir;
    params.filenamePattern = regex("1");
    params.matchPattern = "te.t";
    params.matchOperation = Operation::Match;
    auto result = AuditFileRegexMatch(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(FileRegexMatchTest, Audit_Match_5)
{
    MakeTempfile("test");
    FileRegexMatchParams params;
    params.path = mTempdir;
    params.filenamePattern = regex("1");
    params.matchPattern = "^te.t$";
    params.matchOperation = Operation::Match;
    auto result = AuditFileRegexMatch(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(FileRegexMatchTest, Audit_Match_6)
{
    MakeTempfile(" \ttesting");
    FileRegexMatchParams params;
    params.path = mTempdir;
    params.filenamePattern = regex("1");
    params.matchPattern = R"(^[[:space:]]*te[a-z]t.*$)";
    params.matchOperation = Operation::Match;
    auto result = AuditFileRegexMatch(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(FileRegexMatchTest, Audit_CaseInsensitive_1)
{
    MakeTempfile(" \ttesTing");
    FileRegexMatchParams params;
    params.path = mTempdir;
    params.filenamePattern = regex("1");
    params.matchPattern = R"(^[[:space:]]*Te[a-z]t.*$)";
    params.matchOperation = Operation::Match;
    params.ignoreCase = ComplianceEngine::IgnoreCase::MatchPattern;
    auto result = AuditFileRegexMatch(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(FileRegexMatchTest, Audit_State_1)
{
    MakeTempfile("key=foo");
    FileRegexMatchParams params;
    params.path = mTempdir;
    params.filenamePattern = regex("1");
    params.matchPattern = R"(^key=.*$)";
    params.statePattern = string(R"(^key=foo$)");
    params.behavior = Behavior::AllExist;
    auto result = AuditFileRegexMatch(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(FileRegexMatchTest, Audit_State_2_CaseInsensitve)
{
    MakeTempfile("key=foo");
    FileRegexMatchParams params;
    params.path = mTempdir;
    params.filenamePattern = regex("1");
    params.matchPattern = R"(^key=.*$)";
    params.statePattern = string(R"(^key=FoO$)");
    params.behavior = Behavior::AllExist;
    params.ignoreCase = IgnoreCase::StatePattern;
    auto result = AuditFileRegexMatch(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(FileRegexMatchTest, Audit_State_2_CaseInsensitveBoth)
{
    MakeTempfile("key=foo");
    FileRegexMatchParams params;
    params.path = mTempdir;
    params.filenamePattern = regex("1");
    params.matchPattern = R"(^Key=.*$)";
    params.statePattern = string(R"(^Key=FoO$)");
    params.behavior = Behavior::AllExist;
    params.ignoreCase = IgnoreCase::Both;
    auto result = AuditFileRegexMatch(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(FileRegexMatchTest, Audit_State_2_CaseInsensitveBothDiffetnArg)
{
    MakeTempfile("key=foo");
    FileRegexMatchParams params;
    params.path = mTempdir;
    params.filenamePattern = regex("1");
    params.matchPattern = R"(^Key=.*$)";
    params.statePattern = string(R"(^Key=FoO$)");
    params.behavior = Behavior::AllExist;
    params.ignoreCase = IgnoreCase::Both;
    auto result = AuditFileRegexMatch(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}
TEST_F(FileRegexMatchTest, Audit_State_2)
{
    MakeTempfile("key=foo");
    FileRegexMatchParams params;
    params.path = mTempdir;
    params.filenamePattern = regex("1");
    params.matchPattern = R"(^key=.*$)";
    params.matchOperation = Operation::Match;
    params.statePattern = string(R"(^key=bar$)");
    params.stateOperation = Operation::Match;
    params.behavior = Behavior::AllExist;
    auto result = AuditFileRegexMatch(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(FileRegexMatchTest, Audit_State_3)
{
    MakeTempfile("key=foo");
    FileRegexMatchParams params;
    params.path = mTempdir;
    params.filenamePattern = regex("1");
    params.matchPattern = R"(^key=.*$)";
    params.matchOperation = Operation::Match;
    params.statePattern = string(R"(^key=bar$)");
    params.stateOperation = Operation::Match;
    params.behavior = Behavior::NoneExist;
    auto result = AuditFileRegexMatch(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(FileRegexMatchTest, Audit_State_4)
{
    MakeTempfile("key=bar\nkey=foo");
    FileRegexMatchParams params;
    params.path = mTempdir;
    params.filenamePattern = regex("1");
    params.matchPattern = R"(^key=.*$)";
    params.matchOperation = Operation::Match;
    params.statePattern = string(R"(^key=foo$)");
    params.stateOperation = Operation::Match;
    params.behavior = Behavior::NoneExist;
    auto result = AuditFileRegexMatch(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(FileRegexMatchTest, Audit_Multiline_Match_1)
{
    MakeTempfile("key=foo\nkey=bar\nkey=baz");
    FileRegexMatchParams params;
    params.path = mTempdir;
    params.filenamePattern = regex("1");
    params.matchPattern = R"(^key=.*$)";
    params.matchOperation = Operation::Match;
    params.behavior = Behavior::AllExist;
    auto result = AuditFileRegexMatch(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(FileRegexMatchTest, Audit_Multiline_Match_2)
{
    MakeTempfile("key=foo\nkey=bar\nkey=baz\nky=typo");
    FileRegexMatchParams params;
    params.path = mTempdir;
    params.filenamePattern = regex("1");
    params.matchPattern = R"(^key=.*$)";
    params.matchOperation = Operation::Match;
    params.behavior = Behavior::AtLeastOneExists;
    auto result = AuditFileRegexMatch(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(FileRegexMatchTest, Audit_Multiline_Match_3)
{
    MakeTempfile("key=foo\nkey=bar\nkey=baz\nky=typo");
    FileRegexMatchParams params;
    params.path = mTempdir;
    params.filenamePattern = regex("1");
    params.matchPattern = R"(^key=.*$)";
    params.matchOperation = Operation::Match;
    params.behavior = Behavior::AllExist;
    auto result = AuditFileRegexMatch(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(FileRegexMatchTest, Audit_Multiline_State_1)
{
    MakeTempfile("key=foo\nkey=bar\nkey=baz");
    FileRegexMatchParams params;
    params.path = mTempdir;
    params.filenamePattern = regex("1");
    params.matchPattern = R"(^key=.*$)";
    params.matchOperation = Operation::Match;
    params.statePattern = string(R"(^key=bar$)");
    params.stateOperation = Operation::Match;
    params.behavior = Behavior::AllExist;
    auto result = AuditFileRegexMatch(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(FileRegexMatchTest, Audit_Multiline_State_2)
{
    MakeTempfile("key=foo\nkey=bar\nkey=baz");
    FileRegexMatchParams params;
    params.path = mTempdir;
    params.filenamePattern = regex("1");
    params.matchPattern = R"(^key=.*$)";
    params.matchOperation = Operation::Match;
    params.statePattern = string(R"(^key=(foo|bar|baz)$)");
    params.stateOperation = Operation::Match;
    params.behavior = Behavior::AllExist;
    auto result = AuditFileRegexMatch(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(FileRegexMatchTest, Audit_Multiline_State_4)
{
    MakeTempfile("key=foo\nkey=bar\nkey=baz");
    FileRegexMatchParams params;
    params.path = mTempdir;
    params.filenamePattern = regex("1");
    params.matchPattern = R"(^key=.*$)";
    params.matchOperation = Operation::Match;
    params.statePattern = string(R"(^key=(foo|bar)$)");
    params.stateOperation = Operation::Match;
    params.behavior = Behavior::AllExist;
    auto result = AuditFileRegexMatch(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(FileRegexMatchTest, Audit_FilenamePattern_1)
{
    MakeTempfile("key=foo\nkey=bar\nkey=baz");
    FileRegexMatchParams params;
    params.path = mTempdir;
    params.filenamePattern = regex("1");
    params.matchPattern = R"(^key=.*$)";
    params.statePattern = string(R"(^key=(foo|bar)$)");
    params.behavior = Behavior::AllExist;
    auto result = AuditFileRegexMatch(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(FileRegexMatchTest, Audit_FilenamePattern_2)
{
    MakeTempfile("key=foo\nkey=bar\nkey=baz");
    FileRegexMatchParams params;
    params.path = mTempdir;
    params.filenamePattern = regex("2"); // no such file
    params.matchPattern = R"(^key=.*$)";
    params.statePattern = string(R"(^key=(foo|bar)$)");
    params.behavior = Behavior::AllExist;
    auto result = AuditFileRegexMatch(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(FileRegexMatchTest, Audit_FilenamePattern_3)
{
    MakeTempfile("nothing important here");
    MakeTempfile("key=foo\nkey=bar\nkey=baz");
    MakeTempfile("nothing important here as well");
    FileRegexMatchParams params;
    params.path = mTempdir;
    params.filenamePattern = regex(".*");
    params.matchPattern = R"(^key=.*$)";
    params.statePattern = string(R"(^key=(foo|bar)$)");
    params.behavior = Behavior::AllExist;
    auto result = AuditFileRegexMatch(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);

    CompactListFormatter formatter;
    auto payload = formatter.Format(mIndicators);
    ASSERT_TRUE(payload.HasValue());
    std::cerr << "Payload: " << payload.Value() << std::endl;
    EXPECT_NE(payload.Value().find("[NonCompliant] At least one file did not match the pattern"), string::npos);
}

TEST_F(FileRegexMatchTest, Audit_FilenamePattern_4)
{
    MakeTempfile("nothing important here");
    MakeTempfile("key=foo\nkey=bar\nkey=baz");
    MakeTempfile("nothing important here as well");
    FileRegexMatchParams params;
    params.path = mTempdir;
    params.filenamePattern = regex("2");
    params.matchPattern = R"(^key=.*$)";
    params.statePattern = string(R"(^key=(foo|bar|baz)$)");
    params.behavior = Behavior::AllExist;
    auto result = AuditFileRegexMatch(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(FileRegexMatchTest, Audit_FilenamePattern_5)
{
    MakeTempfile("nothing important here");
    MakeTempfile("key=foo\nkey=bar\nkey=baz");
    MakeTempfile("nothing important here as well");
    FileRegexMatchParams params;
    params.path = mTempdir;
    params.filenamePattern = regex(".*");
    params.matchPattern = R"(^key=.*$)";
    params.statePattern = string(R"(^key=(foo|bar|baz)$)");
    params.behavior = Behavior::AtLeastOneExists;
    auto result = AuditFileRegexMatch(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(FileRegexMatchTest, Audit_FilenamePattern_6)
{
    MakeTempfile("nothing important here");
    MakeTempfile("key=foo\nkey=bar\nkey=baz");
    MakeTempfile("nothing important here as well");
    FileRegexMatchParams params;
    params.path = mTempdir;
    params.filenamePattern = regex("2");
    params.matchPattern = R"(^key=(.*)$)";
    params.statePattern = string(R"(^(foo|bar|baz)$)"); // Unlike the previous test, this matches against 'foo', 'bar', and 'baz'
    params.behavior = Behavior::AllExist;
    auto result = AuditFileRegexMatch(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(FileRegexMatchTest, Audit_FilenamePattern_7)
{
    MakeTempfile("nothing important here");
    MakeTempfile("key=foo\nkey=bar\nkey=baz");
    MakeTempfile("nothing important here as well");
    FileRegexMatchParams params;
    params.path = mTempdir;
    params.filenamePattern = regex("2");
    params.matchPattern = R"(^key=(.*)$)";
    params.statePattern = string(R"(^key=(foo|bar|baz)$)"); // This won't work now as we match against 'foo', 'bar', and 'baz'
    params.behavior = Behavior::AllExist;
    auto result = AuditFileRegexMatch(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(FileRegexMatchTest, Audit_FilenamePattern_8)
{
    MakeTempfile("nothing important here");
    MakeTempfile("key=foo\nkey=bar\nkey=baz");
    MakeTempfile("nothing important here as well");
    FileRegexMatchParams params;
    params.path = mTempdir;
    params.filenamePattern = regex("2");
    params.matchPattern = R"(^(key=(.*))$)";
    params.statePattern = string(R"(^key=(foo|bar|baz)$)"); // This should work again as we added a capturing group for the full key=value
    params.behavior = Behavior::AllExist;
    auto result = AuditFileRegexMatch(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(FileRegexMatchTest, Audit_FilenamePatternSuffix)
{
    const string filename = string(mTempdir) + "/example.repo";
    mTempfiles.push_back(filename);
    std::ofstream(filename) << "setting=true";
    FileRegexMatchParams params;
    params.path = mTempdir;
    params.filenamePattern = regex(R"(\.repo$)");
    params.filenameSearch = true;
    params.matchPattern = R"(^setting=true$)";

    const auto result = AuditFileRegexMatch(params, mIndicators, mContext);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());
}

TEST_F(FileRegexMatchTest, Audit_RepositoryChecksIgnoreUnselectedFiles)
{
    MakeTempfile("[base]\nname=Base\ngpgcheck=1\n");
    MakeTempfile("");
    FileRegexMatchParams params;
    params.path = mTempdir;
    params.filenamePattern = regex(".*");
    params.matchPattern = R"(^[ \t]*\[[^\]]+\][ \t]*\n(?:[^\[]*\n)*)";
    params.wholeFile = true;
    params.allMatches = true;
    params.statePattern = string(R"(\n[ \t]*gpgcheck[ \t]*=[ \t]*(True|1|yes)[ \t]*(\n|$))");

    auto result = AuditFileRegexMatch(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());

    params.allMatches = false;
    params.noneMatches = true;
    params.statePattern = string(R"(\n[ \t]*gpgcheck[ \t]*=[ \t]*(False|0|no)[ \t]*(\n|$))");
    result = AuditFileRegexMatch(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());

    MakeTempfile("[disabled]\ngpgcheck=0\n");
    for (const auto behavior : {Behavior::AllExist, Behavior::AnyExist, Behavior::AtLeastOneExists})
    {
        params.behavior = behavior;
        result = AuditFileRegexMatch(params, mIndicators, mContext);
        ASSERT_TRUE(result.HasValue());
        EXPECT_EQ(Status::NonCompliant, result.Value());
    }
}

TEST_F(FileRegexMatchTest, Audit_ExactFilenameDoesNotSelectBackup)
{
    const string filename = string(mTempdir) + "/shadow";
    const string backup = filename + "-";
    mTempfiles.insert(mTempfiles.end(), {filename, backup});
    std::ofstream(filename) << "root:!";
    std::ofstream(backup) << "root:unlocked";
    FileRegexMatchParams params;
    params.path = mTempdir;
    params.filenamePattern = regex("shadow");
    params.matchPattern = R"(^root:(!|\*|!!))";

    const auto result = AuditFileRegexMatch(params, mIndicators, mContext);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());
}

TEST_F(FileRegexMatchTest, Audit_TestPattern)
{
    MakeTempfile(
        "# here are the per-package modules (the \"Primary\" block)\naccount\t[success=1 new_authtok_reqd=done default=ignore]\tpam_unix.so \n# here's "
        "the fallback if no module succeeds\n");
    FileRegexMatchParams params;
    params.path = mTempdir;
    params.filenamePattern = regex("1");
    params.matchOperation = Operation::Match;
    params.matchPattern = R"(^[ \t]*account[ \t]+[^#\n\r]+[ \t]+pam_unix\.so\b)";
    params.behavior = Behavior::AtLeastOneExists;
    auto result = AuditFileRegexMatch(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(FileRegexMatchTest, Audit_SymlinkFollow_1)
{
    MakeTempfile("test");
    const auto targetFilename = mTempfiles.back();
    const auto linkFilename = targetFilename + ".link";

    FileRegexMatchParams params;
    params.path = mTempdir;
    params.filenamePattern = regex(".*\\.link");
    params.matchOperation = Operation::Match;
    params.matchPattern = R"(^test$)";
    params.behavior = Behavior::AtLeastOneExists;

    ASSERT_EQ(0, symlink(targetFilename.c_str(), linkFilename.c_str()));
    auto result = AuditFileRegexMatch(params, mIndicators, mContext);
    EXPECT_EQ(0, unlink(linkFilename.c_str()));
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(FileRegexMatchTest, Audit_SymlinkFollow_2)
{
    MakeTempfile("test");
    const auto targetFilename = mTempfiles.back();
    const auto linkFilename = targetFilename + ".link";

    FileRegexMatchParams params;
    params.path = mTempdir;
    params.filenamePattern = regex(".*\\.link");
    params.matchOperation = Operation::Match;
    params.matchPattern = R"(^foo$)"; // pattern mismatch against 'test'
    params.behavior = Behavior::AtLeastOneExists;

    ASSERT_EQ(0, symlink(targetFilename.c_str(), linkFilename.c_str()));
    auto result = AuditFileRegexMatch(params, mIndicators, mContext);
    EXPECT_EQ(0, unlink(linkFilename.c_str()));
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(FileRegexMatchTest, Audit_SymlinkFollow_Directory)
{
    const auto targetDirectory = std::string(mTempdir) + "/Audit_SymlinkFollow_Directory";
    const auto linkFilename = targetDirectory + ".link";

    FileRegexMatchParams params;
    params.path = mTempdir;
    params.filenamePattern = regex(".*\\.link");
    params.matchOperation = Operation::Match;
    params.matchPattern = R"(.*)";
    params.behavior = Behavior::NoneExist;

    ASSERT_EQ(0, mkdir(targetDirectory.c_str(), 0755));
    EXPECT_EQ(0, symlink(targetDirectory.c_str(), linkFilename.c_str()));
    auto result = AuditFileRegexMatch(params, mIndicators, mContext);
    EXPECT_EQ(0, unlink(linkFilename.c_str()));
    EXPECT_EQ(0, rmdir(targetDirectory.c_str()));
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(FileRegexMatchTest, Audit_SymlinkFollow_DanglingLink)
{
    MakeTempfile("test");
    const auto targetFilename = mTempfiles.back();
    const auto linkFilename = targetFilename + ".link";

    FileRegexMatchParams params;
    params.path = mTempdir;
    params.filenamePattern = regex(".*\\.link");
    params.matchOperation = Operation::Match;
    params.matchPattern = R"(^foo$)"; // pattern mismatch against 'test'
    params.behavior = Behavior::AtLeastOneExists;

    ASSERT_EQ(0, symlink(targetFilename.c_str(), linkFilename.c_str()));
    EXPECT_EQ(0, unlink(targetFilename.c_str()));
    auto result = AuditFileRegexMatch(params, mIndicators, mContext);
    EXPECT_EQ(0, unlink(linkFilename.c_str()));
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
}
