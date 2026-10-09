// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "CommonUtils.h"
#include "MockContext.h"

#include <Optional.h>
#include <SystemAccountShell.h>
#include <fstream>
#include <parsers/LoginDefs.h>
#include <sys/stat.h>

using ComplianceEngine::AuditSystemAccountShell;
using ComplianceEngine::CompactListFormatter;
using ComplianceEngine::Error;
using ComplianceEngine::IndicatorsTree;
using ComplianceEngine::Optional;
using ComplianceEngine::Result;
using ComplianceEngine::Status;
using std::map;
using std::string;

namespace
{
string LoginDefsAtByteLimit()
{
    string contents = "UID_MIN 2000\n";
    const string commentLine = string(4095, '#') + '\n';
    while (contents.size() + commentLine.size() <= ComplianceEngine::LoginDefs::MaxBytes)
    {
        contents += commentLine;
    }
    contents.append(ComplianceEngine::LoginDefs::MaxBytes - contents.size(), '#');
    return contents;
}
} // namespace

class EnsureSystemAccountsDoNotHaveValidShellTest : public ::testing::Test
{
protected:
    MockContext mContext;
    IndicatorsTree mIndicators;
    CompactListFormatter mFormatter;
    string mTempDir;

    void SetUp() override
    {
        mIndicators.Push("EnsureAccountsWithoutShellAreLocked");
        auto filename = mContext.MakeTempfile("/bin/bash\n/bin/nologin");
        mContext.SetSpecialFilePath("/etc/shells", filename);
        filename = mContext.MakeTempfile("UID_MIN 100");
        mContext.SetSpecialFilePath("/etc/login.defs", filename);
        filename = CreateTestPasswdFile(101, "/bin/bash");
        mContext.SetSpecialFilePath("/etc/passwd", filename);
    }

    void TearDown() override
    {
    }

    string CreateTestPasswdFile(uid_t uid, string shell, std::string username = "testuser")
    {
        auto content = username + ":x";
        content += ":" + std::to_string(uid);
        content += ":" + std::to_string(uid);
        content += ":::";
        content += shell;
        return mContext.MakeTempfile(std::move(content));
    }
};

TEST_F(EnsureSystemAccountsDoNotHaveValidShellTest, NoEtcPasswdFile)
{
    mContext.SetSpecialFilePath("/etc/passwd", mContext.GetTempdirPath() + "/missing-passwd");
    auto result = AuditSystemAccountShell(mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
}

TEST_F(EnsureSystemAccountsDoNotHaveValidShellTest, NoLoginDefsFile_1)
{
    mContext.SetSpecialFilePath("/etc/login.defs", mContext.GetTempdirPath() + "/missing-login-defs");
    mContext.SetSpecialFilePath("/etc/passwd", mContext.MakeTempfile(""));
    auto result = AuditSystemAccountShell(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    // No system accounts found
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureSystemAccountsDoNotHaveValidShellTest, NoLoginDefsFile_2)
{
    mContext.SetSpecialFilePath("/etc/login.defs", mContext.GetTempdirPath() + "/missing-login-defs");
    auto filename = CreateTestPasswdFile(1001, "/bin/bash");
    mContext.SetSpecialFilePath("/etc/passwd", filename);
    auto result = AuditSystemAccountShell(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    // UID_MIN defaults to 1000 in case there's no /etc/login.defs file
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureSystemAccountsDoNotHaveValidShellTest, NoLoginDefsFile_3)
{
    mContext.SetSpecialFilePath("/etc/login.defs", mContext.GetTempdirPath() + "/missing-login-defs");
    auto result = AuditSystemAccountShell(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    // Min UID is 1000 as there's no /etc/login.defs file
    // We currently have one user: 101 with /bin/bash
    EXPECT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureSystemAccountsDoNotHaveValidShellTest, LoginDefs_1)
{
    auto filename = mContext.MakeTempfile("UID_MIN -1");
    mContext.SetSpecialFilePath("/etc/login.defs", filename);
    auto result = AuditSystemAccountShell(mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
}

TEST_F(EnsureSystemAccountsDoNotHaveValidShellTest, LoginDefs_2)
{
    auto filename = mContext.MakeTempfile("#UID_MIN -1");
    mContext.SetSpecialFilePath("/etc/login.defs", filename);
    auto result = AuditSystemAccountShell(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
}

TEST_F(EnsureSystemAccountsDoNotHaveValidShellTest, LoginDefs_3)
{
    auto filename = mContext.MakeTempfile("UID_MIN  foo bar");
    mContext.SetSpecialFilePath("/etc/login.defs", filename);
    auto result = AuditSystemAccountShell(mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
}

TEST_F(EnsureSystemAccountsDoNotHaveValidShellTest, LoginDefs_4)
{
    auto filename = mContext.MakeTempfile("UID_MIN\t0 foo");
    mContext.SetSpecialFilePath("/etc/login.defs", filename);
    auto result = AuditSystemAccountShell(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
}

TEST_F(EnsureSystemAccountsDoNotHaveValidShellTest, UidMinMatchesExactKeyNotSubstring)
{
    mContext.SetSpecialFilePath("/etc/login.defs", mContext.MakeTempfile("NOT_UID_MIN 2000\n"));
    mContext.SetSpecialFilePath("/etc/passwd", CreateTestPasswdFile(1500, "/bin/bash"));
    const auto result = AuditSystemAccountShell(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());
    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    EXPECT_TRUE(root->indicators.empty());
}

TEST_F(EnsureSystemAccountsDoNotHaveValidShellTest, CorruptedUidMinKeyDoesNotBecomeMissingKeyDefault)
{
    const string contents("UID_MIN\0 2000\n", 14);
    mContext.SetSpecialFilePath("/etc/login.defs", mContext.MakeTempfile(contents));
    mContext.SetSpecialFilePath("/etc/passwd", CreateTestPasswdFile(1500, "/bin/bash"));
    const auto result = AuditSystemAccountShell(mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EINVAL, result.Error().code);
    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    EXPECT_TRUE(root->indicators.empty());
}

TEST_F(EnsureSystemAccountsDoNotHaveValidShellTest, CorruptedFirstUidMinKeyDoesNotSelectLaterValue)
{
    const string contents("UID_MIN\0 2000\nUID_MIN 1000\n", 27);
    mContext.SetSpecialFilePath("/etc/login.defs", mContext.MakeTempfile(contents));
    mContext.SetSpecialFilePath("/etc/passwd", CreateTestPasswdFile(1500, "/bin/bash"));
    const auto result = AuditSystemAccountShell(mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EINVAL, result.Error().code);
    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    EXPECT_TRUE(root->indicators.empty());
}

TEST_F(EnsureSystemAccountsDoNotHaveValidShellTest, UnrelatedCorruptedKeyRetainsMissingKeyDefault)
{
    const string contents("NOT_UID_MIN\0 2000\n", 18);
    mContext.SetSpecialFilePath("/etc/login.defs", mContext.MakeTempfile(contents));
    mContext.SetSpecialFilePath("/etc/passwd", CreateTestPasswdFile(1500, "/bin/bash"));
    const auto result = AuditSystemAccountShell(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());
    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    EXPECT_TRUE(root->indicators.empty());
}

TEST_F(EnsureSystemAccountsDoNotHaveValidShellTest, CorruptedLaterKeyDoesNotOverrideFirstUidMin)
{
    const string contents("UID_MIN 2000\nUID_MIN\0 1000\n", 27);
    mContext.SetSpecialFilePath("/etc/login.defs", mContext.MakeTempfile(contents));
    mContext.SetSpecialFilePath("/etc/passwd", CreateTestPasswdFile(1500, "/bin/bash"));
    const auto result = AuditSystemAccountShell(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::NonCompliant, result.Value());
    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    ASSERT_EQ(1U, root->indicators.size());
    EXPECT_EQ(Status::NonCompliant, root->indicators.front().status);
}

TEST_F(EnsureSystemAccountsDoNotHaveValidShellTest, LoginDefsFileAtByteLimitUsesSelectedUidMin)
{
    const string contents = LoginDefsAtByteLimit();
    ASSERT_EQ(ComplianceEngine::LoginDefs::MaxBytes, contents.size());
    const string filename = mContext.MakeTempfile(contents);
    struct stat fileStat;
    ASSERT_EQ(0, ::stat(filename.c_str(), &fileStat));
    ASSERT_EQ(static_cast<off_t>(ComplianceEngine::LoginDefs::MaxBytes), fileStat.st_size);
    mContext.SetSpecialFilePath("/etc/login.defs", filename);
    mContext.SetSpecialFilePath("/etc/passwd", CreateTestPasswdFile(1500, "/bin/bash"));

    const auto result = AuditSystemAccountShell(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::NonCompliant, result.Value());
    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    ASSERT_EQ(1U, root->indicators.size());
    EXPECT_EQ(Status::NonCompliant, root->indicators.front().status);
}

TEST_F(EnsureSystemAccountsDoNotHaveValidShellTest, LoginDefsFileOverByteLimitReturnsErrorWithoutIndicators)
{
    string contents = LoginDefsAtByteLimit();
    contents += '#';
    ASSERT_EQ(ComplianceEngine::LoginDefs::MaxBytes + 1, contents.size());
    const string filename = mContext.MakeTempfile(contents);
    struct stat fileStat;
    ASSERT_EQ(0, ::stat(filename.c_str(), &fileStat));
    ASSERT_EQ(static_cast<off_t>(ComplianceEngine::LoginDefs::MaxBytes + 1), fileStat.st_size);
    mContext.SetSpecialFilePath("/etc/login.defs", filename);
    mContext.SetSpecialFilePath("/etc/passwd", CreateTestPasswdFile(1500, "/bin/bash"));

    const auto result = AuditSystemAccountShell(mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(E2BIG, result.Error().code);
    EXPECT_EQ("login.defs byte limit exceeded", result.Error().message);
    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    EXPECT_TRUE(root->indicators.empty());
}

TEST_F(EnsureSystemAccountsDoNotHaveValidShellTest, UidMinRejectsInlineHashWithoutIndicators)
{
    mContext.SetSpecialFilePath("/etc/login.defs", mContext.MakeTempfile("UID_MIN 100#note\n"));
    const auto result = AuditSystemAccountShell(mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EINVAL, result.Error().code);
    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    EXPECT_TRUE(root->indicators.empty());
}

TEST_F(EnsureSystemAccountsDoNotHaveValidShellTest, UidMinRejectsSelectedEmbeddedNul)
{
    const string contents("UID_MIN 100 \0ignored\n", 21);
    mContext.SetSpecialFilePath("/etc/login.defs", mContext.MakeTempfile(contents));
    const auto result = AuditSystemAccountShell(mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EINVAL, result.Error().code);
    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    EXPECT_TRUE(root->indicators.empty());
}

TEST_F(EnsureSystemAccountsDoNotHaveValidShellTest, UidMinSelectsFirstExactOccurrence)
{
    mContext.SetSpecialFilePath("/etc/login.defs", mContext.MakeTempfile("UID_MIN 100\nUID_MIN 2000\n"));
    const auto result = AuditSystemAccountShell(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());
    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    EXPECT_TRUE(root->indicators.empty());
}

TEST_F(EnsureSystemAccountsDoNotHaveValidShellTest, AllowlistedAccount_1)
{
    auto filename = CreateTestPasswdFile(0, "/bin/bash", "root");
    mContext.SetSpecialFilePath("/etc/passwd", filename);
    auto result = AuditSystemAccountShell(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    // 'root' is allowlisted
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureSystemAccountsDoNotHaveValidShellTest, AllowlistedAccount_2)
{
    auto filename = CreateTestPasswdFile(0, "/bin/bash", "halt");
    mContext.SetSpecialFilePath("/etc/passwd", filename);
    auto result = AuditSystemAccountShell(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    // 'halt' is allowlisted
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureSystemAccountsDoNotHaveValidShellTest, AllowlistedAccount_3)
{
    auto filename = CreateTestPasswdFile(0, "/bin/bash", "shutdown");
    mContext.SetSpecialFilePath("/etc/passwd", filename);
    auto result = AuditSystemAccountShell(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    // 'shutdown' is allowlisted
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureSystemAccountsDoNotHaveValidShellTest, AllowlistedAccount_4)
{
    auto filename = CreateTestPasswdFile(0, "/bin/bash", "nfsnobody");
    mContext.SetSpecialFilePath("/etc/passwd", filename);
    auto result = AuditSystemAccountShell(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    // 'nfsnobody' is allowlisted
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureSystemAccountsDoNotHaveValidShellTest, SystemUser_1)
{
    auto filename = CreateTestPasswdFile(99, "/bin/bash");
    mContext.SetSpecialFilePath("/etc/passwd", filename);
    auto result = AuditSystemAccountShell(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    ASSERT_FALSE(root->indicators.empty());
    EXPECT_EQ(root->indicators.back().message, "System user 99 has a valid login shell");
    EXPECT_EQ(root->indicators.back().status, Status::NonCompliant);
}

TEST_F(EnsureSystemAccountsDoNotHaveValidShellTest, SystemUser_2)
{
    auto filename = CreateTestPasswdFile(99, "/bin/nologin");
    mContext.SetSpecialFilePath("/etc/passwd", filename);
    auto result = AuditSystemAccountShell(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    ASSERT_FALSE(root->indicators.empty());
    EXPECT_EQ(root->indicators.back().message, "System user 99 does not have a valid login shell");
    EXPECT_EQ(root->indicators.back().status, Status::Compliant);
}

TEST_F(EnsureSystemAccountsDoNotHaveValidShellTest, RegularUser_1)
{
    auto filename = CreateTestPasswdFile(100, "/bin/bash");
    mContext.SetSpecialFilePath("/etc/passwd", filename);
    auto result = AuditSystemAccountShell(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    EXPECT_TRUE(root->indicators.empty());
}

TEST_F(EnsureSystemAccountsDoNotHaveValidShellTest, RegularUser_2)
{
    auto filename = CreateTestPasswdFile(100, "/bin/nologin");
    mContext.SetSpecialFilePath("/etc/passwd", filename);
    auto result = AuditSystemAccountShell(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    EXPECT_TRUE(root->indicators.empty());
}
