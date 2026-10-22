// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "CommonUtils.h"
#include "Evaluator.h"
#include "MockContext.h"

#include <DefaultUmask.h>
#include <Optional.h>
#include <cerrno>
#include <fstream>
#include <iterator>
#include <unistd.h>

using ComplianceEngine::AuditDefaultUmask;
using ComplianceEngine::Error;
using ComplianceEngine::IndicatorsTree;
using ComplianceEngine::Optional;
using ComplianceEngine::RemediateDefaultUmask;
using ComplianceEngine::Result;
using ComplianceEngine::Status;
using std::map;
using std::string;

class EnsureDefaultUserUmaskIsConfiguredTest : public ::testing::Test
{
protected:
    MockContext mContext;
    IndicatorsTree mIndicators;

    string mTempDir;

    void SetUp() override
    {
        mIndicators.Push("EnsurePasswordChangeIsInPast");
        const auto missingPath = mContext.GetTempdirPath() + "/missing-config";
        mContext.SetSpecialFilePath("/etc/bashrc", missingPath);
        mContext.SetSpecialFilePath("/etc/bash.bashrc", missingPath);
        mContext.SetSpecialFilePath("/etc/profile", missingPath);
        mContext.SetSpecialFilePath("/etc/profile.d/", mContext.GetTempdirPath());
        mContext.SetSpecialFilePath("/etc/pam.d/postlogin", missingPath);
        mContext.SetSpecialFilePath("/etc/login.defs", missingPath);
        mContext.SetSpecialFilePath("/etc/default/login", missingPath);
    }

    void TearDown() override
    {
    }
};

TEST_F(EnsureDefaultUserUmaskIsConfiguredTest, CorrectValue_1)
{
    auto filename = mContext.MakeTempfile("umask 027");
    mContext.SetSpecialFilePath("/etc/bashrc", filename);
    auto result = AuditDefaultUmask(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);

    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    ASSERT_FALSE(root->indicators.empty());
    EXPECT_EQ(root->indicators.back().message, string("umask is correctly set in ") + filename);
}

TEST_F(EnsureDefaultUserUmaskIsConfiguredTest, ReachedReadFailureIsNotAbsentSetting)
{
    const auto path = mContext.MakeTempfile("umask 027\n");
    mContext.SetSpecialFilePath("/etc/bashrc", path);
    ON_CALL(mContext, ReadFileDescriptor(testing::_, testing::_, testing::_)).WillByDefault([](int, void*, std::size_t) -> ssize_t {
        errno = EIO;
        return -1;
    });

    const auto result = AuditDefaultUmask(mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EIO, result.Error().code);
    EXPECT_EQ("Failed to read file bytes", result.Error().message);
    EXPECT_TRUE(mIndicators.Back().indicators.empty());
}

TEST_F(EnsureDefaultUserUmaskIsConfiguredTest, NulAndDefaultByteLimitAreErrors)
{
    const auto path = mContext.MakeTempfile(string("umask 027\0\n", 11));
    mContext.SetSpecialFilePath("/etc/bashrc", path);
    auto result = AuditDefaultUmask(mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EBADMSG, result.Error().code);

    const auto oversized = mContext.MakeTempfile(string(1024 * 1024 + 1, '#'));
    mContext.SetSpecialFilePath("/etc/bashrc", oversized);
    result = AuditDefaultUmask(mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(E2BIG, result.Error().code);
    EXPECT_TRUE(mIndicators.Back().indicators.empty());
}

TEST_F(EnsureDefaultUserUmaskIsConfiguredTest, CrBeforeLfRemainsPartOfLine)
{
    const auto path = mContext.MakeTempfile("umask 027\r\n");
    mContext.SetSpecialFilePath("/etc/bashrc", path);
    const auto result = AuditDefaultUmask(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::NonCompliant, result.Value());
    EXPECT_EQ("umask is not set", mIndicators.Back().indicators.back().message);
}

TEST_F(EnsureDefaultUserUmaskIsConfiguredTest, CorrectValueStopsWithoutReadingTail)
{
    const auto path = mContext.MakeTempfile("umask 027\nunread tail\n");
    mContext.SetSpecialFilePath("/etc/bashrc", path);
    int reads = 0;
    int closes = 0;
    ON_CALL(mContext, ReadFileDescriptor(testing::_, testing::_, testing::_)).WillByDefault([&](int descriptor, void* buffer, std::size_t size) -> ssize_t {
        ++reads;
        if (reads == 1)
        {
            return mContext.ContextInterface::ReadFileDescriptor(descriptor, buffer, size);
        }
        errno = EIO;
        return -1;
    });
    ON_CALL(mContext, CloseFileDescriptor(testing::_)).WillByDefault([&](int descriptor) {
        ++closes;
        return mContext.ContextInterface::CloseFileDescriptor(descriptor);
    });

    const auto result = AuditDefaultUmask(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());
    EXPECT_EQ("umask is correctly set in " + path, mIndicators.Back().indicators.back().message);
    EXPECT_EQ(1, reads);
    EXPECT_EQ(2, closes);
}

TEST_F(EnsureDefaultUserUmaskIsConfiguredTest, CorrectValueCloseFailurePrecedesEarlyVerdict)
{
    const auto path = mContext.MakeTempfile("umask 027\n");
    mContext.SetSpecialFilePath("/etc/bashrc", path);
    int closes = 0;
    ON_CALL(mContext, CloseFileDescriptor(testing::_)).WillByDefault([&](int descriptor) {
        ++closes;
        mContext.ContextInterface::CloseFileDescriptor(descriptor);
        if (closes == 1)
        {
            errno = EIO;
            return -1;
        }
        return 0;
    });

    const auto result = AuditDefaultUmask(mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EIO, result.Error().code);
    EXPECT_EQ(2, closes);
    EXPECT_TRUE(mIndicators.Back().indicators.empty());
}

TEST_F(EnsureDefaultUserUmaskIsConfiguredTest, CorrectValue_2)
{
    auto filename = mContext.MakeTempfile("umask u=rwx,g=rx,o=");
    mContext.SetSpecialFilePath("/etc/bashrc", filename);
    auto result = AuditDefaultUmask(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);

    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    ASSERT_FALSE(root->indicators.empty());
    EXPECT_EQ(root->indicators.back().message, string("umask is correctly set in ") + filename);
}

TEST_F(EnsureDefaultUserUmaskIsConfiguredTest, CorrectValue_3)
{
    auto filename = mContext.MakeTempfile("   umask\t\tu=rwx,g=rx,o=");
    mContext.SetSpecialFilePath("/etc/bashrc", filename);
    auto result = AuditDefaultUmask(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);

    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    ASSERT_FALSE(root->indicators.empty());
    EXPECT_EQ(root->indicators.back().message, string("umask is correctly set in ") + filename);
}

TEST_F(EnsureDefaultUserUmaskIsConfiguredTest, CorrectValue_4)
{
    auto filename = mContext.MakeTempfile("UMASK 027");
    mContext.SetSpecialFilePath("/etc/login.defs", filename);
    auto result = AuditDefaultUmask(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);

    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    ASSERT_FALSE(root->indicators.empty());
    EXPECT_EQ(root->indicators.back().message, string("umask is correctly set in ") + filename);
}

TEST_F(EnsureDefaultUserUmaskIsConfiguredTest, CorrectValue_MoreRestrictive_1)
{
    auto filename = mContext.MakeTempfile("umask u=rwx,g=r,o=");
    mContext.SetSpecialFilePath("/etc/bashrc", filename);
    auto result = AuditDefaultUmask(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);

    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    ASSERT_FALSE(root->indicators.empty());
    EXPECT_EQ(root->indicators.back().message, string("umask is correctly set in ") + filename);
}

TEST_F(EnsureDefaultUserUmaskIsConfiguredTest, CorrectValue_MoreRestrictive_2)
{
    auto filename = mContext.MakeTempfile("umask u=rwx,g=x,o=");
    mContext.SetSpecialFilePath("/etc/bashrc", filename);
    auto result = AuditDefaultUmask(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);

    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    ASSERT_FALSE(root->indicators.empty());
    EXPECT_EQ(root->indicators.back().message, string("umask is correctly set in ") + filename);
}

TEST_F(EnsureDefaultUserUmaskIsConfiguredTest, CorrectValue_MoreRestrictive_3)
{
    auto filename = mContext.MakeTempfile("umask u=rx,g=rx,o=");
    mContext.SetSpecialFilePath("/etc/bashrc", filename);
    auto result = AuditDefaultUmask(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);

    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    ASSERT_FALSE(root->indicators.empty());
    EXPECT_EQ(root->indicators.back().message, string("umask is correctly set in ") + filename);
}

TEST_F(EnsureDefaultUserUmaskIsConfiguredTest, CorrectValue_MoreRestrictive_4)
{
    auto filename = mContext.MakeTempfile("umask 037");
    mContext.SetSpecialFilePath("/etc/bashrc", filename);
    auto result = AuditDefaultUmask(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);

    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    ASSERT_FALSE(root->indicators.empty());
    EXPECT_EQ(root->indicators.back().message, string("umask is correctly set in ") + filename);
}

TEST_F(EnsureDefaultUserUmaskIsConfiguredTest, CorrectValue_MoreRestrictive_5)
{
    auto filename = mContext.MakeTempfile("umask 127");
    mContext.SetSpecialFilePath("/etc/bashrc", filename);
    auto result = AuditDefaultUmask(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);

    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    ASSERT_FALSE(root->indicators.empty());
    EXPECT_EQ(root->indicators.back().message, string("umask is correctly set in ") + filename);
}

TEST_F(EnsureDefaultUserUmaskIsConfiguredTest, IncorrectValue_1)
{
    auto filename = mContext.MakeTempfile("umask 026");
    mContext.SetSpecialFilePath("/etc/bashrc", filename);
    auto result = AuditDefaultUmask(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);

    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    ASSERT_FALSE(root->indicators.empty());
    EXPECT_EQ(root->indicators.back().message, string("umask is incorrectly set in ") + filename);
}

TEST_F(EnsureDefaultUserUmaskIsConfiguredTest, RemediateShellUmask)
{
    auto filename = mContext.MakeTempfile("umask u=rwx,g=rwx,o= # permissive\n");
    mContext.SetSpecialFilePath("/etc/bashrc", filename);

    auto result = RemediateDefaultUmask(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);

    std::ifstream input(filename);
    EXPECT_EQ(string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()), "umask 027 # permissive\n");
}

TEST_F(EnsureDefaultUserUmaskIsConfiguredTest, RemediatePamUmask)
{
    auto filename = mContext.MakeTempfile("session required pam_umask.so umask=022\n");
    mContext.SetSpecialFilePath("/etc/pam.d/postlogin", filename);

    auto result = RemediateDefaultUmask(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);

    std::ifstream input(filename);
    EXPECT_EQ(string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()), "session required pam_umask.so umask=027\n");
}

TEST_F(EnsureDefaultUserUmaskIsConfiguredTest, RemediateMissingUmaskInProfile)
{
    auto filename = mContext.MakeTempfile("# profile");
    mContext.SetSpecialFilePath("/etc/profile", filename);

    auto result = RemediateDefaultUmask(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);

    std::ifstream input(filename);
    EXPECT_EQ(string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()), "# profile\numask 027\n");
}

TEST_F(EnsureDefaultUserUmaskIsConfiguredTest, RemediateRejectsSymlink)
{
    const auto target = mContext.MakeTempfile("umask 022\n");
    const auto link = mContext.GetTempdirPath() + "/bashrc";
    ASSERT_EQ(symlink(target.c_str(), link.c_str()), 0);
    mContext.SetSpecialFilePath("/etc/bashrc", link);

    auto result = RemediateDefaultUmask(mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, EINVAL);

    std::ifstream input(target);
    EXPECT_EQ(string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()), "umask 022\n");
}

TEST_F(EnsureDefaultUserUmaskIsConfiguredTest, IncorrectValue_2)
{
    auto filename = mContext.MakeTempfile("umask 017");
    mContext.SetSpecialFilePath("/etc/bashrc", filename);
    auto result = AuditDefaultUmask(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);

    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    ASSERT_FALSE(root->indicators.empty());
    EXPECT_EQ(root->indicators.back().message, string("umask is incorrectly set in ") + filename);
}

TEST_F(EnsureDefaultUserUmaskIsConfiguredTest, IncorrectValue_3)
{
    auto filename = mContext.MakeTempfile("umask u=rwx,g=rwx,o=");
    mContext.SetSpecialFilePath("/etc/bashrc", filename);
    auto result = AuditDefaultUmask(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);

    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    ASSERT_FALSE(root->indicators.empty());
    EXPECT_EQ(root->indicators.back().message, string("umask is incorrectly set in ") + filename);
}

TEST_F(EnsureDefaultUserUmaskIsConfiguredTest, IncorrectValue_4)
{
    auto filename = mContext.MakeTempfile("umask u=rwx,g=rx,o=r");
    mContext.SetSpecialFilePath("/etc/bashrc", filename);
    auto result = AuditDefaultUmask(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);

    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    ASSERT_FALSE(root->indicators.empty());
    EXPECT_EQ(root->indicators.back().message, string("umask is incorrectly set in ") + filename);
}

TEST_F(EnsureDefaultUserUmaskIsConfiguredTest, IncorrectValue_5)
{
    auto filename = mContext.MakeTempfile("umask u=rwx,g=rx,o=w");
    mContext.SetSpecialFilePath("/etc/bashrc", filename);
    auto result = AuditDefaultUmask(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);

    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    ASSERT_FALSE(root->indicators.empty());
    EXPECT_EQ(root->indicators.back().message, string("umask is incorrectly set in ") + filename);
}

TEST_F(EnsureDefaultUserUmaskIsConfiguredTest, IncorrectValue_6)
{
    auto filename = mContext.MakeTempfile("umask u=rwx,g=rx,o=x");
    mContext.SetSpecialFilePath("/etc/bashrc", filename);
    auto result = AuditDefaultUmask(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);

    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    ASSERT_FALSE(root->indicators.empty());
    EXPECT_EQ(root->indicators.back().message, string("umask is incorrectly set in ") + filename);
}

TEST_F(EnsureDefaultUserUmaskIsConfiguredTest, IncorrectValue_7)
{
    auto filename = mContext.MakeTempfile("umask 028");
    mContext.SetSpecialFilePath("/etc/bashrc", filename);
    auto result = AuditDefaultUmask(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);

    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    ASSERT_FALSE(root->indicators.empty());
    EXPECT_EQ(root->indicators.back().message, string("umask is not set"));
}

TEST_F(EnsureDefaultUserUmaskIsConfiguredTest, NoUmask)
{
    auto result = AuditDefaultUmask(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);

    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    ASSERT_FALSE(root->indicators.empty());
    EXPECT_EQ(root->indicators.back().message, string("umask is not set"));
}

TEST_F(EnsureDefaultUserUmaskIsConfiguredTest, Precedence_1)
{
    auto filename1 = mContext.MakeTempfile("umask u=rwx,g=rx,o=x", ".sh");
    auto filename2 = mContext.MakeTempfile("umask u=rwx,g=rx,o=");
    mContext.SetSpecialFilePath("/etc/bashrc", filename2);
    auto result = AuditDefaultUmask(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);

    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    ASSERT_EQ(root->indicators.size(), 2u);
    EXPECT_EQ(root->indicators[0].message, string("umask is incorrectly set in ") + filename1);
    EXPECT_EQ(root->indicators[1].message, string("umask is correctly set in ") + filename2);
}

TEST_F(EnsureDefaultUserUmaskIsConfiguredTest, Precedence_2)
{
    auto filename1 = mContext.MakeTempfile("umask u=rwx,g=rx,o=", ".sh");
    auto filename2 = mContext.MakeTempfile("umask u=rwx,g=rx,o=x");
    mContext.SetSpecialFilePath("/etc/bashrc", filename2);
    auto result = AuditDefaultUmask(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);

    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    ASSERT_EQ(root->indicators.size(), 1u);
    EXPECT_EQ(root->indicators[0].message, string("umask is correctly set in ") + filename1);
}

TEST_F(EnsureDefaultUserUmaskIsConfiguredTest, CorrectValue_PAM_1)
{
    auto filename = mContext.MakeTempfile("session pam_umask.so umask=027");
    mContext.SetSpecialFilePath("/etc/pam.d/postlogin", filename);
    auto result = AuditDefaultUmask(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);

    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    ASSERT_EQ(root->indicators.size(), 1u);
    EXPECT_EQ(root->indicators[0].message, string("umask is correctly set in ") + filename);
}

TEST_F(EnsureDefaultUserUmaskIsConfiguredTest, CorrectValue_PAM_2)
{
    auto filename = mContext.MakeTempfile("session\tpam_umask.so\t \tumask=027");
    mContext.SetSpecialFilePath("/etc/pam.d/postlogin", filename);
    auto result = AuditDefaultUmask(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);

    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    ASSERT_EQ(root->indicators.size(), 1u);
    EXPECT_EQ(root->indicators[0].message, string("umask is correctly set in ") + filename);
}

TEST_F(EnsureDefaultUserUmaskIsConfiguredTest, IncorrectValue_PAM_1)
{
    auto filename = mContext.MakeTempfile("session\tpam_umask.so\t \tumask=026");
    mContext.SetSpecialFilePath("/etc/pam.d/postlogin", filename);
    auto result = AuditDefaultUmask(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);

    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    ASSERT_EQ(root->indicators.size(), 1u);
    EXPECT_EQ(root->indicators[0].message, string("umask is incorrectly set in ") + filename);
}

TEST_F(EnsureDefaultUserUmaskIsConfiguredTest, IncorrectValue_PAM_2)
{
    auto filename = mContext.MakeTempfile("session\tpam_umask.so\t \tumask=007");
    mContext.SetSpecialFilePath("/etc/pam.d/postlogin", filename);
    auto result = AuditDefaultUmask(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);

    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    ASSERT_EQ(root->indicators.size(), 1u);
    EXPECT_EQ(root->indicators[0].message, string("umask is incorrectly set in ") + filename);
}
