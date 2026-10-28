// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Clean minimal test file begins
#include "Evaluator.h"
#include "MockContext.h"

#include <SshKeyPermissions.h>
#include <cerrno>
#include <fstream>
#include <gtest/gtest.h>
#include <map>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

using ComplianceEngine::AuditSshKeyPermissions;
using ComplianceEngine::IndicatorsTree;
using ComplianceEngine::RemediateSshKeyPermissions;
using ComplianceEngine::SshKeyPermissionsParams;
using ComplianceEngine::SshKeyType;
using ComplianceEngine::Status;

static const char kPublicKeySample[] = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyMaterial user@example\n";
static const char kPrivateKeyHeader[] = "-----BEGIN OPENSSH PRIVATE KEY-----\n";

TEST(SshKeyRangeTest, MissingRootRemainsCompliantAndDeniedRootIsAnError)
{
    MockContext context;
    IndicatorsTree indicators;
    indicators.Push("SSH");
    const std::string root = context.GetTempdirPath() + "/missing-ssh";
    context.SetSpecialFilePath("/etc/ssh", root);
    SshKeyPermissionsParams params;
    params.type = SshKeyType::Public;
    const auto absent = AuditSshKeyPermissions(params, indicators, context);
    ASSERT_TRUE(absent.HasValue());
    EXPECT_EQ(Status::Compliant, absent.Value());

    ON_CALL(context, LstatPath(::testing::_, ::testing::_)).WillByDefault([](const char*, struct stat*) {
        errno = EACCES;
        return -1;
    });
    const auto denied = RemediateSshKeyPermissions(params, indicators, context);
    ASSERT_FALSE(denied.HasValue());
    EXPECT_EQ(EACCES, denied.Error().code);
}

TEST(SshKeyRangeTest, FirstNoncomplianceBreaksWithoutReadingRemainderButCloseErrorWins)
{
    MockContext context;
    IndicatorsTree indicators;
    indicators.Push("SSH");
    const std::string root = context.GetTempdirPath() + "/ssh";
    ASSERT_EQ(0, mkdir(root.c_str(), 0700));
    const std::string key = root + "/key";
    std::ofstream(key) << kPublicKeySample;
    context.SetSpecialFilePath("/etc/ssh", root);
    EXPECT_CALL(context, GetFileContents(key)).WillOnce(::testing::Return(ComplianceEngine::Result<std::string>(kPublicKeySample)));
    std::size_t entries = 0;
    ON_CALL(context, ReadDirectory(::testing::_)).WillByDefault([&entries](DIR * directory) -> struct dirent* {
        if (entries == 1)
        {
            errno = EIO;
            return nullptr;
        }
        struct dirent* item = readdir(directory);
        if (item && std::string(item->d_name) != "." && std::string(item->d_name) != "..")
        {
            ++entries;
        }
        return item;
    });
    SshKeyPermissionsParams params;
    params.type = SshKeyType::Public;
    const auto verdict = AuditSshKeyPermissions(params, indicators, context);
    ASSERT_TRUE(verdict.HasValue());
    EXPECT_EQ(Status::NonCompliant, verdict.Value());
    EXPECT_EQ(1u, entries);

    ON_CALL(context, CloseDirectory(::testing::_)).WillByDefault([](DIR* stream) {
        const int result = closedir(stream);
        if (0 == result)
        {
            errno = EIO;
            return -1;
        }
        return result;
    });
    EXPECT_CALL(context, GetFileContents(key)).WillOnce(::testing::Return(ComplianceEngine::Result<std::string>(kPublicKeySample)));
    entries = 0;
    const auto closeError = AuditSshKeyPermissions(params, indicators, context);
    ASSERT_FALSE(closeError.HasValue());
    EXPECT_EQ(EIO, closeError.Error().code);
}

TEST(SshKeyRangeTest, RequiredNonYieldedDirectoryFailureAndReachedReadErrorPropagate)
{
    MockContext context;
    IndicatorsTree indicators;
    indicators.Push("SSH");
    const std::string root = context.GetTempdirPath() + "/ssh";
    ASSERT_EQ(0, mkdir(root.c_str(), 0700));
    const std::string nested = root + "/nested";
    ASSERT_EQ(0, mkdir(nested.c_str(), 0700));
    context.SetSpecialFilePath("/etc/ssh", root);
    struct stat expectedNested = {};
    ASSERT_EQ(0, stat(nested.c_str(), &expectedNested));
    ON_CALL(context, ReadDirectory(::testing::_)).WillByDefault([expectedNested](DIR * stream) -> struct dirent* {
        struct stat actual = {};
        if (0 == fstat(dirfd(stream), &actual) && actual.st_dev == expectedNested.st_dev && actual.st_ino == expectedNested.st_ino)
        {
            errno = EACCES;
            return nullptr;
        }
        return readdir(stream);
    });
    SshKeyPermissionsParams params;
    params.type = SshKeyType::Private;
    const auto blocked = RemediateSshKeyPermissions(params, indicators, context);
    ASSERT_FALSE(blocked.HasValue());
    EXPECT_EQ(EACCES, blocked.Error().code);

    ON_CALL(context, ReadDirectory(::testing::_)).WillByDefault([](DIR*) -> struct dirent* {
        errno = EIO;
        return nullptr;
    });
    const auto readError = AuditSshKeyPermissions(params, indicators, context);
    ASSERT_FALSE(readError.HasValue());
    EXPECT_EQ(EIO, readError.Error().code);
}

TEST(SshKeyRangeTest, OriginalKeyReadErrorOutranksDestructorCloseFailure)
{
    MockContext context;
    IndicatorsTree indicators;
    indicators.Push("SSH");
    const std::string root = context.GetTempdirPath() + "/ssh";
    ASSERT_EQ(0, mkdir(root.c_str(), 0700));
    const std::string key = root + "/key";
    std::ofstream(key) << kPrivateKeyHeader;
    context.SetSpecialFilePath("/etc/ssh", root);
    EXPECT_CALL(context, GetFileContents(key))
        .WillOnce(::testing::Return(ComplianceEngine::Result<std::string>(ComplianceEngine::Error("key read failed", EACCES))));
    ON_CALL(context, CloseDirectory(::testing::_)).WillByDefault([](DIR* stream) {
        const int result = closedir(stream);
        if (0 == result)
        {
            errno = EIO;
            return -1;
        }
        return result;
    });
    SshKeyPermissionsParams params;
    params.type = SshKeyType::Private;
    const auto result = RemediateSshKeyPermissions(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EACCES, result.Error().code);
    EXPECT_EQ("key read failed", result.Error().message);
}

TEST(SshKeyRangeTest, DeepTraversalRejectsDescriptorBudgetEvenThoughDirectoriesAreNotYielded)
{
    MockContext context;
    IndicatorsTree indicators;
    indicators.Push("SSH");
    std::string directory = context.GetTempdirPath() + "/ssh";
    ASSERT_EQ(0, mkdir(directory.c_str(), 0700));
    context.SetSpecialFilePath("/etc/ssh", directory);
    for (int depth = 0; depth < 33; ++depth)
    {
        directory += "/d";
        ASSERT_EQ(0, mkdir(directory.c_str(), 0700));
    }
    SshKeyPermissionsParams params;
    params.type = SshKeyType::Public;
    const auto result = AuditSshKeyPermissions(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EMFILE, result.Error().code);
    EXPECT_EQ("Filesystem directory continuation exceeds descriptor budget", result.Error().message);
}

TEST(SshKeyRangeTest, RootSymlinkIsFollowedButInteriorDirectorySymlinkIsNot)
{
    MockContext context;
    IndicatorsTree indicators;
    indicators.Push("SSH");
    const std::string root = context.GetTempdirPath() + "/ssh";
    ASSERT_EQ(0, mkdir(root.c_str(), 0700));
    const std::string outside = context.GetTempdirPath() + "/outside";
    ASSERT_EQ(0, mkdir(outside.c_str(), 0700));
    std::ofstream(outside + "/key") << kPublicKeySample;
    ASSERT_EQ(0, symlink(outside.c_str(), (root + "/linked").c_str()));
    const std::string alias = context.GetTempdirPath() + "/ssh-alias";
    ASSERT_EQ(0, symlink(root.c_str(), alias.c_str()));
    context.SetSpecialFilePath("/etc/ssh", alias);
    EXPECT_CALL(context, GetFileContents(::testing::_)).Times(0);
    SshKeyPermissionsParams params;
    params.type = SshKeyType::Public;
    const auto result = AuditSshKeyPermissions(params, indicators, context);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());
}

class EnsureSshKeyPermsTest : public ::testing::Test
{
protected:
    MockContext mContext;
    IndicatorsTree mIndicators;
    std::string mSshDir;
    void SetUp() override
    {
        if (0 != getuid())
        {
            GTEST_SKIP() << "This test suite requires root privileges or fakeroot";
        }

        mIndicators.Push("EnsureSshKeyPerms");
        mSshDir = mContext.GetFilesystemScannerRoot() + std::string("/etc/ssh");
        ::mkdir((mContext.GetFilesystemScannerRoot() + std::string("/etc")).c_str(), 0755);
        ::mkdir(mSshDir.c_str(), 0755);
        mContext.SetSpecialFilePath("/etc/ssh", mSshDir);
        using ::testing::Invoke;
        // Generic default: return file contents if exists, else empty string.
        ON_CALL(mContext, GetFileContents(::testing::_)).WillByDefault(Invoke([&](const std::string& path) -> ComplianceEngine::Result<std::string> {
            std::string physical = path;
            if (physical.rfind("/etc/ssh/", 0) == 0)
            {
                physical = mSshDir + physical.substr(std::string("/etc/ssh").size());
            }
            std::ifstream in(physical);
            if (!in.good())
            {
                return std::string();
            }
            std::ostringstream ss;
            ss << in.rdbuf();
            return ss.str();
        }));
    }
};

TEST_F(EnsureSshKeyPermsTest, PublicKeyCompliant)
{
    std::string keyPath = mSshDir + "/id_ed25519.pub";
    {
        std::ofstream f(keyPath);
        f << kPublicKeySample;
    }
    EXPECT_CALL(mContext, GetFileContents(keyPath)).WillOnce(::testing::Return(ComplianceEngine::Result<std::string>(kPublicKeySample)));
    chmod(keyPath.c_str(), (0644 & ~0133));
    SshKeyPermissionsParams params;
    params.type = SshKeyType::Public;

    auto result = AuditSshKeyPermissions(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureSshKeyPermsTest, RegularFileRootPropagatesTraversalError)
{
    const auto root = mContext.GetTempdirPath() + "/ssh-root-file";
    std::ofstream(root) << "not a directory\n";
    mContext.SetSpecialFilePath("/etc/ssh", root);
    SshKeyPermissionsParams params;
    params.type = SshKeyType::Public;

    const auto result = AuditSshKeyPermissions(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(ENOTDIR, result.Error().code);
}

TEST_F(EnsureSshKeyPermsTest, AuditFailedKeyReadPropagatesErrorWithoutIndicator)
{
    const std::string keyPath = mSshDir + "/id_ed25519.pub";
    std::ofstream key(keyPath);
    ASSERT_TRUE(key.is_open());
    key << kPublicKeySample;
    key.close();
    ASSERT_TRUE(key.good());
    EXPECT_CALL(mContext, GetFileContents(keyPath))
        .WillOnce(::testing::Return(ComplianceEngine::Result<std::string>(ComplianceEngine::Error("Key read failed", EACCES))));
    SshKeyPermissionsParams params;
    params.type = SshKeyType::Public;

    const auto result = AuditSshKeyPermissions(params, mIndicators, mContext);

    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EACCES, result.Error().code);
    EXPECT_EQ("Key read failed", result.Error().message);
    EXPECT_TRUE(mIndicators.Back().indicators.empty());
}

TEST_F(EnsureSshKeyPermsTest, RemediationFailedKeyReadPropagatesErrorWithoutIndicator)
{
    const std::string keyPath = mSshDir + "/id_ed25519";
    std::ofstream key(keyPath);
    ASSERT_TRUE(key.is_open());
    key << kPrivateKeyHeader;
    key.close();
    ASSERT_TRUE(key.good());
    EXPECT_CALL(mContext, GetFileContents(keyPath))
        .WillOnce(::testing::Return(ComplianceEngine::Result<std::string>(ComplianceEngine::Error("Key read failed", EIO))));
    SshKeyPermissionsParams params;
    params.type = SshKeyType::Private;

    const auto result = RemediateSshKeyPermissions(params, mIndicators, mContext);

    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EIO, result.Error().code);
    EXPECT_EQ("Key read failed", result.Error().message);
    EXPECT_TRUE(mIndicators.Back().indicators.empty());
}

TEST_F(EnsureSshKeyPermsTest, PublicKeyNonCompliantBitMask)
{
    std::string keyPath = mSshDir + "/id_test.pub";
    {
        std::ofstream f(keyPath);
        f << kPublicKeySample;
    }
    EXPECT_CALL(mContext, GetFileContents(keyPath)).WillOnce(::testing::Return(ComplianceEngine::Result<std::string>(kPublicKeySample)));
    chmod(keyPath.c_str(), 0644 | 0020); // forbidden group write bit
    SshKeyPermissionsParams params;
    params.type = SshKeyType::Public;
    auto result = AuditSshKeyPermissions(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureSshKeyPermsTest, PrivateKeyCompliant)
{
    std::string keyPath = mSshDir + "/id_ed25519";
    {
        std::ofstream f(keyPath);
        f << kPrivateKeyHeader << "...payload...\n";
    }
    EXPECT_CALL(mContext, GetFileContents(keyPath)).WillOnce(::testing::Return(ComplianceEngine::Result<std::string>(std::string(kPrivateKeyHeader) + "...payload...\n")));
    chmod(keyPath.c_str(), 0600);
    SshKeyPermissionsParams params;
    params.type = SshKeyType::Private;
    auto result = AuditSshKeyPermissions(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureSshKeyPermsTest, PrivateKeyRemediation)
{
    std::string keyPath = mSshDir + "/id_ed25519";
    {
        std::ofstream f(keyPath);
        f << kPrivateKeyHeader << "...payload...\n";
    }
    EXPECT_CALL(mContext, GetFileContents(keyPath)).WillRepeatedly(::testing::Return(ComplianceEngine::Result<std::string>(std::string(kPrivateKeyHeader) + "...payload...\n")));
    chmod(keyPath.c_str(), 0777); // bad perms
    SshKeyPermissionsParams params;
    params.type = SshKeyType::Private;
    auto remediate = RemediateSshKeyPermissions(params, mIndicators, mContext);
    ASSERT_TRUE(remediate.HasValue());
    ASSERT_EQ(remediate.Value(), Status::Compliant);
    struct stat st;
    ASSERT_EQ(0, stat(keyPath.c_str(), &st));
    ASSERT_EQ(0u, (st.st_mode & 0137));
    auto post = AuditSshKeyPermissions(params, mIndicators, mContext);
    ASSERT_TRUE(post.HasValue());
    ASSERT_EQ(post.Value(), Status::Compliant);
}

TEST_F(EnsureSshKeyPermsTest, RemediationNoKeys)
{
    SshKeyPermissionsParams params;
    params.type = SshKeyType::Public;
    auto result = RemediateSshKeyPermissions(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureSshKeyPermsTest, NestedRecognizedKeyIsChecked)
{
    const std::string nested = mSshDir + "/nested";
    ASSERT_EQ(0, ::mkdir(nested.c_str(), 0755));
    const std::string keyPath = nested + "/host-key";
    std::ofstream(keyPath) << kPrivateKeyHeader << "payload\n";
    ASSERT_EQ(0, ::chmod(keyPath.c_str(), 0777));
    EXPECT_CALL(mContext, GetFileContents(keyPath)).WillOnce(::testing::Return(ComplianceEngine::Result<std::string>(std::string(kPrivateKeyHeader) + "payload\n")));
    SshKeyPermissionsParams params;
    params.type = SshKeyType::Private;

    const auto result = AuditSshKeyPermissions(params, mIndicators, mContext);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::NonCompliant, result.Value());
}

TEST_F(EnsureSshKeyPermsTest, SimilarlyNamedNonKeyIsIgnored)
{
    const std::string decoyPath = mSshDir + "/host-key.pub";
    std::ofstream(decoyPath) << "not a key\n";
    ASSERT_EQ(0, ::chmod(decoyPath.c_str(), 0777));
    EXPECT_CALL(mContext, GetFileContents(decoyPath)).WillOnce(::testing::Return(ComplianceEngine::Result<std::string>("not a key\n")));
    SshKeyPermissionsParams params;
    params.type = SshKeyType::Public;

    const auto result = AuditSshKeyPermissions(params, mIndicators, mContext);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());
}
