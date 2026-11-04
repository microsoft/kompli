// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Clean minimal test file begins
#include "Evaluator.h"
#include "MockContext.h"

#include <SshKeyPermissions.h>
#include <cerrno>
#include <fcntl.h>
#include <fstream>
#include <gtest/gtest.h>
#include <iterator>
#include <map>
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

    // Fail direct acquisition of the missing root name, not a retired
    // pathname stat; EACCES must remain an error rather than typed Missing.
    std::size_t deniedPins = 0;
    ON_CALL(context, OpenNativeAt(::testing::_, ::testing::StrEq("missing-ssh"), ::testing::_)).WillByDefault([&deniedPins](int, const char*, int) {
        ++deniedPins;
        errno = EACCES;
        return -1;
    });
    const auto denied = RemediateSshKeyPermissions(params, indicators, context);
    ASSERT_FALSE(denied.HasValue());
    EXPECT_EQ(EACCES, denied.Error().code);
    EXPECT_EQ(1u, deniedPins);
}

TEST(SshKeyRangeTest, FirstNoncomplianceBreaksWithoutReadingRemainderAndCloseDoesNotOverride)
{
    MockContext context;
    IndicatorsTree indicators;
    indicators.Push("SSH");
    const std::string root = context.GetTempdirPath() + "/ssh";
    ASSERT_EQ(0, mkdir(root.c_str(), 0700));
    const std::string key = root + "/key";
    std::ofstream(key) << kPublicKeySample;
    context.SetSpecialFilePath("/etc/ssh", root);
    EXPECT_CALL(context, GetFileContents(::testing::_)).Times(0);
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

    const auto logPath = context.GetTempdirPath() + "/ssh-key-close.log";
    OsConfigLogHandle logHandle = OpenLog(logPath.c_str(), nullptr);
    ASSERT_NE(nullptr, logHandle);
    context.SetLogHandle(logHandle);
    int closeAttempts = 0;
    ON_CALL(context, CloseDirectory(::testing::_)).WillByDefault([&](DIR* stream) {
        ++closeAttempts;
        const int result = closedir(stream);
        if (0 == result)
        {
            errno = EIO;
            return -1;
        }
        return result;
    });
    entries = 0;
    const auto closeResult = AuditSshKeyPermissions(params, indicators, context);
    ASSERT_TRUE(closeResult.HasValue()) << closeResult.Error().message;
    EXPECT_EQ(Status::NonCompliant, closeResult.Value());
    EXPECT_EQ(1u, entries);
    EXPECT_EQ(1, closeAttempts);
    CloseLog(&logHandle);
    context.SetLogHandle(nullptr);
    std::ifstream log(logPath);
    ASSERT_TRUE(log.is_open());
    const std::string text((std::istreambuf_iterator<char>(log)), std::istreambuf_iterator<char>());
    const auto diagnostic = "Cannot close pinned directory cursor: " + std::to_string(EIO);
    const auto first = text.find(diagnostic);
    ASSERT_NE(std::string::npos, first);
    EXPECT_EQ(std::string::npos, text.find(diagnostic, first + diagnostic.size()));
}

TEST(SshKeyRangeTest, ReplacementAfterPinCannotRedirectClassificationOrRemediation)
{
    MockContext context;
    IndicatorsTree indicators;
    indicators.Push("SSH");
    const std::string root = context.GetTempdirPath() + "/ssh";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    const std::string key = root + "/key";
    const std::string held = context.GetTempdirPath() + "/held-ssh-key";
    const std::string replacement = context.GetTempdirPath() + "/replacement-ssh-key";
    std::ofstream(key) << kPublicKeySample;
    std::ofstream(replacement) << "not a key\n";
    ASSERT_EQ(0, ::chmod(key.c_str(), 0666));
    ASSERT_EQ(0, ::chmod(replacement.c_str(), 0666));
    struct stat original = {};
    ASSERT_EQ(0, ::stat(key.c_str(), &original));
    context.SetSpecialFilePath("/etc/ssh", root);
    EXPECT_CALL(context, GetFileContents(::testing::_)).Times(0);
    bool swapped = false;
    EXPECT_CALL(context, OpenNativeAt(::testing::_, ::testing::_, ::testing::_)).WillRepeatedly([&](int directory, const char* name, int flags) {
        const int fd = context.RealOpenNativeAt(directory, name, flags);
        if (!swapped && fd >= 0 && std::string(name) == "key" && (flags & O_PATH))
        {
            swapped = true;
            EXPECT_EQ(0, ::rename(key.c_str(), held.c_str()));
            EXPECT_EQ(0, ::rename(replacement.c_str(), key.c_str()));
        }
        return fd;
    });
    SshKeyPermissionsParams params;
    params.type = SshKeyType::Public;
    auto audit = AuditSshKeyPermissions(params, indicators, context);
    ASSERT_TRUE(audit.HasValue()) << audit.Error().message;
    EXPECT_EQ(Status::NonCompliant, audit.Value());
    ASSERT_TRUE(swapped);

    // Restore names so the same deterministic swap exercises the mutation
    // phase on a second traversal, without touching the old held inode.
    ASSERT_EQ(0, ::rename(key.c_str(), replacement.c_str()));
    ASSERT_EQ(0, ::rename(held.c_str(), key.c_str()));
    swapped = false;
    EXPECT_CALL(context, ChownPinnedFileDescriptor(::testing::_, ::testing::_, ::testing::_)).Times(::testing::AtMost(1)).WillOnce([&](int descriptor, uid_t, gid_t) {
        struct stat pinned = {};
        EXPECT_EQ(0, ::fstat(descriptor, &pinned));
        EXPECT_EQ(original.st_ino, pinned.st_ino);
        return 0;
    });
    EXPECT_CALL(context, ChmodPinnedAlias(::testing::_, ::testing::_, ::testing::_)).Times(1);
    auto remediate = RemediateSshKeyPermissions(params, indicators, context);
    ASSERT_TRUE(remediate.HasValue()) << remediate.Error().message;
    EXPECT_TRUE(swapped);
    struct stat changed = {}, untouched = {};
    ASSERT_EQ(0, ::stat(held.c_str(), &changed));
    ASSERT_EQ(0, ::stat(key.c_str(), &untouched));
    EXPECT_EQ(original.st_ino, changed.st_ino);
    EXPECT_NE(original.st_ino, untouched.st_ino);
    EXPECT_EQ(0644, changed.st_mode & 0777);
    EXPECT_EQ(0666, untouched.st_mode & 0777);
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
    struct stat expectedKey = {};
    ASSERT_EQ(0, ::stat(key.c_str(), &expectedKey));
    EXPECT_CALL(context, GetFileContents(::testing::_)).Times(0);
    EXPECT_CALL(context, ReadFileDescriptor(::testing::_, ::testing::_, ::testing::_)).WillRepeatedly([&](int fd, void* data, std::size_t size) {
        struct stat actual = {};
        if (::fstat(fd, &actual) == 0 && actual.st_dev == expectedKey.st_dev && actual.st_ino == expectedKey.st_ino)
        {
            errno = EACCES;
            return static_cast<ssize_t>(-1);
        }
        return context.RealReadFileDescriptor(fd, data, size);
    });
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
    EXPECT_EQ("Cannot read acquired file", result.Error().message);
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
    std::size_t mKeyReads = 0;
    std::size_t mExpectedKeyReads = 0;
    void SetUp() override
    {
        mIndicators.Push("EnsureSshKeyPerms");
        mSshDir = mContext.GetFilesystemScannerRoot() + std::string("/etc/ssh");
        ASSERT_EQ(0, ::mkdir((mContext.GetFilesystemScannerRoot() + std::string("/etc")).c_str(), 0755));
        ASSERT_EQ(0, ::mkdir(mSshDir.c_str(), 0755));
        mContext.SetSpecialFilePath("/etc/ssh", mSshDir);
        EXPECT_CALL(mContext, GetFileContents(::testing::_)).Times(0);
    }

    void ExpectPinnedKeyReads(const std::string& path, std::size_t count, int readError = 0)
    {
        struct stat expectedKey = {};
        ASSERT_EQ(0, ::stat(path.c_str(), &expectedKey));
        mKeyReads = 0;
        mExpectedKeyReads = count;
        EXPECT_CALL(mContext, ReadFileDescriptor(::testing::_, ::testing::_, ::testing::_))
            .WillRepeatedly([this, expectedKey, readError](int fd, void* data, std::size_t size) -> ssize_t {
                struct stat actual = {};
                if (::fstat(fd, &actual) == 0 && actual.st_dev == expectedKey.st_dev && actual.st_ino == expectedKey.st_ino)
                {
                    ++mKeyReads;
                    if (readError != 0)
                    {
                        errno = readError;
                        return -1;
                    }
                }
                return mContext.RealReadFileDescriptor(fd, data, size);
            });
    }

    void CheckPinnedKeyReadCount()
    {
        EXPECT_EQ(mExpectedKeyReads, mKeyReads);
    }
};

TEST_F(EnsureSshKeyPermsTest, PublicKeyCompliant)
{
    if (0 != ::geteuid())
        GTEST_SKIP() << "Actual root ownership is required for a compliant-owner result";
    std::string keyPath = mSshDir + "/id_ed25519.pub";
    {
        std::ofstream f(keyPath);
        f << kPublicKeySample;
    }
    ExpectPinnedKeyReads(keyPath, 2);
    ASSERT_EQ(0, ::chmod(keyPath.c_str(), (0644 & ~0133)));
    SshKeyPermissionsParams params;
    params.type = SshKeyType::Public;

    auto result = AuditSshKeyPermissions(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
    CheckPinnedKeyReadCount();
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
    ExpectPinnedKeyReads(keyPath, 1, EACCES);
    SshKeyPermissionsParams params;
    params.type = SshKeyType::Public;

    const auto result = AuditSshKeyPermissions(params, mIndicators, mContext);

    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EACCES, result.Error().code);
    EXPECT_EQ("Cannot read acquired file", result.Error().message);
    EXPECT_TRUE(mIndicators.Back().indicators.empty());
    CheckPinnedKeyReadCount();
}

TEST_F(EnsureSshKeyPermsTest, RemediationFailedKeyReadPropagatesErrorWithoutIndicator)
{
    const std::string keyPath = mSshDir + "/id_ed25519";
    std::ofstream key(keyPath);
    ASSERT_TRUE(key.is_open());
    key << kPrivateKeyHeader;
    key.close();
    ASSERT_TRUE(key.good());
    ExpectPinnedKeyReads(keyPath, 1, EIO);
    SshKeyPermissionsParams params;
    params.type = SshKeyType::Private;

    const auto result = RemediateSshKeyPermissions(params, mIndicators, mContext);

    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EIO, result.Error().code);
    EXPECT_EQ("Cannot read acquired file", result.Error().message);
    EXPECT_TRUE(mIndicators.Back().indicators.empty());
    CheckPinnedKeyReadCount();
}

TEST_F(EnsureSshKeyPermsTest, PublicKeyNonCompliantBitMask)
{
    std::string keyPath = mSshDir + "/id_test.pub";
    {
        std::ofstream f(keyPath);
        f << kPublicKeySample;
    }
    ExpectPinnedKeyReads(keyPath, 2);
    ASSERT_EQ(0, ::chmod(keyPath.c_str(), 0644 | 0020)); // forbidden group write bit
    SshKeyPermissionsParams params;
    params.type = SshKeyType::Public;
    auto result = AuditSshKeyPermissions(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
    CheckPinnedKeyReadCount();
}

TEST_F(EnsureSshKeyPermsTest, PrivateKeyCompliant)
{
    if (0 != ::geteuid())
        GTEST_SKIP() << "Actual root ownership is required for a compliant-owner result";
    std::string keyPath = mSshDir + "/id_ed25519";
    {
        std::ofstream f(keyPath);
        f << kPrivateKeyHeader << "...payload...\n";
    }
    ExpectPinnedKeyReads(keyPath, 2);
    ASSERT_EQ(0, ::chmod(keyPath.c_str(), 0600));
    SshKeyPermissionsParams params;
    params.type = SshKeyType::Private;
    auto result = AuditSshKeyPermissions(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
    CheckPinnedKeyReadCount();
}

TEST_F(EnsureSshKeyPermsTest, PrivateKeyRemediation)
{
    if (0 != ::geteuid())
        GTEST_SKIP() << "Actual root ownership is required for this ownership remediation";
    std::string keyPath = mSshDir + "/id_ed25519";
    {
        std::ofstream f(keyPath);
        f << kPrivateKeyHeader << "...payload...\n";
    }
    ExpectPinnedKeyReads(keyPath, 4);
    ASSERT_EQ(0, ::chmod(keyPath.c_str(), 0777)); // bad perms
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
    CheckPinnedKeyReadCount();
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
    ExpectPinnedKeyReads(keyPath, 2);
    SshKeyPermissionsParams params;
    params.type = SshKeyType::Private;

    const auto result = AuditSshKeyPermissions(params, mIndicators, mContext);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::NonCompliant, result.Value());
    CheckPinnedKeyReadCount();
}

TEST_F(EnsureSshKeyPermsTest, SimilarlyNamedNonKeyIsIgnored)
{
    const std::string decoyPath = mSshDir + "/host-key.pub";
    std::ofstream(decoyPath) << "not a key\n";
    ASSERT_EQ(0, ::chmod(decoyPath.c_str(), 0777));
    ExpectPinnedKeyReads(decoyPath, 2);
    SshKeyPermissionsParams params;
    params.type = SshKeyType::Public;

    const auto result = AuditSshKeyPermissions(params, mIndicators, mContext);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());
    CheckPinnedKeyReadCount();
}
