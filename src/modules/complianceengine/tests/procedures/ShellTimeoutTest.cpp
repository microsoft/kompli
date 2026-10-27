// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "CommonUtils.h"
#include "MockContext.h"

#include <Optional.h>
#include <ShellTimeout.h>
#include <cerrno>
#include <fcntl.h>
#include <fstream>
#include <iterator>
#include <sys/stat.h>
#include <unistd.h>

using ComplianceEngine::AuditShellTimeout;
using ComplianceEngine::Error;
using ComplianceEngine::IndicatorsTree;
using ComplianceEngine::Optional;
using ComplianceEngine::RemediateShellTimeout;
using ComplianceEngine::Result;
using ComplianceEngine::Status;
using std::map;
using std::string;

class EnsureDefaultShellTimeoutIsConfiguredTest : public ::testing::Test
{
protected:
    bool IsData(int fd, const string& path) const
    {
        struct stat held = {}, fixture = {};
        const int flags = ::fcntl(fd, F_GETFL);
        return flags >= 0 && !(flags & O_PATH) && (flags & O_ACCMODE) == O_RDONLY && ::fstat(fd, &held) == 0 && ::stat(path.c_str(), &fixture) == 0 &&
               held.st_dev == fixture.st_dev && held.st_ino == fixture.st_ino;
    }
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
        mContext.SetSpecialFilePath("/etc/profile.d/", mContext.GetTempdirPath() + "/missing-config-directory");
    }

    void TearDown() override
    {
    }
};

TEST_F(EnsureDefaultShellTimeoutIsConfiguredTest, NoSpecialFiles)
{
    auto result = AuditShellTimeout(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);

    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    ASSERT_GE(root->indicators.size(), 1u);
    EXPECT_EQ(root->indicators.back().status, Status::NonCompliant);
    EXPECT_EQ(root->indicators.back().message, string("TMOUT is not set"));
}

TEST_F(EnsureDefaultShellTimeoutIsConfiguredTest, IncorrectValue)
{
    auto path = mContext.MakeTempfile("TMOUT=901"); // Acceptance threshold is 900
    mContext.SetSpecialFilePath("/etc/bashrc", path);
    auto result = AuditShellTimeout(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);

    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    ASSERT_GE(root->indicators.size(), 1u);
    EXPECT_EQ(root->indicators.back().status, Status::NonCompliant);
    EXPECT_EQ(root->indicators.back().message, string("TMOUT is set to an incorrect value in ") + path);
}

TEST_F(EnsureDefaultShellTimeoutIsConfiguredTest, MalformedNumericSuffixReturnsConversionError)
{
    const auto path = mContext.MakeTempfile("TMOUT=900junk\nreadonly TMOUT\nexport TMOUT\n");
    mContext.SetSpecialFilePath("/etc/bashrc", path);
    const auto result = AuditShellTimeout(mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, EINVAL);
    EXPECT_EQ(result.Error().message, "Invalid integer value: 900junk");
    EXPECT_TRUE(mIndicators.Back().indicators.empty());
}

TEST_F(EnsureDefaultShellTimeoutIsConfiguredTest, NoReadonly)
{
    auto path = mContext.MakeTempfile("TMOUT=900\n");
    mContext.SetSpecialFilePath("/etc/bashrc", path);
    auto result = AuditShellTimeout(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);

    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    ASSERT_GE(root->indicators.size(), 1u);
    EXPECT_EQ(root->indicators.back().status, Status::NonCompliant);
    EXPECT_EQ(root->indicators.back().message, string("TMOUT is not readonly in ") + path);
}

TEST_F(EnsureDefaultShellTimeoutIsConfiguredTest, NoExport)
{
    auto path = mContext.MakeTempfile("TMOUT=900\nreadonly TMOUT\n");
    mContext.SetSpecialFilePath("/etc/bashrc", path);
    auto result = AuditShellTimeout(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);

    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    ASSERT_GE(root->indicators.size(), 1u);
    EXPECT_EQ(root->indicators.back().status, Status::NonCompliant);
    EXPECT_EQ(root->indicators.back().message, string("TMOUT is not exported in ") + path);
}

TEST_F(EnsureDefaultShellTimeoutIsConfiguredTest, ProperlyConfigured)
{
    auto path = mContext.MakeTempfile("TMOUT=900\nreadonly TMOUT\nexport TMOUT\n");
    mContext.SetSpecialFilePath("/etc/bashrc", path);
    auto result = AuditShellTimeout(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);

    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    ASSERT_GE(root->indicators.size(), 1u);
    EXPECT_EQ(root->indicators.back().status, Status::Compliant);
    EXPECT_EQ(root->indicators.back().message, string("TMOUT variable is properly defined"));
}

TEST_F(EnsureDefaultShellTimeoutIsConfiguredTest, MultipleEntries)
{
    auto path = mContext.MakeTempfile("TMOUT=100\nTMOUT=200\n");
    mContext.SetSpecialFilePath("/etc/bashrc", path);
    auto result = AuditShellTimeout(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);

    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    ASSERT_GE(root->indicators.size(), 1u);
    EXPECT_EQ(root->indicators.back().status, Status::NonCompliant);
    EXPECT_EQ(root->indicators.back().message, string("TMOUT is set multiple times in ") + path);
}

TEST_F(EnsureDefaultShellTimeoutIsConfiguredTest, ReachedReadFailureIsNotMissingSetting)
{
    const auto path = mContext.MakeTempfile("TMOUT=900\nreadonly TMOUT\nexport TMOUT\n");
    mContext.SetSpecialFilePath("/etc/bashrc", path);
    ON_CALL(mContext, ReadFileDescriptor(testing::_, testing::_, testing::_)).WillByDefault([&](int fd, void* buffer, std::size_t size) -> ssize_t {
        if (!IsData(fd, path))
            return mContext.ContextInterface::ReadFileDescriptor(fd, buffer, size);
        errno = EIO;
        return -1;
    });

    const auto result = AuditShellTimeout(mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EIO, result.Error().code);
    EXPECT_EQ("Failed to read file bytes", result.Error().message);
    EXPECT_TRUE(mIndicators.Back().indicators.empty());
}

TEST_F(EnsureDefaultShellTimeoutIsConfiguredTest, OpenFailurePreservesErrno)
{
    const auto path = mContext.MakeTempfile("TMOUT=900\n");
    mContext.SetSpecialFilePath("/etc/bashrc", path);
    const auto name = path.substr(path.find_last_of('/') + 1);
    ON_CALL(mContext, OpenNativeAt(testing::_, testing::_, testing::_)).WillByDefault([&](int directory, const char* component, int flags) {
        struct stat held = {}, parent = {};
        const bool fixtureParent = ::fstat(directory, &held) == 0 && ::stat(path.substr(0, path.find_last_of('/')).c_str(), &parent) == 0 &&
                                   held.st_dev == parent.st_dev && held.st_ino == parent.st_ino;
        if (fixtureParent && name == component && (flags & O_PATH))
        {
            errno = EACCES;
            return -1;
        }
        return mContext.ContextInterface::OpenNativeAt(directory, component, flags);
    });

    const auto result = AuditShellTimeout(mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EACCES, result.Error().code);
    EXPECT_EQ("Cannot pin confined component", result.Error().message);
    EXPECT_TRUE(mIndicators.Back().indicators.empty());
}

TEST_F(EnsureDefaultShellTimeoutIsConfiguredTest, NulAndDefaultByteLimitAreErrors)
{
    const auto path = mContext.MakeTempfile(string("TMOUT=900\0\n", 11));
    mContext.SetSpecialFilePath("/etc/bashrc", path);
    auto result = AuditShellTimeout(mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EBADMSG, result.Error().code);

    // A physical byte past the reader's default 1 MiB budget is not "not set".
    const auto oversized = mContext.MakeTempfile(string(1024 * 1024 + 1, '#'));
    mContext.SetSpecialFilePath("/etc/bashrc", oversized);
    result = AuditShellTimeout(mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(E2BIG, result.Error().code);
    EXPECT_TRUE(mIndicators.Back().indicators.empty());
}

TEST_F(EnsureDefaultShellTimeoutIsConfiguredTest, ExistingNonRegularSourceIsAnError)
{
    mContext.SetSpecialFilePath("/etc/bashrc", mContext.GetTempdirPath());
    const auto result = AuditShellTimeout(mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EINVAL, result.Error().code);
    EXPECT_EQ("File target is not regular", result.Error().message);
    EXPECT_TRUE(mIndicators.Back().indicators.empty());
}

TEST_F(EnsureDefaultShellTimeoutIsConfiguredTest, DuplicateStopsWithoutReadingTail)
{
    const auto path = mContext.MakeTempfile("TMOUT=100\nTMOUT=200\nunread tail\n");
    mContext.SetSpecialFilePath("/etc/bashrc", path);
    int reads = 0;
    int closes = 0;
    ON_CALL(mContext, ReadFileDescriptor(testing::_, testing::_, testing::_)).WillByDefault([&](int descriptor, void* buffer, std::size_t size) -> ssize_t {
        if (!IsData(descriptor, path))
            return mContext.ContextInterface::ReadFileDescriptor(descriptor, buffer, size);
        ++reads;
        if (reads == 1)
        {
            return mContext.ContextInterface::ReadFileDescriptor(descriptor, buffer, size);
        }
        errno = EIO;
        return -1;
    });
    ON_CALL(mContext, CloseFileDescriptor(testing::_)).WillByDefault([&](int descriptor) {
        closes += IsData(descriptor, path);
        return mContext.ContextInterface::CloseFileDescriptor(descriptor);
    });

    const auto result = AuditShellTimeout(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::NonCompliant, result.Value());
    EXPECT_EQ("TMOUT is set multiple times in " + path, mIndicators.Back().indicators.back().message);
    EXPECT_EQ(1, reads);
    EXPECT_EQ(1, closes);
}

TEST_F(EnsureDefaultShellTimeoutIsConfiguredTest, DuplicateCloseFailurePrecedesEarlyVerdict)
{
    const auto path = mContext.MakeTempfile("TMOUT=100\nTMOUT=200\n");
    mContext.SetSpecialFilePath("/etc/bashrc", path);
    int closes = 0;
    ON_CALL(mContext, CloseFileDescriptor(testing::_)).WillByDefault([&](int descriptor) {
        const bool data = IsData(descriptor, path);
        mContext.ContextInterface::CloseFileDescriptor(descriptor);
        if (data)
        {
            ++closes;
            errno = EIO;
            return -1;
        }
        return 0;
    });

    const auto result = AuditShellTimeout(mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EIO, result.Error().code);
    EXPECT_EQ("Cannot close readable file", result.Error().message);
    EXPECT_EQ(1, closes);
    EXPECT_TRUE(mIndicators.Back().indicators.empty());
}

TEST_F(EnsureDefaultShellTimeoutIsConfiguredTest, MultipleEntriesInDifferentFiles)
{
    auto path1 = mContext.MakeTempfile("TMOUT=900\nreadonly TMOUT\nexport TMOUT\n");
    mContext.SetSpecialFilePath("/etc/bashrc", path1);
    auto path2 = mContext.MakeTempfile("TMOUT=900\nreadonly TMOUT\nexport TMOUT\n");
    mContext.SetSpecialFilePath("/etc/profile", path2);
    auto result = AuditShellTimeout(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);

    const auto* root = mIndicators.GetRootNode();
    ASSERT_NE(nullptr, root);
    ASSERT_GE(root->indicators.size(), 1u);
    EXPECT_EQ(root->indicators.back().status, Status::NonCompliant);
    EXPECT_EQ(root->indicators.back().message, string("TMOUT is set in multiple locations"));
}

TEST_F(EnsureDefaultShellTimeoutIsConfiguredTest, RemediateExistingDefinition)
{
    auto path = mContext.MakeTempfile("  export TMOUT=901 # old value\n");
    mContext.SetSpecialFilePath("/etc/bashrc", path);

    auto result = RemediateShellTimeout(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);

    std::ifstream input(path);
    EXPECT_EQ(string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()), "  export TMOUT=900 # old value\nreadonly TMOUT\n");
}

TEST_F(EnsureDefaultShellTimeoutIsConfiguredTest, RemediateMissingDefinitionInProfile)
{
    auto path = mContext.MakeTempfile("# system profile");
    mContext.SetSpecialFilePath("/etc/profile", path);

    auto result = RemediateShellTimeout(mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);

    std::ifstream input(path);
    EXPECT_EQ(string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()),
        "# system profile\nTMOUT=900\nreadonly TMOUT\nexport TMOUT\n");
}

TEST_F(EnsureDefaultShellTimeoutIsConfiguredTest, RemediateRejectsMultipleDefinitions)
{
    const string original = "TMOUT=100\nTMOUT=200\n";
    auto path = mContext.MakeTempfile(original);
    mContext.SetSpecialFilePath("/etc/bashrc", path);

    auto result = RemediateShellTimeout(mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, ENOTSUP);

    std::ifstream input(path);
    EXPECT_EQ(string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()), original);
}

TEST_F(EnsureDefaultShellTimeoutIsConfiguredTest, RemediateRejectsAssignmentAfterReadonly)
{
    const string original = "readonly TMOUT\nTMOUT=901\n";
    auto path = mContext.MakeTempfile(original);
    mContext.SetSpecialFilePath("/etc/bashrc", path);

    auto result = RemediateShellTimeout(mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, ENOTSUP);

    std::ifstream input(path);
    EXPECT_EQ(string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()), original);
}

TEST_F(EnsureDefaultShellTimeoutIsConfiguredTest, RemediateRejectsSymlink)
{
    const auto target = mContext.MakeTempfile("TMOUT=901\n");
    const auto link = mContext.GetTempdirPath() + "/bashrc";
    ASSERT_EQ(symlink(target.c_str(), link.c_str()), 0);
    mContext.SetSpecialFilePath("/etc/bashrc", link);

    auto result = RemediateShellTimeout(mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, EINVAL);

    std::ifstream input(target);
    EXPECT_EQ(string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()), "TMOUT=901\n");
}
