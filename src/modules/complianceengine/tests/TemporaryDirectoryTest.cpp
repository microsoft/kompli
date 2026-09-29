// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "TemporaryDirectory.h"

#include "CliContext.h"
#include "MockContext.h"

#include <cstdlib>
#include <fstream>
#include <gtest/gtest.h>
#include <memory>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

namespace
{
class ScopedTmpdir
{
public:
    explicit ScopedTmpdir(const char* value)
    {
        const char* current = std::getenv("TMPDIR");
        if (current != nullptr)
        {
            mHadValue = true;
            mValue = current;
        }

        if (value == nullptr)
        {
            if (::unsetenv("TMPDIR") != 0)
            {
                throw std::runtime_error("Failed to unset TMPDIR");
            }
        }
        else if (::setenv("TMPDIR", value, 1) != 0)
        {
            throw std::runtime_error("Failed to set TMPDIR");
        }
    }

    ~ScopedTmpdir()
    {
        if (mHadValue)
        {
            (void)::setenv("TMPDIR", mValue.c_str(), 1);
        }
        else
        {
            (void)::unsetenv("TMPDIR");
        }
    }

private:
    bool mHadValue{false};
    std::string mValue;
};
} // namespace

TEST(TemporaryDirectoryTest, SelectsConfiguredParent)
{
    ScopedTmpdir environment("/configured/temporary/root");
    auto result = ComplianceEngine::Detail::GetTemporaryDirectoryParent();
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ("/configured/temporary/root", result.Value());
}

TEST(TemporaryDirectoryTest, EmptyParentUsesCompatibilityFallback)
{
    ScopedTmpdir environment("");
    auto result = ComplianceEngine::Detail::GetTemporaryDirectoryParent();
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ("/tmp", result.Value());
}

TEST(TemporaryDirectoryTest, UnsetParentUsesCompatibilityFallback)
{
    ScopedTmpdir environment(nullptr);
    auto result = ComplianceEngine::Detail::GetTemporaryDirectoryParent();
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ("/tmp", result.Value());
}

TEST(TemporaryDirectoryTest, RejectsRelativeParent)
{
    ScopedTmpdir environment("relative/path");
    auto result = ComplianceEngine::Detail::GetTemporaryDirectoryParent();
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EINVAL, result.Error().code);
}

TEST(TemporaryDirectoryTest, RejectsWhitespaceInConfiguredParent)
{
    for (const char* value : {"/configured/temporary root", "/configured/temporary\troot", "/configured/temporary\nroot"})
    {
        ScopedTmpdir environment(value);
        auto selected = ComplianceEngine::Detail::GetTemporaryDirectoryParent();
        ASSERT_FALSE(selected.HasValue());
        EXPECT_EQ(EINVAL, selected.Error().code);

        auto created = ComplianceEngine::Detail::CreateTemporaryDirectory("whitespace");
        ASSERT_FALSE(created.HasValue());
        EXPECT_EQ(EINVAL, created.Error().code);
    }
}

TEST(TemporaryDirectoryTest, RejectsWhitespaceInDirectParentValidation)
{
    auto result = ComplianceEngine::Detail::ValidateTemporaryDirectoryParent("/configured/temporary root");
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EINVAL, result.Error().code);
}

TEST(TemporaryDirectoryTest, CliContextReportsInvalidParent)
{
    ScopedTmpdir environment("relative/path");
    auto result = ComplianceEngine::Cli::Context::Make(nullptr);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EINVAL, result.Error().code);
}

TEST(TemporaryDirectoryTest, CliContextReportsWhitespaceInParent)
{
    ScopedTmpdir environment("/configured/temporary root");
    auto result = ComplianceEngine::Cli::Context::Make(nullptr);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EINVAL, result.Error().code);
}

TEST(TemporaryDirectoryTest, MockContextCreatesPrivateUniqueRootsUnderConfiguredParent)
{
    MockContext owner;
    const std::string parent = owner.GetTempdirPath() + "/configured-parent";
    ASSERT_EQ(0, ::mkdir(parent.c_str(), 0700));
    ScopedTmpdir environment((parent + "/").c_str());

    MockContext first;
    MockContext second;
    EXPECT_EQ(0u, first.GetTempdirPath().rfind(parent + "/ComplianceEngineTest.", 0));
    EXPECT_EQ(0u, second.GetTempdirPath().rfind(parent + "/ComplianceEngineTest.", 0));
    EXPECT_NE(first.GetTempdirPath(), second.GetTempdirPath());

    struct stat status;
    ASSERT_EQ(0, ::stat(first.GetTempdirPath().c_str(), &status));
    EXPECT_EQ(static_cast<mode_t>(0700), status.st_mode & 0777);
}

TEST(TemporaryDirectoryTest, CreationFailureDoesNotFallBack)
{
    MockContext owner;
    const std::string missingParent = owner.GetTempdirPath() + "/missing/parent";
    ScopedTmpdir environment(missingParent.c_str());

    auto result = ComplianceEngine::Detail::CreateTemporaryDirectory("failure");
    EXPECT_FALSE(result.HasValue());
}

TEST(TemporaryDirectoryTest, RejectsParentTraversal)
{
    MockContext owner;
    const std::string parent = owner.GetTempdirPath() + "/parent";
    ASSERT_EQ(0, ::mkdir(parent.c_str(), 0700));
    ScopedTmpdir environment((parent + "/../parent").c_str());

    auto result = ComplianceEngine::Detail::CreateTemporaryDirectory("traversal");
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EINVAL, result.Error().code);
}

TEST(TemporaryDirectoryTest, RejectsPrefixTraversal)
{
    auto result = ComplianceEngine::Detail::CreateTemporaryDirectory("../escape");
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EINVAL, result.Error().code);
}

TEST(TemporaryDirectoryTest, RejectsSymlinkedParent)
{
    MockContext owner;
    const std::string parent = owner.GetTempdirPath() + "/parent";
    const std::string link = owner.GetTempdirPath() + "/parent-link";
    ASSERT_EQ(0, ::mkdir(parent.c_str(), 0700));
    ASSERT_EQ(0, ::symlink(parent.c_str(), link.c_str()));
    ScopedTmpdir environment(link.c_str());

    auto result = ComplianceEngine::Detail::CreateTemporaryDirectory("symlink");
    EXPECT_FALSE(result.HasValue());
}

TEST(TemporaryDirectoryTest, RejectsUntrustedWritableParent)
{
    MockContext owner;
    const std::string parent = owner.GetTempdirPath() + "/writable-parent";
    ASSERT_EQ(0, ::mkdir(parent.c_str(), 0700));
    ASSERT_EQ(0, ::chmod(parent.c_str(), 0777));
    ScopedTmpdir environment(parent.c_str());

    auto result = ComplianceEngine::Detail::CreateTemporaryDirectory("writable");
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EPERM, result.Error().code);
}

TEST(TemporaryDirectoryTest, CreationUsesValidatedParentAfterPathReplacement)
{
    MockContext owner;
    const std::string parent = owner.GetTempdirPath() + "/parent";
    const std::string movedParent = parent + ".moved";
    const std::string outside = owner.GetTempdirPath() + "/outside";
    ASSERT_EQ(0, ::mkdir(parent.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir(outside.c_str(), 0700));
    auto validated = ComplianceEngine::Detail::ValidateTemporaryDirectoryParent(parent);
    ASSERT_TRUE(validated.HasValue()) << validated.Error().message;

    ASSERT_EQ(0, ::rename(parent.c_str(), movedParent.c_str()));
    ASSERT_EQ(0, ::symlink(outside.c_str(), parent.c_str()));
    auto created = ComplianceEngine::Detail::CreateTemporaryDirectoryInParent(std::move(validated).Value(), "pinned");
    ASSERT_TRUE(created.HasValue()) << created.Error().message;
    auto directory = std::move(created).Value();
    const std::string name = directory.Path().substr(parent.size() + 1);

    EXPECT_EQ(0, ::access((movedParent + "/" + name).c_str(), F_OK));
    EXPECT_NE(0, ::access((outside + "/" + name).c_str(), F_OK));
    EXPECT_TRUE(directory.Remove());
    EXPECT_NE(0, ::access((movedParent + "/" + name).c_str(), F_OK));
}

TEST(TemporaryDirectoryTest, MockContextCleanupDoesNotFollowReplacedRoot)
{
    MockContext owner;
    const std::string parent = owner.GetTempdirPath() + "/parent";
    const std::string outside = owner.GetTempdirPath() + "/outside";
    const std::string sentinel = outside + "/sentinel";
    ASSERT_EQ(0, ::mkdir(parent.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir(outside.c_str(), 0700));
    std::ofstream sentinelFile(sentinel);
    ASSERT_TRUE(sentinelFile.is_open());
    sentinelFile << "preserve";
    sentinelFile.close();
    ScopedTmpdir environment(parent.c_str());

    std::unique_ptr<MockContext> context(new MockContext());
    const std::string originalRoot = context->GetTempdirPath();
    const std::string movedRoot = originalRoot + ".moved";
    ASSERT_EQ(0, ::rename(originalRoot.c_str(), movedRoot.c_str()));
    ASSERT_EQ(0, ::symlink(outside.c_str(), originalRoot.c_str()));

    context.reset();

    EXPECT_EQ(0, ::access(sentinel.c_str(), F_OK));
}

TEST(TemporaryDirectoryTest, CleanupDoesNotDeleteReplacementDirectory)
{
    MockContext owner;
    const std::string parent = owner.GetTempdirPath() + "/parent";
    const std::string sentinel = owner.GetTempdirPath() + "/sentinel";
    ASSERT_EQ(0, ::mkdir(parent.c_str(), 0700));
    std::ofstream sentinelFile(sentinel);
    ASSERT_TRUE(sentinelFile.is_open());
    sentinelFile << "preserve";
    sentinelFile.close();
    ScopedTmpdir environment(parent.c_str());

    auto contextResult = ComplianceEngine::Cli::Context::Make(nullptr);
    ASSERT_TRUE(contextResult.HasValue()) << contextResult.Error().message;
    auto context = std::move(contextResult).Value();
    const std::string root = context->GetStatePath();
    ASSERT_EQ(0, ::rename(root.c_str(), (root + ".moved").c_str()));
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    ASSERT_EQ(0, ::link(sentinel.c_str(), (root + "/sentinel").c_str()));

    context.reset();

    EXPECT_EQ(0, ::access((root + "/sentinel").c_str(), F_OK));
    EXPECT_EQ(0, ::access(sentinel.c_str(), F_OK));
}

TEST(TemporaryDirectoryTest, CliContextCleanupDoesNotFollowReplacedRoot)
{
    MockContext owner;
    const std::string parent = owner.GetTempdirPath() + "/parent";
    const std::string outside = owner.GetTempdirPath() + "/outside";
    const std::string sentinel = outside + "/sentinel";
    ASSERT_EQ(0, ::mkdir(parent.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir(outside.c_str(), 0700));
    std::ofstream sentinelFile(sentinel);
    ASSERT_TRUE(sentinelFile.is_open());
    sentinelFile << "preserve";
    sentinelFile.close();
    ScopedTmpdir environment(parent.c_str());

    auto contextResult = ComplianceEngine::Cli::Context::Make(nullptr);
    ASSERT_TRUE(contextResult.HasValue()) << contextResult.Error().message;
    auto context = std::move(contextResult).Value();
    const std::string originalRoot = context->GetStatePath();
    const std::string movedRoot = originalRoot + ".moved";
    ASSERT_EQ(0, ::rename(originalRoot.c_str(), movedRoot.c_str()));
    ASSERT_EQ(0, ::symlink(outside.c_str(), originalRoot.c_str()));

    context.reset();

    EXPECT_EQ(0, ::access(sentinel.c_str(), F_OK));
}
