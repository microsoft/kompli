// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "CliContext.h"

#include <fstream>
#include <gtest/gtest.h>
#include <memory>
#include <sys/stat.h>
#include <utility>

namespace
{
std::unique_ptr<ComplianceEngine::Cli::Context> MakeContext()
{
    auto result = ComplianceEngine::Cli::Context::Make(nullptr);
    if (!result.HasValue())
    {
        ADD_FAILURE() << result.Error().message;
        return nullptr;
    }
    return std::move(result).Value();
}
} // namespace

class ContextTest : public ::testing::Test
{
};

TEST_F(ContextTest, DirectoryCreatedOnConstruction)
{
    auto ctx = MakeContext();
    ASSERT_NE(nullptr, ctx);
    struct stat st;
    ASSERT_EQ(0, stat(ctx->GetStatePath().c_str(), &st));
    EXPECT_TRUE(S_ISDIR(st.st_mode));
}

TEST_F(ContextTest, DirectoryHasCorrectPrefix)
{
    auto ctx = MakeContext();
    ASSERT_NE(nullptr, ctx);
    const std::string statePath = ctx->GetStatePath();
    const auto separator = statePath.find_last_of('/');
    ASSERT_NE(std::string::npos, separator);
    auto parent = ComplianceEngine::Detail::GetTemporaryDirectoryParent();
    ASSERT_TRUE(parent.HasValue()) << parent.Error().message;
    auto validatedParent = ComplianceEngine::Detail::ValidateTemporaryDirectoryParent(parent.Value());
    ASSERT_TRUE(validatedParent.HasValue()) << validatedParent.Error().message;
    EXPECT_EQ(validatedParent.Value().path, statePath.substr(0, separator));
    EXPECT_EQ(0u, statePath.substr(separator + 1).rfind("kompli-cli.", 0));
}

TEST_F(ContextTest, DirectoryPermissionsAre0700)
{
    auto ctx = MakeContext();
    ASSERT_NE(nullptr, ctx);
    struct stat st;
    ASSERT_EQ(0, stat(ctx->GetStatePath().c_str(), &st));
    EXPECT_EQ(static_cast<mode_t>(0700), st.st_mode & 0777);
}

TEST_F(ContextTest, EmptyDirectoryRemovedOnDestruction)
{
    std::string statePath;
    {
        auto ctx = MakeContext();
        ASSERT_NE(nullptr, ctx);
        statePath = ctx->GetStatePath();
        struct stat st;
        ASSERT_EQ(0, stat(statePath.c_str(), &st));
    }
    struct stat st;
    EXPECT_NE(0, stat(statePath.c_str(), &st));
}

TEST_F(ContextTest, RecursiveRemovalOnDestruction)
{
    std::string statePath;
    std::string subDir;
    std::string topFile;
    std::string nestedFile;

    {
        auto ctx = MakeContext();
        ASSERT_NE(nullptr, ctx);
        statePath = ctx->GetStatePath();

        subDir = statePath + "/subdir";
        ASSERT_EQ(0, mkdir(subDir.c_str(), 0700));

        topFile = statePath + "/file.txt";
        std::ofstream(topFile) << "test";

        nestedFile = subDir + "/nested.txt";
        std::ofstream(nestedFile) << "nested";

        // Confirm all exist before destruction
        struct stat st;
        ASSERT_EQ(0, stat(topFile.c_str(), &st));
        ASSERT_EQ(0, stat(nestedFile.c_str(), &st));
        ASSERT_EQ(0, stat(subDir.c_str(), &st));
    }

    struct stat st;
    EXPECT_NE(0, stat(nestedFile.c_str(), &st)) << "nested file should be removed";
    EXPECT_NE(0, stat(topFile.c_str(), &st)) << "top-level file should be removed";
    EXPECT_NE(0, stat(subDir.c_str(), &st)) << "subdirectory should be removed";
    EXPECT_NE(0, stat(statePath.c_str(), &st)) << "state directory itself should be removed";
}

TEST_F(ContextTest, UniqueDirectoryPerInstance)
{
    auto ctx1 = MakeContext();
    auto ctx2 = MakeContext();
    ASSERT_NE(nullptr, ctx1);
    ASSERT_NE(nullptr, ctx2);
    EXPECT_NE(ctx1->GetStatePath(), ctx2->GetStatePath());
}
