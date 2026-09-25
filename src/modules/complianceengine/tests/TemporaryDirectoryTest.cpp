// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "TemporaryDirectory.h"

#include "MockContext.h"

#include <cstdlib>
#include <gtest/gtest.h>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

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
    EXPECT_EQ("/configured/temporary/root", ComplianceEngine::Detail::GetTemporaryDirectoryParent());
}

TEST(TemporaryDirectoryTest, EmptyParentUsesCompatibilityFallback)
{
    ScopedTmpdir environment("");
    EXPECT_EQ("/tmp", ComplianceEngine::Detail::GetTemporaryDirectoryParent());
}

TEST(TemporaryDirectoryTest, UnsetParentUsesCompatibilityFallback)
{
    ScopedTmpdir environment(nullptr);
    EXPECT_EQ("/tmp", ComplianceEngine::Detail::GetTemporaryDirectoryParent());
}

TEST(TemporaryDirectoryTest, MockContextCreatesPrivateUniqueRootsUnderConfiguredParent)
{
    MockContext owner;
    const std::string parent = owner.GetTempdirPath() + "/configured parent";
    ASSERT_EQ(0, ::mkdir(parent.c_str(), 0700));
    ScopedTmpdir environment(parent.c_str());

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

    EXPECT_THROW(ComplianceEngine::Detail::CreateTemporaryDirectory("failure"), std::runtime_error);
}
