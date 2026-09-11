#include <FileSymlinkTarget.h>
#include <MockContext.h>
#include <fstream>
#include <gtest/gtest.h>
#include <unistd.h>

using namespace ComplianceEngine;

class FileSymlinkTargetTest : public ::testing::Test
{
protected:
    char directoryTemplate[64] = "/tmp/symlink-target.XXXXXX";
    std::string directory;
    MockContext context;
    IndicatorsTree indicators;

    void SetUp() override
    {
        auto created = mkdtemp(directoryTemplate);
        ASSERT_NE(created, nullptr);
        directory = created;
        std::ofstream(directory + "/expected").close();
        indicators.Push("FileSymlinkTarget");
    }

    void TearDown() override
    {
        unlink((directory + "/link").c_str());
        unlink((directory + "/chain").c_str());
        unlink((directory + "/expected").c_str());
        rmdir(directory.c_str());
    }

    Status Audit(const std::string& name, const std::string& pattern)
    {
        FileSymlinkTargetParams params;
        params.filename = directory + "/" + name;
        params.targetPattern = regex(pattern);
        auto result = AuditFileSymlinkTarget(params, indicators, context);
        EXPECT_TRUE(result.HasValue());
        return result.HasValue() ? result.Value() : Status::NonCompliant;
    }
};

TEST_F(FileSymlinkTargetTest, RelativeLinkMatchesCanonicalTarget)
{
    ASSERT_EQ(symlink("expected", (directory + "/link").c_str()), 0);
    EXPECT_EQ(Audit("link", R"(/expected$)"), Status::Compliant);
    EXPECT_EQ(Audit("link", R"(/wrong$)"), Status::NonCompliant);
}

TEST_F(FileSymlinkTargetTest, LinkChainResolvesToFinalTarget)
{
    ASSERT_EQ(symlink("expected", (directory + "/chain").c_str()), 0);
    ASSERT_EQ(symlink("chain", (directory + "/link").c_str()), 0);
    EXPECT_EQ(Audit("link", R"(/expected$)"), Status::Compliant);
}

TEST_F(FileSymlinkTargetTest, OrdinaryAndMissingFilesAreNotSymlinks)
{
    EXPECT_EQ(Audit("expected", ".*"), Status::NonCompliant);
    EXPECT_EQ(Audit("missing", ".*"), Status::NonCompliant);
}

TEST_F(FileSymlinkTargetTest, BrokenLinkIsNoncompliant)
{
    ASSERT_EQ(symlink("missing", (directory + "/link").c_str()), 0);
    EXPECT_EQ(Audit("link", ".*"), Status::NonCompliant);
}

TEST_F(FileSymlinkTargetTest, CyclicLinkIsNoncompliant)
{
    ASSERT_EQ(symlink("link", (directory + "/link").c_str()), 0);
    EXPECT_EQ(Audit("link", ".*"), Status::NonCompliant);
}
