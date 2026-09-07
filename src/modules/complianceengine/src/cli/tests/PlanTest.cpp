// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
//
// Tests for kompli plan/run: HashFile, GeneratePlan, ParsePlanFile.
//
// GeneratePlan/ParsePlanFile/HashFile apply the same file input-hardening
// posture as benchmark-definition parsing (root-owned file, root-owned
// non-writable parent directory - see benchmarkio/InputSecurity.hpp). Files
// are created inside a per-test mkdtemp() tree managed by MockContext, mirroring
// InputSecurityTest.cpp's convention; tests that need a successfully-opened
// file are skipped when running as non-root, since only root can chown a
// fixture to itself.

#include <MockContext.h>
#include <Plan.hpp>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

using ComplianceEngine::Cli::GeneratePlan;
using ComplianceEngine::Cli::HashFile;
using ComplianceEngine::Cli::ParsePlanFile;
using ComplianceEngine::Cli::Toggle;
using ComplianceEngine::Cli::ToggleMode;

namespace
{
// A minimal, schema-valid benchmark definition with two rules
// (section "1.1.1.1" and "1.1.1.2").
const char* const kBenchmarkJson = R"({
  "apiVersion": "v1",
  "kind": "BenchmarkDefinition",
  "metadata": {
    "name": "test_benchmark",
    "labels": {},
    "annotations": {}
  },
  "spec": {
    "rules": [
      {
        "section": "1.1.1.1",
        "ruleId": "00000000-0000-0000-0000-000000000001",
        "ruleName": "TestingProceduresPass",
        "title": "Rule one",
        "payloadKey": "/cis/ubuntu/22.04/v1.0.0/1/1/1/1",
        "tags": [],
        "metadata": {"description": "", "rationale": "", "fixtext": "", "references": "", "severity": "Low"},
        "payload": {"audit": {}, "remediate": {}, "parameters": {}}
      },
      {
        "section": "1.1.1.2",
        "ruleId": "00000000-0000-0000-0000-000000000002",
        "ruleName": "TestingProceduresPass",
        "title": "Rule two",
        "payloadKey": "/cis/ubuntu/22.04/v1.0.0/1/1/1/2",
        "tags": [],
        "metadata": {"description": "", "rationale": "", "fixtext": "", "references": "", "severity": "Low"},
        "payload": {"audit": {}, "remediate": {}, "parameters": {}}
      }
    ]
  }
})";

bool WriteFile(const std::string& path, const std::string& content)
{
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file.is_open())
    {
        return false;
    }
    file << content;
    return static_cast<bool>(file);
}

// Base fixture: owns a MockContext whose mkdtemp() tree is removed on
// TearDown, same convention as InputSecurityTest.cpp.
class PlanFixture : public ::testing::Test
{
protected:
    std::string TempPath(const std::string& name) const
    {
        return mCtx.GetTempdirPath() + "/" + name;
    }

    std::string MakeSubdir(const std::string& name, mode_t mode = 0755) const
    {
        std::string path = TempPath(name);
        EXPECT_EQ(0, ::mkdir(path.c_str(), mode)) << std::strerror(errno);
        return path;
    }

    // Creates `dir` (root-owned, mode 0755) and a root-owned file inside it
    // with `content`. Returns the file's full path. Requires root (chown).
    std::string MakeVerifiedFile(const std::string& dirName, const std::string& fileName, const std::string& content) const
    {
        const std::string dir = MakeSubdir(dirName);
        EXPECT_EQ(0, ::chown(dir.c_str(), 0, 0)) << std::strerror(errno);
        const std::string path = dir + "/" + fileName;
        EXPECT_TRUE(WriteFile(path, content));
        EXPECT_EQ(0, ::chown(path.c_str(), 0, 0)) << std::strerror(errno);
        EXPECT_EQ(0, ::chmod(path.c_str(), 0644)) << std::strerror(errno);
        return path;
    }

    MockContext mCtx;
};

class HashFileTest : public PlanFixture
{
};
class GeneratePlanTest : public PlanFixture
{
};
class ParsePlanFileTest : public PlanFixture
{
};
} // namespace

TEST_F(HashFileTest, ComputesKnownSha256)
{
    if (::geteuid() != 0)
    {
        GTEST_SKIP() << "chown requires root";
    }
    const std::string path = MakeVerifiedFile("hash_dir", "content.txt", "hello-kompli-plan");

    auto result = HashFile(path, nullptr);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(result.Value(), "e5c27f78fc7d6c3799ca25a9f562e9bd1a7d04b538f63f9de705146b7d5777c0");
}

TEST_F(HashFileTest, DifferentContentProducesDifferentHash)
{
    if (::geteuid() != 0)
    {
        GTEST_SKIP() << "chown requires root";
    }
    const std::string pathA = MakeVerifiedFile("hash_dir_a", "content.txt", "content-a");
    const std::string pathB = MakeVerifiedFile("hash_dir_b", "content.txt", "content-b");

    auto resultA = HashFile(pathA, nullptr);
    auto resultB = HashFile(pathB, nullptr);
    ASSERT_TRUE(resultA.HasValue());
    ASSERT_TRUE(resultB.HasValue());
    EXPECT_NE(resultA.Value(), resultB.Value());
}

TEST_F(HashFileTest, RefusesNonRootOwnedFile)
{
    // No root/chown involved: in a normal (non-root) test run the freshly
    // created directory/file are owned by the invoking user, which
    // OpenVerifiedInput must refuse.
    if (::geteuid() == 0)
    {
        GTEST_SKIP() << "already root; this test needs a non-root-owned file";
    }
    const std::string dir = MakeSubdir("plain_dir");
    const std::string path = dir + "/content.txt";
    ASSERT_TRUE(WriteFile(path, "hello"));

    auto result = HashFile(path, nullptr);
    EXPECT_FALSE(result.HasValue());
}

TEST_F(GeneratePlanTest, SeedsEveryRuleAtAudit)
{
    if (::geteuid() != 0)
    {
        GTEST_SKIP() << "chown requires root";
    }
    const std::string path = MakeVerifiedFile("plan_bench_dir", "bench.benchmark.json", kBenchmarkJson);

    auto result = GeneratePlan(path, {}, nullptr);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;

    // Parse the generated plan back rather than string-matching its raw JSON:
    // parson escapes '/' as '\/' when serializing (see parson_escape_slashes),
    // so a literal substring search for a '/'-containing path would never match.
    const std::string planPath = MakeVerifiedFile("plan_seed_out_dir", "plan.json", result.Value());
    auto planResult = ParsePlanFile(planPath, nullptr);
    ASSERT_TRUE(planResult.HasValue()) << planResult.Error().message;
    const auto& plan = planResult.Value();

    EXPECT_EQ(plan.benchmarkFile, path);
    EXPECT_EQ(plan.benchmarkName, "test_benchmark");
    ASSERT_EQ(plan.rules.size(), 2u);
    EXPECT_EQ(plan.rules.at("1.1.1.1").mode, ToggleMode::Audit);
    EXPECT_EQ(plan.rules.at("1.1.1.2").mode, ToggleMode::Audit);
}

TEST_F(GeneratePlanTest, TogglesOverrideDefaultAndLastWriteWins)
{
    if (::geteuid() != 0)
    {
        GTEST_SKIP() << "chown requires root";
    }
    const std::string path = MakeVerifiedFile("plan_bench_dir2", "bench.benchmark.json", kBenchmarkJson);

    // --remediate=1.1.1.1 --audit=1.1.1.1 : the later flag wins, so 1.1.1.1
    // ends up back at audit despite being toggled to remediate first.
    const std::vector<Toggle> toggles = {
        Toggle{"1.1.1.1", ToggleMode::Remediate},
        Toggle{"1.1.1.1", ToggleMode::Audit},
        Toggle{"1.1.1.2", ToggleMode::Enforce},
    };
    auto result = GeneratePlan(path, toggles, nullptr);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;

    const std::string planPath = MakeVerifiedFile("plan_out_dir", "plan.json", result.Value());
    auto planResult = ParsePlanFile(planPath, nullptr);
    ASSERT_TRUE(planResult.HasValue()) << planResult.Error().message;
    const auto& plan = planResult.Value();

    ASSERT_EQ(plan.rules.count("1.1.1.1"), 1u);
    EXPECT_EQ(plan.rules.at("1.1.1.1").mode, ToggleMode::Audit);
    ASSERT_EQ(plan.rules.count("1.1.1.2"), 1u);
    EXPECT_EQ(plan.rules.at("1.1.1.2").mode, ToggleMode::Enforce);
}

TEST_F(GeneratePlanTest, UnknownSectionInToggleIsRejected)
{
    if (::geteuid() != 0)
    {
        GTEST_SKIP() << "chown requires root";
    }
    const std::string path = MakeVerifiedFile("plan_bench_dir3", "bench.benchmark.json", kBenchmarkJson);

    const std::vector<Toggle> toggles = {Toggle{"9.9.9.9", ToggleMode::Remediate}};
    auto result = GeneratePlan(path, toggles, nullptr);
    EXPECT_FALSE(result.HasValue());
}

TEST_F(ParsePlanFileTest, ParsesValidPlan)
{
    if (::geteuid() != 0)
    {
        GTEST_SKIP() << "chown requires root";
    }
    const char* const planJson = R"({
      "benchmark": {"file": "/etc/kompli/definitions/x.benchmark.json", "name": "x", "sha256": "abc123"},
      "rules": {
        "1.1.1.1": {"mode": "audit", "parameters": {}},
        "1.1.1.2": {"mode": "remediate", "parameters": {}}
      }
    })";
    const std::string path = MakeVerifiedFile("parse_plan_dir", "plan.json", planJson);

    auto result = ParsePlanFile(path, nullptr);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    const auto& plan = result.Value();
    EXPECT_EQ(plan.benchmarkFile, "/etc/kompli/definitions/x.benchmark.json");
    EXPECT_EQ(plan.benchmarkName, "x");
    EXPECT_EQ(plan.benchmarkSha256, "abc123");
    ASSERT_EQ(plan.rules.size(), 2u);
    EXPECT_EQ(plan.rules.at("1.1.1.1").mode, ToggleMode::Audit);
    EXPECT_EQ(plan.rules.at("1.1.1.2").mode, ToggleMode::Remediate);
}

TEST_F(ParsePlanFileTest, RejectsMissingBenchmarkObject)
{
    if (::geteuid() != 0)
    {
        GTEST_SKIP() << "chown requires root";
    }
    const char* const planJson = R"({"rules": {}})";
    const std::string path = MakeVerifiedFile("parse_plan_dir2", "plan.json", planJson);

    auto result = ParsePlanFile(path, nullptr);
    EXPECT_FALSE(result.HasValue());
}

TEST_F(ParsePlanFileTest, RejectsInvalidMode)
{
    if (::geteuid() != 0)
    {
        GTEST_SKIP() << "chown requires root";
    }
    const char* const planJson = R"({
      "benchmark": {"file": "x.json", "name": "x", "sha256": "abc"},
      "rules": {"1.1.1.1": {"mode": "bogus", "parameters": {}}}
    })";
    const std::string path = MakeVerifiedFile("parse_plan_dir3", "plan.json", planJson);

    auto result = ParsePlanFile(path, nullptr);
    EXPECT_FALSE(result.HasValue());
}

TEST_F(ParsePlanFileTest, RefusesNonRootOwnedFile)
{
    if (::geteuid() == 0)
    {
        GTEST_SKIP() << "already root; this test needs a non-root-owned file";
    }
    const std::string dir = MakeSubdir("plain_plan_dir");
    const std::string path = dir + "/plan.json";
    ASSERT_TRUE(WriteFile(path, R"({"benchmark":{"file":"x","name":"x","sha256":"a"},"rules":{}})"));

    auto result = ParsePlanFile(path, nullptr);
    EXPECT_FALSE(result.HasValue());
}
