// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
//
// Tests for kompli plan/run: GeneratePlan, ParsePlanFile.
//
// GeneratePlan/ParsePlanFile apply the same file input-hardening
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

using ComplianceEngine::Kompli::ApplyParameterOverrides;
using ComplianceEngine::Kompli::CheckUniqueBenchmarkFiles;
using ComplianceEngine::Kompli::GeneratePlan;
using ComplianceEngine::Kompli::ParamOverride;
using ComplianceEngine::Kompli::ParsePlanFile;
using ComplianceEngine::Kompli::Toggle;
using ComplianceEngine::Kompli::ToggleMode;
using ComplianceEngine::Kompli::ValidatePlanForRun;
using ComplianceEngine::Kompli::WritePlanFile;

namespace
{
// A minimal, schema-valid benchmark definition with two human-facing ids and
// their stable ruleIds.
const char* const kBenchmarkJson = R"({
  "apiVersion": "v1",
  "kind": "BenchmarkDefinition",
  "metadata": {
    "name": "test_benchmark",
    "labels": {"framework": "cis", "distribution": "ubuntu", "distributionVersion": "22.04"},
    "annotations": {"benchmarkVersion": "v1.0.0"}
  },
  "spec": {
    "version": "1.0.0",
    "rules": [
      {
        "ruleName": "TestingProceduresPass",
        "title": "Rule one",
        "id": "1.1.1.1",
        "ruleId": "rule-1",
        "tags": ["level:l1", "severity:low"],
        "metadata": {"description": "", "rationale": "", "fixtext": "", "references": "", "severity": "Low"},
        "payload": {"audit": {}, "remediate": {}, "parameters": {}}
      },
      {
        "ruleName": "TestingProceduresPass",
        "title": "Rule two",
        "id": "1.1.1.2",
        "ruleId": "rule-2",
        "tags": ["level:l2", "severity:critical"],
        "metadata": {"description": "", "rationale": "", "fixtext": "", "references": "", "severity": "Low"},
        "payload": {"audit": {}, "remediate": {}, "parameters": {}}
      }
    ]
  }
})";

// Same as kBenchmarkJson, but rule "1.1.1.1" carries a parameterMetadata
// entry (docs/CLI.md "Parametrization"), for tests exercising default
// pre-filling and --param= override validation.
const char* const kParameterizedBenchmarkJson = R"({
  "apiVersion": "v1",
  "kind": "BenchmarkDefinition",
  "metadata": {
    "name": "test_benchmark",
    "labels": {"framework": "cis", "distribution": "ubuntu", "distributionVersion": "22.04"},
    "annotations": {"benchmarkVersion": "v1.0.0"}
  },
  "spec": {
    "version": "1.0.0",
    "rules": [
      {
        "ruleName": "TestingProceduresPass",
        "title": "Rule one",
        "id": "1.1.1.1",
        "ruleId": "rule-1",
        "tags": [],
        "metadata": {"description": "", "rationale": "", "fixtext": "", "references": "", "severity": "Low"},
        "payload": {"audit": {}, "remediate": {}, "parameters": {"mountPoint": "/tmp"}},
        "parameterMetadata": {
          "mountPoint": {"type": "string", "default": "/tmp", "validationRegex": "^/[a-zA-Z0-9/_.-]+$"}
        }
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

std::string ReadFile(const std::string& path)
{
    std::ifstream file(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
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

class GeneratePlanTest : public PlanFixture
{
};
class ParsePlanFileTest : public PlanFixture
{
};
} // namespace

TEST_F(GeneratePlanTest, SeedsEveryRuleAtAudit)
{
    if (::geteuid() != 0)
    {
        GTEST_SKIP() << "chown requires root";
    }
    const std::string path = MakeVerifiedFile("plan_bench_dir", "bench.benchmark.json", kBenchmarkJson);

    auto result = GeneratePlan({path}, {}, {}, nullptr);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;

    // Parse the generated plan back rather than string-matching its raw JSON:
    // parson escapes '/' as '\/' when serializing (see parson_escape_slashes),
    // so a literal substring search for a '/'-containing path would never match.
    const std::string planPath = MakeVerifiedFile("plan_seed_out_dir", "plan.json", result.Value());
    auto planResult = ParsePlanFile(planPath, nullptr);
    ASSERT_TRUE(planResult.HasValue()) << planResult.Error().message;
    const auto& plan = planResult.Value();

    ASSERT_EQ(plan.benchmarks.size(), 1u);
    const auto& benchmark = plan.benchmarks[0];
    EXPECT_EQ(benchmark.file, path);
    EXPECT_EQ(benchmark.name, "test_benchmark");
    EXPECT_EQ(benchmark.version.major, "1");
    EXPECT_EQ(benchmark.version.minor, "0");
    EXPECT_EQ(benchmark.version.patch, "0");
    EXPECT_EQ(benchmark.versionConstraint, "^1.0.0");
    EXPECT_NE(result.Value().find("\"version\": \"1.0.0\""), std::string::npos);
    EXPECT_NE(result.Value().find("\"versionConstraint\": \"^1.0.0\""), std::string::npos);
    ASSERT_EQ(benchmark.rules.size(), 2u);
    EXPECT_EQ(benchmark.rules.at("1.1.1.1").mode, ToggleMode::Audit);
    EXPECT_EQ(benchmark.rules.at("1.1.1.2").mode, ToggleMode::Audit);
}

TEST_F(GeneratePlanTest, RejectsDefinitionWithoutContentVersion)
{
    if (::geteuid() != 0)
    {
        GTEST_SKIP() << "chown requires root";
    }
    std::string json = kBenchmarkJson;
    const std::string version = "\"version\": \"1.0.0\",\n    ";
    const auto position = json.find(version);
    ASSERT_NE(position, std::string::npos);
    json.erase(position, version.size());
    const std::string path = MakeVerifiedFile("plan_legacy_dir", "bench.benchmark.json", json);

    auto result = GeneratePlan({path}, {}, {}, nullptr);
    ASSERT_FALSE(result.HasValue());
    EXPECT_NE(result.Error().message.find("version"), std::string::npos);
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
    auto result = GeneratePlan({path}, toggles, {}, nullptr);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;

    const std::string planPath = MakeVerifiedFile("plan_out_dir", "plan.json", result.Value());
    auto planResult = ParsePlanFile(planPath, nullptr);
    ASSERT_TRUE(planResult.HasValue()) << planResult.Error().message;
    ASSERT_EQ(planResult.Value().benchmarks.size(), 1u);
    const auto& rules = planResult.Value().benchmarks[0].rules;

    ASSERT_EQ(rules.count("1.1.1.1"), 1u);
    EXPECT_EQ(rules.at("1.1.1.1").mode, ToggleMode::Audit);
    ASSERT_EQ(rules.count("1.1.1.2"), 1u);
    EXPECT_EQ(rules.at("1.1.1.2").mode, ToggleMode::Enforce);
}

TEST_F(GeneratePlanTest, UnknownSectionInToggleIsRejected)
{
    if (::geteuid() != 0)
    {
        GTEST_SKIP() << "chown requires root";
    }
    const std::string path = MakeVerifiedFile("plan_bench_dir3", "bench.benchmark.json", kBenchmarkJson);

    const std::vector<Toggle> toggles = {Toggle{"9.9.9.9", ToggleMode::Remediate}};
    auto result = GeneratePlan({path}, toggles, {}, nullptr);
    EXPECT_FALSE(result.HasValue());
}

TEST_F(GeneratePlanTest, RejectsAmbiguousQualifiedReferenceWithDuplicateBasenames)
{
    if (::geteuid() != 0)
    {
        GTEST_SKIP() << "chown requires root";
    }
    const std::string firstPath = MakeVerifiedFile("duplicate_basename_first", "bench.json", kBenchmarkJson);
    std::string secondJson = kBenchmarkJson;
    secondJson.replace(secondJson.find("\"v1.0.0\""), std::string("\"v1.0.0\"").size(), "\"v2.0.0\"");
    const std::string secondPath = MakeVerifiedFile("duplicate_basename_second", "bench.json", secondJson);

    const std::vector<Toggle> toggles = {Toggle{"bench.json:1.1.1.1", ToggleMode::Remediate}};
    auto result = GeneratePlan({firstPath, secondPath}, toggles, {}, nullptr);
    ASSERT_FALSE(result.HasValue());
    EXPECT_NE(result.Error().message.find("Ambiguous file"), std::string::npos);
}

TEST_F(ParsePlanFileTest, ParsesValidPlan)
{
    if (::geteuid() != 0)
    {
        GTEST_SKIP() << "chown requires root";
    }
    const char* const planJson = R"({
      "benchmarks": [{"file": "/etc/kompli/definitions/x.benchmark.json", "name": "x", "version": "1.0.0", "versionConstraint": "^1.0.0", "rules": {
        "1/1/1/1": {"mode": "audit", "parameters": {}},
        "1/1/1/2": {"mode": "remediate", "parameters": {}}
      }}]
    })";
    const std::string path = MakeVerifiedFile("parse_plan_dir", "plan.json", planJson);

    auto result = ParsePlanFile(path, nullptr);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    ASSERT_EQ(result.Value().benchmarks.size(), 1u);
    const auto& benchmark = result.Value().benchmarks[0];
    EXPECT_EQ(benchmark.file, "/etc/kompli/definitions/x.benchmark.json");
    EXPECT_EQ(benchmark.name, "x");
    EXPECT_EQ(benchmark.version.major, "1");
    ASSERT_EQ(benchmark.rules.size(), 2u);
    EXPECT_EQ(benchmark.rules.at("1/1/1/1").mode, ToggleMode::Audit);
    EXPECT_EQ(benchmark.rules.at("1/1/1/2").mode, ToggleMode::Remediate);
}

TEST_F(ParsePlanFileTest, RejectsInvalidVersionPins)
{
    if (::geteuid() != 0)
    {
        GTEST_SKIP() << "chown requires root";
    }
    const std::string path = MakeVerifiedFile("parse_plan_version_dir", "plan.json", R"({"benchmarks":[{"file":"bench.json","version":"1.0.0","rules":{}}]})");
    EXPECT_FALSE(ParsePlanFile(path, nullptr).HasValue());

    ASSERT_TRUE(WriteFile(path, R"({"benchmarks":[{"file":"bench.json","rules":{}}]})"));
    auto missing = ParsePlanFile(path, nullptr);
    ASSERT_FALSE(missing.HasValue());
    EXPECT_NE(missing.Error().message.find("version"), std::string::npos);

    ASSERT_TRUE(WriteFile(path, R"({"benchmarks":[{"file":"bench.json","versionConstraint":"^1.0.0","rules":{}}]})"));
    EXPECT_FALSE(ParsePlanFile(path, nullptr).HasValue());
    ASSERT_TRUE(WriteFile(path, R"({"benchmarks":[{"file":"bench.json","version":null,"versionConstraint":"^1.0.0","rules":{}}]})"));
    EXPECT_FALSE(ParsePlanFile(path, nullptr).HasValue());

    for (const std::string& version : {"1.0", "01.0.0", "1.0.0-beta", "1.0.0.0", R"(1.0.0\u0000)"})
    {
        const std::string json = R"({"benchmarks":[{"file":"bench.json","version":")" + version + R"(","versionConstraint":"^1.0.0","rules":{}}]})";
        ASSERT_TRUE(WriteFile(path, json));
        EXPECT_FALSE(ParsePlanFile(path, nullptr).HasValue()) << version;
    }

    ASSERT_TRUE(WriteFile(path, R"({"benchmarks":[{"file":"bench.json","version":"1.0.0","versionConstraint":"^2.0.0","rules":{}}]})"));
    EXPECT_FALSE(ParsePlanFile(path, nullptr).HasValue());

    ASSERT_TRUE(WriteFile(path, R"({"benchmarks":[{"file":"bench.json","version":"1.0.0","versionConstraint":"^1.0.0 || 2.0.0","rules":{}}]})"));
    EXPECT_FALSE(ParsePlanFile(path, nullptr).HasValue());

    ASSERT_TRUE(WriteFile(path,
        R"({"benchmarks":[{"file":"bench.json","version":"184467440737095516160.999999999999999999999.0","versionConstraint":"^184467440737095516160.999999999999999999999.0","rules":{}}]})"));
    auto large = ParsePlanFile(path, nullptr);
    ASSERT_TRUE(large.HasValue()) << large.Error().message;
    EXPECT_EQ(large.Value().benchmarks[0].version.major, "184467440737095516160");
}

TEST_F(ParsePlanFileTest, ParsesRuleParameters)
{
    if (::geteuid() != 0)
    {
        GTEST_SKIP() << "chown requires root";
    }
    const char* const planJson = R"({
      "benchmarks": [{"file": "/etc/kompli/definitions/x.benchmark.json", "name": "x", "version": "1.0.0", "versionConstraint": "^1.0.0", "rules": {
        "1.1.1.1": {"mode": "audit", "parameters": {"mountPoint": "/tmp"}}
      }}]
    })";
    const std::string path = MakeVerifiedFile("parse_plan_params_dir", "plan.json", planJson);

    auto result = ParsePlanFile(path, nullptr);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    ASSERT_EQ(result.Value().benchmarks.size(), 1u);
    const auto& rule = result.Value().benchmarks[0].rules.at("1.1.1.1");
    ASSERT_EQ(rule.parameters.count("mountPoint"), 1u);
    EXPECT_EQ(rule.parameters.at("mountPoint"), "/tmp");
}

TEST_F(GeneratePlanTest, PreFillsParameterDefaultsFromMetadata)
{
    if (::geteuid() != 0)
    {
        GTEST_SKIP() << "chown requires root";
    }
    const std::string path = MakeVerifiedFile("plan_param_dir", "bench.benchmark.json", kParameterizedBenchmarkJson);

    auto result = GeneratePlan({path}, {}, {}, nullptr);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;

    const std::string planPath = MakeVerifiedFile("plan_param_out_dir", "plan.json", result.Value());
    auto planResult = ParsePlanFile(planPath, nullptr);
    ASSERT_TRUE(planResult.HasValue()) << planResult.Error().message;
    const auto& rule = planResult.Value().benchmarks[0].rules.at("1.1.1.1");
    ASSERT_EQ(rule.parameters.count("mountPoint"), 1u);
    EXPECT_EQ(rule.parameters.at("mountPoint"), "/tmp");
}

TEST_F(GeneratePlanTest, ParamOverrideReplacesDefault)
{
    if (::geteuid() != 0)
    {
        GTEST_SKIP() << "chown requires root";
    }
    const std::string path = MakeVerifiedFile("plan_param_override_dir", "bench.benchmark.json", kParameterizedBenchmarkJson);

    const std::vector<ParamOverride> overrides = {ParamOverride{"1.1.1.1.mountPoint", "/var/tmp"}};
    auto result = GeneratePlan({path}, {}, overrides, nullptr);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;

    const std::string planPath = MakeVerifiedFile("plan_param_override_out_dir", "plan.json", result.Value());
    auto planResult = ParsePlanFile(planPath, nullptr);
    ASSERT_TRUE(planResult.HasValue()) << planResult.Error().message;
    const auto& rule = planResult.Value().benchmarks[0].rules.at("1.1.1.1");
    EXPECT_EQ(rule.parameters.at("mountPoint"), "/var/tmp");
}

TEST_F(GeneratePlanTest, ParamOverrideEmptyValueReplacesDefault)
{
    if (::geteuid() != 0)
    {
        GTEST_SKIP() << "chown requires root";
    }
    std::string json = kParameterizedBenchmarkJson;
    const std::string originalRegex = R"("validationRegex": "^/[a-zA-Z0-9/_.-]+$")";
    const auto position = json.find(originalRegex);
    ASSERT_NE(position, std::string::npos);
    json.replace(position, originalRegex.size(), R"("validationRegex": "^(/[a-zA-Z0-9/_.-]+)?$")");
    const std::string path = MakeVerifiedFile("plan_param_empty_dir", "bench.benchmark.json", json);

    auto result = GeneratePlan({path}, {}, {ParamOverride{"1.1.1.1.mountPoint", ""}}, nullptr);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;

    const std::string planPath = MakeVerifiedFile("plan_param_empty_out_dir", "plan.json", result.Value());
    auto planResult = ParsePlanFile(planPath, nullptr);
    ASSERT_TRUE(planResult.HasValue()) << planResult.Error().message;
    const auto& parameters = planResult.Value().benchmarks[0].rules.at("1.1.1.1").parameters;
    ASSERT_EQ(parameters.count("mountPoint"), 1u);
    EXPECT_TRUE(parameters.at("mountPoint").empty());
}

TEST_F(GeneratePlanTest, ParamOverrideEmptyValueRejectsValidationRegex)
{
    if (::geteuid() != 0)
    {
        GTEST_SKIP() << "chown requires root";
    }
    const std::string path = MakeVerifiedFile("plan_param_empty_regex_dir", "bench.benchmark.json", kParameterizedBenchmarkJson);

    auto result = GeneratePlan({path}, {}, {ParamOverride{"1.1.1.1.mountPoint", ""}}, nullptr);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, EINVAL);
    EXPECT_NE(result.Error().message.find("does not match its required pattern"), std::string::npos);
}

TEST_F(GeneratePlanTest, ParamOverrideRejectsValueNotMatchingValidationRegex)
{
    if (::geteuid() != 0)
    {
        GTEST_SKIP() << "chown requires root";
    }
    const std::string path = MakeVerifiedFile("plan_param_regex_dir", "bench.benchmark.json", kParameterizedBenchmarkJson);

    const std::vector<ParamOverride> overrides = {ParamOverride{"1.1.1.1.mountPoint", "relative/path"}};
    auto result = GeneratePlan({path}, {}, overrides, nullptr);
    EXPECT_FALSE(result.HasValue());
}

TEST_F(GeneratePlanTest, ParamOverrideRejectsUnknownParameterName)
{
    if (::geteuid() != 0)
    {
        GTEST_SKIP() << "chown requires root";
    }
    const std::string path = MakeVerifiedFile("plan_param_unknown_dir", "bench.benchmark.json", kParameterizedBenchmarkJson);

    const std::vector<ParamOverride> overrides = {ParamOverride{"1.1.1.1.notAParameter", "x"}};
    auto result = GeneratePlan({path}, {}, overrides, nullptr);
    EXPECT_FALSE(result.HasValue());
}

TEST_F(GeneratePlanTest, ParamOverrideRejectsUnknownRule)
{
    if (::geteuid() != 0)
    {
        GTEST_SKIP() << "chown requires root";
    }
    const std::string path = MakeVerifiedFile("plan_param_unknown_rule_dir", "bench.benchmark.json", kParameterizedBenchmarkJson);

    const std::vector<ParamOverride> overrides = {ParamOverride{"9.9.9.9.mountPoint", "/var/tmp"}};
    auto result = GeneratePlan({path}, {}, overrides, nullptr);
    EXPECT_FALSE(result.HasValue());
}

TEST_F(GeneratePlanTest, ResolvesDottedParameterNameFromMetadata)
{
    if (::geteuid() != 0)
    {
        GTEST_SKIP() << "chown requires root";
    }
    std::string json = kParameterizedBenchmarkJson;
    const std::string name = "mountPoint";
    for (std::size_t position = json.find(name); position != std::string::npos; position = json.find(name, position + 1))
    {
        json.replace(position, name.size(), "mount.point");
        position += std::string("mount.point").size() - 1;
    }
    const std::string path = MakeVerifiedFile("plan_dotted_param_dir", "bench.benchmark.json", json);

    auto result = GeneratePlan({path}, {}, {ParamOverride{"1.1.1.1.mount.point", "/var/tmp"}}, nullptr);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    const std::string planPath = MakeVerifiedFile("plan_dotted_param_out_dir", "plan.json", result.Value());
    auto planResult = ParsePlanFile(planPath, nullptr);
    ASSERT_TRUE(planResult.HasValue()) << planResult.Error().message;
    EXPECT_EQ(planResult.Value().benchmarks[0].rules.at("1.1.1.1").parameters.at("mount.point"), "/var/tmp");
}

TEST_F(GeneratePlanTest, ValidatesParametersAfterApplyingAllOverrides)
{
    if (::geteuid() != 0)
    {
        GTEST_SKIP() << "chown requires root";
    }
    std::string json = kParameterizedBenchmarkJson;
    const std::string oldPayload = R"("parameters": {"mountPoint": "/tmp"})";
    const std::string newPayload = R"("parameters": {"first": "", "second": ""})";
    const std::string oldMetadata = R"("mountPoint": {"type": "string", "default": "/tmp", "validationRegex": "^/[a-zA-Z0-9/_.-]+$"})";
    const std::string newMetadata =
        R"("first": {"type": "string", "default": "", "validationRegex": "^.+$"}, "second": {"type": "string", "default": "", "validationRegex": "^.+$"})";
    auto position = json.find(oldPayload);
    ASSERT_NE(position, std::string::npos);
    json.replace(position, oldPayload.size(), newPayload);
    position = json.find(oldMetadata);
    ASSERT_NE(position, std::string::npos);
    json.replace(position, oldMetadata.size(), newMetadata);
    const std::string path = MakeVerifiedFile("plan_multi_override_dir", "bench.benchmark.json", json);

    auto result = GeneratePlan({path}, {}, {ParamOverride{"1.1.1.1.first", "one"}, ParamOverride{"1.1.1.1.second", "two"}}, nullptr);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
}

TEST_F(GeneratePlanTest, RejectsPlanThatExceedsParserLimit)
{
    if (::geteuid() != 0)
    {
        GTEST_SKIP() << "chown requires root";
    }
    std::string json = kParameterizedBenchmarkJson;
    const std::string validationRegex = R"(, "validationRegex": "^/[a-zA-Z0-9/_.-]+$")";
    const auto position = json.find(validationRegex);
    ASSERT_NE(position, std::string::npos);
    json.erase(position, validationRegex.size());
    const std::string path = MakeVerifiedFile("plan_oversized_dir", "bench.benchmark.json", json);

    auto result = GeneratePlan({path}, {}, {ParamOverride{"1.1.1.1.mountPoint", std::string(8 * 1024 * 1024, 'x')}}, nullptr);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, EFBIG);
}

TEST(ApplyParameterOverridesTest, AddsParametersObjectWhenAbsent)
{
    auto result = ApplyParameterOverrides(R"({"audit":{}})", {{"mountPoint", "tmp"}});
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_NE(result.Value().find("\"mountPoint\""), std::string::npos);
    EXPECT_NE(result.Value().find("\"tmp\""), std::string::npos);
}

TEST(ApplyParameterOverridesTest, OverwritesExistingParameterValue)
{
    auto result = ApplyParameterOverrides(R"({"audit":{},"parameters":{"mountPoint":"tmp"}})", {{"mountPoint", "vartmp"}});
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_NE(result.Value().find("\"vartmp\""), std::string::npos);
    EXPECT_EQ(result.Value().find("\"tmp\""), std::string::npos);
}

TEST(ApplyParameterOverridesTest, RejectsNonObjectProcedureJson)
{
    auto result = ApplyParameterOverrides("[]", {{"mountPoint", "tmp"}});
    EXPECT_FALSE(result.HasValue());
}

TEST_F(PlanFixture, WritePlanFileOverwritesRegularFile)
{
    const std::string path = TempPath("output.json");
    ASSERT_TRUE(WriteFile(path, "old"));

    auto error = WritePlanFile(path, "new plan");
    EXPECT_FALSE(error.HasValue());
    EXPECT_EQ(ReadFile(path), "new plan");
}

TEST_F(PlanFixture, WritePlanFileRefusesSymlinkWithoutChangingTarget)
{
    const std::string target = TempPath("target.json");
    const std::string link = TempPath("output.json");
    ASSERT_TRUE(WriteFile(target, "preserve me"));
    ASSERT_EQ(0, ::symlink(target.c_str(), link.c_str())) << std::strerror(errno);

    auto error = WritePlanFile(link, "replacement");
    EXPECT_TRUE(error.HasValue());
    EXPECT_EQ(ReadFile(target), "preserve me");
}

TEST_F(PlanFixture, WritePlanFileRefusesSymlinkedParent)
{
    const std::string targetDir = MakeSubdir("output_target");
    const std::string alias = TempPath("output_alias");
    ASSERT_EQ(0, ::symlink(targetDir.c_str(), alias.c_str())) << std::strerror(errno);

    auto error = WritePlanFile(alias + "/plan.json", "replacement");
    EXPECT_TRUE(error.HasValue());
    EXPECT_NE(0, ::access((targetDir + "/plan.json").c_str(), F_OK));
}

TEST_F(PlanFixture, CheckUniqueBenchmarkFilesRejectsLiteralAndCanonicalDuplicates)
{
    const std::string path = TempPath("definition.json");
    const std::string alias = TempPath("alias.json");
    ASSERT_TRUE(WriteFile(path, "{}"));
    ASSERT_EQ(0, ::symlink(path.c_str(), alias.c_str())) << std::strerror(errno);

    EXPECT_TRUE(CheckUniqueBenchmarkFiles({path, path}).HasValue());
    EXPECT_TRUE(CheckUniqueBenchmarkFiles({path, alias}).HasValue());
    EXPECT_FALSE(CheckUniqueBenchmarkFiles({path, TempPath("different.json")}).HasValue());
}

TEST_F(ParsePlanFileTest, RejectsMissingBenchmarksArray)
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

TEST_F(ParsePlanFileTest, RejectsEmptyBenchmarksArray)
{
    if (::geteuid() != 0)
    {
        GTEST_SKIP() << "chown requires root";
    }
    const char* const planJson = R"({"benchmarks": []})";
    const std::string path = MakeVerifiedFile("parse_plan_dir_empty", "plan.json", planJson);

    auto result = ParsePlanFile(path, nullptr);
    EXPECT_FALSE(result.HasValue());
}

TEST_F(ParsePlanFileTest, ParsesMultipleBenchmarkEntries)
{
    if (::geteuid() != 0)
    {
        GTEST_SKIP() << "chown requires root";
    }
    const char* const planJson = R"({
      "benchmarks": [
        {"file": "/etc/kompli/definitions/cis.benchmark.json", "name": "cis", "version": "1.0.0", "versionConstraint": "^1.0.0", "rules": {"1/1/1/1": {"mode": "audit", "parameters": {}}}},
        {"file": "/etc/kompli/definitions/stig.benchmark.json", "name": "stig", "version": "1.0.0", "versionConstraint": "^1.0.0", "rules": {"SV-1": {"mode": "remediate", "parameters": {}}}}
      ]
    })";
    const std::string path = MakeVerifiedFile("parse_plan_dir_multi", "plan.json", planJson);

    auto result = ParsePlanFile(path, nullptr);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    ASSERT_EQ(result.Value().benchmarks.size(), 2u);
    EXPECT_EQ(result.Value().benchmarks[0].name, "cis");
    EXPECT_EQ(result.Value().benchmarks[1].name, "stig");
    EXPECT_EQ(result.Value().benchmarks[1].rules.at("SV-1").mode, ToggleMode::Remediate);
}

TEST_F(ParsePlanFileTest, RejectsInvalidMode)
{
    if (::geteuid() != 0)
    {
        GTEST_SKIP() << "chown requires root";
    }
    const char* const planJson = R"({
      "benchmarks": [{"file": "x.json", "name": "x", "version": "1.0.0", "versionConstraint": "^1.0.0", "rules": {"1/1/1/1": {"mode": "bogus", "parameters": {}}}}]
    })";
    const std::string path = MakeVerifiedFile("parse_plan_dir3", "plan.json", planJson);

    auto result = ParsePlanFile(path, nullptr);
    EXPECT_FALSE(result.HasValue());
}

TEST_F(ParsePlanFileTest, RejectsRawNulByte)
{
    if (::geteuid() != 0)
    {
        GTEST_SKIP() << "chown requires root";
    }
    std::string planJson = R"({"benchmarks":[{"file":"x.json","rules":{}}]})";
    planJson.insert(planJson.find("x.json") + 1, 1, '\0');
    const std::string path = MakeVerifiedFile("parse_plan_raw_nul", "plan.json", planJson);

    auto result = ParsePlanFile(path, nullptr);
    ASSERT_FALSE(result.HasValue());
    EXPECT_NE(result.Error().message.find("raw NUL"), std::string::npos);
}

TEST_F(ParsePlanFileTest, RejectsEscapedNulInDecodedString)
{
    if (::geteuid() != 0)
    {
        GTEST_SKIP() << "chown requires root";
    }
    const char* const planJson = R"({
      "benchmarks": [{"file": "x\u0000.json", "version": "1.0.0", "versionConstraint": "^1.0.0", "rules": {}}]
    })";
    const std::string path = MakeVerifiedFile("parse_plan_escaped_nul", "plan.json", planJson);

    auto result = ParsePlanFile(path, nullptr);
    ASSERT_FALSE(result.HasValue());
    EXPECT_NE(result.Error().message.find("embedded NUL"), std::string::npos);
}

TEST_F(ParsePlanFileTest, RejectsTrailingData)
{
    if (::geteuid() != 0)
    {
        GTEST_SKIP() << "chown requires root";
    }
    const std::string valid = R"({"benchmarks":[{"file":"x","version":"1.0.0","versionConstraint":"^1.0.0","rules":{}}]})";
    const std::string garbagePath = MakeVerifiedFile("parse_plan_trailing_garbage", "plan.json", valid + " garbage");
    auto result = ParsePlanFile(garbagePath, nullptr);
    ASSERT_FALSE(result.HasValue());
    EXPECT_NE(result.Error().message.find("trailing data"), std::string::npos);

    const std::string secondPath = MakeVerifiedFile("parse_plan_second_document", "plan.json", valid + valid);
    result = ParsePlanFile(secondPath, nullptr);
    ASSERT_FALSE(result.HasValue());
    EXPECT_NE(result.Error().message.find("trailing data"), std::string::npos);
}

TEST_F(ParsePlanFileTest, RejectsPresentNonObjectParameters)
{
    if (::geteuid() != 0)
    {
        GTEST_SKIP() << "chown requires root";
    }
    const char* const planJson = R"({
      "benchmarks": [{"file": "x.json", "version": "1.0.0", "versionConstraint": "^1.0.0", "rules": {"1.1": {"mode": "audit", "parameters": []}}}]
    })";
    const std::string path = MakeVerifiedFile("parse_plan_parameters_type", "plan.json", planJson);

    auto result = ParsePlanFile(path, nullptr);
    ASSERT_FALSE(result.HasValue());
    EXPECT_NE(result.Error().message.find("not a JSON object"), std::string::npos);
}

TEST_F(ParsePlanFileTest, RefusesNonRootOwnedFile)
{
    if (::geteuid() == 0)
    {
        GTEST_SKIP() << "already root; this test needs a non-root-owned file";
    }
    const std::string dir = MakeSubdir("plain_plan_dir");
    const std::string path = dir + "/plan.json";
    ASSERT_TRUE(WriteFile(path, R"({"benchmarks":[{"file":"x","name":"x","rules":{}}]})"));

    auto result = ParsePlanFile(path, nullptr);
    EXPECT_FALSE(result.HasValue());
}

namespace
{
// No filesystem/root needed: CheckUniqueBenchmarkIdentities operates purely
// on already-parsed BenchmarkInfo values.
ComplianceEngine::BenchmarkInfo MakeInfo(const std::string& framework, const std::string& distribution, const std::string& version, const std::string& benchmarkVersion)
{
    auto result = ComplianceEngine::BenchmarkInfo::FromMetadata(framework, distribution, version, benchmarkVersion);
    EXPECT_TRUE(result.HasValue()) << result.Error().message;
    return result.Value();
}

ComplianceEngine::DistributionInfo MakeDistribution(const std::string& version = "22.04")
{
    ComplianceEngine::DistributionInfo result;
    result.distribution = ComplianceEngine::LinuxDistribution::Ubuntu;
    result.version = version;
    return result;
}

ComplianceEngine::BenchmarkDefinition::BenchmarkDocument ParseDocument(const std::string& json)
{
    auto result = ComplianceEngine::BenchmarkDefinition::ParseString(json, nullptr);
    EXPECT_TRUE(result.HasValue()) << result.Error().message;
    return std::move(result.Value());
}
} // namespace

TEST(ValidatePlanForRunTest, AcceptsKnownRuleAndValidParameters)
{
    auto document = ParseDocument(kParameterizedBenchmarkJson);
    ComplianceEngine::Kompli::Plan plan;
    ComplianceEngine::Kompli::PlanBenchmark benchmark;
    benchmark.file = "bench.json";
    benchmark.version = {"1", "0", "0"};
    benchmark.versionConstraint = "^1.0.0";
    ComplianceEngine::Kompli::PlanRuleMode rule(ToggleMode::Audit);
    rule.parameters["mountPoint"] = "/var/tmp";
    benchmark.rules["1.1.1.1"] = rule;
    plan.benchmarks.push_back(benchmark);

    EXPECT_FALSE(ValidatePlanForRun(plan, {document}, MakeDistribution()).HasValue());
}

TEST(ValidatePlanForRunTest, RejectsInapplicableBlock)
{
    auto document = ParseDocument(kBenchmarkJson);
    ComplianceEngine::Kompli::Plan plan;
    ComplianceEngine::Kompli::PlanBenchmark benchmark;
    benchmark.file = "bench.json";
    benchmark.version = {"1", "0", "0"};
    benchmark.versionConstraint = "^1.0.0";
    plan.benchmarks.push_back(benchmark);

    EXPECT_TRUE(ValidatePlanForRun(plan, {document}, MakeDistribution("24.04")).HasValue());
}

TEST(ValidatePlanForRunTest, RejectsUnknownRule)
{
    auto document = ParseDocument(kBenchmarkJson);
    ComplianceEngine::Kompli::Plan plan;
    ComplianceEngine::Kompli::PlanBenchmark benchmark;
    benchmark.file = "bench.json";
    benchmark.version = {"1", "0", "0"};
    benchmark.versionConstraint = "^1.0.0";
    benchmark.rules["unknown"] = ComplianceEngine::Kompli::PlanRuleMode(ToggleMode::Audit);
    plan.benchmarks.push_back(benchmark);

    EXPECT_TRUE(ValidatePlanForRun(plan, {document}, MakeDistribution()).HasValue());
}

TEST(ValidatePlanForRunTest, RejectsUnknownOrInvalidParameter)
{
    auto document = ParseDocument(kParameterizedBenchmarkJson);
    ComplianceEngine::Kompli::Plan plan;
    ComplianceEngine::Kompli::PlanBenchmark benchmark;
    benchmark.file = "bench.json";
    benchmark.version = {"1", "0", "0"};
    benchmark.versionConstraint = "^1.0.0";
    ComplianceEngine::Kompli::PlanRuleMode rule(ToggleMode::Audit);
    rule.parameters["unknown"] = "value";
    benchmark.rules["1.1.1.1"] = rule;
    plan.benchmarks.push_back(benchmark);
    EXPECT_TRUE(ValidatePlanForRun(plan, {document}, MakeDistribution()).HasValue());

    plan.benchmarks[0].rules["1.1.1.1"].parameters.clear();
    plan.benchmarks[0].rules["1.1.1.1"].parameters["mountPoint"] = "relative";
    EXPECT_TRUE(ValidatePlanForRun(plan, {document}, MakeDistribution()).HasValue());
}

TEST(ValidatePlanForRunTest, RejectsMissingMandatoryParameter)
{
    auto document = ParseDocument(kParameterizedBenchmarkJson);
    document.resources[0].parameterMetadata["mountPoint"].mandatory = true;
    ComplianceEngine::Kompli::Plan plan;
    ComplianceEngine::Kompli::PlanBenchmark benchmark;
    benchmark.file = "bench.json";
    benchmark.version = {"1", "0", "0"};
    benchmark.versionConstraint = "^1.0.0";
    benchmark.rules["1.1.1.1"] = ComplianceEngine::Kompli::PlanRuleMode(ToggleMode::Audit);
    plan.benchmarks.push_back(benchmark);

    auto error = ValidatePlanForRun(plan, {document}, MakeDistribution());
    ASSERT_TRUE(error.HasValue());
    EXPECT_NE(error.Value().message.find("Missing mandatory parameter 'mountPoint'"), std::string::npos);
}

TEST(ValidatePlanForRunTest, GatesContentVersionBeforeEvaluatingRules)
{
    ComplianceEngine::Kompli::Plan plan;
    ComplianceEngine::Kompli::PlanBenchmark benchmark;
    benchmark.file = "bench.json";
    benchmark.version = {"1", "0", "0"};
    benchmark.versionConstraint = "^1.0.0";
    benchmark.rules["1.1.1.1"] = ComplianceEngine::Kompli::PlanRuleMode(ToggleMode::Audit);
    plan.benchmarks.push_back(benchmark);

    auto checkVersion = [&](const std::string& version) {
        std::string json = kBenchmarkJson;
        const std::string oldVersion = "\"version\": \"1.0.0\"";
        const auto position = json.find(oldVersion);
        EXPECT_NE(position, std::string::npos);
        json.replace(position, oldVersion.size(), "\"version\": \"" + version + "\"");
        if (version == "1.1.0")
        {
            const auto endOfRules = json.find("\n    ]", json.find("\"rules\""));
            EXPECT_NE(endOfRules, std::string::npos);
            json.insert(endOfRules, R"(,
      {"ruleName":"TestingProceduresPass","title":"New optional rule","id":"1.1.1.3",
       "ruleId":"rule-3","tags":[],"metadata":{"description":"","rationale":"","fixtext":"","references":"","severity":"Low"},
       "payload":{"audit":{},"remediate":{},"parameters":{}}})");
        }
        return ValidatePlanForRun(plan, {ParseDocument(json)}, MakeDistribution()).HasValue();
    };

    EXPECT_FALSE(checkVersion("1.0.0"));
    EXPECT_FALSE(checkVersion("1.0.1"));
    EXPECT_FALSE(checkVersion("1.1.0"));
    EXPECT_TRUE(checkVersion("2.0.0"));
    EXPECT_TRUE(checkVersion("0.9.0"));
    EXPECT_FALSE(checkVersion("1.0.184467440737095516160"));
    EXPECT_FALSE(checkVersion("1.184467440737095516160.0"));

    plan.benchmarks[0].versionConstraint = "~1.0.0";
    EXPECT_FALSE(checkVersion("1.0.1"));
    EXPECT_TRUE(checkVersion("1.1.0"));

    plan.benchmarks[0].versionConstraint = "1.0.0";
    EXPECT_FALSE(checkVersion("1.0.0"));
    EXPECT_TRUE(checkVersion("1.0.1"));

    plan.benchmarks[0].version = {};
    plan.benchmarks[0].versionConstraint.clear();
    EXPECT_TRUE(checkVersion("1.0.0"));
}

TEST(CheckUniqueBenchmarkIdentitiesTest, AcceptsDistinctIdentities)
{
    const std::vector<std::pair<std::string, ComplianceEngine::BenchmarkInfo>> benchmarks = {
        {"cis_ubuntu24.04.benchmark.json", MakeInfo("cis", "ubuntu", "24.04", "v1.0.0")},
        {"stig_ubuntu24.04.benchmark.json", MakeInfo("stig", "ubuntu", "24.04", "v1.0.0")},
    };

    auto result = ComplianceEngine::Kompli::CheckUniqueBenchmarkIdentities(benchmarks);
    EXPECT_FALSE(result.HasValue());
}

TEST(CheckUniqueBenchmarkIdentitiesTest, AcceptsDistinctIdentitiesWithDelimiterCharacters)
{
    const std::vector<std::pair<std::string, ComplianceEngine::BenchmarkInfo>> benchmarks = {
        {"first.benchmark.json", MakeInfo("custom/ubuntu", "ubuntu", "24.04", "1.0.0")},
        {"second.benchmark.json", MakeInfo("custom", "ubuntu", "ubuntu/24.04", "1.0.0")},
    };
    ASSERT_EQ(std::to_string(benchmarks[0].second), std::to_string(benchmarks[1].second));

    auto result = ComplianceEngine::Kompli::CheckUniqueBenchmarkIdentities(benchmarks);
    EXPECT_FALSE(result.HasValue());
}

TEST(CheckUniqueBenchmarkIdentitiesTest, RejectsDuplicateIdentity)
{
    const std::vector<std::pair<std::string, ComplianceEngine::BenchmarkInfo>> benchmarks = {
        {"cis_ubuntu24.04.benchmark.json", MakeInfo("cis", "ubuntu", "24.04", "v1.0.0")},
        {"cis_ubuntu24.04_copy.benchmark.json", MakeInfo("cis", "ubuntu", "24.04", "v1.0.0")},
    };

    auto result = ComplianceEngine::Kompli::CheckUniqueBenchmarkIdentities(benchmarks);
    ASSERT_TRUE(result.HasValue());
    EXPECT_NE(result.Value().message.find("cis_ubuntu24.04.benchmark.json"), std::string::npos);
    EXPECT_NE(result.Value().message.find("cis_ubuntu24.04_copy.benchmark.json"), std::string::npos);
}

TEST(CheckUniqueBenchmarkIdentitiesTest, DifferingBenchmarkVersionIsNotADuplicate)
{
    const std::vector<std::pair<std::string, ComplianceEngine::BenchmarkInfo>> benchmarks = {
        {"cis_ubuntu24.04_v1.benchmark.json", MakeInfo("cis", "ubuntu", "24.04", "v1.0.0")},
        {"cis_ubuntu24.04_v2.benchmark.json", MakeInfo("cis", "ubuntu", "24.04", "v2.0.0")},
    };

    auto result = ComplianceEngine::Kompli::CheckUniqueBenchmarkIdentities(benchmarks);
    EXPECT_FALSE(result.HasValue());
}

TEST(CheckUniqueBenchmarkIdentitiesTest, RejectsOptionalBenchmarkVersionPrefixDifference)
{
    const std::vector<std::pair<std::string, ComplianceEngine::BenchmarkInfo>> benchmarks = {
        {"first.json", MakeInfo("cis", "ubuntu", "22.04", "v2.0.0")}, {"second.json", MakeInfo("cis", "ubuntu", "22.04", "2.0.0")}};

    EXPECT_TRUE(ComplianceEngine::Kompli::CheckUniqueBenchmarkIdentities(benchmarks).HasValue());
}
