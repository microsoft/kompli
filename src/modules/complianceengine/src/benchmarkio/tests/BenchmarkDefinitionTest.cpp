// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// Unit tests for the benchmark-definition JSON parser
// (ComplianceEngine::BenchmarkDefinition). The parser reads the in-repo
// data/definitions/*.benchmark.json documents produced by the Compliance
// Augmentation Engine and yields file-level identity plus the
// BenchmarkIO::Resource entries the kompli CLI consumes.

#include "BenchmarkDefinition.hpp"

#include <gtest/gtest.h>
#include <string>
#include <vector>

using ComplianceEngine::Result;
using ComplianceEngine::BenchmarkDefinition::ParseString;
using ComplianceEngine::BenchmarkDefinition::Resource;

namespace
{
const char* const kValidRule = R"({
    "id": "1.1.1.1",
    "ruleId": "2b568469-ea61-c184-66ba-db6720414ddd",
    "ruleName": "EnsureCramfsKernelModuleIsNotAvailable",
    "title": "1.1.1.1 Ensure cramfs kernel module is not available",
    "tags": ["level:l1"],
    "metadata": {
        "description": "d",
        "rationale": "r",
        "fixtext": "f",
        "severity": "Warning",
        "references": "x"
    },
    "payload": {
        "audit": {"KernelModuleUnavailable": {"moduleName": "cramfs"}},
        "parameters": {}
    }
})";

// Wraps a `spec.rules` array body into a complete benchmark-definition document.
std::string MakeDoc(const std::string& rulesArray)
{
    return std::string(R"({"apiVersion":"v1","kind":"BenchmarkDefinition",)"
                       R"("metadata":{"name":"cis_ubuntu_22.04_2.0.0",)"
                       R"("labels":{"framework":"cis","distribution":"ubuntu","distributionVersion":"22.04"},)"
                       R"("annotations":{"benchmarkVersion":"v2.0.0"}},)"
                       R"("spec":{"rules":)") +
           rulesArray + "}}";
}

std::string MakeDocWithMetadata(const std::string& metadataObject, const std::string& rulesArray)
{
    return std::string(R"({"apiVersion":"v1","kind":"BenchmarkDefinition","metadata":)") + metadataObject + R"(,"spec":{"rules":)" + rulesArray + "}}";
}

std::string OneRuleDoc()
{
    return MakeDoc(std::string("[") + kValidRule + "]");
}
} // namespace

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

TEST(BenchmarkDefinitionParserTest, ParsesValidDocument)
{
    auto result = ParseString(OneRuleDoc(), nullptr);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(result.Value().name, "cis_ubuntu_22.04_2.0.0");
    EXPECT_EQ(result.Value().benchmarkInfo.framework, "cis");
    EXPECT_EQ(result.Value().benchmarkInfo.distribution, ComplianceEngine::LinuxDistribution::Ubuntu);
    EXPECT_EQ(result.Value().benchmarkInfo.version, "22.04");
    EXPECT_EQ(result.Value().benchmarkInfo.benchmarkVersion, "v2.0.0");
    ASSERT_EQ(result.Value().resources.size(), 1u);

    const Resource& res = result.Value().resources[0];
    EXPECT_EQ(res.resourceID, "1.1.1.1 Ensure cramfs kernel module is not available");
    EXPECT_EQ(res.id, "1.1.1.1");
    EXPECT_EQ(res.ruleId, "2b568469-ea61-c184-66ba-db6720414ddd");
    EXPECT_EQ(res.ruleName, "EnsureCramfsKernelModuleIsNotAvailable");
    EXPECT_TRUE(res.hasInitAudit);
    EXPECT_FALSE(res.payload.HasValue());
    // The procedure is the rule's payload serialized as plain JSON.
    EXPECT_NE(res.procedure.find("KernelModuleUnavailable"), std::string::npos);
    EXPECT_NE(res.procedure.find("cramfs"), std::string::npos);
}

TEST(BenchmarkDefinitionParserTest, ParsesMultipleRulesInOrder)
{
    const char* const secondRule =
        R"({"id":"1.1.1.2","ruleId":"second-rule","ruleName":"SecondRule","title":"1.1.1.2 Second rule","payload":{"audit":{},"parameters":{}}})";
    const std::string rules = std::string("[") + kValidRule + "," + secondRule + "]";
    auto result = ParseString(MakeDoc(rules), nullptr);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    ASSERT_EQ(result.Value().resources.size(), 2u);
    EXPECT_EQ(result.Value().resources[0].id, "1.1.1.1");
    EXPECT_EQ(result.Value().resources[1].id, "1.1.1.2");
}

TEST(BenchmarkDefinitionParserTest, EmptyRulesArrayYieldsNoResources)
{
    auto result = ParseString(MakeDoc("[]"), nullptr);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_TRUE(result.Value().resources.empty());
}

TEST(BenchmarkDefinitionParserTest, IgnoresUnknownFields)
{
    // The definition schema allows additional properties; extra keys must not
    // cause a rejection.
    const char* const ruleWithExtras = R"({
        "id": "1.1.1.1",
        "ruleId": "rule-id",
        "ruleName": "EnsureCramfsKernelModuleIsNotAvailable",
        "title": "1.1.1.1 Ensure cramfs kernel module is not available",
        "unexpected": "ignored",
        "payload": {"audit": {"X": {}}, "parameters": {}}
    })";
    auto result = ParseString(MakeDoc(std::string("[") + ruleWithExtras + "]"), nullptr);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(result.Value().resources.size(), 1u);
}

TEST(BenchmarkDefinitionParserTest, ParsesLegacyRuleIdentity)
{
    const char* const legacyRule = R"({
        "section": "1.1.1.1",
        "payloadKey": "/cis/ubuntu/22.04/v2.0.0/1/1/1/1",
        "ruleId": "2b568469-ea61-c184-66ba-db6720414ddd",
        "ruleName": "EnsureCramfsKernelModuleIsNotAvailable",
        "title": "1.1.1.1 Ensure cramfs kernel module is not available",
        "payload": {"audit": {"KernelModuleUnavailable": {"moduleName": "cramfs"}}, "parameters": {}}
    })";
    auto result = ParseString(MakeDoc(std::string("[") + legacyRule + "]"), nullptr);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    ASSERT_EQ(result.Value().resources.size(), 1u);
    EXPECT_EQ(result.Value().resources[0].id, "1.1.1.1");
    EXPECT_EQ(result.Value().resources[0].ruleId, "2b568469-ea61-c184-66ba-db6720414ddd");
}

// ---------------------------------------------------------------------------
// Malformed documents
// ---------------------------------------------------------------------------

TEST(BenchmarkDefinitionParserTest, RejectsInvalidJson)
{
    EXPECT_FALSE(ParseString("{ not json", nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsNonObjectRoot)
{
    EXPECT_FALSE(ParseString("[]", nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsWrongKind)
{
    std::string doc = OneRuleDoc();
    const std::string::size_type pos = doc.find("BenchmarkDefinition");
    ASSERT_NE(pos, std::string::npos);
    doc.replace(pos, std::string("BenchmarkDefinition").size(), "SomethingElse");
    EXPECT_FALSE(ParseString(doc, nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsMissingApiVersion)
{
    const std::string doc = std::string(R"({"kind":"BenchmarkDefinition","metadata":{"name":"n"},"spec":{"rules":[)") + kValidRule + "]}}";
    EXPECT_FALSE(ParseString(doc, nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsMissingMetadata)
{
    const std::string doc = std::string(R"({"apiVersion":"v1","kind":"BenchmarkDefinition","spec":{"rules":[)") + kValidRule + "]}}";
    EXPECT_FALSE(ParseString(doc, nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsMissingLabels)
{
    const std::string metadata = R"({"name":"n","annotations":{"benchmarkVersion":"v1.0.0"}})";
    EXPECT_FALSE(ParseString(MakeDocWithMetadata(metadata, std::string("[") + kValidRule + "]"), nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsMissingAnnotations)
{
    const std::string metadata = R"({"name":"n","labels":{"framework":"cis","distribution":"ubuntu","distributionVersion":"22.04"}})";
    EXPECT_FALSE(ParseString(MakeDocWithMetadata(metadata, std::string("[") + kValidRule + "]"), nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, AcceptsArbitraryFrameworkAndBenchmarkVersion)
{
    const std::string metadata =
        R"({"name":"n","labels":{"framework":"custom","distribution":"ubuntu","distributionVersion":"22.04"},"annotations":{"benchmarkVersion":"1.0.0"}})";
    auto result = ParseString(MakeDocWithMetadata(metadata, std::string("[") + kValidRule + "]"), nullptr);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(result.Value().benchmarkInfo.framework, "custom");
    EXPECT_EQ(result.Value().benchmarkInfo.benchmarkVersion, "1.0.0");
}

TEST(BenchmarkDefinitionParserTest, RejectsEmptyFramework)
{
    const std::string metadata =
        R"({"name":"n","labels":{"framework":"","distribution":"ubuntu","distributionVersion":"22.04"},"annotations":{"benchmarkVersion":"v1.0.0"}})";
    EXPECT_FALSE(ParseString(MakeDocWithMetadata(metadata, std::string("[") + kValidRule + "]"), nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsMissingHoistedIdentity)
{
    const std::string metadata = R"({"name":"n","labels":{"framework":"cis","distribution":"ubuntu"},"annotations":{"benchmarkVersion":"v1.0.0"}})";
    EXPECT_FALSE(ParseString(MakeDocWithMetadata(metadata, std::string("[") + kValidRule + "]"), nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsMissingSpec)
{
    const std::string doc = R"({"apiVersion":"v1","kind":"BenchmarkDefinition","metadata":{"name":"n"}})";
    EXPECT_FALSE(ParseString(doc, nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsMissingRulesArray)
{
    const std::string doc = R"({"apiVersion":"v1","kind":"BenchmarkDefinition","metadata":{"name":"n"},"spec":{}})";
    EXPECT_FALSE(ParseString(doc, nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsRulesNotAnArray)
{
    const std::string doc = R"({"apiVersion":"v1","kind":"BenchmarkDefinition","metadata":{"name":"n"},"spec":{"rules":{}}})";
    EXPECT_FALSE(ParseString(doc, nullptr).HasValue());
}

// ---------------------------------------------------------------------------
// Malformed rules
// ---------------------------------------------------------------------------

TEST(BenchmarkDefinitionParserTest, RejectsRuleMissingTitle)
{
    const char* const rule = R"({
        "id": "1.1.1.1",
        "ruleId": "rule-id",
        "ruleName": "R",
        "payload": {"audit": {}, "parameters": {}}
    })";
    EXPECT_FALSE(ParseString(MakeDoc(std::string("[") + rule + "]"), nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsRuleMissingRuleName)
{
    const char* const rule = R"({
        "id": "1.1.1.1",
        "ruleId": "rule-id",
        "title": "t",
        "payload": {"audit": {}, "parameters": {}}
    })";
    EXPECT_FALSE(ParseString(MakeDoc(std::string("[") + rule + "]"), nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsRuleWithEmptyStringField)
{
    const char* const rule = R"({
        "id": "1.1.1.1",
        "ruleId": "rule-id",
        "ruleName": "",
        "title": "t",
        "payload": {"audit": {}, "parameters": {}}
    })";
    EXPECT_FALSE(ParseString(MakeDoc(std::string("[") + rule + "]"), nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsRuleMissingPayload)
{
    const char* const rule = R"({
        "id": "1.1.1.1",
        "ruleId": "rule-id",
        "ruleName": "R",
        "title": "t"
    })";
    EXPECT_FALSE(ParseString(MakeDoc(std::string("[") + rule + "]"), nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsRulePayloadNotAnObject)
{
    const char* const rule = R"({
        "id": "1.1.1.1",
        "ruleId": "rule-id",
        "ruleName": "R",
        "title": "t",
        "payload": "not-an-object"
    })";
    EXPECT_FALSE(ParseString(MakeDoc(std::string("[") + rule + "]"), nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsRuleMissingId)
{
    const char* const rule = R"({
        "ruleName": "R",
        "title": "t",
        "ruleId": "rule-id",
        "payload": {"audit": {}, "parameters": {}}
    })";
    EXPECT_FALSE(ParseString(MakeDoc(std::string("[") + rule + "]"), nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsRuleWithEmptyId)
{
    const char* const rule = R"({
        "id": "",
        "ruleId": "rule-id",
        "ruleName": "R",
        "title": "t",
        "payload": {"audit": {}, "parameters": {}}
    })";
    EXPECT_FALSE(ParseString(MakeDoc(std::string("[") + rule + "]"), nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsRuleMissingRuleId)
{
    const char* const rule = R"({
        "id": "1.1.1.1",
        "ruleName": "R",
        "title": "t",
        "payload": {"audit": {}, "parameters": {}}
    })";
    EXPECT_FALSE(ParseString(MakeDoc(std::string("[") + rule + "]"), nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsRuleWithMixedIdentityShapes)
{
    const char* const rule = R"({
        "id": "1.1.1.1",
        "section": "1.1.1.1",
        "payloadKey": "/cis/ubuntu/22.04/v2.0.0/1/1/1/1",
        "ruleId": "rule-id",
        "ruleName": "R",
        "title": "t",
        "payload": {"audit": {}, "parameters": {}}
    })";
    EXPECT_FALSE(ParseString(MakeDoc(std::string("[") + rule + "]"), nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsIncompleteLegacyIdentity)
{
    const char* const rule = R"({
        "section": "1.1.1.1",
        "ruleId": "rule-id",
        "ruleName": "R",
        "title": "t",
        "payload": {"audit": {}, "parameters": {}}
    })";
    EXPECT_FALSE(ParseString(MakeDoc(std::string("[") + rule + "]"), nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsEmptyLegacyIdentity)
{
    const char* const rule = R"({
        "section": "",
        "payloadKey": "/cis/ubuntu/22.04/v2.0.0/1/1/1/1",
        "ruleId": "rule-id",
        "ruleName": "R",
        "title": "t",
        "payload": {"audit": {}, "parameters": {}}
    })";
    EXPECT_FALSE(ParseString(MakeDoc(std::string("[") + rule + "]"), nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsLegacySectionPayloadKeyMismatch)
{
    const char* const rule = R"({
        "section": "1.1.1.2",
        "payloadKey": "/cis/ubuntu/22.04/v2.0.0/1/1/1/1",
        "ruleId": "rule-id",
        "ruleName": "R",
        "title": "t",
        "payload": {"audit": {}, "parameters": {}}
    })";
    EXPECT_FALSE(ParseString(MakeDoc(std::string("[") + rule + "]"), nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsDuplicateIds)
{
    const std::string rules = std::string("[") + kValidRule + "," + kValidRule + "]";
    EXPECT_FALSE(ParseString(MakeDoc(rules), nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsEmbeddedNulByte)
{
    // A NUL would otherwise truncate the NUL-terminated JSON parse and hide
    // everything after it; the parser must fail closed instead of parsing a
    // prefix. Splice a NUL into the middle of an otherwise-valid document.
    std::string doc = OneRuleDoc();
    doc.insert(doc.size() / 2, std::string(1, '\0'));
    EXPECT_FALSE(ParseString(doc, nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsLeadingNulByte)
{
    std::string doc = std::string(1, '\0') + OneRuleDoc();
    EXPECT_FALSE(ParseString(doc, nullptr).HasValue());
}
