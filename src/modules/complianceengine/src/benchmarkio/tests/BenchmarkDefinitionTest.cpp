// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// Unit tests for the benchmark-definition JSON parser
// (ComplianceEngine::BenchmarkDefinition). The parser reads the in-repo
// data/definitions/*.benchmark.json documents produced by the Compliance
// Augmentation Engine and yields a BenchmarkDocument: a file-level
// CISBenchmarkInfo prefix (framework/distribution/distributionVersion/
// benchmarkVersion) plus the BenchmarkIO::Resource entries the kompli CLI's
// main loop consumes. These tests cover the happy path, the field mapping,
// and a broad set of malformed / adversarial inputs.

#include "BenchmarkDefinition.hpp"

#include <gtest/gtest.h>
#include <string>
#include <vector>

using ComplianceEngine::Result;
using ComplianceEngine::BenchmarkDefinition::BenchmarkDocument;
using ComplianceEngine::BenchmarkDefinition::ParseString;
using ComplianceEngine::BenchmarkDefinition::Resource;

namespace
{
// A single, valid rule matching what the augmentation engine emits. The
// payloadKey is now just the opaque remainder (see docs/payload-key-format.md);
// the file-level framework/distribution/distributionVersion/benchmarkVersion
// prefix is hoisted into metadata (see MakeDoc below).
const char* const kValidRule = R"({
    "section": "1.1.1.1",
    "ruleId": "f2d04986-59ab-6ceb-99da-f074b6ea0073",
    "ruleName": "EnsureCramfsKernelModuleIsNotAvailable",
    "title": "1.1.1.1 Ensure cramfs kernel module is not available",
    "payloadKey": "1/1/1/1",
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

// A second, distinct valid rule (different section/payloadKey/ruleId) for tests
// that need more than one rule without tripping the duplicate-payloadKey check.
const char* const kValidRule2 = R"({
    "section": "1.1.1.2",
    "ruleId": "a3e15c7a-2b3d-4e1f-9c8b-6d5a4f3e2d1c",
    "ruleName": "EnsureFreevxfsKernelModuleIsNotAvailable",
    "title": "1.1.1.2 Ensure freevxfs kernel module is not available",
    "payloadKey": "1/1/1/2",
    "tags": ["level:l1"],
    "metadata": {
        "description": "d",
        "rationale": "r",
        "fixtext": "f",
        "severity": "Warning",
        "references": "x"
    },
    "payload": {
        "audit": {"KernelModuleUnavailable": {"moduleName": "freevxfs"}},
        "parameters": {}
    }
})";

// Wraps a `spec.rules` array body into a complete benchmark-definition document,
// with a valid file-level metadata prefix (labels + annotations).
std::string MakeDoc(const std::string& rulesArray)
{
    return std::string(R"({"apiVersion":"v1","kind":"BenchmarkDefinition",)"
                       R"("metadata":{"name":"cis_ubuntu_22.04_2.0.0",)"
                       R"("labels":{"framework":"cis","distribution":"ubuntu","distributionVersion":"22.04"},)"
                       R"("annotations":{"benchmarkVersion":"v2.0.0"}},)"
                       R"("spec":{"rules":)") +
           rulesArray + "}}";
}

// Same as MakeDoc, but lets the caller substitute the whole metadata object -
// used by the malformed-document tests that need to omit or corrupt just one
// piece of it.
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
    const BenchmarkDocument& doc = result.Value();
    EXPECT_EQ(doc.name, "cis_ubuntu_22.04_2.0.0");
    EXPECT_EQ(doc.benchmarkInfo.version, "22.04");
    EXPECT_EQ(doc.benchmarkInfo.benchmarkVersion, "v2.0.0");
    ASSERT_EQ(doc.resources.size(), 1u);

    const Resource& res = doc.resources[0];
    EXPECT_EQ(res.resourceID, "1.1.1.1 Ensure cramfs kernel module is not available");
    EXPECT_EQ(res.ruleId, "f2d04986-59ab-6ceb-99da-f074b6ea0073");
    EXPECT_EQ(res.ruleName, "EnsureCramfsKernelModuleIsNotAvailable");
    EXPECT_TRUE(res.hasInitAudit);
    EXPECT_FALSE(res.payload.HasValue());
    EXPECT_EQ(res.section, "1.1.1.1");
    // payloadKey is now stored verbatim (the opaque remainder, no path parsing).
    EXPECT_EQ(res.payloadKey, "1/1/1/1");
    // The procedure is the rule's payload serialized as plain JSON.
    EXPECT_NE(res.procedure.find("KernelModuleUnavailable"), std::string::npos);
    EXPECT_NE(res.procedure.find("cramfs"), std::string::npos);
}

TEST(BenchmarkDefinitionParserTest, ParsesMultipleRulesInOrder)
{
    const std::string rules = std::string("[") + kValidRule + "," + kValidRule2 + "]";
    auto result = ParseString(MakeDoc(rules), nullptr);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    ASSERT_EQ(result.Value().resources.size(), 2u);
    EXPECT_EQ(result.Value().resources[0].section, "1.1.1.1");
    EXPECT_EQ(result.Value().resources[1].section, "1.1.1.2");
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
        "section": "1.1.1.1",
        "ruleId": "f2d04986-59ab-6ceb-99da-f074b6ea0073",
        "ruleName": "EnsureCramfsKernelModuleIsNotAvailable",
        "title": "1.1.1.1 Ensure cramfs kernel module is not available",
        "payloadKey": "1/1/1/1",
        "unexpected": "ignored",
        "payload": {"audit": {"X": {}}, "parameters": {}}
    })";
    auto result = ParseString(MakeDoc(std::string("[") + ruleWithExtras + "]"), nullptr);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(result.Value().resources.size(), 1u);
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
    const std::string doc =
        std::string(R"({"kind":"BenchmarkDefinition","metadata":)") +
        R"({"name":"n","labels":{"framework":"cis","distribution":"ubuntu","distributionVersion":"22.04"},"annotations":{"benchmarkVersion":"v1.0.0"}},"spec":{"rules":[)" +
        kValidRule + "]}}";
    EXPECT_FALSE(ParseString(doc, nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsMissingMetadata)
{
    const std::string doc = std::string(R"({"apiVersion":"v1","kind":"BenchmarkDefinition","spec":{"rules":[)") + kValidRule + "]}}";
    EXPECT_FALSE(ParseString(doc, nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsMissingLabels)
{
    const std::string doc = MakeDocWithMetadata(R"({"name":"n","annotations":{"benchmarkVersion":"v1.0.0"}})", std::string("[") + kValidRule + "]");
    EXPECT_FALSE(ParseString(doc, nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsMissingFrameworkLabel)
{
    const std::string doc =
        MakeDocWithMetadata(R"({"name":"n","labels":{"distribution":"ubuntu","distributionVersion":"22.04"},"annotations":{"benchmarkVersion":"v1.0.0"}})",
            std::string("[") + kValidRule + "]");
    EXPECT_FALSE(ParseString(doc, nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsUnknownFrameworkLabel)
{
    const std::string doc =
        MakeDocWithMetadata(R"({"name":"n","labels":{"framework":"unknown","distribution":"ubuntu","distributionVersion":"22.04"},"annotations":{"benchmarkVersion":"v1.0.0"}})",
            std::string("[") + kValidRule + "]");
    EXPECT_FALSE(ParseString(doc, nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsMissingDistributionLabel)
{
    const std::string doc = MakeDocWithMetadata(R"({"name":"n","labels":{"framework":"cis","distributionVersion":"22.04"},"annotations":{"benchmarkVersion":"v1.0.0"}})",
        std::string("[") + kValidRule + "]");
    EXPECT_FALSE(ParseString(doc, nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsMissingDistributionVersionLabel)
{
    const std::string doc = MakeDocWithMetadata(R"({"name":"n","labels":{"framework":"cis","distribution":"ubuntu"},"annotations":{"benchmarkVersion":"v1.0.0"}})",
        std::string("[") + kValidRule + "]");
    EXPECT_FALSE(ParseString(doc, nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsMissingAnnotations)
{
    const std::string doc = MakeDocWithMetadata(R"({"name":"n","labels":{"framework":"cis","distribution":"ubuntu","distributionVersion":"22.04"}})",
        std::string("[") + kValidRule + "]");
    EXPECT_FALSE(ParseString(doc, nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsMissingBenchmarkVersionAnnotation)
{
    const std::string doc = MakeDocWithMetadata(R"({"name":"n","labels":{"framework":"cis","distribution":"ubuntu","distributionVersion":"22.04"},"annotations":{}})",
        std::string("[") + kValidRule + "]");
    EXPECT_FALSE(ParseString(doc, nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsBenchmarkVersionWithoutVPrefix)
{
    // New (non-MOF-sourced) definitions must use a 'v'-prefixed benchmark
    // version (see docs/payload-key-format.md §8); legacy MOF-sourced full
    // payload keys parsed via CISBenchmarkInfo::Parse are unaffected.
    const std::string doc =
        MakeDocWithMetadata(R"({"name":"n","labels":{"framework":"cis","distribution":"ubuntu","distributionVersion":"22.04"},"annotations":{"benchmarkVersion":"1.0.0"}})",
            std::string("[") + kValidRule + "]");
    EXPECT_FALSE(ParseString(doc, nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsMissingSpec)
{
    const std::string doc =
        std::string(R"({"apiVersion":"v1","kind":"BenchmarkDefinition","metadata":)") +
        R"({"name":"n","labels":{"framework":"cis","distribution":"ubuntu","distributionVersion":"22.04"},"annotations":{"benchmarkVersion":"v1.0.0"}}})";
    EXPECT_FALSE(ParseString(doc, nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsMissingRulesArray)
{
    const std::string doc =
        std::string(R"({"apiVersion":"v1","kind":"BenchmarkDefinition","metadata":)") +
        R"({"name":"n","labels":{"framework":"cis","distribution":"ubuntu","distributionVersion":"22.04"},"annotations":{"benchmarkVersion":"v1.0.0"}},"spec":{}})";
    EXPECT_FALSE(ParseString(doc, nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsRulesNotAnArray)
{
    const std::string doc =
        MakeDocWithMetadata(R"({"name":"n","labels":{"framework":"cis","distribution":"ubuntu","distributionVersion":"22.04"},"annotations":{"benchmarkVersion":"v1.0.0"}})",
            "{}");
    EXPECT_FALSE(ParseString(doc, nullptr).HasValue());
}

// ---------------------------------------------------------------------------
// Malformed rules
// ---------------------------------------------------------------------------

TEST(BenchmarkDefinitionParserTest, RejectsRuleMissingTitle)
{
    const char* const rule = R"({
        "section": "1.1.1.1",
        "ruleId": "f2d04986-59ab-6ceb-99da-f074b6ea0073",
        "ruleName": "R",
        "payloadKey": "1/1/1/1",
        "payload": {"audit": {}, "parameters": {}}
    })";
    EXPECT_FALSE(ParseString(MakeDoc(std::string("[") + rule + "]"), nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsRuleMissingRuleName)
{
    const char* const rule = R"({
        "section": "1.1.1.1",
        "ruleId": "f2d04986-59ab-6ceb-99da-f074b6ea0073",
        "title": "t",
        "payloadKey": "1/1/1/1",
        "payload": {"audit": {}, "parameters": {}}
    })";
    EXPECT_FALSE(ParseString(MakeDoc(std::string("[") + rule + "]"), nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsRuleWithEmptyStringField)
{
    const char* const rule = R"({
        "section": "1.1.1.1",
        "ruleId": "f2d04986-59ab-6ceb-99da-f074b6ea0073",
        "ruleName": "",
        "title": "t",
        "payloadKey": "1/1/1/1",
        "payload": {"audit": {}, "parameters": {}}
    })";
    EXPECT_FALSE(ParseString(MakeDoc(std::string("[") + rule + "]"), nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsRuleMissingPayload)
{
    const char* const rule = R"({
        "section": "1.1.1.1",
        "ruleId": "f2d04986-59ab-6ceb-99da-f074b6ea0073",
        "ruleName": "R",
        "title": "t",
        "payloadKey": "1/1/1/1"
    })";
    EXPECT_FALSE(ParseString(MakeDoc(std::string("[") + rule + "]"), nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsRulePayloadNotAnObject)
{
    const char* const rule = R"({
        "section": "1.1.1.1",
        "ruleId": "f2d04986-59ab-6ceb-99da-f074b6ea0073",
        "ruleName": "R",
        "title": "t",
        "payloadKey": "1/1/1/1",
        "payload": "not-an-object"
    })";
    EXPECT_FALSE(ParseString(MakeDoc(std::string("[") + rule + "]"), nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsRuleMissingPayloadKey)
{
    const char* const rule = R"({
        "section": "1.1.1.1",
        "ruleId": "f2d04986-59ab-6ceb-99da-f074b6ea0073",
        "ruleName": "R",
        "title": "t",
        "payload": {"audit": {}, "parameters": {}}
    })";
    EXPECT_FALSE(ParseString(MakeDoc(std::string("[") + rule + "]"), nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsRuleMissingSection)
{
    const char* const rule = R"({
        "ruleId": "f2d04986-59ab-6ceb-99da-f074b6ea0073",
        "ruleName": "R",
        "title": "t",
        "payloadKey": "1/1/1/1",
        "payload": {"audit": {}, "parameters": {}}
    })";
    EXPECT_FALSE(ParseString(MakeDoc(std::string("[") + rule + "]"), nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsDuplicatePayloadKey)
{
    // kompli's plan/run rule-reference model (docs/CLI.md,
    // docs/payload-key-format.md) requires a rule reference to be unambiguous
    // within one file; two rules parsed from the same payloadKey must be
    // rejected rather than silently kept as separate entries with an
    // ambiguous reference.
    const char* const ruleA = R"({
        "section": "1.1.1.1",
        "ruleId": "f2d04986-59ab-6ceb-99da-f074b6ea0073",
        "ruleName": "RuleA",
        "title": "Rule A",
        "payloadKey": "1/1/1/1",
        "payload": {"audit": {}, "parameters": {}}
    })";
    const char* const ruleB = R"({
        "section": "1.1.1.9",
        "ruleId": "6f5902ac-237024bd-d823-d6626c5f5d20",
        "ruleName": "RuleB",
        "title": "Rule B, accidental duplicate payloadKey",
        "payloadKey": "1/1/1/1",
        "payload": {"audit": {}, "parameters": {}}
    })";
    EXPECT_FALSE(ParseString(MakeDoc(std::string("[") + ruleA + "," + ruleB + "]"), nullptr).HasValue());
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
