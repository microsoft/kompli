// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// Unit tests for the benchmark-definition JSON parser
// (ComplianceEngine::BenchmarkDefinition). The parser reads the in-repo
// data/definitions/*.benchmark.json documents produced by the Compliance
// Augmentation Engine and yields the BenchmarkIO::Resource entries the kompli
// CLI's main loop consumes. These tests cover the happy path, the field mapping, and
// a broad set of malformed / adversarial inputs.

#include "BenchmarkDefinition.hpp"

#include <gtest/gtest.h>
#include <string>
#include <vector>

using ComplianceEngine::Result;
using ComplianceEngine::BenchmarkDefinition::ParseString;
using ComplianceEngine::BenchmarkDefinition::Resource;

namespace
{
// A single, valid rule matching what the augmentation engine emits.
const char* const kValidRule = R"({
    "section": "1.1.1.1",
    "ruleId": "f2d04986-59ab-6ceb-99da-f074b6ea0073",
    "ruleName": "EnsureCramfsKernelModuleIsNotAvailable",
    "title": "1.1.1.1 Ensure cramfs kernel module is not available",
    "payloadKey": "/cis/ubuntu/22.04/v2.0.0/1/1/1/1",
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
                       R"("metadata":{"name":"cis_ubuntu_22.04_2.0.0","labels":{"distribution":"ubuntu"}},)"
                       R"("spec":{"rules":)") +
           rulesArray + "}}";
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
    ASSERT_EQ(result.Value().size(), 1u);

    const Resource& res = result.Value()[0];
    EXPECT_EQ(res.resourceID, "1.1.1.1 Ensure cramfs kernel module is not available");
    EXPECT_EQ(res.ruleId, "f2d04986-59ab-6ceb-99da-f074b6ea0073");
    EXPECT_EQ(res.ruleName, "EnsureCramfsKernelModuleIsNotAvailable");
    EXPECT_TRUE(res.hasInitAudit);
    EXPECT_FALSE(res.payload.HasValue());
    // The '/'-separated payload-key section is normalized to dotted notation.
    EXPECT_EQ(res.benchmarkInfo.section, "1.1.1.1");
    // The procedure is the rule's payload serialized as plain JSON.
    EXPECT_NE(res.procedure.find("KernelModuleUnavailable"), std::string::npos);
    EXPECT_NE(res.procedure.find("cramfs"), std::string::npos);
}

TEST(BenchmarkDefinitionParserTest, ParsesMultipleRulesInOrder)
{
    const std::string rules = std::string("[") + kValidRule + "," + kValidRule + "]";
    auto result = ParseString(MakeDoc(rules), nullptr);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(result.Value().size(), 2u);
}

TEST(BenchmarkDefinitionParserTest, EmptyRulesArrayYieldsNoResources)
{
    auto result = ParseString(MakeDoc("[]"), nullptr);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_TRUE(result.Value().empty());
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
        "payloadKey": "/cis/ubuntu/22.04/v2.0.0/1/1/1/1",
        "unexpected": "ignored",
        "payload": {"audit": {"X": {}}, "parameters": {}}
    })";
    auto result = ParseString(MakeDoc(std::string("[") + ruleWithExtras + "]"), nullptr);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(result.Value().size(), 1u);
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
        "section": "1.1.1.1",
        "ruleId": "f2d04986-59ab-6ceb-99da-f074b6ea0073",
        "ruleName": "R",
        "payloadKey": "/cis/ubuntu/22.04/v2.0.0/1/1/1/1",
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
        "payloadKey": "/cis/ubuntu/22.04/v2.0.0/1/1/1/1",
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
        "payloadKey": "/cis/ubuntu/22.04/v2.0.0/1/1/1/1",
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
        "payloadKey": "/cis/ubuntu/22.04/v2.0.0/1/1/1/1"
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
        "payloadKey": "/cis/ubuntu/22.04/v2.0.0/1/1/1/1",
        "payload": "not-an-object"
    })";
    EXPECT_FALSE(ParseString(MakeDoc(std::string("[") + rule + "]"), nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsInvalidPayloadKey)
{
    const char* const rule = R"({
        "section": "1.1.1",
        "ruleId": "f2d04986-59ab-6ceb-99da-f074b6ea0073",
        "ruleName": "R",
        "title": "t",
        "payloadKey": "not-a-valid-key",
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
        "payloadKey": "/cis/ubuntu/22.04/v2.0.0/1/1/1/1",
        "payload": {"audit": {}, "parameters": {}}
    })";
    EXPECT_FALSE(ParseString(MakeDoc(std::string("[") + rule + "]"), nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsSectionPayloadKeyMismatch)
{
    // The explicit `section` ("9.9.9") disagrees with the section encoded in the
    // payloadKey ("1.1.1.1"); a corrupt or hand-edited definition must be
    // rejected rather than silently resolved to the payloadKey value.
    const char* const rule = R"({
        "section": "9.9.9",
        "ruleId": "f2d04986-59ab-6ceb-99da-f074b6ea0073",
        "ruleName": "R",
        "title": "t",
        "payloadKey": "/cis/ubuntu/22.04/v2.0.0/1/1/1/1",
        "payload": {"audit": {}, "parameters": {}}
    })";
    EXPECT_FALSE(ParseString(MakeDoc(std::string("[") + rule + "]"), nullptr).HasValue());
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
