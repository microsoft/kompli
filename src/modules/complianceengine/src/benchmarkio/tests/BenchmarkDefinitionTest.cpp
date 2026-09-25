// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// Unit tests for the benchmark-definition JSON parser
// (ComplianceEngine::BenchmarkDefinition). The parser reads the in-repo
// data/definitions/*.benchmark.json documents produced by the Compliance
// Augmentation Engine and yields a BenchmarkDocument: a file-level
// BenchmarkInfo prefix (framework/distribution/distributionVersion/
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
// A single, valid rule matching what the definitions generator emits. The
// id is the human-facing framework identifier; ruleId is the stable
// benchmark-agnostic identifier retained for external correlation. The
// file-level framework/distribution/distributionVersion/benchmarkVersion
// prefix is hoisted into metadata (see MakeDoc below).
const char* const kValidRule = R"({
    "ruleName": "EnsureCramfsKernelModuleIsNotAvailable",
    "title": "1.1.1.1 Ensure cramfs kernel module is not available",
    "id": "1.1.1.1",
    "ruleId": "2b568469-ea61-c184-66ba-db6720414ddd",
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

// A second, distinct valid rule (different id) for tests
// that need more than one rule without tripping the duplicate-id check.
const char* const kValidRule2 = R"({
    "ruleName": "EnsureFreevxfsKernelModuleIsNotAvailable",
    "title": "1.1.1.2 Ensure freevxfs kernel module is not available",
    "id": "1.1.1.2",
    "ruleId": "9fd6f537-1234-4e42-a456-426614174000",
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
    EXPECT_EQ(res.ruleName, "EnsureCramfsKernelModuleIsNotAvailable");
    EXPECT_TRUE(res.hasInitAudit);
    EXPECT_FALSE(res.payload.HasValue());
    // id is stored verbatim (no path parsing), while ruleId preserves the
    // stable benchmark-agnostic identifier emitted by the producer.
    EXPECT_EQ(res.id, "1.1.1.1");
    EXPECT_EQ(res.ruleId, "2b568469-ea61-c184-66ba-db6720414ddd");
    // The procedure is the rule's payload serialized as plain JSON.
    EXPECT_NE(res.procedure.find("KernelModuleUnavailable"), std::string::npos);
    EXPECT_NE(res.procedure.find("cramfs"), std::string::npos);
    ASSERT_EQ(res.tags.size(), 1u);
    EXPECT_EQ(res.tags[0], "level:l1");
    EXPECT_EQ(res.metadata.description, "d");
    EXPECT_EQ(res.metadata.rationale, "r");
    EXPECT_EQ(res.metadata.fixtext, "f");
    EXPECT_EQ(res.metadata.severity, "Warning");
    EXPECT_EQ(res.metadata.references, "x");
}

TEST(BenchmarkDefinitionParserTest, ParsesMultipleRulesInOrder)
{
    const std::string rules = std::string("[") + kValidRule + "," + kValidRule2 + "]";
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
        "ruleName": "EnsureCramfsKernelModuleIsNotAvailable",
        "title": "1.1.1.1 Ensure cramfs kernel module is not available",
        "id": "1.1.1.1",
        "ruleId": "rule-id",
        "unexpected": "ignored",
        "tags": [],
        "metadata": {"description": "d", "rationale": "r", "fixtext": "f", "severity": "Warning", "references": "x"},
        "payload": {"audit": {"X": {}}, "parameters": {}}
    })";
    auto result = ParseString(MakeDoc(std::string("[") + ruleWithExtras + "]"), nullptr);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(result.Value().resources.size(), 1u);
}

TEST(BenchmarkDefinitionParserTest, ParsesLegacyRuleIdentity)
{
    const char* const legacyRule = R"({
        "ruleName": "EnsureCramfsKernelModuleIsNotAvailable",
        "title": "1.1.1.1 Ensure cramfs kernel module is not available",
        "section": "1.1.1.1",
        "payloadKey": "/cis/ubuntu/22.04/v2.0.0/1/1/1/1",
        "ruleId": "2b568469-ea61-c184-66ba-db6720414ddd",
        "tags": ["level:l1"],
        "metadata": {"description": "d", "rationale": "r", "fixtext": "f", "severity": "Warning", "references": "x"},
        "payload": {"audit": {"KernelModuleUnavailable": {"moduleName": "cramfs"}}, "parameters": {}}
    })";
    auto result = ParseString(MakeDoc(std::string("[") + legacyRule + "]"), nullptr);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    ASSERT_EQ(result.Value().resources.size(), 1u);
    EXPECT_EQ(result.Value().resources[0].id, "1.1.1.1");
    EXPECT_EQ(result.Value().resources[0].ruleId, "2b568469-ea61-c184-66ba-db6720414ddd");
}

// ---------------------------------------------------------------------------
// parameterMetadata (docs/CLI.md "Parametrization")
// ---------------------------------------------------------------------------

TEST(BenchmarkDefinitionParserTest, RuleWithNoParameterMetadataYieldsEmptyMap)
{
    auto result = ParseString(OneRuleDoc(), nullptr);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_TRUE(result.Value().resources[0].parameterMetadata.empty());
}

TEST(BenchmarkDefinitionParserTest, ParsesParameterMetadataFields)
{
    const char* const ruleWithParams = R"({
        "ruleName": "EnsureMountPoint",
        "title": "1.1.2.1.1 Ensure mount point",
        "id": "1.1.2.1.1",
        "ruleId": "rule-id",
        "tags": [],
        "metadata": {"description": "d", "rationale": "r", "fixtext": "f", "severity": "Warning", "references": "x"},
        "payload": {"audit": {"X": {}}, "parameters": {"mountPoint": "/tmp"}},
        "parameterMetadata": {
            "mountPoint": {
                "type": "string",
                "default": "/tmp",
                "displayName": "Mount Point",
                "validationRegex": "^/[a-zA-Z0-9/_.-]+$",
                "validationFailedMessage": "Must be an absolute path.",
                "mandatory": true
            }
        }
    })";
    auto result = ParseString(MakeDoc(std::string("[") + ruleWithParams + "]"), nullptr);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    ASSERT_EQ(result.Value().resources.size(), 1u);
    const auto& metadata = result.Value().resources[0].parameterMetadata;
    ASSERT_EQ(metadata.count("mountPoint"), 1u);
    const auto& mountPoint = metadata.at("mountPoint");
    EXPECT_EQ(mountPoint.type, "string");
    EXPECT_EQ(mountPoint.defaultValue, "/tmp");
    ASSERT_TRUE(mountPoint.displayName.HasValue());
    EXPECT_EQ(mountPoint.displayName.Value(), "Mount Point");
    ASSERT_TRUE(mountPoint.validationRegex.HasValue());
    EXPECT_EQ(mountPoint.validationRegex.Value(), "^/[a-zA-Z0-9/_.-]+$");
    ASSERT_TRUE(mountPoint.validationFailedMessage.HasValue());
    EXPECT_EQ(mountPoint.validationFailedMessage.Value(), "Must be an absolute path.");
    EXPECT_TRUE(mountPoint.mandatory);
}

TEST(BenchmarkDefinitionParserTest, ParsesMultipleParameterMetadataEntries)
{
    const char* const ruleWithParams = R"({
        "ruleName": "EnsureMountPoint",
        "title": "1.1.2.1.2 Ensure mount point options",
        "id": "1.1.2.1.2",
        "ruleId": "rule-id",
        "tags": [],
        "metadata": {"description": "d", "rationale": "r", "fixtext": "f", "severity": "Warning", "references": "x"},
        "payload": {"audit": {"X": {}}, "parameters": {"mountPoint": "/tmp", "requiredMountOptions": "nodev"}},
        "parameterMetadata": {
            "mountPoint": {"type": "string", "default": "/tmp"},
            "requiredMountOptions": {"type": "string", "default": "nodev"}
        }
    })";
    auto result = ParseString(MakeDoc(std::string("[") + ruleWithParams + "]"), nullptr);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(result.Value().resources[0].parameterMetadata.size(), 2u);
}

TEST(BenchmarkDefinitionParserTest, RejectsParameterMetadataNotAnObject)
{
    const char* const ruleWithParams = R"({
        "ruleName": "EnsureMountPoint",
        "title": "1.1.2.1.1 Ensure mount point",
        "id": "1.1.2.1.1",
        "ruleId": "rule-id",
        "tags": [],
        "metadata": {"description": "d", "rationale": "r", "fixtext": "f", "severity": "Warning", "references": "x"},
        "payload": {"audit": {"X": {}}, "parameters": {}},
        "parameterMetadata": "not-an-object"
    })";
    auto result = ParseString(MakeDoc(std::string("[") + ruleWithParams + "]"), nullptr);
    EXPECT_FALSE(result.HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsParameterMetadataMissingDefault)
{
    const char* const ruleWithParams = R"({
        "ruleName": "EnsureMountPoint",
        "title": "1.1.2.1.1 Ensure mount point",
        "id": "1.1.2.1.1",
        "ruleId": "rule-id",
        "tags": [],
        "metadata": {"description": "d", "rationale": "r", "fixtext": "f", "severity": "Warning", "references": "x"},
        "payload": {"audit": {"X": {}}, "parameters": {}},
        "parameterMetadata": {"mountPoint": {"type": "string"}}
    })";
    auto result = ParseString(MakeDoc(std::string("[") + ruleWithParams + "]"), nullptr);
    EXPECT_FALSE(result.HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsParameterMetadataEntryNotAnObject)
{
    const char* const ruleWithParams = R"({
        "ruleName": "EnsureMountPoint",
        "title": "1.1.2.1.1 Ensure mount point",
        "id": "1.1.2.1.1",
        "ruleId": "rule-id",
        "tags": [],
        "metadata": {"description": "d", "rationale": "r", "fixtext": "f", "severity": "Warning", "references": "x"},
        "payload": {"audit": {"X": {}}, "parameters": {}},
        "parameterMetadata": {"mountPoint": "not-an-object"}
    })";
    auto result = ParseString(MakeDoc(std::string("[") + ruleWithParams + "]"), nullptr);
    EXPECT_FALSE(result.HasValue());
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

TEST(BenchmarkDefinitionParserTest, RejectsUnsupportedApiVersion)
{
    std::string doc = OneRuleDoc();
    const std::string::size_type pos = doc.find(R"("apiVersion":"v1")");
    ASSERT_NE(pos, std::string::npos);
    doc.replace(pos, std::string(R"("apiVersion":"v1")").size(), R"("apiVersion":"v2")");
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

TEST(BenchmarkDefinitionParserTest, AcceptsArbitraryFrameworkLabel)
{
    const std::string doc =
        MakeDocWithMetadata(R"({"name":"n","labels":{"framework":"custom","distribution":"ubuntu","distributionVersion":"22.04"},"annotations":{"benchmarkVersion":"v1.0.0"}})",
            std::string("[") + kValidRule + "]");
    auto result = ParseString(doc, nullptr);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(result.Value().benchmarkInfo.framework, "custom");
}

TEST(BenchmarkDefinitionParserTest, RejectsEmptyFrameworkLabel)
{
    const std::string doc =
        MakeDocWithMetadata(R"({"name":"n","labels":{"framework":"","distribution":"ubuntu","distributionVersion":"22.04"},"annotations":{"benchmarkVersion":"v1.0.0"}})",
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

TEST(BenchmarkDefinitionParserTest, AcceptsBenchmarkVersionWithoutVPrefix)
{
    const std::string doc =
        MakeDocWithMetadata(R"({"name":"n","labels":{"framework":"cis","distribution":"ubuntu","distributionVersion":"22.04"},"annotations":{"benchmarkVersion":"1.0.0"}})",
            std::string("[") + kValidRule + "]");
    auto result = ParseString(doc, nullptr);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(result.Value().benchmarkInfo.benchmarkVersion, "1.0.0");
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
        "ruleName": "R",
        "id": "1.1.1.1",
        "ruleId": "rule-id",
        "payload": {"audit": {}, "parameters": {}}
    })";
    EXPECT_FALSE(ParseString(MakeDoc(std::string("[") + rule + "]"), nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsRuleMissingRuleName)
{
    const char* const rule = R"({
        "title": "t",
        "id": "1.1.1.1",
        "ruleId": "rule-id",
        "payload": {"audit": {}, "parameters": {}}
    })";
    EXPECT_FALSE(ParseString(MakeDoc(std::string("[") + rule + "]"), nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsRuleWithEmptyStringField)
{
    const char* const rule = R"({
        "ruleName": "",
        "title": "t",
        "id": "1.1.1.1",
        "ruleId": "rule-id",
        "payload": {"audit": {}, "parameters": {}}
    })";
    EXPECT_FALSE(ParseString(MakeDoc(std::string("[") + rule + "]"), nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsRuleMissingPayload)
{
    const char* const rule = R"({
        "ruleName": "R",
        "title": "t",
        "id": "1.1.1.1",
        "ruleId": "rule-id"
    })";
    EXPECT_FALSE(ParseString(MakeDoc(std::string("[") + rule + "]"), nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsRulePayloadNotAnObject)
{
    const char* const rule = R"({
        "ruleName": "R",
        "title": "t",
        "id": "1.1.1.1",
        "ruleId": "rule-id",
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

TEST(BenchmarkDefinitionParserTest, RejectsRuleWithMixedIdentityShapes)
{
    const char* const rule = R"({
        "ruleName": "R",
        "title": "t",
        "id": "1.1.1.1",
        "section": "1.1.1.1",
        "payloadKey": "/cis/ubuntu/22.04/v2.0.0/1/1/1/1",
        "ruleId": "rule-id",
        "tags": [],
        "metadata": {"description": "d", "rationale": "r", "fixtext": "f", "severity": "Warning", "references": "x"},
        "payload": {"audit": {}, "parameters": {}}
    })";
    EXPECT_FALSE(ParseString(MakeDoc(std::string("[") + rule + "]"), nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsIncompleteLegacyIdentity)
{
    const char* const rule = R"({
        "ruleName": "R",
        "title": "t",
        "section": "1.1.1.1",
        "ruleId": "rule-id",
        "tags": [],
        "metadata": {"description": "d", "rationale": "r", "fixtext": "f", "severity": "Warning", "references": "x"},
        "payload": {"audit": {}, "parameters": {}}
    })";
    EXPECT_FALSE(ParseString(MakeDoc(std::string("[") + rule + "]"), nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsLegacySectionPayloadKeyMismatch)
{
    const char* const rule = R"({
        "ruleName": "R",
        "title": "t",
        "section": "1.1.1.2",
        "payloadKey": "/cis/ubuntu/22.04/v2.0.0/1/1/1/1",
        "ruleId": "rule-id",
        "tags": [],
        "metadata": {"description": "d", "rationale": "r", "fixtext": "f", "severity": "Warning", "references": "x"},
        "payload": {"audit": {}, "parameters": {}}
    })";
    EXPECT_FALSE(ParseString(MakeDoc(std::string("[") + rule + "]"), nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsRuleMissingRuleId)
{
    const char* const rule = R"({
        "ruleName": "R",
        "title": "t",
        "id": "1.1.1.1",
        "payload": {"audit": {}, "parameters": {}}
    })";
    EXPECT_FALSE(ParseString(MakeDoc(std::string("[") + rule + "]"), nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsRuleMissingTags)
{
    const char* const rule = R"({
        "ruleName": "R",
        "title": "t",
        "id": "1.1.1.1",
        "ruleId": "rule-id",
        "metadata": {"description": "d", "rationale": "r", "fixtext": "f", "severity": "Warning", "references": "x"},
        "payload": {"audit": {}, "parameters": {}}
    })";
    EXPECT_FALSE(ParseString(MakeDoc(std::string("[") + rule + "]"), nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsRuleTagsNotAnArray)
{
    const char* const rule = R"({
        "ruleName": "R",
        "title": "t",
        "id": "1.1.1.1",
        "ruleId": "rule-id",
        "tags": "not-an-array",
        "metadata": {"description": "d", "rationale": "r", "fixtext": "f", "severity": "Warning", "references": "x"},
        "payload": {"audit": {}, "parameters": {}}
    })";
    EXPECT_FALSE(ParseString(MakeDoc(std::string("[") + rule + "]"), nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsRuleNonStringTagEntry)
{
    const char* const rule = R"({
        "ruleName": "R",
        "title": "t",
        "id": "1.1.1.1",
        "ruleId": "rule-id",
        "tags": ["level:l1", 1],
        "metadata": {"description": "d", "rationale": "r", "fixtext": "f", "severity": "Warning", "references": "x"},
        "payload": {"audit": {}, "parameters": {}}
    })";
    EXPECT_FALSE(ParseString(MakeDoc(std::string("[") + rule + "]"), nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsRuleMissingMetadata)
{
    const char* const rule = R"({
        "ruleName": "R",
        "title": "t",
        "id": "1.1.1.1",
        "ruleId": "rule-id",
        "tags": [],
        "payload": {"audit": {}, "parameters": {}}
    })";
    EXPECT_FALSE(ParseString(MakeDoc(std::string("[") + rule + "]"), nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsRuleMetadataMissingSeverity)
{
    const char* const rule = R"({
        "ruleName": "R",
        "title": "t",
        "id": "1.1.1.1",
        "ruleId": "rule-id",
        "tags": [],
        "metadata": {"description": "d", "rationale": "r", "fixtext": "f", "references": "x"},
        "payload": {"audit": {}, "parameters": {}}
    })";
    EXPECT_FALSE(ParseString(MakeDoc(std::string("[") + rule + "]"), nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, AcceptsEmptyDescriptiveMetadata)
{
    const char* const rule = R"({
        "ruleName": "R",
        "title": "t",
        "id": "1.1.1.1",
        "ruleId": "rule-id",
        "tags": [],
        "metadata": {"description": "", "rationale": "", "fixtext": "", "severity": "", "references": ""},
        "payload": {"audit": {}, "parameters": {}}
    })";
    auto result = ParseString(MakeDoc(std::string("[") + rule + "]"), nullptr);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    ASSERT_EQ(result.Value().resources.size(), 1u);
    EXPECT_TRUE(result.Value().resources[0].metadata.references.empty());
}

TEST(BenchmarkDefinitionParserTest, RejectsRuleMetadataNonStringReferences)
{
    const char* const rule = R"({
        "ruleName": "R",
        "title": "t",
        "id": "1.1.1.1",
        "ruleId": "rule-id",
        "tags": [],
        "metadata": {"description": "d", "rationale": "r", "fixtext": "f", "severity": "Warning", "references": []},
        "payload": {"audit": {}, "parameters": {}}
    })";
    EXPECT_FALSE(ParseString(MakeDoc(std::string("[") + rule + "]"), nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsDuplicateId)
{
    // kompli's plan/run rule-reference model (docs/cli.md) requires a rule
    // reference to be unambiguous
    // within one file; two rules parsed from the same id must be
    // rejected rather than silently kept as separate entries with an
    // ambiguous reference.
    const char* const ruleA = R"({
        "ruleName": "RuleA",
        "title": "Rule A",
        "id": "1.1.1.1",
        "ruleId": "rule-a",
        "tags": [],
        "metadata": {"description": "d", "rationale": "r", "fixtext": "f", "severity": "Warning", "references": "x"},
        "payload": {"audit": {}, "parameters": {}}
    })";
    const char* const ruleB = R"({
        "ruleName": "RuleB",
        "title": "Rule B, accidental duplicate id",
        "id": "1.1.1.1",
        "ruleId": "rule-b",
        "tags": [],
        "metadata": {"description": "d", "rationale": "r", "fixtext": "f", "severity": "Warning", "references": "x"},
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
