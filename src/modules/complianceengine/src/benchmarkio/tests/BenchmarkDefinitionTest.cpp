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
                       R"("spec":{"version":"1.0.0","rules":)") +
           rulesArray + "}}";
}

std::string MakeDocWithMetadata(const std::string& metadataObject, const std::string& rulesArray)
{
    return std::string(R"({"apiVersion":"v1","kind":"BenchmarkDefinition","metadata":)") + metadataObject + R"(,"spec":{"version":"1.0.0","rules":)" +
           rulesArray + "}}";
}

std::string OneRuleDoc()
{
    return MakeDoc(std::string("[") + kValidRule + "]");
}

void ReplaceOnce(std::string& value, const std::string& from, const std::string& to)
{
    const std::string::size_type position = value.find(from);
    ASSERT_NE(position, std::string::npos);
    value.replace(position, from.size(), to);
}
} // namespace

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

TEST(BenchmarkDefinitionParserTest, ParsesValidDocument)
{
    auto result = ParseString(OneRuleDoc(), nullptr);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    const auto& doc = result.Value();
    EXPECT_EQ(doc.name, "cis_ubuntu_22.04_2.0.0");
    EXPECT_EQ(doc.version.major, "1");
    EXPECT_EQ(doc.version.minor, "0");
    EXPECT_EQ(doc.version.patch, "0");
    EXPECT_EQ(doc.benchmarkInfo.framework, "cis");
    EXPECT_EQ(doc.benchmarkInfo.distribution, ComplianceEngine::LinuxDistribution::Ubuntu);
    EXPECT_EQ(doc.benchmarkInfo.version, "22.04");
    EXPECT_EQ(doc.benchmarkInfo.benchmarkVersion, "v2.0.0");
    ASSERT_EQ(doc.resources.size(), 1u);

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
    ASSERT_EQ(res.tags.size(), 1u);
    EXPECT_EQ(res.tags[0], "level:l1");
    ASSERT_TRUE(res.metadata.description.HasValue());
    EXPECT_EQ(res.metadata.description.Value(), "d");
    ASSERT_TRUE(res.metadata.rationale.HasValue());
    EXPECT_EQ(res.metadata.rationale.Value(), "r");
    ASSERT_TRUE(res.metadata.fixtext.HasValue());
    EXPECT_EQ(res.metadata.fixtext.Value(), "f");
    ASSERT_TRUE(res.metadata.severity.HasValue());
    EXPECT_EQ(res.metadata.severity.Value(), "Warning");
    ASSERT_TRUE(res.metadata.references.HasValue());
    EXPECT_EQ(res.metadata.references.Value(), "x");
}

TEST(BenchmarkDefinitionParserTest, ParsesMultipleRulesInOrder)
{
    const char* const secondRule =
        R"({"id":"1.1.1.2","ruleId":"second-rule","ruleName":"SecondRule","title":"1.1.1.2 Second rule","tags":[],"metadata":{},"payload":{"audit":{},"parameters":{}}})";
    const std::string rules = std::string("[") + kValidRule + "," + secondRule + "]";
    auto result = ParseString(MakeDoc(rules), nullptr);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    ASSERT_EQ(result.Value().resources.size(), 2u);
    EXPECT_EQ(result.Value().resources[0].id, "1.1.1.1");
    EXPECT_EQ(result.Value().resources[1].id, "1.1.1.2");
}

TEST(BenchmarkDefinitionParserTest, RejectsMissingOrMalformedContentVersion)
{
    for (const std::string& invalid : {"", "1.0", "1.0.0.0", "01.0.0", "1.00.0", "1.0.00", "-1.0.0", "1.0.x", "1.0.0-beta", R"(1.0.0\u0000)"})
    {
        std::string doc = OneRuleDoc();
        ReplaceOnce(doc, R"("version":"1.0.0")", R"("version":")" + invalid + R"(")");
        EXPECT_FALSE(ParseString(doc, nullptr).HasValue()) << invalid;
    }
    std::string doc = OneRuleDoc();
    ReplaceOnce(doc, R"("version":"1.0.0",)", "");
    auto missing = ParseString(doc, nullptr);
    ASSERT_FALSE(missing.HasValue());
    EXPECT_NE(missing.Error().message.find("version"), std::string::npos);
    ReplaceOnce(doc, R"("rules":)", R"("version":null,"rules":)");
    EXPECT_FALSE(ParseString(doc, nullptr).HasValue());

    // Hoisted identity is not required for legacy rules, but a content
    // version is required for both identity shapes.
    const std::string legacyRule = R"({"section":"1.1.1.1","payloadKey":"/cis/ubuntu/22.04/v2.0.0/1/1/1/1",)"
                                   R"("ruleId":"rule-id","ruleName":"R","title":"t","tags":[],"metadata":{},"payload":{"audit":{},"parameters":{}}})";
    std::string legacy = MakeDocWithMetadata(R"({"name":"legacy"})", "[" + legacyRule + "]");
    ReplaceOnce(legacy, R"("version":"1.0.0",)", "");
    EXPECT_FALSE(ParseString(legacy, nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, ParsesArbitrarilyLargeDecimalComponents)
{
    std::string doc = OneRuleDoc();
    ReplaceOnce(doc, R"("version":"1.0.0")", R"("version":"184467440737095516160.999999999999999999999.0")");
    auto result = ParseString(doc, nullptr);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(result.Value().version.major, "184467440737095516160");
    EXPECT_EQ(result.Value().version.minor, "999999999999999999999");
}

TEST(BenchmarkDefinitionParserTest, ComparesDecimalComponentsWithoutIntegerConversion)
{
    auto earlier = ComplianceEngine::ParseContentVersion("1.99999999999999999999.9");
    auto later = ComplianceEngine::ParseContentVersion("1.100000000000000000000.0");
    ASSERT_TRUE(earlier.HasValue());
    ASSERT_TRUE(later.HasValue());
    EXPECT_LT(ComplianceEngine::CompareContentVersion(earlier.Value(), later.Value()), 0);
    EXPECT_GT(ComplianceEngine::CompareContentVersion(later.Value(), earlier.Value()), 0);
    EXPECT_EQ(ComplianceEngine::ContentVersionToString(later.Value()), "1.100000000000000000000.0");
}

TEST(BenchmarkDefinitionParserTest, RejectsEmptyRulesArrayWithHoistedIdentity)
{
    auto result = ParseString(MakeDoc("[]"), nullptr);
    ASSERT_FALSE(result.HasValue());
    EXPECT_NE(result.Error().message.find("spec.rules"), std::string::npos);
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
        "section": "1.1.1.1",
        "payloadKey": "/cis/ubuntu/22.04/v2.0.0/1/1/1/1",
        "ruleId": "2b568469-ea61-c184-66ba-db6720414ddd",
        "ruleName": "EnsureCramfsKernelModuleIsNotAvailable",
        "title": "1.1.1.1 Ensure cramfs kernel module is not available",
        "tags": [],
        "metadata": {},
        "payload": {"audit": {"KernelModuleUnavailable": {"moduleName": "cramfs"}}, "parameters": {}}
    })";
    auto result = ParseString(MakeDoc(std::string("[") + legacyRule + "]"), nullptr);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    ASSERT_EQ(result.Value().resources.size(), 1u);
    EXPECT_EQ(result.Value().resources[0].id, "1.1.1.1");
    EXPECT_EQ(result.Value().resources[0].ruleId, "2b568469-ea61-c184-66ba-db6720414ddd");
}

TEST(BenchmarkDefinitionParserTest, LegacyPayloadKeyAllowsOptionalBenchmarkVersionPrefix)
{
    const char* const legacyRule = R"({
        "section": "1.1.1.1",
        "payloadKey": "/cis/ubuntu/22.04/v2.0.0/1/1/1/1",
        "ruleId": "rule-id",
        "ruleName": "R",
        "title": "t",
        "tags": [],
        "metadata": {},
        "payload": {"audit": {}, "parameters": {}}
    })";
    const std::string metadata =
        R"({"name":"n","labels":{"framework":"cis","distribution":"ubuntu","distributionVersion":"22.04"},"annotations":{"benchmarkVersion":"2.0.0"}})";
    auto result = ParseString(MakeDocWithMetadata(metadata, std::string("[") + legacyRule + "]"), nullptr);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
}

TEST(BenchmarkDefinitionParserTest, ParsesLegacyDocumentWithoutHoistedIdentity)
{
    const char* const legacyRule = R"({
        "section": "1.1.1.1", "payloadKey": "/cis/ubuntu/22.04/v2.0.0/1/1/1/1",
        "ruleId": "rule-id", "ruleName": "R", "title": "t",
        "tags": [], "metadata": {},
        "payload": {"audit": {}, "parameters": {}}
    })";
    auto result = ParseString(MakeDocWithMetadata(R"({"name":"legacy"})", std::string("[") + legacyRule + "]"), nullptr);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(result.Value().benchmarkInfo.framework, "cis");
    EXPECT_EQ(result.Value().benchmarkInfo.distribution, ComplianceEngine::LinuxDistribution::Ubuntu);
    EXPECT_EQ(result.Value().benchmarkInfo.version, "22.04");
    EXPECT_EQ(result.Value().benchmarkInfo.benchmarkVersion, "v2.0.0");
    EXPECT_TRUE(result.Value().benchmarkInfo.section.empty());
}

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

TEST(BenchmarkDefinitionParserTest, RejectsNonBooleanMandatoryParameterMetadata)
{
    const std::string ruleWithParams = R"({
        "ruleName": "EnsureMountPoint",
        "title": "Ensure mount point",
        "id": "1.1.2.1.1",
        "ruleId": "rule-id",
        "tags": [],
        "metadata": {"description": "d", "rationale": "r", "fixtext": "f", "severity": "Warning", "references": "x"},
        "payload": {"audit": {"X": {}}, "parameters": {"mountPoint": "/tmp"}},
        "parameterMetadata": {
            "mountPoint": {
                "type": "string",
                "default": "/tmp",
                "mandatory": INVALID_MANDATORY
            }
        }
    })";

    for (const char* const invalidValue : {R"("true")", "1"})
    {
        std::string invalidRule = ruleWithParams;
        ReplaceOnce(invalidRule, "INVALID_MANDATORY", invalidValue);
        auto result = ParseString(MakeDoc("[" + invalidRule + "]"), nullptr);
        ASSERT_FALSE(result.HasValue());
        EXPECT_NE(result.Error().message.find("'mandatory' field that is not a boolean"), std::string::npos);
    }
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

TEST(BenchmarkDefinitionParserTest, AcceptsEmptyParameterMetadataDefault)
{
    const char* const ruleWithParams = R"({
        "ruleName": "EnsureOptionalValue",
        "title": "Optional value",
        "id": "1.1.2.1.3",
        "ruleId": "rule-id",
        "tags": [],
        "metadata": {"description": "d", "rationale": "r", "fixtext": "f", "severity": "Warning", "references": "x"},
        "payload": {"audit": {"X": {}}, "parameters": {"optionalValue": ""}},
        "parameterMetadata": {
            "optionalValue": {"type": "string", "default": ""}
        }
    })";
    auto result = ParseString(MakeDoc(std::string("[") + ruleWithParams + "]"), nullptr);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(result.Value().resources[0].parameterMetadata.at("optionalValue").defaultValue, "");
}

TEST(BenchmarkDefinitionParserTest, RejectsUnsupportedParameterMetadataType)
{
    const char* const ruleWithParams = R"({
        "ruleName": "EnsureOptionalValue",
        "title": "Optional value",
        "id": "1.1.2.1.3",
        "ruleId": "rule-id",
        "tags": [],
        "metadata": {"description": "d", "rationale": "r", "fixtext": "f", "severity": "Warning", "references": "x"},
        "payload": {"audit": {"X": {}}, "parameters": {"optionalValue": ""}},
        "parameterMetadata": {
            "optionalValue": {"type": "integer", "default": ""}
        }
    })";
    auto result = ParseString(MakeDoc(std::string("[") + ruleWithParams + "]"), nullptr);
    ASSERT_FALSE(result.HasValue());
    EXPECT_NE(result.Error().message.find("only 'string' is supported"), std::string::npos);
}

TEST(BenchmarkDefinitionParserTest, RejectsInvalidParameterMetadata)
{
    const char* const notObject = R"({
        "ruleName": "R", "title": "t", "id": "1", "ruleId": "rule-id", "tags": [],
        "metadata": {}, "payload": {"audit": {}, "parameters": {}},
        "parameterMetadata": "not-an-object"
    })";
    EXPECT_FALSE(ParseString(MakeDoc(std::string("[") + notObject + "]"), nullptr).HasValue());

    const char* const missingDefault = R"({
        "ruleName": "R", "title": "t", "id": "1", "ruleId": "rule-id", "tags": [],
        "metadata": {}, "payload": {"audit": {}, "parameters": {}},
        "parameterMetadata": {"mountPoint": {"type": "string"}}
    })";
    EXPECT_FALSE(ParseString(MakeDoc(std::string("[") + missingDefault + "]"), nullptr).HasValue());

    const char* const entryNotObject = R"({
        "ruleName": "R", "title": "t", "id": "1", "ruleId": "rule-id", "tags": [],
        "metadata": {}, "payload": {"audit": {}, "parameters": {}},
        "parameterMetadata": {"mountPoint": "not-an-object"}
    })";
    EXPECT_FALSE(ParseString(MakeDoc(std::string("[") + entryNotObject + "]"), nullptr).HasValue());
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

TEST(BenchmarkDefinitionParserTest, RejectsUnsupportedApiVersion)
{
    std::string doc = OneRuleDoc();
    ReplaceOnce(doc, R"("apiVersion":"v1")", R"("apiVersion":"v2")");
    auto result = ParseString(doc, nullptr);
    ASSERT_FALSE(result.HasValue());
    EXPECT_NE(result.Error().message.find("unsupported 'apiVersion'"), std::string::npos);
    EXPECT_NE(result.Error().message.find("supported: v1"), std::string::npos);
    EXPECT_EQ(result.Error().message.find("\"v2\""), std::string::npos);
}

TEST(BenchmarkDefinitionParserTest, RejectsUnsupportedApiVersionForLegacyIdentity)
{
    const char* const legacyRule = R"({
        "section": "1.1.1.1", "payloadKey": "/cis/ubuntu/22.04/v2.0.0/1/1/1/1",
        "ruleId": "rule-id", "ruleName": "R", "title": "t",
        "tags": [], "metadata": {}, "payload": {"audit": {}, "parameters": {}}
    })";
    std::string doc = MakeDocWithMetadata(R"({"name":"legacy"})", std::string("[") + legacyRule + "]");
    ReplaceOnce(doc, R"("apiVersion":"v1")", R"("apiVersion":"v2")");
    auto result = ParseString(doc, nullptr);
    ASSERT_FALSE(result.HasValue());
    EXPECT_NE(result.Error().message.find("unsupported 'apiVersion'"), std::string::npos);
}

TEST(BenchmarkDefinitionParserTest, RejectsEmptyApiVersion)
{
    std::string doc = OneRuleDoc();
    ReplaceOnce(doc, R"("apiVersion":"v1")", R"("apiVersion":"")");
    auto result = ParseString(doc, nullptr);
    ASSERT_FALSE(result.HasValue());
    EXPECT_NE(result.Error().message.find("empty 'apiVersion'"), std::string::npos);
}

TEST(BenchmarkDefinitionParserTest, RejectsNonStringApiVersion)
{
    std::string doc = OneRuleDoc();
    ReplaceOnce(doc, R"("apiVersion":"v1")", R"("apiVersion":1)");
    auto result = ParseString(doc, nullptr);
    ASSERT_FALSE(result.HasValue());
    EXPECT_NE(result.Error().message.find("required string field 'apiVersion'"), std::string::npos);
}

TEST(BenchmarkDefinitionParserTest, RejectsEscapedNulInApiVersion)
{
    std::string doc = OneRuleDoc();
    ReplaceOnce(doc, R"("apiVersion":"v1")", R"("apiVersion":"v1\u0000")");
    auto result = ParseString(doc, nullptr);
    ASSERT_FALSE(result.HasValue());
    EXPECT_NE(result.Error().message.find("embedded NUL in 'apiVersion'"), std::string::npos);
}

TEST(BenchmarkDefinitionParserTest, DoesNotEchoUnsupportedApiVersionInError)
{
    std::string doc = OneRuleDoc();
    ReplaceOnce(doc, R"("apiVersion":"v1")", R"("apiVersion":"v2\n\u001b[31m")");
    auto result = ParseString(doc, nullptr);
    ASSERT_FALSE(result.HasValue());
    EXPECT_NE(result.Error().message.find("supported: v1"), std::string::npos);
    EXPECT_EQ(result.Error().message.find("v2"), std::string::npos);
    EXPECT_EQ(result.Error().message.find('\n'), std::string::npos);
    EXPECT_EQ(result.Error().message.find('\x1b'), std::string::npos);

    doc = OneRuleDoc();
    ReplaceOnce(doc, R"("apiVersion":"v1")", R"("apiVersion":")" + std::string(4096, 'x') + R"(")");
    auto longResult = ParseString(doc, nullptr);
    ASSERT_FALSE(longResult.HasValue());
    EXPECT_NE(longResult.Error().message.find("supported: v1"), std::string::npos);
    EXPECT_LT(longResult.Error().message.size(), 256u);
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

TEST(BenchmarkDefinitionParserTest, RejectsPartialHoistedIdentityOnLegacyDocument)
{
    const char* const legacyRule = R"({
        "section": "1.1.1.1", "payloadKey": "/cis/ubuntu/22.04/v2.0.0/1/1/1/1",
        "ruleId": "rule-id", "ruleName": "R", "title": "t",
        "payload": {"audit": {}, "parameters": {}}
    })";
    const std::string metadata = R"({"name":"legacy","labels":{"framework":"cis","distribution":"ubuntu","distributionVersion":"22.04"}})";
    EXPECT_FALSE(ParseString(MakeDocWithMetadata(metadata, std::string("[") + legacyRule + "]"), nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsSoleIdDocumentWithoutHoistedIdentity)
{
    EXPECT_FALSE(ParseString(MakeDocWithMetadata(R"({"name":"n"})", std::string("[") + kValidRule + "]"), nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsEmptyLegacyDocumentWithoutHoistedIdentity)
{
    EXPECT_FALSE(ParseString(MakeDocWithMetadata(R"({"name":"legacy"})", "[]"), nullptr).HasValue());
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

TEST(BenchmarkDefinitionParserTest, RejectsRuleMetadataNotAnObject)
{
    std::string doc = OneRuleDoc();
    ReplaceOnce(doc, R"("metadata": {
        "description": "d",
        "rationale": "r",
        "fixtext": "f",
        "severity": "Warning",
        "references": "x"
    })",
        R"("metadata": [])");
    EXPECT_FALSE(ParseString(doc, nullptr).HasValue());
}

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

TEST(BenchmarkDefinitionParserTest, RejectsLegacyPayloadKeyFrameworkMismatch)
{
    const char* const rule = R"({
        "section": "1.1.1.1", "payloadKey": "/stig/ubuntu/22.04/v2.0.0/1/1/1/1",
        "ruleId": "rule-id", "ruleName": "R", "title": "t",
        "payload": {"audit": {}, "parameters": {}}
    })";
    EXPECT_FALSE(ParseString(MakeDoc(std::string("[") + rule + "]"), nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsLegacyPayloadKeyDistributionMismatch)
{
    const char* const rule = R"({
        "section": "1.1.1.1", "payloadKey": "/cis/rhel/22.04/v2.0.0/1/1/1/1",
        "ruleId": "rule-id", "ruleName": "R", "title": "t",
        "payload": {"audit": {}, "parameters": {}}
    })";
    EXPECT_FALSE(ParseString(MakeDoc(std::string("[") + rule + "]"), nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsLegacyPayloadKeyDistributionVersionMismatch)
{
    const char* const rule = R"({
        "section": "1.1.1.1", "payloadKey": "/cis/ubuntu/18.04/v2.0.0/1/1/1/1",
        "ruleId": "rule-id", "ruleName": "R", "title": "t",
        "payload": {"audit": {}, "parameters": {}}
    })";
    EXPECT_FALSE(ParseString(MakeDoc(std::string("[") + rule + "]"), nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsLegacyPayloadKeyBenchmarkVersionMismatch)
{
    const char* const rule = R"({
        "section": "1.1.1.1", "payloadKey": "/cis/ubuntu/22.04/v1.0.0/1/1/1/1",
        "ruleId": "rule-id", "ruleName": "R", "title": "t",
        "payload": {"audit": {}, "parameters": {}}
    })";
    EXPECT_FALSE(ParseString(MakeDoc(std::string("[") + rule + "]"), nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsInconsistentLegacyPayloadKeysWithoutHoistedIdentity)
{
    const char* const firstRule = R"({
        "section": "1.1.1.1", "payloadKey": "/cis/ubuntu/22.04/v2.0.0/1/1/1/1",
        "ruleId": "rule-a", "ruleName": "A", "title": "a",
        "payload": {"audit": {}, "parameters": {}}
    })";
    const char* const secondRule = R"({
        "section": "1.1.1.2", "payloadKey": "/cis/ubuntu/18.04/v2.0.0/1/1/1/2",
        "ruleId": "rule-b", "ruleName": "B", "title": "b",
        "payload": {"audit": {}, "parameters": {}}
    })";
    const std::string rules = std::string("[") + firstRule + "," + secondRule + "]";
    EXPECT_FALSE(ParseString(MakeDocWithMetadata(R"({"name":"legacy"})", rules), nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsDuplicateIds)
{
    const std::string rules = std::string("[") + kValidRule + "," + kValidRule + "]";
    EXPECT_FALSE(ParseString(MakeDoc(rules), nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsEscapedNulInKind)
{
    std::string doc = OneRuleDoc();
    ReplaceOnce(doc, R"("kind":"BenchmarkDefinition")", R"("kind":"BenchmarkDefinition\u0000Extra")");
    EXPECT_FALSE(ParseString(doc, nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsEscapedNulInDocumentName)
{
    std::string doc = OneRuleDoc();
    ReplaceOnce(doc, R"("name":"cis_ubuntu_22.04_2.0.0")", R"("name":"cis\u0000_ubuntu")");
    EXPECT_FALSE(ParseString(doc, nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsEscapedNulInId)
{
    std::string doc = OneRuleDoc();
    ReplaceOnce(doc, R"("id": "1.1.1.1")", R"("id": "1.1\u0000.1.1")");
    EXPECT_FALSE(ParseString(doc, nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsEscapedNulInRuleId)
{
    std::string doc = OneRuleDoc();
    ReplaceOnce(doc, R"("ruleId": "2b568469-ea61-c184-66ba-db6720414ddd")", R"("ruleId": "2b568469\u0000-ea61-c184-66ba-db6720414ddd")");
    EXPECT_FALSE(ParseString(doc, nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsEscapedNulInRuleName)
{
    std::string doc = OneRuleDoc();
    ReplaceOnce(doc, R"("ruleName": "EnsureCramfsKernelModuleIsNotAvailable")", R"("ruleName": "EnsureCramfs\u0000KernelModuleIsNotAvailable")");
    EXPECT_FALSE(ParseString(doc, nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsTagExceeding256Utf8Bytes)
{
    std::string doc = OneRuleDoc();
    ReplaceOnce(doc, R"("tags": ["level:l1"])", R"("tags": ["x:)" + std::string(254, 'a') + R"("])");
    EXPECT_TRUE(ParseString(doc, nullptr).HasValue());

    ReplaceOnce(doc, R"("x:)" + std::string(254, 'a') + R"(")", R"("x:)" + std::string(255, 'a') + R"(")");
    auto tooLong = ParseString(doc, nullptr);
    EXPECT_FALSE(tooLong.HasValue());
    if (!tooLong.HasValue())
    {
        EXPECT_NE(tooLong.Error().message.find("256 bytes"), std::string::npos);
    }

    std::string utf8 = OneRuleDoc();
    ReplaceOnce(utf8, R"("tags": ["level:l1"])", R"("tags": ["x:)" + std::string(253, 'a') + "\xC3\xA9" + R"("])");
    EXPECT_FALSE(ParseString(utf8, nullptr).HasValue());
}

TEST(BenchmarkDefinitionParserTest, RejectsEscapedNulInLegacyPayloadKey)
{
    const std::string rule = R"({"section":"1.1.1.1","payloadKey":"/cis/ubuntu/22.04/v2.0.0/1/1/1/1",)"
                             R"("ruleId":"rule-id","ruleName":"R","title":"t","payload":{"audit":{},"parameters":{}}})";
    std::string doc = MakeDocWithMetadata(R"({"name":"legacy"})", "[" + rule + "]");
    ReplaceOnce(doc, "/cis/ubuntu/22.04/", "/cis/ubuntu\u0000/22.04/");
    EXPECT_FALSE(ParseString(doc, nullptr).HasValue());
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
