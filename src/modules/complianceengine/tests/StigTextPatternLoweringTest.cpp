// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "Evaluator.h"
#include "JsonWrapper.h"
#include "MockContext.h"
#include "Regex.h"
#include "parson.h"

#include <cerrno>
#include <cstddef>
#include <fstream>
#include <gtest/gtest.h>
#include <initializer_list>
#include <iomanip>
#include <iterator>
#include <memory>
#include <openssl/sha.h>
#include <sstream>
#include <string>
#include <sys/stat.h>

using ComplianceEngine::DebugFormatter;
using ComplianceEngine::Evaluator;
using ComplianceEngine::JsonWrapper;
using ComplianceEngine::ParameterMap;
using ComplianceEngine::Status;

namespace
{
constexpr const char* cSourcePath = "/etc/pam_pkcs11";
constexpr const char* cOriginalPayloadSha256 = "289becee11335b7c880a073a3d00a751e6583fd89c0f381a01d7de7922b68942";
constexpr const char* cCorrectedPayloadSha256 = "becb40b38a4d90b8cb15dd5e1f9ee8a70290162f23ea7cfffb49842e7e5c723f";

std::string FixturePath()
{
    const std::string sourceFile = __FILE__;
    return sourceFile.substr(0, sourceFile.find_last_of('/')) + "/fixtures/stig_text_pattern_lowering_corrected.json";
}

std::string ReadFile(const std::string& path)
{
    std::ifstream input(path);
    return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

struct SourceCase
{
    const char* name;
    const char* contents;
    int selectedItems;
    Status expected;
    const char* firstSourceValue;
    const char* secondSourceValue;
    int stateMatches;
};

constexpr SourceCase cSourceCases[] = {
    {"AOnly", "cert_policy = crl_auto;\n", 1, Status::Compliant, "crl_auto", nullptr, 1},
    {"BOnly", "cert_policy = crl_offline;\n", 1, Status::Compliant, "crl_offline", nullptr, 1},
    {"AAndB", "cert_policy = crl_auto;\ncert_policy = crl_offline;\n", 2, Status::Compliant, "crl_auto", "crl_offline", 2},
    {"AThenNeither", "cert_policy = crl_auto;\ncert_policy = ca;\n", 2, Status::NonCompliant, "crl_auto", "ca", 1},
    {"NeitherThenA", "cert_policy = ca;\ncert_policy = crl_auto;\n", 2, Status::NonCompliant, "ca", "crl_auto", 1},
    {"NeitherOnly", "cert_policy = ca;\n", 1, Status::NonCompliant, "ca", nullptr, 0},
    {"NoSelection", "# cert_policy = crl_auto;\nother = crl_offline;\n", 0, Status::NonCompliant, nullptr, nullptr, 0},
    {"Empty", "", 0, Status::NonCompliant, nullptr, nullptr, 0},
    {"SurroundedToken", "decoy = crl_offline;\ncert_policy = ca, crl_auto, signature;\n", 1, Status::Compliant, "ca, crl_auto, signature", nullptr, 1},
};

class StigTextPatternLoweringTest : public ::testing::TestWithParam<std::size_t>
{
protected:
    MockContext mContext;
    ParameterMap mParameters;
    DebugFormatter mFormatter;
};
} // namespace

TEST(StigTextPatternLoweringPayloadTest, ActualCaptureHasDistinctProvenanceAndCorrectedShape)
{
    const auto artifact = ReadFile(FixturePath());
    ASSERT_FALSE(artifact.empty()) << "Capture actual corrected AE output before running the M-55 native regression";
    auto envelope = JsonWrapper::FromString(artifact);
    ASSERT_TRUE(envelope.HasValue());
    const auto* root = json_value_get_object(envelope->get());
    ASSERT_NE(nullptr, root);
    const auto* source = json_object_get_object(root, "source");
    ASSERT_NE(nullptr, source);
    EXPECT_STREQ("U_CAN_Ubuntu_22-04_LTS_V2R5_STIG_SCAP_1-3_Benchmark.xml", json_object_get_string(source, "benchmark"));
    EXPECT_STREQ("6e135dc2128d7cfa08bdacf7820313c4ef75de87934bc789a02938878b9d8694", json_object_get_string(source, "benchmarkSha256"));
    EXPECT_STREQ("xccdf_mil.disa.stig_rule_SV-260578r1015021_rule", json_object_get_string(source, "rule"));
    EXPECT_STREQ("oval:mil.disa.stig.ind:tst:23823300", json_object_get_string(source, "test"));

    const auto* capture = json_object_get_object(root, "capture");
    ASSERT_NE(nullptr, capture);
    EXPECT_STREQ("M-55-corrected", json_object_get_string(capture, "captureId"));
    EXPECT_STREQ("none", json_object_get_string(capture, "augmentation"));
    EXPECT_STREQ("5ea5c4d96a7b358d8ecf6b1d2368e3f09b64e990", json_object_get_string(capture, "augmentationEngineRevision"));
    EXPECT_STREQ("4e8afd8228df381ae52fc3b2dda10ce5b6dca7a435666616000cc0f2d7ba7229", json_object_get_string(capture, "parsePySha256"));
    EXPECT_STREQ("10b1da0dd72473bffb5959f19733918590c6a514ec932ac3d4996e9ca10b3877", json_object_get_string(capture, "rulePySha256"));
    EXPECT_STREQ("625c1665e8220b70c5e5382f2e95f19822a38dd273674ba7a903f23a4aaaed4b", json_object_get_string(capture, "utilsPySha256"));
    const auto* claimedDigest = json_object_get_string(capture, "payloadSha256");
    ASSERT_NE(nullptr, claimedDigest);
    EXPECT_STRNE(cOriginalPayloadSha256, claimedDigest);
    EXPECT_STREQ(cCorrectedPayloadSha256, claimedDigest);

    const auto* canonicalPayload = json_object_get_string(root, "canonicalPayload");
    ASSERT_NE(nullptr, canonicalPayload);
    unsigned char digest[SHA256_DIGEST_LENGTH];
    ASSERT_NE(nullptr, SHA256(reinterpret_cast<const unsigned char*>(canonicalPayload), std::char_traits<char>::length(canonicalPayload), digest));
    std::ostringstream digestHex;
    digestHex << std::hex << std::setfill('0');
    for (const auto byte : digest)
    {
        digestHex << std::setw(2) << static_cast<unsigned int>(byte);
    }
    EXPECT_EQ(cCorrectedPayloadSha256, digestHex.str());

    auto payload = JsonWrapper::FromString(canonicalPayload);
    ASSERT_TRUE(payload.HasValue());
    const auto* procedure = json_object_get_object(json_value_get_object(payload->get()), "FileRegexMatch");
    ASSERT_NE(nullptr, procedure);
    EXPECT_STREQ(cSourcePath, json_object_get_string(procedure, "path"));
    EXPECT_STREQ("True", json_object_get_string(procedure, "allMatches"));
    EXPECT_STREQ("at_least_one_exists", json_object_get_string(procedure, "behavior"));
    EXPECT_EQ(nullptr, json_object_get_value(procedure, "wholeFile"));
    ASSERT_NE(nullptr, json_object_get_string(procedure, "matchPattern"));
    ASSERT_NE(nullptr, json_object_get_string(procedure, "statePattern"));
}

TEST_P(StigTextPatternLoweringTest, ActualCorrectedPayloadMatchesSourceVerdict)
{
    ASSERT_LT(GetParam(), sizeof(cSourceCases) / sizeof(cSourceCases[0]));
    const auto& testCase = cSourceCases[GetParam()];
    RecordProperty("case", testCase.name);
    RecordProperty("sourceSelectedItems", testCase.selectedItems);
    RecordProperty("sourceExpected", std::to_string(testCase.expected));

    const auto directory = mContext.GetTempdirPath() + "/pam_pkcs11";
    ASSERT_EQ(0, mkdir(directory.c_str(), 0700));
    std::ofstream inputFile(directory + "/pam_pkcs11.conf");
    ASSERT_TRUE(inputFile.is_open());
    inputFile << testCase.contents;
    ASSERT_TRUE(inputFile.good());
    inputFile.flush();
    ASSERT_TRUE(inputFile.good());
    inputFile.close();
    ASSERT_FALSE(inputFile.fail());

    const auto artifact = ReadFile(FixturePath());
    ASSERT_FALSE(artifact.empty());
    auto envelope = JsonWrapper::FromString(artifact);
    ASSERT_TRUE(envelope.HasValue());
    const auto* canonicalPayload = json_object_get_string(json_value_get_object(envelope->get()), "canonicalPayload");
    ASSERT_NE(nullptr, canonicalPayload);
    auto payload = JsonWrapper::FromString(canonicalPayload);
    ASSERT_TRUE(payload.HasValue());
    std::unique_ptr<json_value_t, decltype(&json_value_free)> original(json_value_deep_copy(payload->get()), json_value_free);
    ASSERT_NE(nullptr, original);
    std::unique_ptr<json_value_t, decltype(&json_value_free)> expectedInput(json_value_deep_copy(original.get()), json_value_free);
    ASSERT_NE(nullptr, expectedInput);
    auto* expectedProcedure = json_object_get_object(json_value_get_object(expectedInput.get()), "FileRegexMatch");
    ASSERT_NE(nullptr, expectedProcedure);
    ASSERT_EQ(JSONSuccess, json_object_set_string(expectedProcedure, "path", directory.c_str()));

    auto* procedure = json_object_get_object(json_value_get_object(payload->get()), "FileRegexMatch");
    ASSERT_NE(nullptr, procedure);
    const auto* matchPattern = json_object_get_string(procedure, "matchPattern");
    const auto* statePattern = json_object_get_string(procedure, "statePattern");
    ASSERT_NE(nullptr, matchPattern);
    ASSERT_NE(nullptr, statePattern);
    const regex matchRegex(matchPattern);
    const regex stateRegex(statePattern);
    std::istringstream contents(testCase.contents);
    std::string line;
    int selectedItems = 0;
    while (std::getline(contents, line))
    {
        smatch match;
        if (regex_search(line, match, matchRegex))
        {
            ++selectedItems;
        }
    }
    EXPECT_EQ(testCase.selectedItems, selectedItems);
    int stateMatches = 0;
    for (const auto* value : {testCase.firstSourceValue, testCase.secondSourceValue})
    {
        if (value != nullptr)
        {
            const std::string capturedValue(value);
            if (regex_search(capturedValue, stateRegex))
            {
                ++stateMatches;
            }
        }
    }
    EXPECT_EQ(testCase.stateMatches, stateMatches);
    ASSERT_EQ(JSONSuccess, json_object_set_string(procedure, "path", directory.c_str()));
    ASSERT_EQ(1, json_value_equals(expectedInput.get(), payload->get()));

    Evaluator evaluator("STIG corrected text-pattern lowering", json_value_get_object(payload->get()), mParameters, mContext);
    const auto result = evaluator.ExecuteAudit(mFormatter);
    ASSERT_EQ(JSONSuccess, json_object_set_string(procedure, "path", cSourcePath));
    EXPECT_EQ(1, json_value_equals(original.get(), payload->get()));
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    RecordProperty("nativeStatus", std::to_string(result.Value().status));
    RecordProperty("nativeIndicators", result.Value().payload);
    EXPECT_EQ(testCase.expected, result.Value().status) << result.Value().payload;
}

TEST_F(StigTextPatternLoweringTest, CorrectedPayloadPropagatesRequiredInputOpenError)
{
    const auto notDirectory = mContext.MakeTempfile("not a directory");
    const auto artifact = ReadFile(FixturePath());
    ASSERT_FALSE(artifact.empty());
    auto envelope = JsonWrapper::FromString(artifact);
    ASSERT_TRUE(envelope.HasValue());
    const auto* canonicalPayload = json_object_get_string(json_value_get_object(envelope->get()), "canonicalPayload");
    ASSERT_NE(nullptr, canonicalPayload);
    auto payload = JsonWrapper::FromString(canonicalPayload);
    ASSERT_TRUE(payload.HasValue());
    std::unique_ptr<json_value_t, decltype(&json_value_free)> original(json_value_deep_copy(payload->get()), json_value_free);
    ASSERT_NE(nullptr, original);
    std::unique_ptr<json_value_t, decltype(&json_value_free)> expectedInput(json_value_deep_copy(original.get()), json_value_free);
    ASSERT_NE(nullptr, expectedInput);
    auto* expectedProcedure = json_object_get_object(json_value_get_object(expectedInput.get()), "FileRegexMatch");
    ASSERT_NE(nullptr, expectedProcedure);
    ASSERT_EQ(JSONSuccess, json_object_set_string(expectedProcedure, "path", notDirectory.c_str()));

    auto* procedure = json_object_get_object(json_value_get_object(payload->get()), "FileRegexMatch");
    ASSERT_NE(nullptr, procedure);
    ASSERT_EQ(JSONSuccess, json_object_set_string(procedure, "path", notDirectory.c_str()));
    ASSERT_EQ(1, json_value_equals(expectedInput.get(), payload->get()));

    Evaluator evaluator("STIG corrected text-pattern open error", json_value_get_object(payload->get()), mParameters, mContext);
    const auto result = evaluator.ExecuteAudit(mFormatter);
    ASSERT_EQ(JSONSuccess, json_object_set_string(procedure, "path", cSourcePath));
    EXPECT_EQ(1, json_value_equals(original.get(), payload->get()));
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(ENOTDIR, result.Error().code);
}

INSTANTIATE_TEST_SUITE_P(SourceMatrix, StigTextPatternLoweringTest, ::testing::Values(0U, 1U, 2U, 3U, 4U, 5U, 6U, 7U, 8U),
    [](const ::testing::TestParamInfo<std::size_t>& info) { return cSourceCases[info.param].name; });
