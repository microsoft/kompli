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
constexpr const char* cPayloadSha256 = "289becee11335b7c880a073a3d00a751e6583fd89c0f381a01d7de7922b68942";

std::string FixturePath()
{
    const std::string sourceFile = __FILE__;
    return sourceFile.substr(0, sourceFile.find_last_of('/')) + "/fixtures/stig_text_quantifier_semantics.json";
}

std::string ReadFile(const std::string& path)
{
    std::ifstream input(path);
    return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

std::string CapturedPayload(const JsonWrapper& envelope)
{
    const auto* root = json_value_get_object(envelope.get());
    const auto* payload = json_object_get_string(root, "canonicalPayload");
    return payload == nullptr ? std::string() : payload;
}

struct SourceCase
{
    const char* name;
    const char* contents;
    int selectedItems;
    Status sourceExpected;
    const char* firstSourceValue;
    const char* secondSourceValue;
    int expectedNativeStateMatches;
    bool expectedDivergence;
};

constexpr SourceCase cSourceCases[] = {
    {"AOnly", "cert_policy = crl_auto;\n", 1, Status::Compliant, "crl_auto", nullptr, 1, true},
    {"BOnly", "cert_policy = crl_offline;\n", 1, Status::Compliant, "crl_offline", nullptr, 1, true},
    {"AAndB", "cert_policy = crl_auto;\ncert_policy = crl_offline;\n", 2, Status::Compliant, "crl_auto", "crl_offline", 2, true},
    {"AThenNeither", "cert_policy = crl_auto;\ncert_policy = ca;\n", 2, Status::NonCompliant, "crl_auto", "ca", 1, false},
    {"NeitherThenA", "cert_policy = ca;\ncert_policy = crl_auto;\n", 2, Status::NonCompliant, "ca", "crl_auto", 1, false},
    {"NeitherOnly", "cert_policy = ca;\n", 1, Status::NonCompliant, "ca", nullptr, 0, false},
    {"NoSelection", "# cert_policy = crl_auto;\nother = crl_offline;\n", 0, Status::NonCompliant, nullptr, nullptr, 0, false},
    {"Empty", "", 0, Status::NonCompliant, nullptr, nullptr, 0, false},
    {"SurroundedToken", "decoy = crl_offline;\ncert_policy = ca, crl_auto, signature;\n", 1, Status::Compliant, "ca, crl_auto, signature", nullptr, 0, true},
};

class StigTextQuantifierSemanticsTest : public ::testing::TestWithParam<std::size_t>
{
protected:
    MockContext mContext;
    ParameterMap mParameters;
    DebugFormatter mFormatter;
};
} // namespace

TEST(StigTextQuantifierPayloadTest, CapturedPayloadHasPinnedProvenanceAndShape)
{
    const auto artifact = ReadFile(FixturePath());
    ASSERT_FALSE(artifact.empty());
    auto envelope = JsonWrapper::FromString(artifact);
    ASSERT_TRUE(envelope.HasValue());
    const auto* root = json_value_get_object(envelope->get());
    ASSERT_NE(nullptr, root);

    const auto* source = json_object_get_object(root, "source");
    ASSERT_NE(nullptr, source);
    EXPECT_STREQ("6e135dc2128d7cfa08bdacf7820313c4ef75de87934bc789a02938878b9d8694", json_object_get_string(source, "benchmarkSha256"));
    EXPECT_STREQ("xccdf_mil.disa.stig_rule_SV-260578r1015021_rule", json_object_get_string(source, "rule"));
    EXPECT_STREQ("oval:mil.disa.stig.ind:tst:23823300", json_object_get_string(source, "test"));

    const auto* capture = json_object_get_object(root, "capture");
    ASSERT_NE(nullptr, capture);
    EXPECT_STREQ("none", json_object_get_string(capture, "augmentation"));
    EXPECT_STREQ(cPayloadSha256, json_object_get_string(capture, "payloadSha256"));

    const auto canonicalPayload = CapturedPayload(envelope.Value());
    ASSERT_FALSE(canonicalPayload.empty());
    unsigned char digest[SHA256_DIGEST_LENGTH];
    ASSERT_NE(nullptr, SHA256(reinterpret_cast<const unsigned char*>(canonicalPayload.data()), canonicalPayload.size(), digest));
    std::ostringstream digestHex;
    digestHex << std::hex << std::setfill('0');
    for (const auto byte : digest)
    {
        digestHex << std::setw(2) << static_cast<unsigned int>(byte);
    }
    EXPECT_EQ(cPayloadSha256, digestHex.str());

    auto payload = JsonWrapper::FromString(canonicalPayload);
    ASSERT_TRUE(payload.HasValue());
    const auto* procedure = json_object_get_object(json_value_get_object(payload->get()), "FileRegexMatch");
    ASSERT_NE(nullptr, procedure);
    EXPECT_EQ(6, json_object_get_count(procedure));
    EXPECT_STREQ(cSourcePath, json_object_get_string(procedure, "path"));
    EXPECT_EQ(nullptr, json_object_get_value(procedure, "allMatches"));
    EXPECT_EQ(nullptr, json_object_get_value(procedure, "behavior"));
    EXPECT_EQ(nullptr, json_object_get_value(procedure, "wholeFile"));
}

TEST_P(StigTextQuantifierSemanticsTest, OriginalPayloadRetainsRecordedSourceDivergence)
{
    ASSERT_LT(GetParam(), sizeof(cSourceCases) / sizeof(cSourceCases[0]));
    const auto& testCase = cSourceCases[GetParam()];
    RecordProperty("case", testCase.name);
    RecordProperty("sourceSelectedItems", testCase.selectedItems);
    RecordProperty("sourceExpected", std::to_string(testCase.sourceExpected));
    constexpr auto historicalNativeExpected = Status::NonCompliant;
    RecordProperty("historicalNativeExpected", std::to_string(historicalNativeExpected));
    EXPECT_EQ(testCase.expectedDivergence, testCase.sourceExpected != historicalNativeExpected);

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

    auto envelope = JsonWrapper::FromString(ReadFile(FixturePath()));
    ASSERT_TRUE(envelope.HasValue());
    auto payload = JsonWrapper::FromString(CapturedPayload(envelope.Value()));
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
    ASSERT_EQ(JSONSuccess, json_object_set_string(procedure, "path", directory.c_str()));
    ASSERT_EQ(1, json_value_equals(expectedInput.get(), payload->get()));

    Evaluator evaluator("STIG text quantifier verification", json_value_get_object(payload->get()), mParameters, mContext);
    const auto result = evaluator.ExecuteAudit(mFormatter);

    ASSERT_EQ(JSONSuccess, json_object_set_string(procedure, "path", cSourcePath));
    EXPECT_EQ(1, json_value_equals(original.get(), payload->get()));
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    RecordProperty("nativeStatus", std::to_string(result.Value().status));
    RecordProperty("nativeIndicators", result.Value().payload);
    RecordProperty("sourceNativeDivergence", std::to_string(testCase.sourceExpected != result.Value().status));
    EXPECT_EQ(historicalNativeExpected, result.Value().status) << result.Value().payload;
    EXPECT_EQ(testCase.expectedDivergence, testCase.sourceExpected != result.Value().status);
}

TEST_P(StigTextQuantifierSemanticsTest, CapturedPatternsExposeNativeStages)
{
    ASSERT_LT(GetParam(), sizeof(cSourceCases) / sizeof(cSourceCases[0]));
    const auto& testCase = cSourceCases[GetParam()];
    auto envelope = JsonWrapper::FromString(ReadFile(FixturePath()));
    ASSERT_TRUE(envelope.HasValue());
    auto payload = JsonWrapper::FromString(CapturedPayload(envelope.Value()));
    ASSERT_TRUE(payload.HasValue());
    const auto* procedure = json_object_get_object(json_value_get_object(payload->get()), "FileRegexMatch");
    ASSERT_NE(nullptr, procedure);
    const auto* matchPattern = json_object_get_string(procedure, "matchPattern");
    const auto* statePattern = json_object_get_string(procedure, "statePattern");
    ASSERT_NE(nullptr, matchPattern);
    ASSERT_NE(nullptr, statePattern);

    const regex matchRegex(matchPattern);
    const regex stateRegex(statePattern);
    std::istringstream input(testCase.contents);
    std::string line;
    int nativeSelectedItems = 0;
    std::string nativeCapturedValues;
    while (std::getline(input, line))
    {
        smatch match;
        if (regex_search(line, match, matchRegex))
        {
            ++nativeSelectedItems;
            if (!nativeCapturedValues.empty())
            {
                nativeCapturedValues += "|";
            }
            nativeCapturedValues += match.size() > 1 ? match[1].str() : match[0].str();
        }
    }

    int nativeStateMatches = 0;
    for (const auto* sourceValue : {testCase.firstSourceValue, testCase.secondSourceValue})
    {
        if (sourceValue == nullptr)
        {
            continue;
        }
        const std::string value(sourceValue);
        if (regex_search(value, stateRegex))
        {
            ++nativeStateMatches;
        }
    }

    RecordProperty("case", testCase.name);
    RecordProperty("nativeSelectedItems", nativeSelectedItems);
    RecordProperty("nativeCapturedValues", nativeCapturedValues);
    RecordProperty("nativeStateMatchesForSourceValues", nativeStateMatches);
    EXPECT_EQ(0, nativeSelectedItems);
    EXPECT_EQ(testCase.expectedNativeStateMatches, nativeStateMatches);
}

TEST_F(StigTextQuantifierSemanticsTest, ActualPayloadPropagatesRequiredInputOpenError)
{
    const auto notDirectory = mContext.MakeTempfile("not a directory");
    auto envelope = JsonWrapper::FromString(ReadFile(FixturePath()));
    ASSERT_TRUE(envelope.HasValue());
    auto payload = JsonWrapper::FromString(CapturedPayload(envelope.Value()));
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

    Evaluator evaluator("STIG text quantifier open error", json_value_get_object(payload->get()), mParameters, mContext);
    const auto result = evaluator.ExecuteAudit(mFormatter);

    ASSERT_EQ(JSONSuccess, json_object_set_string(procedure, "path", cSourcePath));
    EXPECT_EQ(1, json_value_equals(original.get(), payload->get()));
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(ENOTDIR, result.Error().code);
}

INSTANTIATE_TEST_SUITE_P(SourceMatrix, StigTextQuantifierSemanticsTest, ::testing::Values(0U, 1U, 2U, 3U, 4U, 5U, 6U, 7U, 8U),
    [](const ::testing::TestParamInfo<std::size_t>& info) { return cSourceCases[info.param].name; });
