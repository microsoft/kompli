// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <Protocol.hpp>

#include <JsonWrapper.h>
#include <gtest/gtest.h>
#include <parson.h>
#include <string>

using ComplianceEngine::JsonWrapper;
using std::string;

namespace Komplid
{
namespace
{
// Owns a parsed JSON document and exposes the root object (mirrors
// cli/tests/BenchmarkFormatterTest.cpp's ParsedJson).
struct ParsedJson
{
    JSON_Value* value = nullptr;
    JSON_Object* object = nullptr;

    explicit ParsedJson(const string& text)
        : value(json_parse_string(text.c_str()))
    {
        if (nullptr != value)
        {
            object = json_value_get_object(value);
        }
    }
    ~ParsedJson()
    {
        if (nullptr != value)
        {
            json_value_free(value);
        }
    }
    ParsedJson(const ParsedJson&) = delete;
    ParsedJson& operator=(const ParsedJson&) = delete;
};

string ValidRequestLine()
{
    return R"({"requestId":"r1","benchmark":"cis_ubuntu","id":"1.1","mode":"audit"})";
}
} // namespace

// --- ExtractRequestId ---

TEST(ExtractRequestIdTest, ExtractsFromValidRequest)
{
    EXPECT_EQ("r1", ExtractRequestId(ValidRequestLine()));
}

TEST(ExtractRequestIdTest, ReturnsEmptyForMalformedJson)
{
    EXPECT_EQ("", ExtractRequestId("not json"));
}

TEST(ExtractRequestIdTest, ReturnsEmptyForNonObjectJson)
{
    EXPECT_EQ("", ExtractRequestId("[1,2,3]"));
}

TEST(ExtractRequestIdTest, ReturnsEmptyWhenRequestIdMissing)
{
    EXPECT_EQ("", ExtractRequestId(R"({"benchmark":"cis_ubuntu"})"));
}

TEST(ExtractRequestIdTest, ReturnsEmptyWhenRequestIdIsNotAString)
{
    EXPECT_EQ("", ExtractRequestId(R"({"requestId":123})"));
}

// --- ParseRequest ---

TEST(ParseRequestTest, ParsesValidRequest)
{
    auto result = ParseRequest(ValidRequestLine());
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ("r1", result.Value().requestId);
    EXPECT_EQ("cis_ubuntu", result.Value().benchmark);
    EXPECT_EQ("1.1", result.Value().id);
    EXPECT_EQ(RequestMode::Audit, result.Value().mode);
    EXPECT_TRUE(result.Value().parameters.empty());
}

TEST(ParseRequestTest, ParsesRemediateMode)
{
    auto result = ParseRequest(R"({"requestId":"r1","benchmark":"b","id":"1.1","mode":"remediate"})");
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(RequestMode::Remediate, result.Value().mode);
}

TEST(ParseRequestTest, ParsesEnforceModeSuccessfully)
{
    // enforce parses fine at the protocol layer; RequestHandler is
    // responsible for rejecting it as unsupported (see README.md).
    auto result = ParseRequest(R"({"requestId":"r1","benchmark":"b","id":"1.1","mode":"enforce"})");
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(RequestMode::Enforce, result.Value().mode);
}

TEST(ParseRequestTest, ParsesParameters)
{
    auto result = ParseRequest(R"({"requestId":"r1","benchmark":"b","id":"1.1","mode":"audit","parameters":{"k1":"v1","k2":"v2"}})");
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(2u, result.Value().parameters.size());
    EXPECT_EQ("v1", result.Value().parameters.at("k1"));
    EXPECT_EQ("v2", result.Value().parameters.at("k2"));
}

TEST(ParseRequestTest, RejectsMalformedJson)
{
    EXPECT_FALSE(ParseRequest("not json").HasValue());
}

TEST(ParseRequestTest, RejectsNonObjectJson)
{
    EXPECT_FALSE(ParseRequest("[1,2,3]").HasValue());
}

TEST(ParseRequestTest, RejectsMissingRequestId)
{
    EXPECT_FALSE(ParseRequest(R"({"benchmark":"b","id":"1.1","mode":"audit"})").HasValue());
}

TEST(ParseRequestTest, RejectsMissingBenchmark)
{
    EXPECT_FALSE(ParseRequest(R"({"requestId":"r1","id":"1.1","mode":"audit"})").HasValue());
}

TEST(ParseRequestTest, RejectsMissingId)
{
    EXPECT_FALSE(ParseRequest(R"({"requestId":"r1","benchmark":"b","mode":"audit"})").HasValue());
}

TEST(ParseRequestTest, RejectsMissingMode)
{
    EXPECT_FALSE(ParseRequest(R"({"requestId":"r1","benchmark":"b","id":"1.1"})").HasValue());
}

TEST(ParseRequestTest, RejectsEmptyStringFields)
{
    EXPECT_FALSE(ParseRequest(R"({"requestId":"","benchmark":"b","id":"1.1","mode":"audit"})").HasValue());
}

TEST(ParseRequestTest, RejectsUnrecognizedMode)
{
    EXPECT_FALSE(ParseRequest(R"({"requestId":"r1","benchmark":"b","id":"1.1","mode":"bogus"})").HasValue());
}

TEST(ParseRequestTest, RejectsBenchmarkContainingSlash)
{
    EXPECT_FALSE(ParseRequest(R"({"requestId":"r1","benchmark":"../etc/passwd","id":"1.1","mode":"audit"})").HasValue());
}

TEST(ParseRequestTest, RejectsNonObjectParameters)
{
    EXPECT_FALSE(ParseRequest(R"({"requestId":"r1","benchmark":"b","id":"1.1","mode":"audit","parameters":[1,2]})").HasValue());
}

TEST(ParseRequestTest, RejectsNonStringParameterValue)
{
    EXPECT_FALSE(ParseRequest(R"({"requestId":"r1","benchmark":"b","id":"1.1","mode":"audit","parameters":{"k1":42}})").HasValue());
}

// --- ToString(ErrorCode) ---

TEST(ErrorCodeToStringTest, MapsEveryCode)
{
    EXPECT_STREQ("invalid_request", ToString(ErrorCode::InvalidRequest));
    EXPECT_STREQ("unknown_benchmark", ToString(ErrorCode::UnknownBenchmark));
    EXPECT_STREQ("unknown_rule", ToString(ErrorCode::UnknownRule));
    EXPECT_STREQ("unsupported_mode", ToString(ErrorCode::UnsupportedMode));
    EXPECT_STREQ("benchmark_not_applicable", ToString(ErrorCode::BenchmarkNotApplicable));
    EXPECT_STREQ("unauthorized", ToString(ErrorCode::Unauthorized));
    EXPECT_STREQ("internal_error", ToString(ErrorCode::InternalError));
}

// --- BuildResultResponse ---

TEST(BuildResultResponseTest, EmbedsResultAndEnvelopeFields)
{
    auto resultJsonResult = JsonWrapper::MakeObject();
    ASSERT_TRUE(resultJsonResult.HasValue());
    auto* resultObject = json_value_get_object(resultJsonResult.Value().get());
    ASSERT_EQ(JSONSuccess, json_object_set_string(resultObject, "status", "compliant"));

    auto responseResult = BuildResultResponse("r1", std::move(resultJsonResult.Value()));
    ASSERT_TRUE(responseResult.HasValue());

    ParsedJson parsed(responseResult.Value());
    ASSERT_NE(nullptr, parsed.object);
    EXPECT_STREQ("result", json_object_get_string(parsed.object, "type"));
    EXPECT_STREQ("r1", json_object_get_string(parsed.object, "requestId"));
    const JSON_Object* embedded = json_object_get_object(parsed.object, "result");
    ASSERT_NE(nullptr, embedded);
    EXPECT_STREQ("compliant", json_object_get_string(embedded, "status"));
}

TEST(BuildResultResponseTest, SerializesAsSingleLine)
{
    auto resultJsonResult = JsonWrapper::MakeObject();
    ASSERT_TRUE(resultJsonResult.HasValue());

    auto responseResult = BuildResultResponse("r1", std::move(resultJsonResult.Value()));
    ASSERT_TRUE(responseResult.HasValue());
    // JSONL framing requires exactly one line per message.
    EXPECT_EQ(string::npos, responseResult.Value().find('\n'));
}

// --- BuildErrorResponse ---

TEST(BuildErrorResponseTest, ContainsCodeAndMessage)
{
    auto responseResult = BuildErrorResponse("r1", ErrorCode::UnknownRule, "no such rule");
    ASSERT_TRUE(responseResult.HasValue());

    ParsedJson parsed(responseResult.Value());
    ASSERT_NE(nullptr, parsed.object);
    EXPECT_STREQ("error", json_object_get_string(parsed.object, "type"));
    EXPECT_STREQ("r1", json_object_get_string(parsed.object, "requestId"));
    EXPECT_STREQ("unknown_rule", json_object_get_string(parsed.object, "code"));
    EXPECT_STREQ("no such rule", json_object_get_string(parsed.object, "message"));
}

TEST(BuildErrorResponseTest, AllowsEmptyRequestId)
{
    // Connection-level errors (e.g. Unauthorized) have no request to
    // correlate with.
    auto responseResult = BuildErrorResponse("", ErrorCode::Unauthorized, "not authorized");
    ASSERT_TRUE(responseResult.HasValue());

    ParsedJson parsed(responseResult.Value());
    ASSERT_NE(nullptr, parsed.object);
    EXPECT_STREQ("", json_object_get_string(parsed.object, "requestId"));
}

} // namespace Komplid
