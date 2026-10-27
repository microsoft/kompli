// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <Bindings.h>
#include <Evaluator.h>
#include <JsonWrapper.h>
#include <MockContext.h>
#include <NameserverCount.h>
#include <gtest/gtest.h>
#include <map>

using ComplianceEngine::NameserverCountParams;
using ComplianceEngine::Status;

namespace
{
ComplianceEngine::Result<Status> Evaluate(const std::string& contents, NameserverCountParams params = {})
{
    MockContext context;
    ComplianceEngine::IndicatorsTree indicators;
    indicators.Push("NameserverCount");
    const auto path = context.MakeTempfile(contents);
    context.SetSpecialFilePath("/etc/resolv.conf", path);
    return ComplianceEngine::AuditNameserverCount(params, indicators, context);
}
} // namespace

TEST(NameserverCountTest, RequiresTwoDistinctValidAddressSpellings)
{
    auto result = Evaluate("nameserver 192.0.2.1\n");
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::NonCompliant, result.Value());

    result = Evaluate("nameserver 192.0.2.1\nnameserver 192.0.2.1\n");
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::NonCompliant, result.Value());

    result = Evaluate("nameserver 192.0.2.1\nnameserver 2001:db8::1\n");
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());

    // Both IPv6 tokens decode to the same address, but the existing Unique
    // range compares original strings, not canonical address bytes.
    result = Evaluate("nameserver 2001:0db8::1\nnameserver 2001:db8::1\n");
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());
}

TEST(NameserverCountTest, ZeroCapturesAndReadFailuresAreErrors)
{
    auto result = Evaluate("# none\n");
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(ENODATA, result.Error().code);

    MockContext context;
    ComplianceEngine::IndicatorsTree indicators;
    indicators.Push("NameserverCount");
    NameserverCountParams params;
    context.SetSpecialFilePath("/etc/resolv.conf", context.GetTempdirPath() + "/missing");
    result = ComplianceEngine::AuditNameserverCount(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(ENOENT, result.Error().code);
}

TEST(NameserverCountTest, MalformedNameserverEvidenceCannotBecomeACompliantPrefix)
{
    for (const auto& contents : {"nameserver \n 192.0.2.1\nnameserver 2001:db8::1\n", "nameserver one\nnameserver two\n",
             "nameserver 192.0.2.1\nnameserver 2001:db8::1\nnameserver invalid\n", "nameserver 192.0.2.1 # inline\nnameserver 2001:db8::1\n"})
    {
        const auto result = Evaluate(contents);
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ(EBADMSG, result.Error().code);
    }
}

TEST(NameserverCountTest, MalformedUnrelatedRecordsFailButUnknownRecordsDoNot)
{
    for (const auto& unrelated : {"search\n", "options ndots:bad\n", "sortlist invalid\n", " domain indented\n"})
    {
        const auto result = Evaluate(std::string("nameserver 192.0.2.1\n") + unrelated + "nameserver 2001:db8::1\n");
        ASSERT_FALSE(result.HasValue()) << unrelated;
        EXPECT_EQ(EBADMSG, result.Error().code);
    }
    const auto unknown = Evaluate("mystery anything\noptions vendor-option\nnameserver 192.0.2.1\nnameserver 2001:db8::1\n");
    ASSERT_TRUE(unknown.HasValue());
    EXPECT_EQ(Status::Compliant, unknown.Value());
}

TEST(NameserverCountTest, RejectsInvalidPathsAndUnknownArguments)
{
    MockContext context;
    ComplianceEngine::IndicatorsTree indicators;
    indicators.Push("NameserverCount");
    NameserverCountParams params;
    params.path = std::string("relative/resolv.conf");
    auto result = ComplianceEngine::AuditNameserverCount(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EINVAL, result.Error().code);

    params.path = std::string();
    result = ComplianceEngine::AuditNameserverCount(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EINVAL, result.Error().code);

    params.path = std::string("/custom\0/resolv.conf", 19);
    result = ComplianceEngine::AuditNameserverCount(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EINVAL, result.Error().code);

    std::map<std::string, std::string> arguments = {{"path", "/etc/resolv.conf"}};
    const auto valid = ComplianceEngine::BindingsImpl::ParseArguments<NameserverCountParams>(arguments);
    ASSERT_TRUE(valid.HasValue());
    ASSERT_TRUE(valid.Value().path.HasValue());
    EXPECT_EQ("/etc/resolv.conf", valid.Value().path.Value());

    arguments.clear();
    const auto defaulted = ComplianceEngine::BindingsImpl::ParseArguments<NameserverCountParams>(arguments);
    ASSERT_TRUE(defaulted.HasValue());
    ASSERT_TRUE(defaulted.Value().path.HasValue());
    EXPECT_EQ("/etc/resolv.conf", defaulted.Value().path.Value());
    arguments = {{"path", "/etc/resolv.conf"}, {"unknown", "value"}};
    EXPECT_FALSE(ComplianceEngine::BindingsImpl::ParseArguments<NameserverCountParams>(arguments).HasValue());
}

TEST(NameserverCountTest, SerializedProcedureExecutesTheProductionPipeline)
{
    MockContext context;
    const auto path = context.MakeTempfile("nameserver 192.0.2.1\nnameserver 2001:db8::1\n");
    context.SetSpecialFilePath("/etc/resolv.conf", path);
    auto json = ComplianceEngine::JsonWrapper::FromString(R"({"NameserverCount":{"path":"/etc/resolv.conf"}})");
    ASSERT_TRUE(json.HasValue());
    ComplianceEngine::ParameterMap parameters;
    ComplianceEngine::DebugFormatter formatter;
    ComplianceEngine::Evaluator evaluator("STIG DNS nameserver count", json_value_get_object(json->get()), parameters, context);

    const auto result = evaluator.ExecuteAudit(formatter);

    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(Status::Compliant, result.Value().status);
}

TEST(NameserverCountTest, SerializedProcedureUsesDefaultPathWhenOmitted)
{
    MockContext context;
    context.SetSpecialFilePath("/etc/resolv.conf", context.MakeTempfile("nameserver 192.0.2.1\nnameserver 2001:db8::1\n"));
    auto json = ComplianceEngine::JsonWrapper::FromString(R"({"NameserverCount":{}})");
    ASSERT_TRUE(json.HasValue());
    ComplianceEngine::ParameterMap parameters;
    ComplianceEngine::DebugFormatter formatter;
    ComplianceEngine::Evaluator evaluator("STIG DNS nameserver count", json_value_get_object(json->get()), parameters, context);

    const auto result = evaluator.ExecuteAudit(formatter);

    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(Status::Compliant, result.Value().status);
}

TEST(NameserverCountTest, SerializedProcedureUsesExplicitCustomPath)
{
    MockContext context;
    const auto path = context.MakeTempfile("nameserver 192.0.2.1\nnameserver 2001:db8::1\n");
    auto json = ComplianceEngine::JsonWrapper::FromString(R"({"NameserverCount":{"path":")" + path + R"("}})");
    ASSERT_TRUE(json.HasValue());
    ComplianceEngine::ParameterMap parameters;
    ComplianceEngine::DebugFormatter formatter;
    ComplianceEngine::Evaluator evaluator("custom DNS nameserver count", json_value_get_object(json->get()), parameters, context);

    const auto result = evaluator.ExecuteAudit(formatter);

    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(Status::Compliant, result.Value().status);
}

TEST(NameserverCountTest, SerializedProcedureResolvesCustomPathParameter)
{
    MockContext context;
    const auto path = context.MakeTempfile("nameserver 192.0.2.1\nnameserver 2001:db8::1\n");
    auto json = ComplianceEngine::JsonWrapper::FromString(R"({"NameserverCount":{"path":"$source"}})");
    ASSERT_TRUE(json.HasValue());
    ComplianceEngine::ParameterMap parameters{{"source", path}};
    ComplianceEngine::DebugFormatter formatter;
    ComplianceEngine::Evaluator evaluator("STIG DNS nameserver count", json_value_get_object(json->get()), parameters, context);

    const auto result = evaluator.ExecuteAudit(formatter);

    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(Status::Compliant, result.Value().status);
}

TEST(NameserverCountTest, SerializedProcedureRejectsInvalidResolvedPath)
{
    MockContext context;
    auto json = ComplianceEngine::JsonWrapper::FromString(R"({"NameserverCount":{"path":"$source"}})");
    ASSERT_TRUE(json.HasValue());
    ComplianceEngine::ParameterMap parameters{{"source", "relative/resolv.conf"}};
    ComplianceEngine::DebugFormatter formatter;
    ComplianceEngine::Evaluator evaluator("invalid DNS source", json_value_get_object(json->get()), parameters, context);

    const auto result = evaluator.ExecuteAudit(formatter);

    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EINVAL, result.Error().code);
}
