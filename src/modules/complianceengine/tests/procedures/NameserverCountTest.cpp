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
    params.path = "/etc/resolv.conf";
    return ComplianceEngine::AuditNameserverCount(params, indicators, context);
}
} // namespace

TEST(NameserverCountTest, RequiresTwoDistinctNameserverCaptures)
{
    auto result = Evaluate("nameserver one\n");
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::NonCompliant, result.Value());

    result = Evaluate("nameserver one\nnameserver one\n");
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::NonCompliant, result.Value());

    result = Evaluate("nameserver one\nnameserver two\n");
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
    params.path = "/etc/resolv.conf";
    context.SetSpecialFilePath("/etc/resolv.conf", context.GetTempdirPath() + "/missing");
    result = ComplianceEngine::AuditNameserverCount(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(ENOENT, result.Error().code);
}

TEST(NameserverCountTest, PreservesGreedySourceWhitespaceSemantics)
{
    const auto result = Evaluate("nameserver \n one\nnameserver two\n");
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());
}

TEST(NameserverCountTest, RejectsUnsupportedPathAndBindingShape)
{
    MockContext context;
    ComplianceEngine::IndicatorsTree indicators;
    indicators.Push("NameserverCount");
    NameserverCountParams params;
    params.path = "/tmp/resolv.conf";
    auto result = ComplianceEngine::AuditNameserverCount(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EINVAL, result.Error().code);

    std::map<std::string, std::string> arguments = {{"path", "/etc/resolv.conf"}};
    const auto valid = ComplianceEngine::BindingsImpl::ParseArguments<NameserverCountParams>(arguments);
    ASSERT_TRUE(valid.HasValue());
    EXPECT_EQ("/etc/resolv.conf", valid.Value().path);

    arguments.clear();
    EXPECT_FALSE(ComplianceEngine::BindingsImpl::ParseArguments<NameserverCountParams>(arguments).HasValue());
    arguments = {{"path", "/etc/resolv.conf"}, {"unknown", "value"}};
    EXPECT_FALSE(ComplianceEngine::BindingsImpl::ParseArguments<NameserverCountParams>(arguments).HasValue());
}

TEST(NameserverCountTest, SerializedProcedureExecutesTheProductionPipeline)
{
    MockContext context;
    const auto path = context.MakeTempfile("nameserver one\nnameserver two\n");
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

TEST(NameserverCountTest, SerializedProcedureRejectsParameterIndirection)
{
    MockContext context;
    auto json = ComplianceEngine::JsonWrapper::FromString(R"({"NameserverCount":{"path":"$source"}})");
    ASSERT_TRUE(json.HasValue());
    ComplianceEngine::ParameterMap parameters{{"source", "/etc/resolv.conf"}};
    ComplianceEngine::DebugFormatter formatter;
    ComplianceEngine::Evaluator evaluator("STIG DNS nameserver count", json_value_get_object(json->get()), parameters, context);

    const auto result = evaluator.ExecuteAudit(formatter);

    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().message, "Parameter references are not supported by NameserverCount");
}
