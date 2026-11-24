// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <Bindings.h>
#include <Evaluator.h>
#include <JsonWrapper.h>
#include <MockContext.h>
#include <NameserverCount.h>
#include <gtest/gtest.h>
#include <map>

using Kompli::NameserverCountParams;
using Kompli::Status;

namespace
{
Kompli::Result<Status> Evaluate(const std::string& contents, NameserverCountParams params = {})
{
    MockContext context;
    Kompli::IndicatorsTree indicators;
    indicators.Push("NameserverCount");
    const auto path = context.MakeTempfile(contents);
    context.SetSpecialFilePath("/etc/resolv.conf", path);
    return Kompli::AuditNameserverCount(params, indicators, context);
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
    Kompli::IndicatorsTree indicators;
    indicators.Push("NameserverCount");
    NameserverCountParams params;
    context.SetSpecialFilePath("/etc/resolv.conf", context.GetTempdirPath() + "/missing");
    result = Kompli::AuditNameserverCount(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(ENOENT, result.Error().code);
}

TEST(NameserverCountTest, PreservesGreedySourceWhitespaceSemantics)
{
    const auto result = Evaluate("nameserver \n one\nnameserver two\n");
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());
}

TEST(NameserverCountTest, RejectsInvalidPathsAndUnknownArguments)
{
    MockContext context;
    Kompli::IndicatorsTree indicators;
    indicators.Push("NameserverCount");
    NameserverCountParams params;
    params.path = std::string("relative/resolv.conf");
    auto result = Kompli::AuditNameserverCount(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EINVAL, result.Error().code);

    params.path = std::string();
    result = Kompli::AuditNameserverCount(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EINVAL, result.Error().code);

    params.path = std::string("/custom\0/resolv.conf", 19);
    result = Kompli::AuditNameserverCount(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EINVAL, result.Error().code);

    std::map<std::string, std::string> arguments = {{"path", "/etc/resolv.conf"}};
    const auto valid = Kompli::BindingsImpl::ParseArguments<NameserverCountParams>(arguments);
    ASSERT_TRUE(valid.HasValue());
    ASSERT_TRUE(valid.Value().path.HasValue());
    EXPECT_EQ("/etc/resolv.conf", valid.Value().path.Value());

    arguments.clear();
    const auto defaulted = Kompli::BindingsImpl::ParseArguments<NameserverCountParams>(arguments);
    ASSERT_TRUE(defaulted.HasValue());
    ASSERT_TRUE(defaulted.Value().path.HasValue());
    EXPECT_EQ("/etc/resolv.conf", defaulted.Value().path.Value());
    arguments = {{"path", "/etc/resolv.conf"}, {"unknown", "value"}};
    EXPECT_FALSE(Kompli::BindingsImpl::ParseArguments<NameserverCountParams>(arguments).HasValue());
}

TEST(NameserverCountTest, SerializedProcedureExecutesTheProductionPipeline)
{
    MockContext context;
    const auto path = context.MakeTempfile("nameserver one\nnameserver two\n");
    context.SetSpecialFilePath("/etc/resolv.conf", path);
    auto json = Kompli::JsonWrapper::FromString(R"({"NameserverCount":{"path":"/etc/resolv.conf"}})");
    ASSERT_TRUE(json.HasValue());
    Kompli::ParameterMap parameters;
    Kompli::DebugFormatter formatter;
    Kompli::Evaluator evaluator("STIG DNS nameserver count", json_value_get_object(json->get()), parameters, context);

    const auto result = evaluator.ExecuteAudit(formatter);

    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(Status::Compliant, result.Value().status);
}

TEST(NameserverCountTest, SerializedProcedureUsesDefaultPathWhenOmitted)
{
    MockContext context;
    context.SetSpecialFilePath("/etc/resolv.conf", context.MakeTempfile("nameserver one\nnameserver two\n"));
    auto json = Kompli::JsonWrapper::FromString(R"({"NameserverCount":{}})");
    ASSERT_TRUE(json.HasValue());
    Kompli::ParameterMap parameters;
    Kompli::DebugFormatter formatter;
    Kompli::Evaluator evaluator("STIG DNS nameserver count", json_value_get_object(json->get()), parameters, context);

    const auto result = evaluator.ExecuteAudit(formatter);

    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(Status::Compliant, result.Value().status);
}

TEST(NameserverCountTest, SerializedProcedureUsesExplicitCustomPath)
{
    MockContext context;
    const auto path = context.MakeTempfile("nameserver one\nnameserver two\n");
    auto json = Kompli::JsonWrapper::FromString(R"({"NameserverCount":{"path":")" + path + R"("}})");
    ASSERT_TRUE(json.HasValue());
    Kompli::ParameterMap parameters;
    Kompli::DebugFormatter formatter;
    Kompli::Evaluator evaluator("custom DNS nameserver count", json_value_get_object(json->get()), parameters, context);

    const auto result = evaluator.ExecuteAudit(formatter);

    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(Status::Compliant, result.Value().status);
}

TEST(NameserverCountTest, SerializedProcedureResolvesCustomPathParameter)
{
    MockContext context;
    const auto path = context.MakeTempfile("nameserver one\nnameserver two\n");
    auto json = Kompli::JsonWrapper::FromString(R"({"NameserverCount":{"path":"$source"}})");
    ASSERT_TRUE(json.HasValue());
    Kompli::ParameterMap parameters{{"source", path}};
    Kompli::DebugFormatter formatter;
    Kompli::Evaluator evaluator("STIG DNS nameserver count", json_value_get_object(json->get()), parameters, context);

    const auto result = evaluator.ExecuteAudit(formatter);

    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(Status::Compliant, result.Value().status);
}

TEST(NameserverCountTest, SerializedProcedureRejectsInvalidResolvedPath)
{
    MockContext context;
    auto json = Kompli::JsonWrapper::FromString(R"({"NameserverCount":{"path":"$source"}})");
    ASSERT_TRUE(json.HasValue());
    Kompli::ParameterMap parameters{{"source", "relative/resolv.conf"}};
    Kompli::DebugFormatter formatter;
    Kompli::Evaluator evaluator("invalid DNS source", json_value_get_object(json->get()), parameters, context);

    const auto result = evaluator.ExecuteAudit(formatter);

    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EINVAL, result.Error().code);
}
