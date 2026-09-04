// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "MockContext.h"

#include <AksCommand.h>
#include <gtest/gtest.h>

using namespace ComplianceEngine;
using ::testing::HasSubstr;
using ::testing::Return;

class AksCommandTest : public ::testing::Test
{
protected:
    MockContext context;
    IndicatorsTree indicators;

    void SetUp() override
    {
        indicators.Push("AksCommand");
    }
};

TEST_F(AksCommandTest, ExecutesFixedAzureReadCommand)
{
    AksCommandParams params;
    params.operation = AksCommandOperation::NetworkPolicy;
    params.clusterName = "cluster-1";
    params.resourceGroup = "resource.group";
    params.pattern = "azure";
    EXPECT_CALL(context,
        ExecuteCommand("az aks show --resource-group resource.group --name cluster-1 --output json --query 'networkProfile.networkPolicy'"))
        .WillOnce(Return(Result<std::string>("azure")));

    auto result = AuditAksCommand(params, indicators, context);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(AksCommandTest, RejectsShellMetacharactersWithoutExecution)
{
    AksCommandParams params;
    params.operation = AksCommandOperation::NetworkPolicy;
    params.clusterName = "cluster; kubectl delete ns default";
    params.resourceGroup = "group";
    params.pattern = ".*";
    EXPECT_CALL(context, ExecuteCommand(testing::_)).Times(0);

    auto result = AuditAksCommand(params, indicators, context);

    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, EINVAL);
}

TEST_F(AksCommandTest, KubeletUsesFixedGetRequest)
{
    AksCommandParams params;
    params.operation = AksCommandOperation::Kubelet;
    params.nodeName = "node-1.example";
    params.pattern = "config";
    EXPECT_CALL(context, ExecuteCommand("kubectl get --raw '/api/v1/nodes/node-1.example/proxy/configz'"))
        .WillOnce(Return(Result<std::string>("config")));

    auto result = AuditAksCommand(params, indicators, context);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(AksCommandTest, RejectsNodePathInjectionWithoutExecution)
{
    AksCommandParams params;
    params.operation = AksCommandOperation::Kubelet;
    params.nodeName = "node/../../apis/apps";
    params.pattern = ".*";
    EXPECT_CALL(context, ExecuteCommand(testing::_)).Times(0);

    auto result = AuditAksCommand(params, indicators, context);

    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, EINVAL);
}

TEST_F(AksCommandTest, SupportsInvertedMatchWithoutShellingOutToGrep)
{
    AksCommandParams params;
    params.operation = AksCommandOperation::GeneralPolicies;
    params.pattern = "^default$";
    params.matchMeansCompliant = false;
    EXPECT_CALL(context, ExecuteCommand(HasSubstr("kubectl get pods --all-namespaces"))).WillOnce(Return(Result<std::string>("kube-system\n")));

    auto result = AuditAksCommand(params, indicators, context);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(AksCommandTest, MatchesOutputOneLineAtATime)
{
    AksCommandParams params;
    params.operation = AksCommandOperation::GeneralPolicies;
    params.pattern = "^default$";
    EXPECT_CALL(context, ExecuteCommand(HasSubstr("kubectl get pods --all-namespaces")))
        .WillOnce(Return(Result<std::string>("kube-system\ndefault\n")));

    auto result = AuditAksCommand(params, indicators, context);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(AksCommandTest, PodSecurityUsesFixedReadOnlyQuery)
{
    AksCommandParams params;
    params.operation = AksCommandOperation::PodSecurityStandards;
    params.pattern = ".+";
    params.matchMeansCompliant = false;
    EXPECT_CALL(context, ExecuteCommand(HasSubstr("kubectl get pods --all-namespaces -o json | jq -r"))).WillOnce(Return(Result<std::string>("")));

    auto result = AuditAksCommand(params, indicators, context);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(AksCommandTest, RejectsInvalidRegexBeforeExecution)
{
    AksCommandParams params;
    params.operation = AksCommandOperation::GeneralPolicies;
    params.pattern = "[";
    EXPECT_CALL(context, ExecuteCommand(testing::_)).Times(0);

    auto result = AuditAksCommand(params, indicators, context);

    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, EINVAL);
}
