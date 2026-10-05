// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "CommonUtils.h"
#include "MockContext.h"

#include <Bindings.h>
#include <Evaluator.h>
#include <JsonWrapper.h>
#include <SystemdUnitState.h>
#include <algorithm>
#include <dirent.h>
#include <fstream>
#include <gtest/gtest.h>
#include <map>
#include <string.h>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>

using ComplianceEngine::AuditSystemdUnitState;
using ComplianceEngine::CompactListFormatter;
using ComplianceEngine::Error;
using ComplianceEngine::Evaluator;
using ComplianceEngine::IndicatorsTree;
using ComplianceEngine::JsonWrapper;
using ComplianceEngine::Pattern;
using ComplianceEngine::Result;
using ComplianceEngine::Status;
using ComplianceEngine::SystemdUnitStateParams;

class SystemdUnitStateTest : public ::testing::Test
{
protected:
    MockContext mContext;
    IndicatorsTree mIndicators;

    void SetUp() override
    {
        mIndicators.Push("SystemdUnitState");
    }

    void TearDown() override
    {
    }
};

TEST_F(SystemdUnitStateTest, NullTest)
{

    SystemdUnitStateParams params;
    auto result = AuditSystemdUnitState(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
}

TEST_F(SystemdUnitStateTest, argTestNoStateCheck)
{

    SystemdUnitStateParams params;
    params.unitName = "foo.service";

    auto result = AuditSystemdUnitState(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
}
std::string systemCtlCmd = "systemctl show ";

TEST_F(SystemdUnitStateTest, argTestActiveStateAnyMatch)
{

    SystemdUnitStateParams params;
    params.unitName = "fooArg.service";
    auto pattern = Pattern::Make(".*");
    ASSERT_TRUE(pattern.HasValue());
    params.activeState = std::move(pattern.Value());

    auto executeCmd = systemCtlCmd;
    executeCmd += "-p ActiveState ";
    executeCmd += "\"" + params.unitName + "\"";

    std::string fooServceAnyOutput = "ActiveState=inactive\n";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr(executeCmd))).WillOnce(::testing::Return(Result<std::string>(fooServceAnyOutput)));
    auto result = AuditSystemdUnitState(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(SystemdUnitStateTest, argTestActiveStateNotMatch)
{

    SystemdUnitStateParams params;
    params.unitName = "fooArg.service";
    auto pattern = Pattern::Make("notMatch");
    ASSERT_TRUE(pattern.HasValue());
    params.activeState = std::move(pattern.Value());

    auto executeCmd = systemCtlCmd;
    executeCmd += "-p ActiveState ";
    executeCmd += "\"" + params.unitName + "\"";

    std::string fooServceAnyOutput = "ActiveState=inactive\n";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr(executeCmd))).WillOnce(::testing::Return(Result<std::string>(fooServceAnyOutput)));
    auto result = AuditSystemdUnitState(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(SystemdUnitStateTest, argTestActiveStateNoOuptu)
{

    SystemdUnitStateParams params;
    params.unitName = "fooArg.service";
    auto pattern = Pattern::Make("notMatch");
    ASSERT_TRUE(pattern.HasValue());
    params.activeState = std::move(pattern.Value());

    auto executeCmd = systemCtlCmd;
    executeCmd += "-p ActiveState ";
    executeCmd += "\"" + params.unitName + "\"";

    std::string fooServceAnyOutput = "NotanActiveStateActiveState=inactive\n";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr(executeCmd))).WillOnce(::testing::Return(Result<std::string>(fooServceAnyOutput)));
    auto result = AuditSystemdUnitState(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
}

TEST_F(SystemdUnitStateTest, argTestActiveStateActive)
{

    SystemdUnitStateParams params;
    params.unitName = "fooArg.service";
    auto pattern = Pattern::Make("active");
    ASSERT_TRUE(pattern.HasValue());
    params.activeState = std::move(pattern.Value());

    auto executeCmd = systemCtlCmd;
    executeCmd += "-p ActiveState ";
    executeCmd += "\"" + params.unitName + "\"";

    std::string fooServceAnyOutput = "ActiveState=active\n";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr(executeCmd))).WillOnce(::testing::Return(Result<std::string>(fooServceAnyOutput)));
    auto result = AuditSystemdUnitState(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(SystemdUnitStateTest, argTestActiveStateActiveLoadStateAny)
{

    SystemdUnitStateParams params;
    params.unitName = "fooArg.service";
    auto pattern = Pattern::Make("active");
    ASSERT_TRUE(pattern.HasValue());
    params.activeState = std::move(pattern.Value());
    pattern = Pattern::Make(".*");
    ASSERT_TRUE(pattern.HasValue());
    params.loadState = std::move(pattern.Value());

    auto executeCmd = systemCtlCmd;
    executeCmd += "-p ActiveState ";
    executeCmd += "-p LoadState ";
    executeCmd += "\"" + params.unitName + "\"";

    std::string fooServceAnyOutput = "ActiveState=active\nLoadState=masked";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr(executeCmd))).WillOnce(::testing::Return(Result<std::string>(fooServceAnyOutput)));
    auto result = AuditSystemdUnitState(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(SystemdUnitStateTest, argTestActiveStateActiveLoadStateNotPresent)
{

    SystemdUnitStateParams params;
    params.unitName = "fooArg.service";
    auto pattern = Pattern::Make("active");
    ASSERT_TRUE(pattern.HasValue());
    params.activeState = std::move(pattern.Value());
    pattern = Pattern::Make(".*");
    ASSERT_TRUE(pattern.HasValue());
    params.loadState = std::move(pattern.Value());

    auto executeCmd = systemCtlCmd;
    executeCmd += "-p ActiveState ";
    executeCmd += "-p LoadState ";
    executeCmd += "\"" + params.unitName + "\"";

    std::string fooServceAnyOutput = "ActiveState=active\nExtraState=foo\n";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr(executeCmd))).WillOnce(::testing::Return(Result<std::string>(fooServceAnyOutput)));
    auto result = AuditSystemdUnitState(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
}

TEST_F(SystemdUnitStateTest, argTestActiveStateActiveLoadStateMasked)
{

    SystemdUnitStateParams params;
    params.unitName = "fooArg.service";
    auto pattern = Pattern::Make("active");
    ASSERT_TRUE(pattern.HasValue());
    params.activeState = std::move(pattern.Value());
    pattern = Pattern::Make("masked");
    ASSERT_TRUE(pattern.HasValue());
    params.loadState = std::move(pattern.Value());

    auto executeCmd = systemCtlCmd;
    executeCmd += "-p ActiveState ";
    executeCmd += "-p LoadState ";
    executeCmd += "\"" + params.unitName + "\"";

    std::string fooServceAnyOutput = "ActiveState=active\nLoadState=masked\n";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr(executeCmd))).WillOnce(::testing::Return(Result<std::string>(fooServceAnyOutput)));
    auto result = AuditSystemdUnitState(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(SystemdUnitStateTest, argTestActiveStateActiveLoadStateMaskedUnitFileStateAny)
{

    SystemdUnitStateParams params;
    params.unitName = "fooArg.service";
    auto pattern = Pattern::Make("active");
    ASSERT_TRUE(pattern.HasValue());
    params.activeState = std::move(pattern.Value());
    pattern = Pattern::Make("masked");
    ASSERT_TRUE(pattern.HasValue());
    params.loadState = std::move(pattern.Value());
    pattern = Pattern::Make(".*");
    ASSERT_TRUE(pattern.HasValue());
    params.unitFileState = std::move(pattern.Value());

    auto executeCmd = systemCtlCmd;
    executeCmd += "-p ActiveState ";
    executeCmd += "-p LoadState ";
    executeCmd += "-p UnitFileState ";
    executeCmd += "\"" + params.unitName + "\"";

    std::string fooServceAnyOutput = "ActiveState=active\nLoadState=masked\nUnitFileState=masked";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr(executeCmd))).WillOnce(::testing::Return(Result<std::string>(fooServceAnyOutput)));
    auto result = AuditSystemdUnitState(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(SystemdUnitStateTest, argTestActiveStateActiveLoadStateMaskedUnitFileStateAnyDiffrentOrder)
{

    SystemdUnitStateParams params;
    params.unitName = "fooArg.service";
    auto pattern = Pattern::Make("active");
    ASSERT_TRUE(pattern.HasValue());
    params.activeState = std::move(pattern.Value());
    pattern = Pattern::Make("masked");
    ASSERT_TRUE(pattern.HasValue());
    params.loadState = std::move(pattern.Value());
    pattern = Pattern::Make(".*");
    ASSERT_TRUE(pattern.HasValue());
    params.unitFileState = std::move(pattern.Value());

    auto executeCmd = systemCtlCmd;
    executeCmd += "-p ActiveState ";
    executeCmd += "-p LoadState ";
    executeCmd += "-p UnitFileState ";
    executeCmd += "\"" + params.unitName + "\"";

    std::string fooServceAnyOutput = "LoadState=masked\nUnitFileState=masked\nActiveState=active";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr(executeCmd))).WillOnce(::testing::Return(Result<std::string>(fooServceAnyOutput)));
    auto result = AuditSystemdUnitState(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(SystemdUnitStateTest, argTestActiveStateActiveLoadStateMaskedUnitFileStateOutputMissing)
{

    SystemdUnitStateParams params;
    params.unitName = "fooArg.service";
    auto pattern = Pattern::Make("active");
    ASSERT_TRUE(pattern.HasValue());
    params.activeState = std::move(pattern.Value());
    pattern = Pattern::Make("masked");
    ASSERT_TRUE(pattern.HasValue());
    params.loadState = std::move(pattern.Value());
    pattern = Pattern::Make(".*");
    ASSERT_TRUE(pattern.HasValue());
    params.unitFileState = std::move(pattern.Value());

    auto executeCmd = systemCtlCmd;
    executeCmd += "-p ActiveState ";
    executeCmd += "-p LoadState ";
    executeCmd += "-p UnitFileState ";
    executeCmd += "\"" + params.unitName + "\"";

    std::string fooServceAnyOutput = "LoadState=masked\nNotAnUnitFileState=masked\nActiveState=active";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr(executeCmd))).WillOnce(::testing::Return(Result<std::string>(fooServceAnyOutput)));
    auto result = AuditSystemdUnitState(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
}

TEST_F(SystemdUnitStateTest, argTestUnit)
{

    SystemdUnitStateParams params;
    params.unitName = "fooTimer.timer";
    auto pattern = Pattern::Make("foo.service");
    ASSERT_TRUE(pattern.HasValue());
    params.unit = std::move(pattern.Value());

    auto executeCmd = systemCtlCmd;
    executeCmd += "-p Unit ";
    executeCmd += "\"" + params.unitName + "\"";

    std::string fooServceAnyOutput = "Unit=foo.service\n";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr(executeCmd))).WillOnce(::testing::Return(Result<std::string>(fooServceAnyOutput)));
    auto result = AuditSystemdUnitState(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(SystemdUnitStateTest, partialMatchFails)
{

    SystemdUnitStateParams params;
    params.unitName = "fooArg.service";
    auto pattern = Pattern::Make("active");
    ASSERT_TRUE(pattern.HasValue());
    params.activeState = std::move(pattern.Value());

    auto executeCmd = systemCtlCmd;
    executeCmd += "-p ActiveState ";
    executeCmd += "\"" + params.unitName + "\"";

    std::string fooServceAnyOutput = "ActiveState=inactive";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr(executeCmd))).WillOnce(::testing::Return(Result<std::string>(fooServceAnyOutput)));
    auto result = AuditSystemdUnitState(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(SystemdUnitStateTest, partialMatchSucceeds)
{
    SystemdUnitStateParams params;
    params.unitName = "fooArg.service";
    auto pattern = Pattern::Make(".*active");
    ASSERT_TRUE(pattern.HasValue());
    params.activeState = std::move(pattern.Value());

    auto executeCmd = systemCtlCmd;
    executeCmd += "-p ActiveState ";
    executeCmd += "\"" + params.unitName + "\"";

    std::string fooServceAnyOutput = "ActiveState=inactive";

    EXPECT_CALL(mContext, ExecuteCommand(::testing::HasSubstr(executeCmd))).WillOnce(::testing::Return(Result<std::string>(fooServceAnyOutput)));
    auto result = AuditSystemdUnitState(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(SystemdUnitStateTest, SubStateRunning)
{
    SystemdUnitStateParams params;
    params.unitName = "auditd.service";
    auto running = Pattern::Make("running");
    ASSERT_TRUE(running.HasValue());
    params.subState = std::move(running.Value());

    EXPECT_CALL(mContext, ExecuteCommand("systemctl show -p SubState \"auditd.service\""))
        .WillOnce(::testing::Return(Result<std::string>("SubState=running\n")));
    auto result = AuditSystemdUnitState(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(SystemdUnitStateTest, ActiveAndRunningBothRequired)
{
    SystemdUnitStateParams params;
    params.unitName = "auditd.service";
    auto active = Pattern::Make("active");
    auto running = Pattern::Make("running");
    ASSERT_TRUE(active.HasValue());
    ASSERT_TRUE(running.HasValue());
    params.activeState = std::move(active.Value());
    params.subState = std::move(running.Value());

    const std::string command = "systemctl show -p ActiveState -p SubState \"auditd.service\"";
    struct Case
    {
        std::string output;
        bool valid;
        Status expected;
    };
    const Case cases[] = {
        {"ActiveState=active\nSubState=running\n", true, Status::Compliant},
        {"SubState=running\nActiveState=active", true, Status::Compliant},
        {"ActiveState=active\nSubState=dead\n", true, Status::NonCompliant},
        {"ActiveState=inactive\nSubState=running\n", true, Status::NonCompliant},
        {"", false, Status::NonCompliant},
        {"ActiveState=active\n", false, Status::NonCompliant},
        {"SubState=running\n", false, Status::NonCompliant},
        {"ActiveState=active\nActiveState=active\n", false, Status::NonCompliant},
        {"ActiveState=active\nSubState=\n", false, Status::NonCompliant},
        {"ActiveState=active\nSubState", false, Status::NonCompliant},
        {"ActiveState=active\nLoadState=not-found\n", false, Status::NonCompliant},
    };
    for (const auto& testCase : cases)
    {
        EXPECT_CALL(mContext, ExecuteCommand(command)).WillOnce(::testing::Return(Result<std::string>(testCase.output)));
        auto result = AuditSystemdUnitState(params, mIndicators, mContext);
        if (testCase.valid)
        {
            ASSERT_TRUE(result.HasValue()) << testCase.output;
            EXPECT_EQ(result.Value(), testCase.expected) << testCase.output;
        }
        else
        {
            EXPECT_FALSE(result.HasValue()) << "Invalid output: " << testCase.output;
        }
    }
}

TEST_F(SystemdUnitStateTest, CommandErrorCannotPass)
{
    SystemdUnitStateParams params;
    params.unitName = "auditd.service";
    auto running = Pattern::Make("running");
    ASSERT_TRUE(running.HasValue());
    params.subState = std::move(running.Value());

    EXPECT_CALL(mContext, ExecuteCommand("systemctl show -p SubState \"auditd.service\""))
        .WillOnce(::testing::Return(Result<std::string>(Error("Unit not found", 1))));
    auto result = AuditSystemdUnitState(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, 1);
}

TEST_F(SystemdUnitStateTest, SubStateBindingValidatesArguments)
{
    std::map<std::string, std::string> args = {{"unitName", "auditd.service"}, {"subState", "running"}};
    auto parsed = ComplianceEngine::BindingsImpl::ParseArguments<SystemdUnitStateParams>(args);
    ASSERT_TRUE(parsed.HasValue());
    ASSERT_TRUE(parsed.Value().subState.HasValue());
    EXPECT_TRUE(regex_match("running", parsed.Value().subState->GetRegex()));

    args["subState"] = "[";
    EXPECT_FALSE(ComplianceEngine::BindingsImpl::ParseArguments<SystemdUnitStateParams>(args).HasValue());
    args["subState"] = "running";
    args["unknown"] = "anything";
    EXPECT_FALSE(ComplianceEngine::BindingsImpl::ParseArguments<SystemdUnitStateParams>(args).HasValue());
}

TEST_F(SystemdUnitStateTest, NegatedCisPredicateDoesNotAcceptInvalidOutput)
{
    auto json = JsonWrapper::FromString(R"({"not":{"SystemdUnitState":{"unitName":"isc-dhcp-server.service","unitFileState":"enabled"}}})");
    ASSERT_TRUE(json.HasValue());
    ASSERT_TRUE(json->get());
    const std::string command = "systemctl show -p UnitFileState \"isc-dhcp-server.service\"";
    struct Case
    {
        std::string output;
        bool valid;
        Status expected;
    };
    const Case cases[] = {
        {"UnitFileState=disabled\n", true, Status::Compliant},
        {"UnitFileState=enabled\n", true, Status::NonCompliant},
        {"", false, Status::NonCompliant},
        {"ActiveState=active\n", false, Status::NonCompliant},
        {"UnitFileState=\n", false, Status::NonCompliant},
        {"UnitFileState", false, Status::NonCompliant},
    };
    for (const auto& testCase : cases)
    {
        EXPECT_CALL(mContext, ExecuteCommand(command)).WillOnce(::testing::Return(Result<std::string>(testCase.output)));
        Evaluator evaluator("CIS systemd service check", json_value_get_object(json->get()), {}, mContext);
        auto result = evaluator.ExecuteAudit(ComplianceEngine::DebugFormatter{});
        if (testCase.valid)
        {
            ASSERT_TRUE(result.HasValue()) << testCase.output;
            EXPECT_EQ(result.Value().status, testCase.expected) << testCase.output;
        }
        else
        {
            EXPECT_FALSE(result.HasValue()) << "Invalid output: " << testCase.output;
        }
    }
}

TEST_F(SystemdUnitStateTest, NegatedCisPredicateDoesNotAcceptCommandError)
{
    auto json = JsonWrapper::FromString(R"({"not":{"SystemdUnitState":{"unitName":"isc-dhcp-server.service","unitFileState":"enabled"}}})");
    ASSERT_TRUE(json.HasValue());
    ASSERT_TRUE(json->get());

    EXPECT_CALL(mContext, ExecuteCommand("systemctl show -p UnitFileState \"isc-dhcp-server.service\""))
        .WillOnce(::testing::Return(Result<std::string>(Error("Unit not found", 1))));
    Evaluator evaluator("CIS systemd service check", json_value_get_object(json->get()), {}, mContext);
    auto result = evaluator.ExecuteAudit(ComplianceEngine::DebugFormatter{});
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, 1);
}
