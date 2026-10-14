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
        {"ActiveState=active\nSubState=running\nActiveState=active\n", true, Status::Compliant},
        {"ActiveState=active\nSubState=running\nSubState=running\n", true, Status::Compliant},
        {"ActiveState=inactive\nSubState=running\nActiveState=active\n", false, Status::NonCompliant},
        {"ActiveState=active\nSubState=running\nSubState=dead\n", false, Status::NonCompliant},
        {"ActiveState=active\nSubState=dead\nSubState=dead\n", true, Status::NonCompliant},
        {"ActiveState=active\nSubState=dead\n", true, Status::NonCompliant},
        {"ActiveState=inactive\nSubState=running\n", true, Status::NonCompliant},
        {"ActiveState=inactive\nSubState=dead\n", true, Status::NonCompliant},
        {"", false, Status::NonCompliant},
        {"ActiveState=active\n", false, Status::NonCompliant},
        {"ActiveState=inactive\n", false, Status::NonCompliant},
        {"ActiveState=inactive\nSubState", false, Status::NonCompliant},
        {"ActiveState=inactive\nSubState=\n", false, Status::NonCompliant},
        {"ActiveState=inactive\nOtherState=running\n", false, Status::NonCompliant},
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

TEST_F(SystemdUnitStateTest, EmptyUnitFileStateIsAnOrdinaryMismatch)
{
    SystemdUnitStateParams params;
    params.unitName = "isc-dhcp-server.service";
    auto enabled = Pattern::Make("enabled");
    ASSERT_TRUE(enabled.HasValue());
    params.unitFileState = std::move(enabled.Value());

    const std::string command = "systemctl show -p UnitFileState \"isc-dhcp-server.service\"";
    for (const auto& output : {"UnitFileState=\n", "UnitFileState=\nUnitFileState=\n"})
    {
        EXPECT_CALL(mContext, ExecuteCommand(command)).WillOnce(::testing::Return(Result<std::string>(output)));
        auto result = AuditSystemdUnitState(params, mIndicators, mContext);
        ASSERT_TRUE(result.HasValue()) << output;
        EXPECT_EQ(result.Value(), Status::NonCompliant) << output;
    }

    auto anyValue = Pattern::Make(".*");
    ASSERT_TRUE(anyValue.HasValue());
    params.unitFileState = std::move(anyValue.Value());
    EXPECT_CALL(mContext, ExecuteCommand(command)).WillOnce(::testing::Return(Result<std::string>("UnitFileState=\n")));
    auto result = AuditSystemdUnitState(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(SystemdUnitStateTest, OtherEmptyPropertiesRemainErrors)
{
    const struct
    {
        const char* field;
        const char* property;
    } cases[] = {
        {"activeState", "ActiveState"},
        {"subState", "SubState"},
        {"loadState", "LoadState"},
        {"unit", "Unit"},
    };
    for (const auto& testCase : cases)
    {
        const std::map<std::string, std::string> args = {{"unitName", "auditd.service"}, {testCase.field, "expected"}};
        auto params = ComplianceEngine::BindingsImpl::ParseArguments<SystemdUnitStateParams>(args);
        ASSERT_TRUE(params.HasValue()) << testCase.field;
        EXPECT_CALL(mContext, ExecuteCommand("systemctl show -p " + std::string(testCase.property) + " \"auditd.service\""))
            .WillOnce(::testing::Return(Result<std::string>(std::string(testCase.property) + "=\n")));
        auto result = AuditSystemdUnitState(params.Value(), mIndicators, mContext);
        EXPECT_FALSE(result.HasValue()) << testCase.property;
    }
}

TEST_F(SystemdUnitStateTest, EmptyUnitFileStateDoesNotHideIncompleteResponseUnderNot)
{
    auto json = JsonWrapper::FromString(R"({"not":{"SystemdUnitState":{"unitName":"auditd.service","unitFileState":"enabled","activeState":"active"}}})");
    ASSERT_TRUE(json.HasValue());
    ASSERT_TRUE(json->get());
    const std::string command = "systemctl show -p ActiveState -p UnitFileState \"auditd.service\"";
    for (const auto& output :
        {"UnitFileState=\n", "UnitFileState=\nActiveState=\n", "UnitFileState=\nOther=unexpected\n", "UnitFileState=\nActiveState"})
    {
        EXPECT_CALL(mContext, ExecuteCommand(command)).WillOnce(::testing::Return(Result<std::string>(output)));
        Evaluator evaluator("CIS systemd service check", json_value_get_object(json->get()), {}, mContext);
        auto result = evaluator.ExecuteAudit(ComplianceEngine::DebugFormatter{});
        EXPECT_FALSE(result.HasValue()) << output;
    }
    EXPECT_CALL(mContext, ExecuteCommand(command)).WillOnce(::testing::Return(Result<std::string>("UnitFileState=\nActiveState=active\n")));
    Evaluator evaluator("CIS systemd service check", json_value_get_object(json->get()), {}, mContext);
    auto result = evaluator.ExecuteAudit(ComplianceEngine::DebugFormatter{});
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value().status, Status::Compliant);
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
        {"UnitFileState=disabled\nUnitFileState=enabled\n", false, Status::NonCompliant},
        {"UnitFileState=disabled\nUnitFileState=disabled\n", true, Status::Compliant},
        {"UnitFileState=enabled\nUnitFileState=enabled\n", true, Status::NonCompliant},
        {"UnitFileState=\nUnitFileState=\n", true, Status::Compliant},
        {"UnitFileState=\nUnitFileState=enabled\n", false, Status::NonCompliant},
        {"UnitFileState=enabled\nUnitFileState=\n", false, Status::NonCompliant},
        {"", false, Status::NonCompliant},
        {"ActiveState=active\n", false, Status::NonCompliant},
        {"UnitFileState=\n", true, Status::Compliant},
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

TEST_F(SystemdUnitStateTest, NegatedMultiPropertyMismatchRequiresCompleteOutput)
{
    auto json = JsonWrapper::FromString(R"({"not":{"SystemdUnitState":{"unitName":"auditd.service","activeState":"active","subState":"running"}}})");
    ASSERT_TRUE(json.HasValue());
    ASSERT_TRUE(json->get());
    const std::string command = "systemctl show -p ActiveState -p SubState \"auditd.service\"";
    struct Case
    {
        std::string output;
        bool valid;
        Status expected;
    };
    const Case cases[] = {
        {"ActiveState=active\nSubState=running\n", true, Status::NonCompliant},
        {"ActiveState=active\nSubState=running\nSubState=running\n", true, Status::NonCompliant},
        {"ActiveState=inactive\nSubState=running\n", true, Status::Compliant},
        {"ActiveState=inactive\nSubState=running\nActiveState=inactive\n", true, Status::Compliant},
        {"ActiveState=inactive\nSubState=running\nActiveState=active\n", false, Status::NonCompliant},
        {"ActiveState=active\nSubState=running\nSubState=dead\n", false, Status::NonCompliant},
        {"ActiveState=inactive\n", false, Status::NonCompliant},
        {"ActiveState=inactive\nSubState", false, Status::NonCompliant},
        {"ActiveState=inactive\nSubState=\n", false, Status::NonCompliant},
        {"ActiveState=inactive\nOtherState=running\n", false, Status::NonCompliant},
    };
    for (const auto& testCase : cases)
    {
        EXPECT_CALL(mContext, ExecuteCommand(command)).WillOnce(::testing::Return(Result<std::string>(testCase.output)));
        Evaluator evaluator("negated auditd state", json_value_get_object(json->get()), {}, mContext);
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
