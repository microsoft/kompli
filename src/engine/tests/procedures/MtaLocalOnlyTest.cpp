// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "CommonContext.h"
#include "Evaluator.h"
#include "MockContext.h"
#include "NetworkTools.h"

#include <Bindings.h>
#include <MtaLocalOnly.h>
#include <ProcedureMap.h>
#include <arpa/inet.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <sys/socket.h>

using ComplianceEngine::AuditMtaLocalOnly;
using ComplianceEngine::Error;
using ComplianceEngine::IndicatorsTree;
using ComplianceEngine::MtaConfigurationVersion;
using ComplianceEngine::MtaLocalOnlyParams;
using ComplianceEngine::OpenPort;
using ComplianceEngine::Result;
using ComplianceEngine::Status;
using ComplianceEngine::BindingsImpl::ParseArguments;
using ::testing::Return;

class EnsureMTAsLocalOnlyTest : public ::testing::Test
{
protected:
    MockContext mockContext;
    IndicatorsTree indicators;

    void SetUp() override
    {
        indicators.Push("EnsureMTAsLocalOnly");
    }

    Result<Status> AuditConfigurationWithShell(const std::string& version, const std::string& commands)
    {
        ComplianceEngine::CommonContext context(nullptr, "/tmp");
        EXPECT_CALL(mockContext, ExecuteCommand("ss -ptuln")).WillOnce(Return(Result<std::string>("")));
        EXPECT_CALL(mockContext, ExecuteCommand(::testing::HasSubstr("command -v postconf"))).WillOnce(::testing::Invoke([&](const std::string& command) {
            return context.ExecuteCommand("PATH=/nonexistent; " + commands + command);
        }));
        const auto params = ParseArguments<MtaLocalOnlyParams>({{"configurationVersion", version}});
        if (!params.HasValue())
        {
            return params.Error();
        }
        return AuditMtaLocalOnly(params.Value(), indicators, mockContext);
    }

    OpenPort CreateOpenPort(int family, int type, const std::string& ip, unsigned short port)
    {
        OpenPort openPort;
        openPort.family = family;
        openPort.type = type;
        openPort.port = port;

        if (family == AF_INET)
        {
            inet_pton(AF_INET, ip.c_str(), &openPort.ip4);
        }
        else if (family == AF_INET6)
        {
            inet_pton(AF_INET6, ip.c_str(), &openPort.ip6);
        }

        return openPort;
    }
};

TEST_F(EnsureMTAsLocalOnlyTest, ConfigurationVersionBindings)
{
    const auto defaults = ParseArguments<MtaLocalOnlyParams>({});
    ASSERT_TRUE(defaults.HasValue());
    EXPECT_EQ(defaults.Value().configurationVersion.Value(), MtaConfigurationVersion::None);
    const std::vector<std::pair<std::string, MtaConfigurationVersion>> versions = {
        {"none", MtaConfigurationVersion::None},
        {"1", MtaConfigurationVersion::Version1},
        {"2", MtaConfigurationVersion::Version2},
        {"3", MtaConfigurationVersion::Version3},
    };
    for (const auto& version : versions)
    {
        const auto params = ParseArguments<MtaLocalOnlyParams>({{"configurationVersion", version.first}});
        ASSERT_TRUE(params.HasValue()) << version.first;
        EXPECT_EQ(params.Value().configurationVersion.Value(), version.second);
    }
    for (const auto& version : {"", "0", "4", "None", "Version1", "1 "})
    {
        EXPECT_FALSE(ParseArguments<MtaLocalOnlyParams>({{"configurationVersion", version}}).HasValue()) << version;
    }
}

TEST_F(EnsureMTAsLocalOnlyTest, GetOpenPortsFails_ReturnsError)
{
    EXPECT_CALL(mockContext, ExecuteCommand("ss -ptuln")).WillOnce(Return(Error("Command failed", 1)));

    auto result = AuditMtaLocalOnly({}, indicators, mockContext);

    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, 1);
}

TEST_F(EnsureMTAsLocalOnlyTest, NoOpenPorts_ReturnsCompliant)
{
    std::vector<OpenPort> emptyPorts;
    std::string output = "Netid  State   Recv-Q Send-Q  Local Address:Port  Peer Address:Port  Process\n";
    EXPECT_CALL(mockContext, ExecuteCommand("ss -ptuln")).WillOnce(Return(Result<std::string>(output)));

    auto result = AuditMtaLocalOnly({}, indicators, mockContext);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureMTAsLocalOnlyTest, ConfigurationCheckedWithoutListeningPorts)
{
    const std::vector<std::pair<std::string, Status>> cases = {
        {"inet_interfaces = all\n", Status::NonCompliant},
        {"inet_interfaces = ALL, localhost\n", Status::NonCompliant},
        {"inet_interfaces = localhost\n", Status::Compliant},
        {"inet_interfaces = loopback-only\n", Status::Compliant},
        {"local_interfaces = ::1\n", Status::Compliant},
        {"inet_interfaces = 192.168.1.20\n", Status::NonCompliant},
        {"", Status::Compliant},
    };
    ComplianceEngine::MtaLocalOnlyParams params;
    params.configurationVersion = MtaConfigurationVersion::Version2;
    for (const auto& entry : cases)
    {
        SCOPED_TRACE(entry.first);
        EXPECT_CALL(mockContext, ExecuteCommand("ss -ptuln")).WillOnce(Return(Result<std::string>("")));
        EXPECT_CALL(mockContext, ExecuteCommand(::testing::HasSubstr("command -v postconf"))).WillOnce(Return(Result<std::string>(entry.first)));
        const auto result = AuditMtaLocalOnly(params, indicators, mockContext);
        ASSERT_TRUE(result.HasValue());
        EXPECT_EQ(entry.second, result.Value());
    }
}

TEST_F(EnsureMTAsLocalOnlyTest, ConfigurationQueryFailureReturnsError)
{
    ComplianceEngine::MtaLocalOnlyParams params;
    params.configurationVersion = MtaConfigurationVersion::Version2;
    EXPECT_CALL(mockContext, ExecuteCommand("ss -ptuln")).WillOnce(Return(Result<std::string>("")));
    EXPECT_CALL(mockContext, ExecuteCommand(::testing::HasSubstr("command -v postconf"))).WillOnce(Return(Error("postconf failed", 1)));

    const auto result = AuditMtaLocalOnly(params, indicators, mockContext);
    ASSERT_FALSE(result.HasValue());
}

TEST_F(EnsureMTAsLocalOnlyTest, MissingPostfixConfigurationUsesSourceStdoutSemantics)
{
    const auto result = AuditConfigurationWithShell("3",
        "postconf() { printf '%s\\n' 'postconf: fatal: open /etc/postfix/main.cf: No such file or directory' >&2; return 1; }; ");
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(Status::Compliant, result.Value());
}

TEST_F(EnsureMTAsLocalOnlyTest, RealQueriesEvaluateStdoutIndependentlyOfStatusAndDiagnostics)
{
    const std::vector<std::pair<std::string, Status>> cases = {
        {"", Status::Compliant},
        {"inet_interfaces = loopback-only\n", Status::Compliant},
        {"local_interfaces = ::1\n", Status::Compliant},
        {"inet_interfaces = all\n", Status::NonCompliant},
        {"inet_interfaces = ALL, localhost\n", Status::NonCompliant},
        {"inet_interfaces = 192.0.2.1\n", Status::NonCompliant},
        {"inet_interfaces = $(touch /must-not-execute)\n", Status::NonCompliant},
    };
    for (const std::string version : {"1", "2", "3"})
    {
        for (const std::string utility : {"postconf", "exim"})
        {
            for (const int exitCode : {0, 1})
            {
                for (const auto& entry : cases)
                {
                    SCOPED_TRACE(version + ":" + utility + ":" + std::to_string(exitCode) + ":" + entry.first);
                    const auto result = AuditConfigurationWithShell(version, utility + "() { printf '%s' '" + entry.first +
                                                                                 "'; printf '%s\\n' 'diagnostic: all localhost' >&2; return " +
                                                                                 std::to_string(exitCode) + "; }; ");
                    ASSERT_TRUE(result.HasValue()) << result.Error().message;
                    EXPECT_EQ(entry.second, result.Value());
                }
            }
        }
    }
}

TEST_F(EnsureMTAsLocalOnlyTest, RealQueriesPreserveVersionAndSelectionOrder)
{
    for (const std::string version : {"1", "2", "3"})
    {
        SCOPED_TRACE(version);
        auto result = AuditConfigurationWithShell(version, "");
        ASSERT_TRUE(result.HasValue()) << result.Error().message;
        EXPECT_EQ(Status::Compliant, result.Value());

        result = AuditConfigurationWithShell(version, "postconf() { printf '%s\\n' 'inet_interfaces = localhost'; }; ");
        ASSERT_TRUE(result.HasValue()) << result.Error().message;
        EXPECT_EQ(version == "1" ? Status::NonCompliant : Status::Compliant, result.Value());

        result = AuditConfigurationWithShell(version,
            "postconf() { printf '%s\\n' 'inet_interfaces = all'; }; exim() { printf '%s\\n' 'local_interfaces = ::1'; }; ");
        ASSERT_TRUE(result.HasValue()) << result.Error().message;
        EXPECT_EQ(Status::NonCompliant, result.Value());

        result = AuditConfigurationWithShell(version, "postconf() { return 1; }; exim() { printf '%s\\n' 'local_interfaces = all'; }; ");
        ASSERT_TRUE(result.HasValue()) << result.Error().message;
        EXPECT_EQ(Status::Compliant, result.Value());
    }
}

TEST_F(EnsureMTAsLocalOnlyTest, RealSendmailQueryParsesAddressesAndHandlesMissingFile)
{
    const std::vector<std::pair<std::string, Status>> cases = {
        {"", Status::Compliant},
        {"O DaemonPortOptions=Port=smtp,Addr=127.0.0.1, Name=MTA", Status::Compliant},
        {"O DaemonPortOptions=Port=smtp,Addr=::1, Name=MTA", Status::Compliant},
        {"O DaemonPortOptions=Port=smtp,Addr=192.0.2.1, Name=MTA", Status::NonCompliant},
        {"O DaemonPortOptions=Port=smtp,Addr=127.0.0.1, Name=MTA\nO DaemonPortOptions=Port=smtp,Addr=192.0.2.1, Name=MTA", Status::NonCompliant},
    };
    for (const auto& entry : cases)
    {
        SCOPED_TRACE(entry.first);
        const auto result =
            AuditConfigurationWithShell("3", "sendmail() { :; }; awk() { printf '%s\\n' '" + entry.first + "' | /usr/bin/awk \"$1\"; }; ");
        ASSERT_TRUE(result.HasValue()) << result.Error().message;
        EXPECT_EQ(entry.second, result.Value());
    }
    const auto result =
        AuditConfigurationWithShell("3", "sendmail() { :; }; awk() { printf '%s\\n' 'awk: cannot open /etc/mail/sendmail.cf' >&2; return 2; }; ");
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(Status::Compliant, result.Value());
}

TEST_F(EnsureMTAsLocalOnlyTest, ConfigurationErrorsCannotHideNonlocalPorts)
{
    for (const std::string version : {"1", "2", "3"})
    {
        SCOPED_TRACE(version);
        EXPECT_CALL(mockContext, ExecuteCommand("ss -ptuln"))
            .WillOnce(Return(Result<std::string>("tcp LISTEN 0 128 0.0.0.0:25 0.0.0.0:* users:((\"postfix\",pid=1,fd=3))\n")));
        EXPECT_CALL(mockContext, ExecuteCommand(::testing::HasSubstr("command -v postconf"))).Times(0);
        const auto params = ParseArguments<MtaLocalOnlyParams>({{"configurationVersion", version}});
        ASSERT_TRUE(params.HasValue());
        const auto result = AuditMtaLocalOnly(params.Value(), indicators, mockContext);
        ASSERT_TRUE(result.HasValue()) << result.Error().message;
        EXPECT_EQ(Status::NonCompliant, result.Value());
    }
}

TEST_F(EnsureMTAsLocalOnlyTest, ConfigurationVersionsPreserveSourceDifferences)
{
    for (const std::string version : {"1", "2", "3"})
    {
        SCOPED_TRACE(version);
        const auto params = ParseArguments<MtaLocalOnlyParams>({{"configurationVersion", version}});
        ASSERT_TRUE(params.HasValue());
        EXPECT_CALL(mockContext, ExecuteCommand("ss -ptuln")).WillOnce(Return(Result<std::string>("")));
        EXPECT_CALL(mockContext, ExecuteCommand(::testing::HasSubstr("command -v postconf"))).WillOnce(::testing::Invoke([&](const std::string& command) -> Result<std::string> {
            EXPECT_EQ(version == "3", command.find("sendmail.cf") != std::string::npos);
            return std::string("inet_interfaces = localhost\n");
        }));
        const auto result = AuditMtaLocalOnly(params.Value(), indicators, mockContext);
        ASSERT_TRUE(result.HasValue());
        EXPECT_EQ(version == "1" ? Status::NonCompliant : Status::Compliant, result.Value());
    }
}

TEST_F(EnsureMTAsLocalOnlyTest, OnlyNonMTAPorts_ReturnsCompliant)
{
    std::string output =
        "Netid  State   Recv-Q Send-Q  Local Address:Port  Peer Address:Port  Process\n"
        "tcp    LISTEN  0      128           0.0.0.0:22         0.0.0.0:*     users:((\"sshd\",pid=1234,fd=3))\n"
        "tcp    LISTEN  0      128           0.0.0.0:80         0.0.0.0:*     users:((\"httpd\",pid=2345,fd=5))\n"
        "udp    UNCONN  0      0             0.0.0.0:53         0.0.0.0:*     users:((\"dns\",pid=3456,fd=7))\n";

    EXPECT_CALL(mockContext, ExecuteCommand("ss -ptuln")).WillOnce(Return(Result<std::string>(output)));

    auto result = AuditMtaLocalOnly({}, indicators, mockContext);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureMTAsLocalOnlyTest, MTAPortsOnLoopback_ReturnsCompliant)
{
    std::string output =
        "Netid  State   Recv-Q Send-Q  Local Address:Port  Peer Address:Port  Process\n"
        "tcp    LISTEN  0      128         127.0.0.1:25         0.0.0.0:*     users:((\"postfix\",pid=1234,fd=3))\n"
        "tcp    LISTEN  0      128         127.0.0.1:587        0.0.0.0:*     users:((\"postfix\",pid=1234,fd=4))\n"
        "tcp    LISTEN  0      128         127.0.0.1:465        0.0.0.0:*     users:((\"postfix\",pid=1234,fd=5))\n";

    EXPECT_CALL(mockContext, ExecuteCommand("ss -ptuln")).WillOnce(Return(Result<std::string>(output)));

    auto result = AuditMtaLocalOnly({}, indicators, mockContext);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureMTAsLocalOnlyTest, MTAPortsOnIPv6Loopback_ReturnsCompliant)
{
    std::string output =
        "Netid  State   Recv-Q Send-Q  Local Address:Port  Peer Address:Port  Process\n"
        "tcp    LISTEN  0      128              [::1]:25            [::]:*     users:((\"postfix\",pid=1234,fd=3))\n"
        "tcp    LISTEN  0      128              [::1]:587           [::]:*     users:((\"postfix\",pid=1234,fd=4))\n"
        "tcp    LISTEN  0      128              [::1]:465           [::]:*     users:((\"postfix\",pid=1234,fd=5))\n";

    EXPECT_CALL(mockContext, ExecuteCommand("ss -ptuln")).WillOnce(Return(Result<std::string>(output)));

    auto result = AuditMtaLocalOnly({}, indicators, mockContext);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureMTAsLocalOnlyTest, SMTPPort25OnPublicInterface_ReturnsNonCompliant)
{
    std::string output =
        "Netid  State   Recv-Q Send-Q  Local Address:Port  Peer Address:Port  Process\n"
        "tcp    LISTEN  0      128           0.0.0.0:25         0.0.0.0:*     users:((\"postfix\",pid=1234,fd=3))\n";

    EXPECT_CALL(mockContext, ExecuteCommand("ss -ptuln")).WillOnce(Return(Result<std::string>(output)));

    auto result = AuditMtaLocalOnly({}, indicators, mockContext);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureMTAsLocalOnlyTest, SMTPPort587OnPublicInterface_ReturnsNonCompliant)
{
    std::string output =
        "Netid  State   Recv-Q Send-Q  Local Address:Port  Peer Address:Port  Process\n"
        "tcp    LISTEN  0      128           0.0.0.0:587        0.0.0.0:*     users:((\"postfix\",pid=1234,fd=3))\n";

    EXPECT_CALL(mockContext, ExecuteCommand("ss -ptuln")).WillOnce(Return(Result<std::string>(output)));

    auto result = AuditMtaLocalOnly({}, indicators, mockContext);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureMTAsLocalOnlyTest, SMTPSPort465OnPublicInterface_ReturnsNonCompliant)
{
    std::string output =
        "Netid  State   Recv-Q Send-Q  Local Address:Port  Peer Address:Port  Process\n"
        "tcp    LISTEN  0      128           0.0.0.0:465        0.0.0.0:*     users:((\"postfix\",pid=1234,fd=3))\n";

    EXPECT_CALL(mockContext, ExecuteCommand("ss -ptuln")).WillOnce(Return(Result<std::string>(output)));

    auto result = AuditMtaLocalOnly({}, indicators, mockContext);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureMTAsLocalOnlyTest, MTAPortsOnIPv6PublicInterface_ReturnsNonCompliant)
{
    std::string output =
        "Netid  State   Recv-Q Send-Q  Local Address:Port  Peer Address:Port  Process\n"
        "tcp    LISTEN  0      128              [::]:25            [::]:*     users:((\"postfix\",pid=1234,fd=3))\n";

    EXPECT_CALL(mockContext, ExecuteCommand("ss -ptuln")).WillOnce(Return(Result<std::string>(output)));

    auto result = AuditMtaLocalOnly({}, indicators, mockContext);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureMTAsLocalOnlyTest, MixedLocalAndPublicPorts_ReturnsNonCompliant)
{
    std::string output =
        "Netid  State   Recv-Q Send-Q  Local Address:Port  Peer Address:Port  Process\n"
        "tcp    LISTEN  0      128         127.0.0.1:25         0.0.0.0:*     users:((\"postfix\",pid=1234,fd=3))\n"
        "tcp    LISTEN  0      128           0.0.0.0:587        0.0.0.0:*     users:((\"postfix\",pid=1234,fd=4))\n"
        "tcp    LISTEN  0      128         127.0.0.1:465        0.0.0.0:*     users:((\"postfix\",pid=1234,fd=5))\n";

    EXPECT_CALL(mockContext, ExecuteCommand("ss -ptuln")).WillOnce(Return(Result<std::string>(output)));

    auto result = AuditMtaLocalOnly({}, indicators, mockContext);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureMTAsLocalOnlyTest, UDPMTAPortOnPublicInterface_ReturnsNonCompliant)
{
    std::string output =
        "Netid  State   Recv-Q Send-Q  Local Address:Port  Peer Address:Port  Process\n"
        "udp    UNCONN  0      0             0.0.0.0:25         0.0.0.0:*     users:((\"postfix\",pid=1234,fd=3))\n";

    EXPECT_CALL(mockContext, ExecuteCommand("ss -ptuln")).WillOnce(Return(Result<std::string>(output)));

    auto result = AuditMtaLocalOnly({}, indicators, mockContext);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureMTAsLocalOnlyTest, SpecificPrivateIPAddress_ReturnsNonCompliant)
{
    std::string output =
        "Netid  State   Recv-Q Send-Q  Local Address:Port  Peer Address:Port  Process\n"
        "tcp    LISTEN  0      128        192.168.1.100:25       0.0.0.0:*     users:((\"postfix\",pid=1234,fd=3))\n";

    EXPECT_CALL(mockContext, ExecuteCommand("ss -ptuln")).WillOnce(Return(Result<std::string>(output)));

    auto result = AuditMtaLocalOnly({}, indicators, mockContext);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureMTAsLocalOnlyTest, MultipleNonCompliantPorts_ReturnsNonCompliantForFirst)
{
    std::string output =
        "Netid  State   Recv-Q Send-Q  Local Address:Port  Peer Address:Port  Process\n"
        "tcp    LISTEN  0      128           0.0.0.0:25         0.0.0.0:*     users:((\"postfix\",pid=1234,fd=3))\n"
        "tcp    LISTEN  0      128           0.0.0.0:587        0.0.0.0:*     users:((\"postfix\",pid=1234,fd=4))\n"
        "tcp    LISTEN  0      128           0.0.0.0:465        0.0.0.0:*     users:((\"postfix\",pid=1234,fd=5))\n";

    EXPECT_CALL(mockContext, ExecuteCommand("ss -ptuln")).WillOnce(Return(Result<std::string>(output)));

    auto result = AuditMtaLocalOnly({}, indicators, mockContext);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
}
