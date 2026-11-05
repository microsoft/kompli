// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "MockContext.h"

#include <SshdOption.h>
#include <algorithm>
#include <fstream>
#include <iterator>
#include <sys/stat.h>
#include <unistd.h>

using namespace ComplianceEngine;
using testing::_;
using testing::Invoke;

class SshdOptionRemediationTest : public testing::Test
{
protected:
    MockContext context;
    IndicatorsTree indicators;
    SshdOptionParams params;
    std::string config;
    std::string original = "# administrator configuration\nPort 22\nPermitRootLogin yes\n";
    std::string effectiveValue = "yes";
    std::string startup = "{ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D $OPTIONS ; }";
    std::vector<std::string> commands;
    int syntaxCalls = 0;
    int reloadCalls = 0;
    int failSyntax = 0;
    int failReload = 0;
    bool failRecovery = false;
    bool failEffective = false;
    bool activeService = true;
    bool concurrentChange = false;

    static Result<std::string> Read(const std::string& path)
    {
        std::ifstream input(path);
        if (!input.is_open())
        {
            return Error("Cannot read fixture: " + path, ENOENT);
        }
        return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
    }

    void SetUp() override
    {
        indicators.Push("SshdOption");
        params.option = {{"permitrootlogin"}};
        params.value = "no";
        params.remediationValue = std::string("no");
        config = context.MakeTempfile(original);
        context.SetSpecialFilePath("/etc/ssh/sshd_config", config);
        context.SetSpecialFilePath("/etc/default/ssh", context.GetTempdirPath() + "/default-ssh");
        context.SetSpecialFilePath("/etc/sysconfig/sshd", context.GetTempdirPath() + "/sysconfig-sshd");
        EXPECT_CALL(context, GetFileContents(_)).WillRepeatedly([this](const std::string& path) { return Read(context.GetSpecialFilePath(path)); });
        EXPECT_CALL(context, ExecuteCommand(_)).WillRepeatedly(Invoke(this, &SshdOptionRemediationTest::Execute));
    }

    Result<std::string> Execute(const std::string& command)
    {
        commands.push_back(command);
        if (command == "sshd -T" || command == "sshd -T 2>&1")
        {
            const auto prefix =
                "# kompli: explicit global SSH option\n" + params.option.items.front() + " " + params.remediationValue.ValueOr("") + "\n";
            const bool updated = Read(config).Value().find(prefix) == 0;
            return params.option.items.front() + " " + (updated && !failEffective ? params.remediationValue.Value() : effectiveValue) + "\n";
        }
        if (command == "sshd -t")
        {
            if (++syntaxCalls == failSyntax)
            {
                if (concurrentChange)
                {
                    std::ofstream(config) << "# concurrent administrator update\n";
                }
                return Error("syntax failed", EINVAL);
            }
            return std::string();
        }
        if (command.find("--property=LoadState") != std::string::npos)
        {
            return std::string("LoadState=loaded\nActiveState=") + (activeService ? "active\n" : "inactive\n");
        }
        if (command.find("--property=ExecStart") != std::string::npos)
        {
            return startup;
        }
        if (command.find("systemctl reload ") == 0)
        {
            ++reloadCalls;
            if (reloadCalls == failReload || (failRecovery && reloadCalls > 1))
            {
                return Error("reload failed", EIO);
            }
            return std::string();
        }
        return Error("Unexpected command: " + command, EINVAL);
    }

    void ExpectRefusal()
    {
        auto result = RemediateSshdOption(params, indicators, context);
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ(original, Read(config).Value());
        EXPECT_EQ(0, reloadCalls);
    }
};

TEST_F(SshdOptionRemediationTest, ConvergesPreservingContentAndMetadata)
{
    ASSERT_EQ(0, chmod(config.c_str(), 0640));
    auto result = RemediateSshdOption(params, indicators, context);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(Status::Compliant, result.Value());
    EXPECT_EQ("# kompli: explicit global SSH option\npermitrootlogin no\n# administrator configuration\nPort 22\nPermitRootLogin no\n", Read(config).Value());
    EXPECT_EQ(2, syntaxCalls);
    EXPECT_EQ(1, reloadCalls);
    struct stat metadata;
    ASSERT_EQ(0, stat(config.c_str(), &metadata));
    EXPECT_EQ(0640U, metadata.st_mode & 0777U);
}

TEST_F(SshdOptionRemediationTest, AlreadyCompliantDoesNotWriteOrReload)
{
    effectiveValue = "no";
    original = "PermitRootLogin no\n";
    std::ofstream(config) << original;
    auto result = RemediateSshdOption(params, indicators, context);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());
    EXPECT_EQ(original, Read(config).Value());
    EXPECT_EQ(0, syntaxCalls);
    EXPECT_EQ(0, reloadCalls);
}

TEST_F(SshdOptionRemediationTest, MissingTargetRemainsAuditOnly)
{
    SshdOptionParams auditOnly;
    auditOnly.option = params.option;
    auditOnly.value = params.value;
    auto result = RemediateSshdOption(auditOnly, indicators, context);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::NonCompliant, result.Value());
    EXPECT_EQ(original, Read(config).Value());
    EXPECT_EQ(0, reloadCalls);
}

TEST_F(SshdOptionRemediationTest, AllMatchesRemainsAuditOnly)
{
    params.mode = SshdOptionMode::AllMatches;
    auto result = RemediateSshdOption(params, indicators, context);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());
    EXPECT_TRUE(commands.empty());
}

TEST_F(SshdOptionRemediationTest, RejectsTargetThatDoesNotSatisfyCustomerAudit)
{
    params.value = "^prohibit-password$";
    ExpectRefusal();
    EXPECT_TRUE(commands.empty());
}

TEST_F(SshdOptionRemediationTest, RejectsTargetOutsideCustomerNumericThreshold)
{
    params.option = {{"maxauthtries"}};
    params.value = "2";
    params.op = SshdOptionOperation::LessOrEqual;
    params.remediationValue = std::string("4");
    ExpectRefusal();
    EXPECT_TRUE(commands.empty());
}

TEST_F(SshdOptionRemediationTest, RejectsUnsafeTargetAndUnsupportedOptions)
{
    for (const std::string value : {"no\nPort 23", "no;true", "yes", ""})
    {
        params.remediationValue = value;
        ExpectRefusal();
    }
    params.remediationValue = std::string("no");
    params.option = {{"allowusers"}};
    ExpectRefusal();
    params.option = {{"permitrootlogin", "gssapiauthentication"}};
    ExpectRefusal();
    EXPECT_TRUE(commands.empty());
}

TEST_F(SshdOptionRemediationTest, RejectsMainMatchWithoutEditingIt)
{
    original += "Match User administrator\n  PermitRootLogin yes\n";
    std::ofstream(config) << original;
    ExpectRefusal();
    EXPECT_EQ(0, syntaxCalls);
}

TEST_F(SshdOptionRemediationTest, RejectsIncludedMatchWithoutEditingSources)
{
    auto included = context.MakeTempfile("Match all\nPermitRootLogin yes\n");
    original = "Include " + included + "\n" + original;
    std::ofstream(config) << original;
    ExpectRefusal();
    EXPECT_EQ("Match all\nPermitRootLogin yes\n", Read(included).Value());
}

TEST_F(SshdOptionRemediationTest, PreservesGlobalIncludesAndOverridesBeforeThem)
{
    auto included = context.MakeTempfile("PermitRootLogin yes\n");
    original = "Include " + included + "\n" + original;
    std::ofstream(config) << original;
    auto result = RemediateSshdOption(params, indicators, context);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ("# kompli: explicit global SSH option\npermitrootlogin no\nInclude " + included +
                  "\n# administrator configuration\nPort 22\nPermitRootLogin no\n",
        Read(config).Value());
    EXPECT_EQ("PermitRootLogin no\n", Read(included).Value());
}

TEST_F(SshdOptionRemediationTest, ChecksWildcardAndRelativeIncludes)
{
    const auto directory = context.GetTempdirPath() + "/sshd_config.d";
    ASSERT_EQ(0, mkdir(directory.c_str(), 0700));
    std::ofstream(directory + "/conditional.conf") << "Match all\n";
    context.SetSpecialFilePath("/etc/ssh/sshd_config.d/*.conf", directory + "/*.conf");
    original = "Include sshd_config.d/*.conf\n" + original;
    std::ofstream(config) << original;
    ExpectRefusal();
}

TEST_F(SshdOptionRemediationTest, TreatsMissingIncludeDirectoryAsNoMatches)
{
    context.SetSpecialFilePath("/etc/ssh/sshd_config.d/*.conf", context.GetTempdirPath() + "/absent.d/*.conf");
    original = "Include /etc/ssh/sshd_config.d/*.conf\n" + original;
    std::ofstream(config) << original;
    auto result = RemediateSshdOption(params, indicators, context);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(Status::Compliant, result.Value());
    EXPECT_EQ(1, reloadCalls);
}

TEST_F(SshdOptionRemediationTest, RefusesUnreadableIncludeDirectory)
{
    if (geteuid() == 0)
    {
        GTEST_SKIP() << "Root bypasses directory read permissions";
    }
    const auto directory = context.GetTempdirPath() + "/unreadable.d";
    ASSERT_EQ(0, mkdir(directory.c_str(), 0000));
    context.SetSpecialFilePath("/etc/ssh/sshd_config.d/*.conf", directory + "/*.conf");
    original = "Include /etc/ssh/sshd_config.d/*.conf\n" + original;
    std::ofstream(config) << original;
    ExpectRefusal();
    ASSERT_EQ(0, chmod(directory.c_str(), 0700));
}

TEST_F(SshdOptionRemediationTest, RejectsRecursiveIncludes)
{
    original = "Include " + config + "\n" + original;
    std::ofstream(config) << original;
    ExpectRefusal();
}

TEST_F(SshdOptionRemediationTest, RejectsQuotedIncludesAndContinuations)
{
    original = "Include \"a b\"\n" + original;
    std::ofstream(config) << original;
    ExpectRefusal();
    original = "Include test\\\nconfig\n";
    std::ofstream(config) << original;
    ExpectRefusal();
}

TEST_F(SshdOptionRemediationTest, RefusesInvalidOriginalSyntax)
{
    failSyntax = 1;
    ExpectRefusal();
    EXPECT_EQ(1, syntaxCalls);
}

TEST_F(SshdOptionRemediationTest, RollsBackInvalidCandidateBeforeReload)
{
    failSyntax = 2;
    ExpectRefusal();
}

TEST_F(SshdOptionRemediationTest, RollsBackIneffectiveCandidateBeforeReload)
{
    failEffective = true;
    ExpectRefusal();
    EXPECT_EQ(2, syntaxCalls);
}

TEST_F(SshdOptionRemediationTest, RecoversOriginalConfigurationWhenReloadFails)
{
    failReload = 1;
    auto result = RemediateSshdOption(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(original, Read(config).Value());
    EXPECT_EQ(2, reloadCalls);
    EXPECT_EQ(3, syntaxCalls);
}

TEST_F(SshdOptionRemediationTest, ReportsReloadRecoveryFailure)
{
    failReload = 1;
    failRecovery = true;
    auto result = RemediateSshdOption(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_NE(std::string::npos, result.Error().message.find("reload recovery failed"));
    EXPECT_EQ(original, Read(config).Value());
}

TEST_F(SshdOptionRemediationTest, RefusesToOverwriteConcurrentAdministratorUpdateDuringRollback)
{
    failSyntax = 2;
    concurrentChange = true;
    auto result = RemediateSshdOption(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_NE(std::string::npos, result.Error().message.find("rollback refused"));
    EXPECT_EQ("# concurrent administrator update\n", Read(config).Value());
    EXPECT_EQ(0, reloadCalls);
}

TEST_F(SshdOptionRemediationTest, RefusesCustomStartupAndInactiveServices)
{
    startup = "{ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D -f /other/config ; }";
    ExpectRefusal();
    activeService = false;
    ExpectRefusal();
}

TEST_F(SshdOptionRemediationTest, RefusesCustomEnvironmentOptions)
{
    const auto environment = context.MakeTempfile("SSHD_OPTS=\"-o PermitRootLogin=yes\"\n");
    context.SetSpecialFilePath("/etc/default/ssh", environment);
    ExpectRefusal();
    std::ofstream(environment) << "OPTIONS='-f /other/config'\n";
    ExpectRefusal();
}

TEST_F(SshdOptionRemediationTest, AcceptsEmptyEnvironmentOptions)
{
    const auto environment = context.MakeTempfile("# options\nSSHD_OPTS=\"\"\n");
    context.SetSpecialFilePath("/etc/default/ssh", environment);
    auto result = RemediateSshdOption(params, indicators, context);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());
}

TEST_F(SshdOptionRemediationTest, RejectsSymlinkAndHardlinkMainConfigurations)
{
    const auto alias = context.GetTempdirPath() + "/alias";
    ASSERT_EQ(0, symlink(config.c_str(), alias.c_str()));
    context.SetSpecialFilePath("/etc/ssh/sshd_config", alias);
    ExpectRefusal();
    ASSERT_EQ(0, unlink(alias.c_str()));
    ASSERT_EQ(0, link(config.c_str(), alias.c_str()));
    context.SetSpecialFilePath("/etc/ssh/sshd_config", config);
    ExpectRefusal();
}

TEST_F(SshdOptionRemediationTest, ExplicitTargetsCoverAllEightFirstSliceOptions)
{
    for (const auto& entry :
        std::map<std::string, std::string>{{"maxauthtries", "4"}, {"logingracetime", "60"}, {"maxstartups", "10:30:60"}, {"disableforwarding", "yes"},
            {"permitrootlogin", "no"}, {"gssapiauthentication", "no"}, {"clientaliveinterval", "300"}, {"clientalivecountmax", "3"}})
    {
        SCOPED_TRACE(entry.first);
        std::ofstream(config) << original;
        params.option = {{entry.first}};
        params.value = entry.second;
        params.remediationValue = entry.second;
        effectiveValue = entry.first == "disableforwarding" ? "no" : "99";
        auto result = RemediateSshdOption(params, indicators, context);
        ASSERT_TRUE(result.HasValue()) << result.Error().message;
        EXPECT_EQ(Status::Compliant, result.Value());
    }
}

TEST_F(SshdOptionRemediationTest, CleansContradictoryBooleansWhenEffectiveValueAlreadyComplies)
{
    effectiveValue = "no";
    original = "# policy\nPermitRootLogin no\n PermitRootLogin=yes # old setting\n";
    std::ofstream(config) << original;
    auto result = RemediateSshdOption(params, indicators, context);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ("# policy\nPermitRootLogin no\n PermitRootLogin no # old setting\n", Read(config).Value());
    EXPECT_EQ(1, reloadCalls);
}

TEST_F(SshdOptionRemediationTest, PreservesCompliantDeclarationAllowedByCustomerAudit)
{
    params.value = "^(no|prohibit-password)$";
    effectiveValue = "prohibit-password";
    original = "PermitRootLogin prohibit-password\n";
    std::ofstream(config) << original;
    auto result = RemediateSshdOption(params, indicators, context);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(Status::Compliant, result.Value());
    EXPECT_EQ(original, Read(config).Value());
    EXPECT_EQ(0, syntaxCalls);
    EXPECT_EQ(0, reloadCalls);
}

TEST_F(SshdOptionRemediationTest, RewritesOnlyContradictoryDeclarationsAllowedByCustomerAudit)
{
    params.value = "^(no|prohibit-password)$";
    effectiveValue = "prohibit-password";
    original = "PermitRootLogin \"prohibit-password\"\nPermitRootLogin yes\n";
    std::ofstream(config) << original;
    auto result = RemediateSshdOption(params, indicators, context);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(Status::Compliant, result.Value());
    EXPECT_EQ("PermitRootLogin \"prohibit-password\"\nPermitRootLogin no\n", Read(config).Value());
    EXPECT_EQ(1, reloadCalls);
}

TEST_F(SshdOptionRemediationTest, CleansConflictingIncludedBooleansWithoutChangingOtherSettings)
{
    effectiveValue = "no";
    auto included = context.MakeTempfile("# drop-in\nGSSAPIAuthentication yes\nPermitRootLogin yes # conflicting\n");
    original = "PermitRootLogin no\nInclude " + included + "\n";
    std::ofstream(config) << original;
    ASSERT_EQ(0, chmod(included.c_str(), 0640));
    auto result = RemediateSshdOption(params, indicators, context);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(original, Read(config).Value());
    EXPECT_EQ("# drop-in\nGSSAPIAuthentication yes\nPermitRootLogin no # conflicting\n", Read(included).Value());
    struct stat metadata;
    ASSERT_EQ(0, stat(included.c_str(), &metadata));
    EXPECT_EQ(0640U, metadata.st_mode & 0777U);
    EXPECT_EQ(1, reloadCalls);
}

TEST_F(SshdOptionRemediationTest, PreservesStricterAlreadyCompliantNumericValue)
{
    params.option = {{"maxauthtries"}};
    params.value = "4";
    params.op = SshdOptionOperation::LessOrEqual;
    params.remediationValue = std::string("4");
    effectiveValue = "2";
    original = "MaxAuthTries 2\n";
    std::ofstream(config) << original;
    auto result = RemediateSshdOption(params, indicators, context);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(original, Read(config).Value());
    EXPECT_EQ(0, reloadCalls);
}

TEST_F(SshdOptionRemediationTest, RestoresEverySourceWhenCandidateSyntaxFails)
{
    auto included = context.MakeTempfile("PermitRootLogin yes\n");
    original = "Include=" + included + "\nPermitRootLogin yes\n";
    std::ofstream(config) << original;
    failSyntax = 2;
    ExpectRefusal();
    EXPECT_EQ("PermitRootLogin yes\n", Read(included).Value());
}

TEST_F(SshdOptionRemediationTest, RestoresEverySourceAndReloadsOriginalOnReloadFailure)
{
    auto included = context.MakeTempfile("PermitRootLogin yes\n");
    original = "Include " + included + "\nPermitRootLogin yes\n";
    std::ofstream(config) << original;
    failReload = 1;
    auto result = RemediateSshdOption(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(original, Read(config).Value());
    EXPECT_EQ("PermitRootLogin yes\n", Read(included).Value());
    EXPECT_EQ(2, reloadCalls);
}

TEST_F(SshdOptionRemediationTest, RefusesSymlinkedIncludedSourceBeforeAnyWrite)
{
    auto included = context.MakeTempfile("PermitRootLogin yes\n");
    auto alias = context.GetTempdirPath() + "/symlink";
    ASSERT_EQ(0, symlink(included.c_str(), alias.c_str()));
    original = "Include " + alias + "\n" + original;
    std::ofstream(config) << original;
    ExpectRefusal();
    EXPECT_EQ("PermitRootLogin yes\n", Read(included).Value());
    EXPECT_EQ(0, syntaxCalls);
}

TEST_F(SshdOptionRemediationTest, RefusesHardlinkedIncludedSourceBeforeAnyWrite)
{
    auto included = context.MakeTempfile("PermitRootLogin yes\n");
    auto alias = context.GetTempdirPath() + "/hardlink";
    ASSERT_EQ(0, link(included.c_str(), alias.c_str()));
    original = "Include " + alias + "\n" + original;
    std::ofstream(config) << original;
    ExpectRefusal();
    EXPECT_EQ(0, syntaxCalls);
}

TEST_F(SshdOptionRemediationTest, RecognizesEqualsSeparatedConditionalBlocks)
{
    original += "Match=all\nPermitRootLogin yes\n";
    std::ofstream(config) << original;
    ExpectRefusal();
    EXPECT_EQ(0, syntaxCalls);
}

TEST_F(SshdOptionRemediationTest, RestoresOwnedSourceWhenAnotherSourceChangedConcurrently)
{
    const auto included = context.MakeTempfile("PermitRootLogin yes\n");
    original = "Include " + included + "\n" + original;
    std::ofstream(config) << original;
    EXPECT_CALL(context, GetFileContents(included))
        .WillOnce([](const std::string&) -> Result<std::string> { return std::string("PermitRootLogin yes\n"); })
        .WillOnce([](const std::string& path) -> Result<std::string> {
            std::ofstream(path) << "# concurrent update\n";
            return std::string("# concurrent update\n");
        });
    auto result = RemediateSshdOption(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(original, Read(config).Value());
    EXPECT_EQ("# concurrent update\n", Read(included).Value());
    EXPECT_EQ(0, reloadCalls);
}
