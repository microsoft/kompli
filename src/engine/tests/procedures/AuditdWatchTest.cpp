// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "MockContext.h"

#include <AuditdRules.h>
#include <AuditdWatch.h>
#include <JsonWrapper.h>
#include <fstream>
#include <iterator>

using namespace ComplianceEngine;
using testing::_;
using testing::Invoke;
using testing::Return;

class AuditdWatchTest : public testing::Test
{
protected:
    MockContext context;
    IndicatorsTree indicators;
    AuditdWatchParams params;
    std::string directory;
    std::string managed;
    std::string target;
    std::string runtime;
    std::string status = "enabled 1\npid 123\n";
    std::string loader = "{ path=/sbin/augenrules ; argv[]=/sbin/augenrules --load ; ignore_errors=yes ; }\n";
    std::string dependencies;
    std::string dependencyType = "oneshot";
    std::string dependencyLoadState = "loaded";
    std::string dependencyAfter = "auditd.service system.slice";
    std::string dependencyCommand = "{ path=/usr/sbin/augenrules ; argv[]=/usr/sbin/augenrules --load ; ignore_errors=no ; }\n";
    const std::string line = "-w /etc/sudoers -p wa -k kompli_watch\n";
    const std::string add = "auditctl -w '/etc/sudoers' -p wa -k kompli_watch";
    const std::string remove = "auditctl -W '/etc/sudoers' -p wa -k kompli_watch";
    const std::string loaderCommand = "systemctl show auditd.service --property=ExecStartPost --value";
    int additions = 0;
    int removals = 0;

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
        indicators.Push("AuditdWatch");
        params.path = "/etc/sudoers";
        params.permissions = "wa";
        directory = context.GetTempdirPath() + "/rules.d";
        ASSERT_EQ(0, mkdir(directory.c_str(), 0755));
        managed = directory + "/70-kompli-watch-2f6574632f7375646f657273-wa.rules";
        target = context.MakeTempfile("# sudoers fixture\n");
        context.SetSpecialFilePath("/etc/audit/rules.d", directory);
        context.SetSpecialFilePath(params.path, target);
        EXPECT_CALL(context, GetFileContents(_)).WillRepeatedly(Invoke(Read));
        EXPECT_CALL(context, ExecuteCommand(_)).Times(0);
        EXPECT_CALL(context, ExecuteCommand("auditctl -s")).WillRepeatedly(Invoke([&](const std::string&) { return status; }));
        EXPECT_CALL(context, ExecuteCommand(loaderCommand)).WillRepeatedly(Invoke([&](const std::string&) { return loader; }));
        EXPECT_CALL(context, ExecuteCommand("systemctl show auditd.service --property=Requires --property=Wants --value")).WillRepeatedly(Invoke([&](const std::string&) {
            return dependencies;
        }));
        EXPECT_CALL(context, ExecuteCommand("auditctl -l")).WillRepeatedly(Invoke([&](const std::string&) {
            return runtime.empty() ? "No rules\n" : runtime;
        }));
        EXPECT_CALL(context, ExecuteCommand(add)).WillRepeatedly(Invoke([&](const std::string&) {
            ++additions;
            runtime += line;
            return std::string();
        }));
        EXPECT_CALL(context, ExecuteCommand(remove)).WillRepeatedly(Invoke([&](const std::string&) {
            ++removals;
            const auto position = runtime.find(line);
            if (position != std::string::npos)
            {
                runtime.erase(position, line.size());
            }
            return std::string();
        }));
    }

    void Source(const std::string& name, const std::string& contents)
    {
        std::ofstream(directory + "/" + name) << contents;
    }

    void VendorLoader(const std::string& unit)
    {
        loader.clear();
        dependencies = "system.slice " + unit;
        EXPECT_CALL(context, ExecuteCommand("systemctl show " + unit + " --property=Type --value")).WillRepeatedly(Invoke([&](const std::string&) {
            return dependencyType;
        }));
        EXPECT_CALL(context, ExecuteCommand("systemctl show " + unit + " --property=LoadState --value")).WillRepeatedly(Invoke([&](const std::string&) {
            return dependencyLoadState;
        }));
        EXPECT_CALL(context, ExecuteCommand("systemctl show " + unit + " --property=After --value")).WillRepeatedly(Invoke([&](const std::string&) {
            return dependencyAfter;
        }));
        EXPECT_CALL(context, ExecuteCommand("systemctl show " + unit + " --property=ExecStart --value")).WillRepeatedly(Invoke([&](const std::string&) {
            return dependencyCommand;
        }));
    }

    void ExpectUnchanged()
    {
        EXPECT_EQ(additions, 0);
        EXPECT_EQ(removals, 0);
        EXPECT_EQ(-1, access(managed.c_str(), F_OK));
    }
};

TEST_F(AuditdWatchTest, SupportsRhelAuditRulesDependencyWithoutGlobalLoad)
{
    VendorLoader("audit-rules.service");
    auto result = RemediateAuditdWatch(params, indicators, context);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());
    EXPECT_EQ(1, additions);
    EXPECT_EQ(0, removals);
}

TEST_F(AuditdWatchTest, SupportsSuseAugenrulesDependencyWithoutGlobalLoad)
{
    VendorLoader("augenrules.service");
    dependencyCommand = "{ path=/sbin/augenrules ; argv[]=/sbin/augenrules --load ; ignore_errors=no ; }\n";
    auto result = RemediateAuditdWatch(params, indicators, context);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());
    EXPECT_EQ(1, additions);
}

TEST_F(AuditdWatchTest, RefusesUnorderedLoaderDependency)
{
    VendorLoader("audit-rules.service");
    dependencyAfter = "system.slice local-fs.target";
    auto result = RemediateAuditdWatch(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(ENOTSUP, result.Error().code);
    ExpectUnchanged();
}

TEST_F(AuditdWatchTest, RefusesMaskedLoaderDependency)
{
    VendorLoader("audit-rules.service");
    dependencyLoadState = "masked";
    auto result = RemediateAuditdWatch(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(ENOTSUP, result.Error().code);
    ExpectUnchanged();
}

TEST_F(AuditdWatchTest, RefusesNonOneshotLoaderDependency)
{
    VendorLoader("audit-rules.service");
    dependencyType = "simple";
    auto result = RemediateAuditdWatch(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(ENOTSUP, result.Error().code);
    ExpectUnchanged();
}

TEST_F(AuditdWatchTest, RefusesDirectCompiledFileLoaderDependency)
{
    VendorLoader("augenrules.service");
    dependencyCommand = "{ path=/sbin/auditctl ; argv[]=/sbin/auditctl -R /etc/audit/audit.rules ; ignore_errors=no ; }\n";
    auto result = RemediateAuditdWatch(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(ENOTSUP, result.Error().code);
    ExpectUnchanged();
}

TEST_F(AuditdWatchTest, RefusesMultipleLoaderDependencies)
{
    loader.clear();
    dependencies = "audit-rules.service augenrules.service";
    auto result = RemediateAuditdWatch(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(ENOTSUP, result.Error().code);
    ExpectUnchanged();
}

TEST_F(AuditdWatchTest, LoaderDependencyInspectionErrorsPropagate)
{
    VendorLoader("augenrules.service");
    EXPECT_CALL(context, ExecuteCommand("systemctl show augenrules.service --property=LoadState --value"))
        .WillOnce(Return(Result<std::string>(Error("inspection failed", EIO))));
    auto result = RemediateAuditdWatch(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EIO, result.Error().code);
    ExpectUnchanged();
}

TEST_F(AuditdWatchTest, CreatesPersistentSourceAndAddsOnlySelectedRuntimeWatch)
{
    runtime = "-w /etc/passwd -p wa -k administrator\n";
    Source("administrator.rules", runtime);
    auto result = RemediateAuditdWatch(params, indicators, context);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
    EXPECT_EQ(runtime, "-w /etc/passwd -p wa -k administrator\n" + line);
    EXPECT_EQ(Read(managed).Value(), "# Managed by kompli\n" + line);
    EXPECT_EQ(Read(directory + "/administrator.rules").Value(), "-w /etc/passwd -p wa -k administrator\n");
    struct stat metadata;
    ASSERT_EQ(0, stat(managed.c_str(), &metadata));
    EXPECT_EQ(metadata.st_mode & 0777U, 0600U);
    EXPECT_EQ(additions, 1);
    EXPECT_EQ(removals, 0);
    EXPECT_CALL(context, GetFileContents("/etc/login.defs")).WillRepeatedly(Return(std::string("UID_MIN 1000\n")));
    AuditdRulesParams original;
    original.searchItem = "-w /etc/sudoers";
    original.requiredOptions.items = {"-p wa"};
    EXPECT_EQ(AuditAuditdRules(original, indicators, context).Value(), Status::Compliant);
}

TEST_F(AuditdWatchTest, IsIdempotentWithoutReplacingSourceOrAddingDuplicateRule)
{
    ASSERT_EQ(RemediateAuditdWatch(params, indicators, context).Value(), Status::Compliant);
    struct stat before;
    ASSERT_EQ(0, stat(managed.c_str(), &before));
    ASSERT_EQ(RemediateAuditdWatch(params, indicators, context).Value(), Status::Compliant);
    struct stat after;
    ASSERT_EQ(0, stat(managed.c_str(), &after));
    EXPECT_EQ(before.st_ino, after.st_ino);
    EXPECT_EQ(before.st_mtim.tv_sec, after.st_mtim.tv_sec);
    EXPECT_EQ(before.st_mtim.tv_nsec, after.st_mtim.tv_nsec);
    EXPECT_EQ(additions, 1);
}

TEST_F(AuditdWatchTest, ReusesExistingAdministratorRuntimeWatch)
{
    runtime = "-w /etc/sudoers -p wa -k administrator\n";
    auto result = RemediateAuditdWatch(params, indicators, context);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
    EXPECT_EQ(runtime, "-w /etc/sudoers -p wa -k administrator\n");
    EXPECT_EQ(additions, 0);
    EXPECT_EQ(Read(managed).Value(), "# Managed by kompli\n" + line);
}

TEST_F(AuditdWatchTest, ReusesExistingPersistentSourceWithoutChangingIt)
{
    const std::string original = "# administrator\n-w /etc/sudoers -p wa\n";
    Source("administrator.rules", original);
    auto result = RemediateAuditdWatch(params, indicators, context);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
    EXPECT_EQ(Read(directory + "/administrator.rules").Value(), original);
    EXPECT_EQ(-1, access(managed.c_str(), F_OK));
    EXPECT_EQ(additions, 1);
}

TEST_F(AuditdWatchTest, DoesNotMutateCompliantImmutableSystems)
{
    status = "enabled 2\npid 123\n";
    runtime = line;
    Source("administrator.rules", line);
    auto result = RemediateAuditdWatch(params, indicators, context);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
    ExpectUnchanged();
}

TEST_F(AuditdWatchTest, RefusesMutableChangesWhenAuditIsImmutableOrDisabled)
{
    for (const auto& value : {"enabled 2\npid 123\n", "enabled 0\npid 123\n", "pid 0\n", "enabled 1\npid 0\n", ""})
    {
        status = value;
        auto result = RemediateAuditdWatch(params, indicators, context);
        ASSERT_FALSE(result.HasValue()) << value;
        ExpectUnchanged();
    }
}

TEST_F(AuditdWatchTest, RefusesUnconfirmedStartupLoaders)
{
    for (const auto& value : {"", "argv[]=/sbin/auditctl -R /etc/audit/audit.rules ;", "argv[]=/tmp/augenrules --load ;",
             "argv[]=/sbin/augenrules --check ;", "argv[]=/sbin/augenrules --load-something ;",
             "{ path=/sbin/augenrules ; argv[]=/sbin/augenrules --load ; } { path=/sbin/auditctl ; argv[]=/sbin/auditctl -D ; }"})
    {
        loader = value;
        auto result = RemediateAuditdWatch(params, indicators, context);
        ASSERT_FALSE(result.HasValue()) << value;
        EXPECT_EQ(result.Error().code, ENOTSUP);
        ExpectUnchanged();
    }
}

TEST_F(AuditdWatchTest, AcceptsUsrSbinAugenrulesStartupLoader)
{
    loader = "{ path=/usr/sbin/augenrules ; argv[]=/usr/sbin/augenrules --load ; }";
    EXPECT_EQ(RemediateAuditdWatch(params, indicators, context).Value(), Status::Compliant);
}

TEST_F(AuditdWatchTest, DoesNotCreateMissingWatchTargets)
{
    ASSERT_EQ(0, unlink(target.c_str()));
    auto result = RemediateAuditdWatch(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, ENOENT);
    ExpectUnchanged();
    EXPECT_EQ(-1, access(target.c_str(), F_OK));
}

TEST_F(AuditdWatchTest, RefusesNonregularTargets)
{
    ASSERT_EQ(0, unlink(target.c_str()));
    ASSERT_EQ(0, mkfifo(target.c_str(), 0600));
    auto result = RemediateAuditdWatch(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, ENOTSUP);
    ExpectUnchanged();
}

TEST_F(AuditdWatchTest, RejectsInvalidPathsAndPermissionSetsBeforeExecutingCommands)
{
    EXPECT_CALL(context, ExecuteCommand(_)).Times(0);
    for (const auto& path : {"/", "/etc/../shadow", "/etc/./shadow", "etc/passwd", "/etc/passwd;id", "/etc/a'file", "/etc/*", "/etc/a\nfile"})
    {
        params.path = path;
        EXPECT_FALSE(RemediateAuditdWatch(params, indicators, context).HasValue()) << path;
    }
    params.path = "/etc/sudoers";
    for (const auto& permissions : {"", "aw", "ww", "z", "wa -D", "wa\n"})
    {
        params.permissions = permissions;
        EXPECT_FALSE(RemediateAuditdWatch(params, indicators, context).HasValue()) << permissions;
    }
    ExpectUnchanged();
}

TEST_F(AuditdWatchTest, RejectsOverlongPathsBeforeExecutingCommands)
{
    params.path = "/" + std::string(96, 'a');
    EXPECT_CALL(context, ExecuteCommand(_)).Times(0);
    EXPECT_FALSE(RemediateAuditdWatch(params, indicators, context).HasValue());
    ExpectUnchanged();
}

TEST_F(AuditdWatchTest, AuditsAllCanonicalNonemptyPermissionSets)
{
    for (const auto& permissions : {"r", "w", "x", "a", "rw", "rx", "ra", "wx", "wa", "xa", "rwx", "rwa", "rxa", "wxa", "rwxa"})
    {
        params.permissions = permissions;
        runtime = "-w /etc/sudoers -p " + params.permissions + "\n";
        Source("administrator.rules", runtime);
        auto result = AuditAuditdWatch(params, indicators, context);
        ASSERT_TRUE(result.HasValue());
        EXPECT_EQ(result.Value(), Status::Compliant) << permissions;
    }
    ExpectUnchanged();
}

TEST_F(AuditdWatchTest, RefusesDifferentRuntimePermissionsOrSyscallVariants)
{
    for (const auto& value :
        {"-w /etc/sudoers -p r -k administrator\n", "-a always,exit -F path=/etc/sudoers -F perm=wa -k administrator\n", "-W /etc/sudoers\n"})
    {
        runtime = value;
        auto result = RemediateAuditdWatch(params, indicators, context);
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ(result.Error().code, ENOTSUP);
        EXPECT_EQ(runtime, value);
        ExpectUnchanged();
    }
}

TEST_F(AuditdWatchTest, RefusesPersistentConflictsAndSuppressionWithoutMutation)
{
    for (const auto& value :
        {"-w /etc/sudoers -p r\n", "-W /etc/sudoers\n", "-a never,task\n", "-a exit,never -S all\n", "-e 0\n", "-D -k kompli_watch\n"})
    {
        Source("administrator.rules", value);
        auto result = RemediateAuditdWatch(params, indicators, context);
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ(result.Error().code, ENOTSUP);
        EXPECT_EQ(Read(directory + "/administrator.rules").Value(), value);
        ExpectUnchanged();
    }
}

TEST_F(AuditdWatchTest, PreservesPreexistingPersistentImmutableDirectiveWithoutApplyingIt)
{
    Source("99-finalize.rules", "-e 2\n");
    EXPECT_EQ(RemediateAuditdWatch(params, indicators, context).Value(), Status::Compliant);
    EXPECT_EQ(Read(directory + "/99-finalize.rules").Value(), "-e 2\n");
}

TEST_F(AuditdWatchTest, DoesNotOverwriteUnexpectedManagedFilenameContents)
{
    std::ofstream(managed) << "# administrator replacement\n";
    auto result = RemediateAuditdWatch(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, EEXIST);
    EXPECT_EQ(Read(managed).Value(), "# administrator replacement\n");
    EXPECT_EQ(additions, 0);
}

TEST_F(AuditdWatchTest, RefusesSymlinkedRuleSources)
{
    ASSERT_EQ(0, symlink(target.c_str(), managed.c_str()));
    auto result = RemediateAuditdWatch(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(Read(target).Value(), "# sudoers fixture\n");
    EXPECT_EQ(additions, 0);
}

TEST_F(AuditdWatchTest, RefusesHardlinkedRuleSources)
{
    ASSERT_EQ(0, link(target.c_str(), managed.c_str()));
    EXPECT_FALSE(RemediateAuditdWatch(params, indicators, context).HasValue());
    EXPECT_EQ(Read(target).Value(), "# sudoers fixture\n");
    EXPECT_EQ(additions, 0);
}

TEST_F(AuditdWatchTest, ReportsUnreadableSourcesRatherThanIgnoringThem)
{
    Source("administrator.rules", "# source\n");
    EXPECT_CALL(context, GetFileContents(directory + "/administrator.rules")).WillRepeatedly(Return(Error("Unreadable rules", EACCES)));
    auto result = RemediateAuditdWatch(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, EACCES);
    ExpectUnchanged();
}

TEST_F(AuditdWatchTest, RollsBackPersistentCreationWhenRuntimeAddFails)
{
    EXPECT_CALL(context, ExecuteCommand(add)).WillOnce(Return(Error("Add failed", EPERM)));
    auto result = RemediateAuditdWatch(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, EPERM);
    EXPECT_TRUE(runtime.empty());
    EXPECT_EQ(-1, access(managed.c_str(), F_OK));
    EXPECT_EQ(removals, 0);
}

TEST_F(AuditdWatchTest, RemovesOnlyNewOwnedWatchAfterPartialApplicationFailure)
{
    const std::string original = "-w /etc/passwd -p wa -k administrator\n";
    runtime = original;
    EXPECT_CALL(context, ExecuteCommand(add)).WillOnce(Invoke([&](const std::string&) -> Result<std::string> {
        runtime += line;
        return Error("Command failed after applying rule", EIO);
    }));
    auto result = RemediateAuditdWatch(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, EIO);
    EXPECT_EQ(runtime, original);
    EXPECT_EQ(removals, 1);
    EXPECT_EQ(-1, access(managed.c_str(), F_OK));
}

TEST_F(AuditdWatchTest, RollsBackBothStatesWhenPostVerificationFails)
{
    EXPECT_CALL(context, ExecuteCommand(add)).WillOnce(Invoke([&](const std::string&) {
        runtime += line;
        status = "enabled 0\npid 123\n";
        return std::string();
    }));
    auto result = RemediateAuditdWatch(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_TRUE(runtime.empty());
    EXPECT_EQ(removals, 1);
    EXPECT_EQ(-1, access(managed.c_str(), F_OK));
}

TEST_F(AuditdWatchTest, PreservesPreexistingSourceOnRuntimeFailure)
{
    Source("administrator.rules", line);
    EXPECT_CALL(context, ExecuteCommand(add)).WillOnce(Return(Error("Add failed", EPERM)));
    EXPECT_FALSE(RemediateAuditdWatch(params, indicators, context).HasValue());
    EXPECT_EQ(Read(directory + "/administrator.rules").Value(), line);
    EXPECT_EQ(-1, access(managed.c_str(), F_OK));
}

TEST_F(AuditdWatchTest, ReportsRollbackFailureWithoutRemovingUnrelatedRules)
{
    EXPECT_CALL(context, ExecuteCommand(add)).WillOnce(Invoke([&](const std::string&) {
        runtime += line;
        status = "enabled 0\npid 123\n";
        return std::string();
    }));
    EXPECT_CALL(context, ExecuteCommand(remove)).WillOnce(Return(Error("Removal failed", EPERM)));
    auto result = RemediateAuditdWatch(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_NE(result.Error().message.find("rollback failed"), std::string::npos);
    EXPECT_EQ(runtime, line);
    EXPECT_EQ(-1, access(managed.c_str(), F_OK));
}

TEST_F(AuditdWatchTest, DoesNotDeleteConcurrentlyReplacedManagedSource)
{
    const auto replacement = context.MakeTempfile("# replacement source\n");
    EXPECT_CALL(context, ExecuteCommand(add)).WillOnce(Invoke([&](const std::string&) -> Result<std::string> {
        EXPECT_EQ(0, rename(replacement.c_str(), managed.c_str()));
        return Error("Add failed", EIO);
    }));
    auto result = RemediateAuditdWatch(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_NE(result.Error().message.find("changed before rollback"), std::string::npos);
    EXPECT_EQ(Read(managed).Value(), "# replacement source\n");
}

TEST_F(AuditdWatchTest, DoesNotDeleteManagedSourceModifiedInPlaceDuringRollback)
{
    EXPECT_CALL(context, ExecuteCommand(add)).WillOnce(Invoke([&](const std::string&) -> Result<std::string> {
        std::ofstream(managed) << "# administrator edit\n";
        return Error("Add failed", EIO);
    }));
    auto result = RemediateAuditdWatch(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_NE(result.Error().message.find("changed before rollback"), std::string::npos);
    EXPECT_EQ(Read(managed).Value(), "# administrator edit\n");
}

TEST_F(AuditdWatchTest, ReportsChangedOwnedRuntimeRuleRatherThanDeletingIt)
{
    EXPECT_CALL(context, ExecuteCommand(add)).WillOnce(Invoke([&](const std::string&) {
        runtime = "-w /etc/sudoers -p r -k kompli_watch\n";
        return std::string();
    }));
    auto result = RemediateAuditdWatch(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_NE(result.Error().message.find("owned runtime watch changed"), std::string::npos);
    EXPECT_EQ(runtime, "-w /etc/sudoers -p r -k kompli_watch\n");
    EXPECT_EQ(removals, 0);
    EXPECT_EQ(-1, access(managed.c_str(), F_OK));
}

TEST_F(AuditdWatchTest, VerifiesRollbackRemovalRatherThanTrustingCommandSuccess)
{
    EXPECT_CALL(context, ExecuteCommand(add)).WillOnce(Invoke([&](const std::string&) {
        runtime += line;
        status = "enabled 0\npid 123\n";
        return std::string();
    }));
    EXPECT_CALL(context, ExecuteCommand(remove)).WillOnce(Return(std::string()));
    auto result = RemediateAuditdWatch(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_NE(result.Error().message.find("removal could not be verified"), std::string::npos);
    EXPECT_EQ(runtime, line);
}

TEST_F(AuditdWatchTest, RefusesSymlinkedParentWhenCreatingSource)
{
    const auto alias = context.GetTempdirPath() + "/linked-rules";
    ASSERT_EQ(0, symlink(directory.c_str(), alias.c_str()));
    context.SetSpecialFilePath("/etc/audit/rules.d", alias);
    EXPECT_FALSE(RemediateAuditdWatch(params, indicators, context).HasValue());
    EXPECT_TRUE(runtime.empty());
    ExpectUnchanged();
}

TEST_F(AuditdWatchTest, ReportsRuntimeInspectionFailureDuringRollback)
{
    bool applied = false;
    EXPECT_CALL(context, ExecuteCommand(add)).WillOnce(Invoke([&](const std::string&) {
        runtime += line;
        applied = true;
        return std::string();
    }));
    EXPECT_CALL(context, ExecuteCommand("auditctl -l")).WillRepeatedly(Invoke([&](const std::string&) -> Result<std::string> {
        if (applied)
        {
            return Error("Cannot list kernel rules", EIO);
        }
        return std::string("No rules\n");
    }));
    auto result = RemediateAuditdWatch(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_NE(result.Error().message.find("rollback failed"), std::string::npos);
    EXPECT_EQ(runtime, line);
    EXPECT_EQ(-1, access(managed.c_str(), F_OK));
    EXPECT_EQ(removals, 0);
}

TEST_F(AuditdWatchTest, GeneratedTypedLeafBindsAndRemediatesThroughEvaluator)
{
    auto json = JsonWrapper::FromString("{\"AuditdWatch\":{\"path\":\"/etc/sudoers\",\"permissions\":\"wa\"}}");
    ASSERT_TRUE(json.HasValue());
    const ParameterMap parameters;
    Evaluator evaluator("test", json_value_get_object(json->get()), parameters, context);
    auto result = evaluator.ExecuteRemediation();
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
    EXPECT_EQ(runtime, line);
    EXPECT_EQ(Read(managed).Value(), "# Managed by kompli\n" + line);
}
