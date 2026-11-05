// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "MockContext.h"

#include <JsonWrapper.h>
#include <PasswordPolicyOption.h>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <dlfcn.h>
#include <fstream>
#include <iterator>
#include <memory>
#include <regex>
#include <set>
#include <sstream>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace ComplianceEngine;
using testing::_;
using testing::Invoke;
using testing::Return;

class PasswordPolicyOptionTest : public testing::Test
{
protected:
    MockContext context;
    IndicatorsTree indicators;
    PasswordPolicyOptionParams params;
    std::string config;
    std::string pamDirectory;
    std::string pam;
    std::string selection;
    std::string originalSelection;
    std::string activatedStack;
    std::string initialStack;
    bool enableFails = false;
    bool rollbackFails = false;
    bool vendorCheckFails = false;
    bool activated = false;
    bool selectFails = false;
    bool dryRunFails = false;
    bool profileCopyFails = false;
    bool changeNss = false;
    std::string profileRoot;
    std::string profileTemplate;
    std::string nssContents;
    std::string debianDirectory;
    std::set<std::string> debianProfiles;
    bool debianGenerationFails = false;
    bool debconfNoNewline = false;
    std::string runtimeDirectory;
    std::string tmpfilesDirectory;
    std::string historyDatabase;
    bool runtimeCreationFails = false;

    Result<std::string> RuntimeCommand()
    {
        if (mkdir(runtimeDirectory.c_str(), 0755) != 0 && errno != EEXIST)
            return Error("Runtime mkdir failed", errno);
        return runtimeCreationFails ? Result<std::string>(Error("Scoped creation failed", EIO)) : Result<std::string>(std::string("created"));
    }

    void DebianStack(const std::string& type, const std::vector<std::string>& primary, const std::vector<std::string>& additional)
    {
        const auto pamType = type == "session-noninteractive" ? "session" : type;
        std::string generated = "# here are the per-package modules (the \"Primary\" block)\n";
        std::string saved;
        for (const auto& line : primary)
        {
            generated += pamType + " " + line + "\n";
            saved += "Module: fixture\n" + std::regex_replace(line, std::regex("success=[0-9]+"), "success=end") + "\n";
        }
        generated += "# here's the fallback if no module succeeds\n" + pamType + " requisite pam_deny.so\n";
        generated += "# prime the stack with a positive return value if there isn't one already\n" + pamType + " required pam_permit.so\n";
        generated += "# and here are more per-package modules (the \"Additional\" block)\n";
        for (const auto& line : additional)
        {
            generated += pamType + " " + line + "\n";
            saved += "Module: fixture\n" + line + "\n";
        }
        generated += "# end of pam-auth-update config\n";
        std::ofstream(context.GetSpecialFilePath("/etc/pam.d/common-" + type)) << generated;
        std::ofstream(context.GetSpecialFilePath("/var/lib/pam/" + type)) << saved;
    }

    void ManagedDebianFixture()
    {
        AuthselectFixture();
        testing::Mock::VerifyAndClearExpectations(&context);
        EXPECT_CALL(context, GetFileContents(_)).WillRepeatedly(Invoke(Read));
        context.SetSpecialFilePath("/etc/os-release", context.MakeTempfile("ID=ubuntu\nVERSION_ID=22.04\n"));
        context.SetSpecialFilePath("/run/kompli-password-policy.lock", context.GetTempdirPath() + "/policy.lock");
        debianDirectory = context.MakeTempfile("") + ".pam-configs";
        ASSERT_EQ(0, mkdir(debianDirectory.c_str(), 0755));
        const auto state = context.MakeTempfile("") + ".pam-state";
        ASSERT_EQ(0, mkdir(state.c_str(), 0755));
        for (const auto& type : {"auth", "account", "password", "session", "session-noninteractive"})
        {
            context.SetSpecialFilePath(std::string("/etc/pam.d/common-") + type, pamDirectory + "/common-" + type);
            context.SetSpecialFilePath(std::string("/var/lib/pam/") + type, state + "/" + type);
        }
        context.SetSpecialFilePath("/var/lib/pam/seen", state + "/seen");
        std::ofstream(state + "/seen") << "unix\n";
        const auto executable = context.MakeTempfile("");
        ASSERT_EQ(0, chmod(executable.c_str(), 0755));
        context.SetSpecialFilePath("/usr/sbin/pam-auth-update", executable);
        for (const auto& name : {"unix", "kompli-faillock-preauth", "kompli-faillock-authfail", "kompli-faillock-reset"})
        {
            context.SetSpecialFilePath(std::string("/usr/share/pam-configs/") + name, debianDirectory + "/" + name);
        }
        std::ofstream(debianDirectory + "/unix") << "Name: Unix authentication\nPriority: 256\nAuth-Type: Primary\n";
        DebianStack("auth", {"[success=1 default=ignore] pam_unix.so nullok"}, {});
        DebianStack("account", {"[success=1 new_authtok_reqd=done default=ignore] pam_unix.so"}, {});
        DebianStack("password", {"[success=1 default=ignore] pam_unix.so obscure yescrypt"}, {});
        DebianStack("session", {}, {"required pam_unix.so"});
        DebianStack("session-noninteractive", {}, {"required pam_unix.so"});
        debianProfiles = {"unix"};
        EXPECT_CALL(context, ExecuteCommand(_)).WillRepeatedly(Invoke([this](const std::string& command) -> Result<std::string> {
            if (command.find(" --create --prefix=") != std::string::npos)
                return RuntimeCommand();
            if (command.find("debconf-communicate") != std::string::npos)
            {
                EXPECT_NE(command.find("DEBIAN_FRONTEND=noninteractive LC_ALL=C"), std::string::npos);
            }
            if (command.find("FGET libpam-runtime/") != std::string::npos || command.find("GET libpam-runtime/override") != std::string::npos)
            {
                return std::string("0 false\n");
            }
            if (command.find("FSET libpam-runtime/") != std::string::npos || command.find("SET libpam-runtime/override") != std::string::npos)
            {
                return std::string("0 value set\n");
            }
            if (command.find("GET libpam-runtime/profiles") != std::string::npos)
            {
                std::string names;
                for (const auto& name : debianProfiles)
                {
                    names += (names.empty() ? "" : ", ") + name;
                }
                return "0 " + names + (debconfNoNewline ? "" : "\n");
            }
            if (command.find("SET libpam-runtime/profiles") != std::string::npos)
            {
                debianProfiles = {"unix"};
                return std::string("0 value set\n");
            }
            if (command.find(" --package --enable ") != std::string::npos)
            {
                EXPECT_EQ(0U, command.find("DEBIAN_FRONTEND=noninteractive "));
                EXPECT_EQ(std::string::npos, command.find("--force"));
                EXPECT_EQ(std::string::npos, command.find("--help"));
                debianProfiles.insert("kompli-faillock-preauth");
                debianProfiles.insert("kompli-faillock-authfail");
                debianProfiles.insert("kompli-faillock-reset");
                const auto extract = [&](const std::string& profile, const std::string& control) {
                    const auto text = Read(debianDirectory + "/" + profile).Value();
                    const auto start = text.find(control);
                    return text.substr(start, text.find('\n', start) - start);
                };
                DebianStack("auth",
                    {extract("kompli-faillock-preauth", "requisite"), "[success=2 default=ignore] pam_unix.so nullok",
                        extract("kompli-faillock-authfail", "required")},
                    {});
                DebianStack("account", {"[success=1 new_authtok_reqd=done default=ignore] pam_unix.so"}, {extract("kompli-faillock-reset", "required")});
                return debianGenerationFails ? Result<std::string>(Error("Vendor generation failed after writing", EIO)) :
                                               Result<std::string>(std::string("generated"));
            }
            if (command.find(" --package --disable ") != std::string::npos)
            {
                debianProfiles = {"unix"};
                return std::string("disabled");
            }
            ADD_FAILURE() << command;
            return Error("Unexpected Debian command", EINVAL);
        }));
    }

    std::string RenderProfile(const std::string& command, const std::string& name)
    {
        const auto start = command.find("custom/");
        const auto end = command.find('\'', start);
        const auto profile = command.substr(start + 7, end - start - 7);
        auto contents = Read(profileRoot + "/" + profile + "/" + name);
        if (!contents.HasValue())
        {
            ADD_FAILURE() << contents.Error().message;
            return "";
        }
        std::istringstream lines(contents.Value());
        std::string line;
        std::string result;
        while (std::getline(lines, line))
        {
            const auto directive = line.find(" {include if \"");
            if (directive != std::string::npos)
            {
                const auto feature = line.substr(directive + 14, line.find('"', directive + 14) - directive - 14);
                if (command.find(feature) == std::string::npos)
                {
                    continue;
                }
                line.erase(directive);
            }
            result += line + "\n";
        }
        return result;
    }

    void ManagedAuthselectFixture(const std::string& policy = "faillock", bool selected = false)
    {
        AuthselectFixture(policy);
        testing::Mock::VerifyAndClearExpectations(&context);
        EXPECT_CALL(context, GetFileContents(_)).WillRepeatedly(Invoke(Read));
        const auto directory = context.MakeTempfile("") + ".authselect";
        ASSERT_EQ(0, mkdir(directory.c_str(), 0755));
        profileRoot = directory + "/custom";
        ASSERT_EQ(0, mkdir(profileRoot.c_str(), 0755));
        context.SetSpecialFilePath("/etc/authselect", directory);
        context.SetSpecialFilePath("/etc/authselect/custom", profileRoot);
        context.SetSpecialFilePath("/run/kompli-password-policy.lock", context.GetTempdirPath() + "/policy.lock");
        nssContents = "passwd: files systemd\nshadow: files\ngroup: files systemd\nhosts: files dns\n";
        context.SetSpecialFilePath("/etc/nsswitch.conf", context.MakeTempfile(nssContents));
        for (const auto& name : {"authselect.conf", "user-nsswitch.conf", "system-auth", "password-auth", "postlogin", "fingerprint-auth",
                 "smartcard-auth", "nsswitch.conf", "dconf-db", "dconf-locks"})
        {
            context.SetSpecialFilePath(std::string("/etc/authselect/") + name, directory + "/" + name);
        }
        for (const auto& name : {"postlogin", "fingerprint-auth", "smartcard-auth"})
        {
            context.SetSpecialFilePath(std::string("/etc/pam.d/") + name, pamDirectory + "/" + name);
        }
        if (!selected)
        {
            originalSelection = selection = "";
        }
        else
        {
            std::ofstream(directory + "/authselect.conf") << originalSelection << "\n";
        }
        profileTemplate =
            "auth required pam_faillock.so preauth {include if \"with-faillock\"}\n"
            "auth sufficient pam_unix.so\n"
            "auth required pam_faillock.so authfail {include if \"with-faillock\"}\n"
            "auth required pam_deny.so\n"
            "account required pam_faillock.so {include if \"with-faillock\"}\n"
            "account required pam_unix.so\n"
            "password requisite pam_pwquality.so\n"
            "password requisite pam_pwhistory.so use_authtok {include if \"with-pwhistory\"}\n"
            "password sufficient pam_unix.so use_authtok\n"
            "password required pam_deny.so\n";
        EXPECT_CALL(context, ExecuteCommand(_)).WillRepeatedly(Invoke([this](const std::string& command) -> Result<std::string> {
            if (command.find(" --create --prefix=") != std::string::npos)
                return RuntimeCommand();
            if (command.find(" current --raw") != std::string::npos)
            {
                return selection.empty() ? Result<std::string>(Error("No selection", ENOENT)) : Result<std::string>(selection);
            }
            if (command.find(" create-profile ") != std::string::npos)
            {
                const auto start = command.find('\'', command.find(" create-profile ")) + 1;
                const auto name = command.substr(start, command.find('\'', start) - start);
                const auto directory = profileRoot + "/" + name;
                EXPECT_EQ(0, mkdir(directory.c_str(), 0755));
                const auto baseStart = command.find('\'', command.find("--base-on")) + 1;
                const auto base = command.substr(baseStart, command.find('\'', baseStart) - baseStart);
                for (const auto& stack : {"system-auth", "password-auth"})
                {
                    std::ofstream(directory + "/" + stack)
                        << (base.find("custom/kompli-preserved-") == 0 ? Read(profileRoot + "/" + base.substr(7) + "/" + stack).Value() : profileTemplate);
                }
                std::ofstream(directory + "/nsswitch.conf") << nssContents;
                std::ofstream(directory + "/README") << "vendor copy\n";
                return profileCopyFails ? Result<std::string>(Error("Partial vendor profile copy failed", EIO)) : Result<std::string>(std::string("copied"));
            }
            if (command.find(" list-features ") != std::string::npos)
            {
                return std::string("with-faillock\nwith-pwhistory\nwith-mkhomedir\n");
            }
            if (command.find(" test --nsswitch ") != std::string::npos)
            {
                return changeNss ? std::string("passwd: sss\n") : nssContents;
            }
            if (command.find(" test --system-auth ") != std::string::npos)
            {
                if (dryRunFails)
                {
                    return Error("Dry run failed", EIO);
                }
                return "File /etc/pam.d/system-auth:\n" + RenderProfile(command, "system-auth") + "\nFile /etc/pam.d/password-auth:\n" +
                       RenderProfile(command, "password-auth");
            }
            if (command.find(" select ") != std::string::npos)
            {
                const auto start = command.find("custom/");
                selection = command.substr(start, command.find('\'', start) - start);
                if (command.find("with-mkhomedir") != std::string::npos)
                {
                    selection += " with-mkhomedir";
                }
                if (command.find("with-pwhistory") != std::string::npos)
                {
                    selection += " with-pwhistory";
                }
                if (command.find("with-faillock") != std::string::npos)
                {
                    selection += " with-faillock";
                }
                std::ofstream(pamDirectory + "/system-auth") << RenderProfile(command, "system-auth");
                std::ofstream(pamDirectory + "/password-auth") << RenderProfile(command, "password-auth");
                std::ofstream(context.GetSpecialFilePath("/etc/authselect/authselect.conf")) << selection << "\n";
                activated = true;
                return selectFails ? Result<std::string>(Error("Selection failed after generation", EIO)) : Result<std::string>(std::string("selected"));
            }
            if (command.find(" backup-restore ") != std::string::npos)
            {
                if (rollbackFails)
                {
                    return Error("Vendor rollback failed", EIO);
                }
                selection = originalSelection;
                activated = false;
                return std::string("restored");
            }
            if (command.find(" check") != std::string::npos)
            {
                return activated && vendorCheckFails ? Result<std::string>(Error("Vendor check failed", EIO)) : Result<std::string>(std::string("valid"));
            }
            ADD_FAILURE() << command;
            return Error("Unexpected managed command", EINVAL);
        }));
    }

    void SetStacks(const std::string& contents)
    {
        for (const auto& name : {"system-auth", "password-auth"})
        {
            std::ofstream(pamDirectory + "/" + name) << contents;
        }
    }

    size_t ProfileCount() const
    {
        size_t count = 0;
        std::unique_ptr<DIR, int (*)(DIR*)> entries(opendir(profileRoot.c_str()), closedir);
        while (entries && readdir(entries.get()) != nullptr)
        {
            ++count;
        }
        return count >= 2 ? count - 2 : 0;
    }

    void AuthselectFixture(const std::string& policy = "faillock")
    {
        testing::Mock::VerifyAndClearExpectations(&context);
        EXPECT_CALL(context, GetFileContents(_)).WillRepeatedly(Invoke(Read));
        params.integratePam = true;
        context.SetSpecialFilePath("/run/kompli-password-policy.lock", context.GetTempdirPath() + "/policy.lock");
        context.SetSpecialFilePath("/etc/os-release", context.MakeTempfile("ID=rhel\nVERSION_ID=10\n"));
        params.policy = policy;
        params.option = policy == "faillock" ? "deny" : "remember";
        params.value = policy == "faillock" ? "5" : "24";
        std::ofstream(config) << params.option << " = 3\n";
        const auto executable = context.MakeTempfile("");
        ASSERT_EQ(0, chmod(executable.c_str(), 0755));
        context.SetSpecialFilePath("/usr/bin/authselect", executable);
        context.SetSpecialFilePath("/usr/lib64/security/pam_" + policy + ".so", context.MakeTempfile("\177ELF " + policy + ".conf"));
        context.SetSpecialFilePath("/etc/pam.d/common-password", pamDirectory + "/absent");
        for (const auto& name : {"system-auth", "password-auth"})
        {
            context.SetSpecialFilePath(std::string("/etc/pam.d/") + name, pamDirectory + "/" + name);
        }
        selection = originalSelection = "custom/existing with-mkhomedir";
        initialStack =
            "auth sufficient pam_unix.so\n"
            "auth required pam_deny.so\n"
            "account required pam_unix.so\n"
            "password requisite pam_pwquality.so\n"
            "password sufficient pam_unix.so use_authtok\n"
            "password required pam_deny.so\n";
        activatedStack = policy == "faillock" ? "auth required pam_faillock.so preauth silent\n"
                                                "auth sufficient pam_unix.so\n"
                                                "auth [default=die] pam_faillock.so authfail\n"
                                                "auth required pam_deny.so\n"
                                                "account required pam_faillock.so\n"
                                                "account required pam_unix.so\n" :
                                                "password requisite pam_pwquality.so\n"
                                                "password required pam_pwhistory.so use_authtok\n"
                                                "password sufficient pam_unix.so use_authtok\n"
                                                "password required pam_deny.so\n";
        SetStacks(initialStack);
        EXPECT_CALL(context, ExecuteCommand(_)).WillRepeatedly(Invoke([this](const std::string& command) -> Result<std::string> {
            if (command.find(" --create --prefix=") != std::string::npos)
                return RuntimeCommand();
            if (command.find(" current --raw") != std::string::npos)
            {
                return selection;
            }
            if (command.find(" list-features ") != std::string::npos)
            {
                return std::string("with-faillock\nwith-pwhistory\nwith-mkhomedir\n");
            }
            if (command.find(" check") != std::string::npos)
            {
                return activated && vendorCheckFails ? Result<std::string>(Error("Vendor validation failed", EINVAL)) : Result<std::string>(std::string("valid"));
            }
            if (command.find(" apply-changes --backup=") != std::string::npos)
            {
                return std::string("backup created");
            }
            if (command.find(" enable-feature ") != std::string::npos)
            {
                activated = true;
                selection += " with-" + params.policy;
                SetStacks(activatedStack);
                return enableFails ? Result<std::string>(Error("Feature generation failed", EIO)) : Result<std::string>(std::string("enabled"));
            }
            if (command.find(" backup-restore ") != std::string::npos)
            {
                if (rollbackFails)
                {
                    return Error("Backup restore failed", EIO);
                }
                activated = false;
                selection = originalSelection;
                SetStacks(initialStack);
                return std::string("restored");
            }
            ADD_FAILURE() << "Unexpected PAM command: " << command;
            return Error("Unexpected command", EINVAL);
        }));
    }

    static Result<std::string> Read(const std::string& path)
    {
        std::ifstream input(path);
        if (!input.is_open())
        {
            return Error("Cannot read fixture " + path, ENOENT);
        }
        return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
    }

    void SetUp() override
    {
        indicators.Push("PasswordPolicyOption");
        params.policy = "pwquality";
        params.option = "minlen";
        params.value = "14";
        config = context.MakeTempfile("# password policy\nminlen = 8\n");
        pamDirectory = context.GetTempdirPath() + "/pam.d";
        ASSERT_EQ(0, mkdir(pamDirectory.c_str(), 0755));
        pam = pamDirectory + "/common-password";
        std::ofstream(pam) << "password requisite pam_pwquality.so retry=3\n";
        context.SetSpecialFilePath("/etc/pam.d", pamDirectory);
        context.SetSpecialFilePath("/etc/pam.conf", context.GetTempdirPath() + "/pam.conf");
        runtimeDirectory = context.GetTempdirPath() + "/faillock";
        context.SetSpecialFilePath("/var/run/faillock", runtimeDirectory);
        context.SetSpecialFilePath("/run/faillock", runtimeDirectory);
        for (const auto& ancestor : {"/etc", "/etc/security", "/run"})
        {
            const auto trusted = context.GetTempdirPath() + "/trusted" + std::regex_replace(ancestor, std::regex("/"), "-");
            ASSERT_EQ(0, mkdir(trusted.c_str(), 0755));
            ASSERT_EQ(0, chmod(trusted.c_str(), 0755));
            context.SetSpecialFilePath(ancestor, trusted);
        }
        tmpfilesDirectory = context.GetTempdirPath() + "/tmpfiles.d";
        ASSERT_EQ(0, mkdir(tmpfilesDirectory.c_str(), 0755));
        context.SetSpecialFilePath("/etc/tmpfiles.d", tmpfilesDirectory);
        context.SetSpecialFilePath("/usr/lib/tmpfiles.d", context.GetTempdirPath() + "/absent-vendor-tmpfiles");
        context.SetSpecialFilePath("/run/tmpfiles.d", context.GetTempdirPath() + "/absent-runtime-tmpfiles");
        const auto tmpfiles = context.MakeTempfile("");
        ASSERT_EQ(0, chmod(tmpfiles.c_str(), 0755));
        context.SetSpecialFilePath("/usr/bin/systemd-tmpfiles", tmpfiles);
        historyDatabase = context.MakeTempfile("");
        ASSERT_EQ(0, chmod(historyDatabase.c_str(), 0600));
        context.SetSpecialFilePath("/etc/security/opasswd", historyDatabase);
        context.SetSpecialFilePath("/sys/fs/selinux/enforce", context.GetTempdirPath() + "/absent-selinux");
        context.SetSpecialFilePath("/run/kompli-password-policy.lock", context.GetTempdirPath() + "/policy.lock");
        for (const auto& path : {"/etc/dconf/db/distro.d/20-authselect", "/etc/dconf/db/distro.d/locks/20-authselect", "/etc/dconf/db/distro"})
        {
            context.SetSpecialFilePath(path, context.GetTempdirPath() + "/saved-dconf-" + std::to_string(strlen(path)));
        }
        for (const auto& policy : {"pwquality", "faillock", "pwhistory"})
        {
            context.SetSpecialFilePath(std::string("/etc/security/") + policy + ".conf", config);
        }
        EXPECT_CALL(context, GetFileContents(_)).WillRepeatedly(Invoke(Read));
        EXPECT_CALL(context, ExecuteCommand(_)).Times(0);
    }

    void ExpectFile(const std::string& expected)
    {
        auto contents = Read(config);
        ASSERT_TRUE(contents.HasValue());
        EXPECT_EQ(contents.Value(), expected);
    }
};

TEST_F(PasswordPolicyOptionTest, ConvergesAndPreservesUnrelatedOptions)
{
    std::ofstream(config) << "# policy\nminlen = 8 # length\nretry = 3\n";
    ASSERT_EQ(0, chmod(config.c_str(), 0640));
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
    ExpectFile("# policy\nminlen = 14 # length\nretry = 3\n");
    struct stat metadata;
    ASSERT_EQ(0, stat(config.c_str(), &metadata));
    EXPECT_EQ(metadata.st_mode & 0777U, 0640U);
    EXPECT_EQ(Read(pam).Value(), "password requisite pam_pwquality.so retry=3\n");
    EXPECT_EQ(AuditPasswordPolicyOption(params, indicators, context).Value(), Status::Compliant);
}

TEST_F(PasswordPolicyOptionTest, ReplacesEveryDuplicateWithoutChangingSimilarKeys)
{
    std::ofstream(config) << "minlen = 6\nminlength = 1\n minlen=9";
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
    ExpectFile("minlen = 14\nminlength = 1\nminlen = 14");
}

TEST_F(PasswordPolicyOptionTest, AppendsMissingOptionAfterUnterminatedLine)
{
    std::ofstream(config) << "# minlen = 6";
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
    ExpectFile("# minlen = 6\nminlen = 14\n");
}

TEST_F(PasswordPolicyOptionTest, IdempotentWhenAlreadyCompliant)
{
    std::ofstream(config) << "minlen = 14\n";
    struct stat before;
    ASSERT_EQ(0, stat(config.c_str(), &before));
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
    struct stat after;
    ASSERT_EQ(0, stat(config.c_str(), &after));
    EXPECT_EQ(before.st_ino, after.st_ino);
    EXPECT_EQ(before.st_mtim.tv_sec, after.st_mtim.tv_sec);
    EXPECT_EQ(before.st_mtim.tv_nsec, after.st_mtim.tv_nsec);
}

TEST_F(PasswordPolicyOptionTest, WritesAllSupportedNumericTargets)
{
    for (const auto& target :
        std::vector<std::vector<std::string>>{{"pwquality", "difok", "2"}, {"pwquality", "maxrepeat", "3"}, {"pwquality", "maxsequence", "3"},
            {"faillock", "deny", "5"}, {"faillock", "unlock_time", "900"}, {"faillock", "root_unlock_time", "60"}, {"pwhistory", "remember", "24"}})
    {
        params.policy = target[0];
        params.option = target[1];
        params.value = target[2];
        std::ofstream(pam) << "password required pam_" << params.policy << ".so\n";
        std::ofstream(config) << "# main config\n";
        auto result = RemediatePasswordPolicyOption(params, indicators, context);
        ASSERT_TRUE(result.HasValue()) << result.Error().message;
        EXPECT_EQ(result.Value(), Status::Compliant);
        ExpectFile("# main config\n" + params.option + " = " + params.value + "\n");
    }
}

TEST_F(PasswordPolicyOptionTest, WritesBareBooleanFlags)
{
    for (const auto& policy : {"pwquality", "faillock", "pwhistory"})
    {
        params.policy = policy;
        params.option = params.policy == "faillock" ? "even_deny_root" : "enforce_for_root";
        params.value = "true";
        std::ofstream(pam) << "password required pam_" << params.policy << ".so\n";
        std::ofstream(config) << params.option << " = 0 # disabled\n";
        auto result = RemediatePasswordPolicyOption(params, indicators, context);
        ASSERT_TRUE(result.HasValue());
        EXPECT_EQ(result.Value(), Status::Compliant);
        ExpectFile(params.option + " # disabled\n");
    }
}

TEST_F(PasswordPolicyOptionTest, RejectsInvalidTargetsWithoutWriting)
{
    for (const auto& value : {"0", "-1", "5", "1025", "014", " 14", "14\n", "14 # comment", "2147483648", "14;retry=0", ""})
    {
        params.value = value;
        auto result = RemediatePasswordPolicyOption(params, indicators, context);
        ASSERT_FALSE(result.HasValue()) << value;
        EXPECT_EQ(result.Error().code, EINVAL);
        ExpectFile("# password policy\nminlen = 8\n");
    }
}

TEST_F(PasswordPolicyOptionTest, RejectsUnknownPoliciesAndOptions)
{
    params.policy = "../pwquality";
    EXPECT_FALSE(RemediatePasswordPolicyOption(params, indicators, context).HasValue());
    params.policy = "pwquality";
    params.option = "retry";
    EXPECT_FALSE(RemediatePasswordPolicyOption(params, indicators, context).HasValue());
    ExpectFile("# password policy\nminlen = 8\n");
}

TEST_F(PasswordPolicyOptionTest, RejectsDisabledBooleanTarget)
{
    params.option = "enforce_for_root";
    params.value = "false";
    EXPECT_FALSE(RemediatePasswordPolicyOption(params, indicators, context).HasValue());
    ExpectFile("# password policy\nminlen = 8\n");
}

TEST_F(PasswordPolicyOptionTest, RefusesInlineOverridesIncludingDuplicateArguments)
{
    for (const auto& arguments : {"minlen=8", "minlen=14 minlen=8", "minlen = 8"})
    {
        std::ofstream(pam) << "password [success=1 default=ignore] /lib/security/pam_pwquality.so " << arguments << "\n";
        auto result = RemediatePasswordPolicyOption(params, indicators, context);
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ(result.Error().code, ENOTSUP);
        ExpectFile("# password policy\nminlen = 8\n");
    }
}

TEST_F(PasswordPolicyOptionTest, AllowsIdenticalInlineValueAndIgnoresComments)
{
    std::ofstream(pam) << "# password required pam_pwquality.so minlen=1\npassword required pam_pwquality.so minlen=14 # minlen=3\n";
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(PasswordPolicyOptionTest, RefusesCustomConfigurationPaths)
{
    for (const auto& argument : {"conf=/tmp/custom", "config=/tmp/custom"})
    {
        std::ofstream(pam) << "password required pam_pwquality.so " << argument << "\n";
        auto result = RemediatePasswordPolicyOption(params, indicators, context);
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ(result.Error().code, ENOTSUP);
        ExpectFile("# password policy\nminlen = 8\n");
    }
}

TEST_F(PasswordPolicyOptionTest, DetectsOverridesOnContinuedPamLines)
{
    std::ofstream(pam) << "password required pam_pwquality.so \\\n minlen=6\n";
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, ENOTSUP);
    ExpectFile("# password policy\nminlen = 8\n");
}

TEST_F(PasswordPolicyOptionTest, ParsesLinuxPamContinuationsWithoutRewritingStacks)
{
    for (const auto& contents : {"password required pam_pwquality.so \\\n retry=3\n", "password required pam_pwquality.so \\ \t\n retry=3\n",
             "password required \\\n pam_pwquality.so \\\n retry=3\n", "password required pam_pwquality.so \\\\\n retry=3\n",
             "password required pam_pwquality.so # comment \\\npassword required pam_unix.so\n"})
    {
        std::ofstream(pam) << contents;
        std::ofstream(config) << "minlen = 8\n";
        auto result = RemediatePasswordPolicyOption(params, indicators, context);
        ASSERT_TRUE(result.HasValue()) << result.Error().message;
        EXPECT_EQ(result.Value(), Status::Compliant);
        EXPECT_EQ(Read(pam).Value(), contents);
    }
}

TEST_F(PasswordPolicyOptionTest, CarriageReturnDoesNotContinueLinuxPamLine)
{
    std::ofstream(pam) << "password required pam_pwquality.so \\\r\nminlen=8\n";
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(PasswordPolicyOptionTest, RejectsIncompleteContinuationAndNul)
{
    for (const auto& contents : {std::string("password required pam_pwquality.so \\\n"), std::string("password required pam_pwquality.so \\"),
             std::string("password required pam_pwquality.so") + std::string(1, '\0') + " minlen=8\n"})
    {
        std::ofstream(pam) << contents;
        auto result = RemediatePasswordPolicyOption(params, indicators, context);
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ(result.Error().code, EINVAL);
        ExpectFile("# password policy\nminlen = 8\n");
    }
}

TEST_F(PasswordPolicyOptionTest, ContinuedCustomConfigurationIsStillRejected)
{
    std::ofstream(pam) << "password required pam_pwquality.so \\\n conf=/etc/security/custom-quality.conf\n";
    EXPECT_FALSE(RemediatePasswordPolicyOption(params, indicators, context).HasValue());
    ExpectFile("# password policy\nminlen = 8\n");
}

TEST_F(PasswordPolicyOptionTest, EnablesExistingAuthselectFeatureWithoutSelectingProviders)
{
    AuthselectFixture();
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(result.Value(), Status::Compliant);
    EXPECT_EQ(selection, originalSelection + " with-faillock");
    ExpectFile("deny = 3\n");
    EXPECT_EQ(Read(pamDirectory + "/system-auth").Value(), activatedStack);
}

TEST_F(PasswordPolicyOptionTest, GeneratedBindingsEnableExplicitOptIn)
{
    AuthselectFixture();
    auto json =
        JsonWrapper::FromString("{\"PasswordPolicyOption\":{\"policy\":\"faillock\",\"option\":\"deny\",\"value\":\"5\",\"integratePam\":\"true\"}}");
    ASSERT_TRUE(json.HasValue());
    const ParameterMap parameters;
    Evaluator evaluator("test", json_value_get_object(json->get()), parameters, context);
    auto result = evaluator.ExecuteRemediation();
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(result.Value(), Status::Compliant);
    EXPECT_EQ(selection, originalSelection + " with-faillock");
}

TEST_F(PasswordPolicyOptionTest, GeneratedBindingsKeepIntegrationDisabledByDefault)
{
    auto json = JsonWrapper::FromString("{\"PasswordPolicyOption\":{\"policy\":\"pwquality\",\"option\":\"minlen\",\"value\":\"14\"}}");
    ASSERT_TRUE(json.HasValue());
    const ParameterMap parameters;
    Evaluator evaluator("test", json_value_get_object(json->get()), parameters, context);
    auto result = evaluator.ExecuteRemediation();
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
    ExpectFile("# password policy\nminlen = 14\n");
}

TEST_F(PasswordPolicyOptionTest, EnablesPasswordHistoryBeforeTokenConsumingProviders)
{
    ManagedAuthselectFixture("pwhistory", true);
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(result.Value(), Status::Compliant);
    ExpectFile("remember = 3\n");
    EXPECT_NE(selection.find("with-pwhistory"), std::string::npos);
    EXPECT_NE(selection.find("with-mkhomedir"), std::string::npos);
}

TEST_F(PasswordPolicyOptionTest, AdoptsAllSixMeasuredUnconfiguredElCohortsWithoutReplacingProviders)
{
    for (const auto& identity : {"ID=rhel\nVERSION_ID=8\n", "ID=rhel\nVERSION_ID=9\n", "ID=almalinux\nVERSION_ID=8\n", "ID=almalinux\nVERSION_ID=9\n",
             "ID=rocky\nVERSION_ID=8\n", "ID=rocky\nVERSION_ID=9\n"})
    {
        ManagedAuthselectFixture();
        context.SetSpecialFilePath("/etc/os-release", context.MakeTempfile(identity));
        const auto nss = context.GetSpecialFilePath("/etc/nsswitch.conf");
        ASSERT_EQ(0, chmod(pamDirectory.c_str(), 0755));
        ASSERT_EQ(0, chmod((pamDirectory + "/system-auth").c_str(), 0640));
        auto result = RemediatePasswordPolicyOption(params, indicators, context);
        ASSERT_TRUE(result.HasValue()) << result.Error().message;
        EXPECT_EQ(result.Value(), Status::Compliant);
        EXPECT_EQ(Read(nss).Value(), nssContents);
        EXPECT_NE(selection.find("custom/kompli-preserved-"), std::string::npos);
        const auto stack = Read(pamDirectory + "/system-auth").Value();
        EXPECT_NE(stack.find("auth sufficient pam_unix.so"), std::string::npos);
        EXPECT_EQ(stack.find("pam_sss.so"), std::string::npos);
        EXPECT_NE(stack.find("pam_faillock.so preauth deny=3"), std::string::npos);
        struct stat metadata
        {
        };
        ASSERT_EQ(0, stat((pamDirectory + "/system-auth").c_str(), &metadata));
        EXPECT_EQ(0640U, metadata.st_mode & 0777U);
    }
}

TEST_F(PasswordPolicyOptionTest, UnconfiguredElHistoryUsesInlineOptionsWithoutCreatingAConfigFile)
{
    ManagedAuthselectFixture("pwhistory");
    ASSERT_EQ(0, unlink(config.c_str()));
    std::ofstream(context.GetSpecialFilePath("/usr/lib64/security/pam_pwhistory.so")) << "\177ELF inline-only module";
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(result.Value(), Status::Compliant);
    EXPECT_EQ(-1, access(config.c_str(), F_OK));
    EXPECT_NE(Read(pamDirectory + "/system-auth").Value().find("pam_pwhistory.so use_authtok remember=24"), std::string::npos);
}

TEST_F(PasswordPolicyOptionTest, RejectsNssProviderDriftBeforeActivatingCopiedProfile)
{
    ManagedAuthselectFixture();
    changeNss = true;
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_FALSE(activated);
    EXPECT_EQ(selection, originalSelection);
    EXPECT_EQ(Read(pamDirectory + "/system-auth").Value(), initialStack);
    ExpectFile("deny = 3\n");
}

TEST_F(PasswordPolicyOptionTest, FailedManagedSelectionRestoresUnselectedStateAndFileMetadata)
{
    ManagedAuthselectFixture();
    selectFails = true;
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(selection, originalSelection);
    EXPECT_EQ(Read(pamDirectory + "/system-auth").Value(), initialStack);
    EXPECT_EQ(-1, access(context.GetSpecialFilePath("/etc/authselect/authselect.conf").c_str(), F_OK));
    ExpectFile("deny = 3\n");
}

TEST_F(PasswordPolicyOptionTest, ManagedSelectionSurfacesVendorRollbackFailureAndRestoresSnapshots)
{
    ManagedAuthselectFixture();
    selectFails = rollbackFails = true;
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_NE(result.Error().message.find("rollback failed"), std::string::npos);
    EXPECT_EQ(Read(pamDirectory + "/system-auth").Value(), initialStack);
}

TEST_F(PasswordPolicyOptionTest, RefusesPartialVendorProfileCopyBeforeSelection)
{
    ManagedAuthselectFixture("pwhistory", true);
    profileCopyFails = true;
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, EIO);
    EXPECT_NE(result.Error().message.find("Partial vendor profile copy failed"), std::string::npos);
    EXPECT_FALSE(activated);
    EXPECT_EQ(selection, originalSelection);
    EXPECT_EQ(Read(pamDirectory + "/system-auth").Value(), initialStack);
}

TEST_F(PasswordPolicyOptionTest, ManagedAuditPreservesPamReadErrors)
{
    ManagedAuthselectFixture("pwhistory", true);
    EXPECT_CALL(context, GetFileContents(pamDirectory + "/system-auth")).WillRepeatedly(Return(Error("Unreadable PAM stack", EACCES)));
    auto result = AuditPasswordPolicyOption(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, EACCES);
}

TEST_F(PasswordPolicyOptionTest, DebianFaillockUsesThreeVendorProfilesAndPreservesPasswordProviders)
{
    ManagedDebianFixture();
    const auto password = Read(context.GetSpecialFilePath("/etc/pam.d/common-password")).Value();
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(result.Value(), Status::Compliant);
    EXPECT_EQ(Read(context.GetSpecialFilePath("/etc/pam.d/common-password")).Value(), password);
    EXPECT_EQ(1U, debianProfiles.count("unix"));
    EXPECT_EQ(1U, debianProfiles.count("kompli-faillock-preauth"));
    EXPECT_EQ(1U, debianProfiles.count("kompli-faillock-authfail"));
    EXPECT_EQ(1U, debianProfiles.count("kompli-faillock-reset"));
    EXPECT_EQ(AuditPasswordPolicyOption(params, indicators, context).Value(), Status::Compliant);
}

TEST_F(PasswordPolicyOptionTest, DebianFaillockInlinePolicyDoesNotRequireLocalConfigurationReaderMarker)
{
    ManagedDebianFixture();
    std::ofstream(context.GetSpecialFilePath("/usr/lib64/security/pam_faillock.so")) << "\177ELF shared configuration reader";
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(Status::Compliant, result.Value());
    EXPECT_NE(Read(pamDirectory + "/common-auth")->find("pam_faillock.so preauth deny=3"), std::string::npos);
    EXPECT_EQ(0, access(runtimeDirectory.c_str(), F_OK));
}

TEST_F(PasswordPolicyOptionTest, DebianProfileSelectionAcceptsTrimmedCommandOutput)
{
    ManagedDebianFixture();
    debconfNoNewline = true;
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(Status::Compliant, result.Value());
}

TEST_F(PasswordPolicyOptionTest, PreservesStockUbuntuSessionUmaskInsideFallbackBlocks)
{
    ManagedDebianFixture();
    for (const auto& type : {"session", "session-noninteractive"})
    {
        DebianStack(type, {"[default=1] pam_permit.so"}, {"required pam_unix.so"});
        const auto path = context.GetSpecialFilePath(std::string("/etc/pam.d/common-") + type);
        auto contents = Read(path).Value();
        contents.insert(contents.find("# and here are more per-package modules"), "session optional pam_umask.so\n");
        std::ofstream(path) << contents;
    }
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(Status::Compliant, result.Value());
    for (const auto& type : {"session", "session-noninteractive"})
    {
        EXPECT_NE(Read(context.GetSpecialFilePath(std::string("/etc/pam.d/common-") + type))->find("session optional pam_umask.so\n"), std::string::npos);
    }
}

TEST_F(PasswordPolicyOptionTest, AuthselectFaillockInlinePolicyDoesNotRequireLocalConfigurationReaderMarker)
{
    ManagedAuthselectFixture();
    std::ofstream(context.GetSpecialFilePath("/usr/lib64/security/pam_faillock.so")) << "\177ELF shared configuration reader";
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(Status::Compliant, result.Value());
    EXPECT_NE(Read(pamDirectory + "/system-auth")->find("pam_faillock.so preauth deny=3"), std::string::npos);
}

TEST_F(PasswordPolicyOptionTest, DebianFaillockRejectsAdminChangesBeforeGeneratingProfiles)
{
    ManagedDebianFixture();
    std::ofstream(context.GetSpecialFilePath("/etc/pam.d/common-auth"), std::ios::app) << "auth sufficient pam_permit.so\n";
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    // Records outside the managed block are also security-significant.
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(1U, debianProfiles.size());
    EXPECT_EQ(-1, access((debianDirectory + "/kompli-faillock-preauth").c_str(), F_OK));
}

TEST_F(PasswordPolicyOptionTest, DebianPartialGenerationRestoresProfilesStacksAndVendorState)
{
    ManagedDebianFixture();
    const auto auth = Read(context.GetSpecialFilePath("/etc/pam.d/common-auth")).Value();
    const auto state = Read(context.GetSpecialFilePath("/var/lib/pam/auth")).Value();
    debianGenerationFails = true;
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(Read(context.GetSpecialFilePath("/etc/pam.d/common-auth")).Value(), auth);
    EXPECT_EQ(Read(context.GetSpecialFilePath("/var/lib/pam/auth")).Value(), state);
    EXPECT_EQ(std::set<std::string>{"unix"}, debianProfiles);
    EXPECT_EQ(-1, access((debianDirectory + "/kompli-faillock-preauth").c_str(), F_OK));
}

TEST_F(PasswordPolicyOptionTest, SupportsMeasuredVendorRequiredAuthfailAndSssdProviderGates)
{
    AuthselectFixture();
    activatedStack =
        "auth required pam_env.so\n"
        "auth required pam_faillock.so preauth silent\n"
        "auth [default=1 ignore=ignore success=ok] pam_usertype.so isregular\n"
        "auth [default=1 ignore=ignore success=ok] pam_localuser.so\n"
        "auth sufficient pam_unix.so nullok\n"
        "auth [default=1 ignore=ignore success=ok] pam_usertype.so isregular\n"
        "auth sufficient pam_sss.so forward_pass\n"
        "auth required pam_faillock.so authfail\n"
        "auth required pam_deny.so\n"
        "account required pam_faillock.so\n"
        "account required pam_unix.so\n"
        "account sufficient pam_localuser.so\n"
        "account [default=bad success=ok user_unknown=ignore] pam_sss.so\n";
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(result.Value(), Status::Compliant);
    EXPECT_EQ(Read(pamDirectory + "/system-auth").Value(), activatedStack);
}

TEST_F(PasswordPolicyOptionTest, PreservesVendorLocalHistoryScopeAndRemotePasswordProvider)
{
    ManagedAuthselectFixture("pwhistory", true);
    profileTemplate =
        "password requisite pam_pwquality.so local_users_only\n"
        "password [default=1 ignore=ignore success=ok] pam_localuser.so\n"
        "password requisite pam_pwhistory.so use_authtok\n"
        "password sufficient pam_unix.so sha512 shadow nullok use_authtok\n"
        "password [success=1 default=ignore] pam_localuser.so\n"
        "password sufficient pam_sss.so use_authtok\n"
        "password required pam_deny.so\n";
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(result.Value(), Status::Compliant);
    const auto generated = Read(pamDirectory + "/password-auth").Value();
    EXPECT_NE(generated.find("pam_sss.so use_authtok"), std::string::npos);
    EXPECT_NE(generated.find("pam_localuser.so"), std::string::npos);
}

TEST_F(PasswordPolicyOptionTest, DoesNotForceSelectAnUnconfiguredAuthselectSystem)
{
    AuthselectFixture();
    selection.clear();
    EXPECT_FALSE(RemediatePasswordPolicyOption(params, indicators, context).HasValue());
    EXPECT_FALSE(activated);
    ExpectFile("deny = 3\n");
}

TEST_F(PasswordPolicyOptionTest, RequiresInstalledModuleBeforeActivation)
{
    AuthselectFixture();
    ASSERT_EQ(0, unlink(context.GetSpecialFilePath("/usr/lib64/security/pam_faillock.so").c_str()));
    for (const auto& directory : {"/lib64/security/", "/usr/lib/security/", "/lib/security/", "/usr/lib/x86_64-linux-gnu/security/",
             "/lib/x86_64-linux-gnu/security/", "/usr/lib/aarch64-linux-gnu/security/", "/lib/aarch64-linux-gnu/security/"})
    {
        context.SetSpecialFilePath(std::string(directory) + "pam_faillock.so", pamDirectory + "/absent");
    }
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, ENOENT);
    EXPECT_FALSE(activated);
    ExpectFile("deny = 3\n");
}

TEST_F(PasswordPolicyOptionTest, IntegratesOlderHistoryModuleWithoutWritingIgnoredConfiguration)
{
    ManagedAuthselectFixture("pwhistory", true);
    std::ofstream(context.GetSpecialFilePath("/usr/lib64/security/pam_pwhistory.so")) << "\177ELF old inline-only module";
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(result.Value(), Status::Compliant);
    EXPECT_TRUE(activated);
    ExpectFile("remember = 3\n");
}

TEST_F(PasswordPolicyOptionTest, RefusesUnsupportedVendorActivationWithoutRunningCommands)
{
    AuthselectFixture();
    context.SetSpecialFilePath("/etc/os-release", context.MakeTempfile("ID=sles\nVERSION_ID=15\n"));
    EXPECT_CALL(context, ExecuteCommand(_)).Times(0);
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, ENOTSUP);
    ExpectFile("deny = 3\n");
}

TEST_F(PasswordPolicyOptionTest, DoesNotTreatUnmanagedAzureModuleReferencesAsSafeIntegration)
{
    AuthselectFixture();
    context.SetSpecialFilePath("/etc/os-release", context.MakeTempfile("ID=azurelinux\nVERSION_ID=3.0\n"));
    SetStacks(activatedStack);
    EXPECT_CALL(context, ExecuteCommand(_)).Times(0);
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, ENOTSUP);
    ExpectFile("deny = 3\n");
}

TEST_F(PasswordPolicyOptionTest, ValidatesExistingDebianPwqualityTokenFlowWithoutInvokingFramework)
{
    AuthselectFixture();
    context.SetSpecialFilePath("/etc/os-release", context.MakeTempfile("ID=debian\nVERSION_ID=12\n"));
    context.SetSpecialFilePath("/etc/pam.d/common-password", pam);
    params.policy = "pwquality";
    params.option = "minlen";
    params.value = "14";
    context.SetSpecialFilePath("/usr/lib64/security/pam_pwquality.so", context.MakeTempfile("\177ELF installed module"));
    std::ofstream(pam) << "password requisite pam_pwquality.so retry=3\n"
                          "password [success=1 default=ignore] pam_unix.so obscure use_authtok try_first_pass yescrypt\n"
                          "password requisite pam_deny.so\n"
                          "password required pam_permit.so\n";
    EXPECT_CALL(context, ExecuteCommand(_)).Times(0);
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(result.Value(), Status::Compliant);
    ExpectFile("deny = 3\nminlen = 14\n");
}

TEST_F(PasswordPolicyOptionTest, FailedEnableRestoresVendorProfileFeaturesAndStacks)
{
    AuthselectFixture();
    enableFails = true;
    EXPECT_FALSE(RemediatePasswordPolicyOption(params, indicators, context).HasValue());
    EXPECT_EQ(selection, originalSelection);
    EXPECT_EQ(Read(pamDirectory + "/system-auth").Value(), initialStack);
    ExpectFile("deny = 3\n");
}

TEST_F(PasswordPolicyOptionTest, FailedVendorValidationRestoresProfile)
{
    AuthselectFixture();
    vendorCheckFails = true;
    EXPECT_FALSE(RemediatePasswordPolicyOption(params, indicators, context).HasValue());
    EXPECT_EQ(selection, originalSelection);
    EXPECT_EQ(Read(pamDirectory + "/password-auth").Value(), initialStack);
    ExpectFile("deny = 3\n");
}

TEST_F(PasswordPolicyOptionTest, ReportsVendorRollbackFailure)
{
    AuthselectFixture();
    enableFails = rollbackFails = true;
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_NE(result.Error().message.find("rollback failed"), std::string::npos);
    ExpectFile("deny = 3\n");
}

TEST_F(PasswordPolicyOptionTest, RejectsLockoutBypassAndMissingFailureOrResetPaths)
{
    for (const auto& stack : {"auth sufficient pam_unix.so\n"
                              "auth required pam_faillock.so preauth\n"
                              "auth [default=die] pam_faillock.so authfail\n"
                              "account required pam_faillock.so\n",
             "auth required pam_faillock.so preauth\n"
             "auth sufficient pam_unix.so\n"
             "account required pam_faillock.so\n",
             "auth required pam_faillock.so preauth\n"
             "auth sufficient pam_unix.so\n"
             "auth [default=die] pam_faillock.so authfail\n",
             "auth optional pam_faillock.so preauth\n"
             "auth sufficient pam_unix.so\n"
             "auth [default=die] pam_faillock.so authfail\n"
             "account required pam_faillock.so\n"})
    {
        AuthselectFixture();
        activatedStack = stack;
        EXPECT_FALSE(RemediatePasswordPolicyOption(params, indicators, context).HasValue());
        EXPECT_EQ(selection, originalSelection);
        EXPECT_EQ(Read(pamDirectory + "/system-auth").Value(), initialStack);
        ExpectFile("deny = 3\n");
    }
}

TEST_F(PasswordPolicyOptionTest, RejectsHistoryBypassAndMissingTokenSharing)
{
    for (const auto& stack : {"password sufficient pam_unix.so use_authtok\npassword required pam_pwhistory.so use_authtok\n",
             "password optional pam_pwhistory.so use_authtok\npassword sufficient pam_unix.so use_authtok\n",
             "password required pam_pwhistory.so\npassword sufficient pam_unix.so use_authtok\n",
             "password required pam_pwhistory.so use_authtok\npassword sufficient pam_unix.so\n"})
    {
        ManagedAuthselectFixture("pwhistory", true);
        profileTemplate = stack;
        EXPECT_FALSE(RemediatePasswordPolicyOption(params, indicators, context).HasValue());
        EXPECT_EQ(selection, originalSelection);
        ExpectFile("remember = 3\n");
    }
}

TEST_F(PasswordPolicyOptionTest, ConfigFailureAlsoRestoresActivatedProfile)
{
    AuthselectFixture();
    int reads = 0;
    EXPECT_CALL(context, GetFileContents(config)).WillRepeatedly(Invoke([&](const std::string& path) -> Result<std::string> {
        return ++reads == 4 ? Result<std::string>(Error("Post-write verification failed", EIO)) : Read(path);
    }));
    EXPECT_FALSE(RemediatePasswordPolicyOption(params, indicators, context).HasValue());
    EXPECT_EQ(selection, originalSelection);
    EXPECT_EQ(Read(pamDirectory + "/system-auth").Value(), initialStack);
    ExpectFile("deny = 3\n");
}

TEST_F(PasswordPolicyOptionTest, InitializesMissingHistoryDatabaseOnlyAfterValidatedVendorActivation)
{
    ManagedAuthselectFixture("pwhistory", true);
    ASSERT_EQ(0, unlink(historyDatabase.c_str()));
    EXPECT_EQ(Status::NonCompliant, AuditPasswordPolicyOption(params, indicators, context).Value());
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ("", Read(historyDatabase).Value());
    struct stat metadata
    {
    };
    ASSERT_EQ(0, stat(historyDatabase.c_str(), &metadata));
    EXPECT_EQ(0600U, metadata.st_mode & 0777U);
    EXPECT_EQ(0U, metadata.st_uid);
    EXPECT_EQ(0U, metadata.st_gid);
    EXPECT_EQ(Status::Compliant, AuditPasswordPolicyOption(params, indicators, context).Value());
}

TEST_F(PasswordPolicyOptionTest, RetainsExistingHistoryDataAndAdminMetadata)
{
    ManagedAuthselectFixture("pwhistory", true);
    std::ofstream(historyDatabase) << "synthetic:1234:1:synthetic-hash\n";
    ASSERT_EQ(0, chmod(historyDatabase.c_str(), 0400));
    struct stat before
    {
    };
    ASSERT_EQ(0, stat(historyDatabase.c_str(), &before));
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ("synthetic:1234:1:synthetic-hash\n", Read(historyDatabase).Value());
    struct stat after
    {
    };
    ASSERT_EQ(0, stat(historyDatabase.c_str(), &after));
    EXPECT_EQ(before.st_ino, after.st_ino);
    EXPECT_EQ(0400U, after.st_mode & 0777U);
}

TEST_F(PasswordPolicyOptionTest, ManagedAuditReportsUnsafeHistoryDatabaseMetadata)
{
    ManagedAuthselectFixture("pwhistory", true);
    ASSERT_EQ(Status::Compliant, RemediatePasswordPolicyOption(params, indicators, context).Value());
    ASSERT_EQ(0, chmod(historyDatabase.c_str(), 0644));
    auto result = AuditPasswordPolicyOption(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, ENOTSUP);
    EXPECT_NE(result.Error().message.find("metadata is unsafe"), std::string::npos);
}

TEST_F(PasswordPolicyOptionTest, LegacyHistoryIgnoresUnsupportedConfigurationWithoutCreatingAnIgnoredDatabase)
{
    ManagedAuthselectFixture("pwhistory", true);
    context.SetSpecialFilePath("/usr/lib64/security/pam_pwhistory.so", context.MakeTempfile("\177ELF inline-only"));
    std::ofstream(config) << "file = /var/lib/ignored-history\n";
    const auto ignored = context.GetTempdirPath() + "/ignored-history";
    context.SetSpecialFilePath("/var/lib/ignored-history", ignored);
    ASSERT_EQ(0, unlink(historyDatabase.c_str()));
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(0, access(historyDatabase.c_str(), F_OK));
    EXPECT_EQ(-1, access(ignored.c_str(), F_OK));
}

TEST_F(PasswordPolicyOptionTest, RestoresVendorStateWhenHistoryDatabaseParentIsUnsafe)
{
    ManagedAuthselectFixture("pwhistory", true);
    const auto parent = context.GetTempdirPath() + "/unsafe-history";
    ASSERT_EQ(0, mkdir(parent.c_str(), 0777));
    ASSERT_EQ(0, chmod(parent.c_str(), 0777));
    context.SetSpecialFilePath("/etc/security", parent);
    context.SetSpecialFilePath("/etc/security/opasswd", parent + "/opasswd");
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(originalSelection, selection);
    EXPECT_EQ(initialStack, Read(pamDirectory + "/system-auth").Value());
    EXPECT_EQ(-1, access((parent + "/opasswd").c_str(), F_OK));
}

TEST_F(PasswordPolicyOptionTest, ReadsModuleMetadataPastBinaryNulBeforeCheckingHistoryDatabase)
{
    ManagedAuthselectFixture("pwhistory", true);
    const auto module = context.GetSpecialFilePath("/usr/lib64/security/pam_pwhistory.so");
    const auto binary = std::string("\177ELF") + std::string(1, '\0') + "pwhistory.conf";
    std::ofstream(module, std::ios::binary) << binary;
    EXPECT_CALL(context, GetFileContents(module)).WillRepeatedly(Return(std::string("\177ELF")));
    std::ofstream(config) << "file = /var/lib/administrator-history\n";
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, ENOTSUP);
    EXPECT_NE(result.Error().message.find("Custom history database capability"), std::string::npos);
    ExpectFile("file = /var/lib/administrator-history\n");
}

TEST_F(PasswordPolicyOptionTest, ConfigurationFilenameMarkerDoesNotProveCustomHistoryDatabaseSupport)
{
    ManagedAuthselectFixture("pwhistory", true);
    const auto customDatabase = context.MakeTempfile("existing-admin-history\n");
    context.SetSpecialFilePath("/var/lib/custom-history", customDatabase);
    std::ofstream(config) << "file = /var/lib/custom-history\n";
    ASSERT_EQ(0, unlink(historyDatabase.c_str()));
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_NE(std::string::npos, result.Error().message.find("Custom history database capability"));
    EXPECT_EQ("existing-admin-history\n", Read(customDatabase).Value());
    EXPECT_EQ(-1, access(historyDatabase.c_str(), F_OK));
    EXPECT_EQ(originalSelection, selection);
    EXPECT_EQ(initialStack, Read(pamDirectory + "/system-auth").Value());
}

TEST_F(PasswordPolicyOptionTest, CreatesScopedFaillockRuntimeAndBootMetadata)
{
    ManagedDebianFixture();
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    struct stat metadata
    {
    };
    ASSERT_EQ(0, stat(runtimeDirectory.c_str(), &metadata));
    EXPECT_EQ(0755U, metadata.st_mode & 0777U);
    EXPECT_NE(Read(tmpfilesDirectory + "/kompli-faillock.conf")->find("d /run/faillock 755 0 0 -"), std::string::npos);
}

TEST_F(PasswordPolicyOptionTest, RealScopedTmpfilesCreationInAlternateRoot)
{
    if (geteuid() != 0 || access("/usr/bin/systemd-tmpfiles", X_OK) != 0)
    {
        GTEST_SKIP() << "Alternate-root tmpfiles integration requires root and installed systemd-tmpfiles";
    }
    ManagedDebianFixture();
    const auto root = context.GetTempdirPath() + "/tmpfiles-root";
    ASSERT_EQ(0, mkdir(root.c_str(), 0700));
    for (const auto& path : {"/run", "/etc", "/etc/tmpfiles.d"})
    {
        ASSERT_EQ(0, mkdir((root + path).c_str(), 0755));
    }
    runtimeDirectory = root + "/run/faillock";
    tmpfilesDirectory = root + "/etc/tmpfiles.d";
    context.SetSpecialFilePath("/var/run/faillock", runtimeDirectory);
    context.SetSpecialFilePath("/run/faillock", runtimeDirectory);
    context.SetSpecialFilePath("/etc/tmpfiles.d", tmpfilesDirectory);
    EXPECT_CALL(context, ExecuteCommand(testing::HasSubstr(" --create --prefix="))).WillOnce(Invoke([&](const std::string&) -> Result<std::string> {
        const auto command = "/usr/bin/systemd-tmpfiles --root='" + root + "' --create --prefix=/run/faillock kompli-faillock.conf";
        return system(command.c_str()) == 0 ? Result<std::string>(std::string("scoped creation succeeded")) :
                                              Result<std::string>(Error("Scoped tmpfiles integration failed", EIO));
    }));
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    struct stat metadata
    {
    };
    ASSERT_EQ(0, stat(runtimeDirectory.c_str(), &metadata));
    EXPECT_EQ(0755U, metadata.st_mode & 0777U);
    EXPECT_EQ(0U, metadata.st_uid);
}

TEST_F(PasswordPolicyOptionTest, RestoresPamAndBootMetadataWhenScopedCreationFails)
{
    ManagedDebianFixture();
    const auto original = Read(pamDirectory + "/common-auth").Value();
    runtimeCreationFails = true;
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(original, Read(pamDirectory + "/common-auth").Value());
    EXPECT_EQ(1U, debianProfiles.size());
    EXPECT_EQ(-1, access((tmpfilesDirectory + "/kompli-faillock.conf").c_str(), F_OK));
    EXPECT_EQ(-1, access(runtimeDirectory.c_str(), F_OK));
}

TEST_F(PasswordPolicyOptionTest, RejectsFaillockDirectoryBelowUntrustedParent)
{
    ManagedDebianFixture();
    const auto original = Read(pamDirectory + "/common-auth").Value();
    const auto parent = context.GetTempdirPath() + "/unsafe-run";
    ASSERT_EQ(0, mkdir(parent.c_str(), 0777));
    ASSERT_EQ(0, chmod(parent.c_str(), 0777));
    context.SetSpecialFilePath("/run", parent);
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_NE(std::string::npos, result.Error().message.find("Faillock directory parent must already exist with trusted root-owned metadata"));
    EXPECT_EQ(original, Read(pamDirectory + "/common-auth").Value());
    EXPECT_EQ(-1, access(runtimeDirectory.c_str(), F_OK));
}

TEST_F(PasswordPolicyOptionTest, RemovesCreatedFaillockDirectoryWhenAuthselectScopedCreationFails)
{
    ManagedAuthselectFixture();
    runtimeCreationFails = true;
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(originalSelection, selection);
    EXPECT_EQ(-1, access((tmpfilesDirectory + "/kompli-faillock.conf").c_str(), F_OK));
    EXPECT_EQ(-1, access(runtimeDirectory.c_str(), F_OK));
}

TEST_F(PasswordPolicyOptionTest, PreservesConfiguredTallyDirectoryAndExistingAdminTmpfilesMetadata)
{
    ManagedDebianFixture();
    std::ofstream(config) << "deny = 3\ndir = /run/custom-tally\n";
    context.SetSpecialFilePath("/run/custom-tally", runtimeDirectory);
    ASSERT_EQ(0, mkdir(runtimeDirectory.c_str(), 0700));
    const auto profile = tmpfilesDirectory + "/administrator.conf";
    std::ofstream(profile) << "d /run/custom-tally 0700 root root -\n";
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ("d /run/custom-tally 0700 root root -\n", Read(profile).Value());
    EXPECT_EQ(-1, access((tmpfilesDirectory + "/kompli-faillock.conf").c_str(), F_OK));
    struct stat metadata
    {
    };
    ASSERT_EQ(0, stat(runtimeDirectory.c_str(), &metadata));
    EXPECT_EQ(0700U, metadata.st_mode & 0777U);
    EXPECT_NE(Read(config)->find("dir = /run/custom-tally"), std::string::npos);
}

TEST_F(PasswordPolicyOptionTest, SequentialAdoptionRetainsEarlierLockoutAndOriginalProviders)
{
    ManagedAuthselectFixture();
    ASSERT_TRUE(RemediatePasswordPolicyOption(params, indicators, context).HasValue());
    const auto firstProfile = selection.substr(0, selection.find(' '));
    context.SetSpecialFilePath("/usr/lib64/security/pam_pwhistory.so", context.MakeTempfile("\177ELF inline-only"));
    params.policy = "pwhistory";
    params.option = "remember";
    params.value = "24";
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(firstProfile, selection.substr(0, selection.find(' ')));
    EXPECT_EQ(1U, ProfileCount());
    EXPECT_NE(selection.find("with-faillock"), std::string::npos);
    EXPECT_NE(selection.find("with-pwhistory"), std::string::npos);
    const auto stack = Read(pamDirectory + "/system-auth").Value();
    EXPECT_NE(stack.find("pam_faillock.so preauth deny=3"), std::string::npos);
    EXPECT_NE(stack.find("pam_pwhistory.so use_authtok remember=24"), std::string::npos);
    EXPECT_NE(stack.find("auth sufficient pam_unix.so"), std::string::npos);
    EXPECT_EQ(nssContents, Read(context.GetSpecialFilePath("/etc/nsswitch.conf")).Value());
}

TEST_F(PasswordPolicyOptionTest, FailedUpdateOfReusedProfileRestoresItsTemplates)
{
    ManagedAuthselectFixture();
    ASSERT_TRUE(RemediatePasswordPolicyOption(params, indicators, context).HasValue());
    const auto profile = selection.substr(0, selection.find(' '));
    const auto templatePath = profileRoot + "/" + profile.substr(7) + "/system-auth";
    const auto before = Read(templatePath).Value();
    originalSelection = selection;
    context.SetSpecialFilePath("/usr/lib64/security/pam_pwhistory.so", context.MakeTempfile("\177ELF inline-only"));
    params.policy = "pwhistory";
    params.option = "remember";
    params.value = "24";
    selectFails = true;
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(before, Read(templatePath).Value());
    EXPECT_EQ(originalSelection, selection);
    EXPECT_EQ(1U, ProfileCount());
}

TEST_F(PasswordPolicyOptionTest, VendorSuseHistoryPreservesProvidersAndRollsBackProviderDrift)
{
    for (const int remembered : {0, 32})
    {
        for (const bool drift : {false, true})
        {
            AuthselectFixture("pwhistory");
            testing::Mock::VerifyAndClearExpectations(&context);
            EXPECT_CALL(context, GetFileContents(_)).WillRepeatedly(Invoke(Read));
            context.SetSpecialFilePath("/etc/os-release", context.MakeTempfile("ID=sles\nVERSION_ID=12.5\n"));
            const auto executable = context.MakeTempfile("");
            ASSERT_EQ(0, chmod(executable.c_str(), 0755));
            context.SetSpecialFilePath("/usr/sbin/pam-config", executable);
            const auto directory = context.MakeTempfile("") + ".suse";
            ASSERT_EQ(0, mkdir(directory.c_str(), 0755));
            const std::string password = "password requisite pam_cracklib.so retry=3\n" +
                                         (remembered ? std::string("password optional pam_pwhistory.so use_authtok remember=32\n") : "") +
                                         "password required pam_unix.so use_authtok nullok\n";
            for (const auto& type : {"auth", "account", "password", "session"})
            {
                const auto name = std::string("common-") + type;
                context.SetSpecialFilePath("/etc/pam.d/" + name, directory + "/" + name);
                context.SetSpecialFilePath("/etc/pam.d/" + name + "-pc", directory + "/" + name + "-pc");
                std::ofstream(directory + "/" + name + "-pc")
                    << (std::string(type) == "password" ? password : std::string(type) + " required pam_unix.so\n");
                ASSERT_EQ(0, symlink((name + "-pc").c_str(), (directory + "/" + name).c_str()));
            }
            EXPECT_CALL(context, ExecuteCommand(_)).WillRepeatedly(Invoke([&](const std::string& command) -> Result<std::string> {
                const auto target = remembered ? "32" : "24";
                EXPECT_NE(command.find(std::string("--add --pwhistory --pwhistory-use_authtok --pwhistory-remember=") + target), std::string::npos);
                std::ofstream(directory + "/common-password-pc")
                    << "password\trequisite\tpam_cracklib.so\tretry=3 \t\npassword requisite pam_pwhistory.so use_authtok remember=" << target
                    << "\npassword required pam_unix.so use_authtok" << (drift ? "" : " nullok") << "\n";
                return std::string("generated");
            }));
            auto result = RemediatePasswordPolicyOption(params, indicators, context);
            if (drift)
            {
                ASSERT_FALSE(result.HasValue());
                EXPECT_EQ(password, Read(directory + "/common-password-pc").Value());
            }
            else
            {
                ASSERT_TRUE(result.HasValue()) << result.Error().message;
                EXPECT_EQ(Status::Compliant, AuditPasswordPolicyOption(params, indicators, context).Value());
                EXPECT_NE(Read(directory + "/common-password-pc")->find("pam_unix.so use_authtok nullok"), std::string::npos);
            }
        }
    }
}

TEST_F(PasswordPolicyOptionTest, RealPamDispatchChecksSuccessFailureLockoutAndHistoryControlFlow)
{
    // Use real libpam dispatch with permit/deny as deterministic module outcome
    // surrogates. No authentication account, password or host PAM file is changed.
    auto library = std::unique_ptr<void, int (*)(void*)>(dlopen("libpam.so.0", RTLD_NOW), dlclose);
    if (!library)
    {
        GTEST_SKIP() << "libpam is not installed";
    }
    using Start = int (*)(const char*, const char*, const void*, const char*, void**);
    using Operation = int (*)(void*, int);
    using End = int (*)(void*, int);
    const auto start = reinterpret_cast<Start>(dlsym(library.get(), "pam_start_confdir"));
    const auto authenticate = reinterpret_cast<Operation>(dlsym(library.get(), "pam_authenticate"));
    const auto password = reinterpret_cast<Operation>(dlsym(library.get(), "pam_chauthtok"));
    const auto account = reinterpret_cast<Operation>(dlsym(library.get(), "pam_acct_mgmt"));
    const auto end = reinterpret_cast<End>(dlsym(library.get(), "pam_end"));
    if (!start || !authenticate || !password || !account || !end)
    {
        GTEST_SKIP() << "libpam does not support isolated pam_start_confdir";
    }
    struct Conversation
    {
        int (*callback)(int, const void**, void***, void*);
        void* data;
    } conversation = {[](int, const void**, void***, void*) { return 19; }, nullptr};
    for (const auto& outcomes : std::vector<std::vector<bool>>{{true, true, true}, {true, false, false}, {false, true, false}, {false, false, false}})
    {
        std::ofstream(pamDirectory + "/kompli-validation") << "auth required pam_" << (outcomes[0] ? "permit" : "deny")
                                                           << ".so\n"
                                                              "auth sufficient pam_"
                                                           << (outcomes[1] ? "permit" : "deny")
                                                           << ".so\n"
                                                              "auth required pam_deny.so\n"
                                                              "auth required pam_deny.so\n"
                                                              "account required pam_permit.so\n";
        void* handle = nullptr;
        ASSERT_EQ(0, start("kompli-validation", "kompli-nonexistent-fixture", &conversation, pamDirectory.c_str(), &handle));
        const auto result = authenticate(handle, 0);
        EXPECT_EQ(outcomes[2], result == 0);
        if (result == 0)
        {
            EXPECT_EQ(0, account(handle, 0));
        }
        EXPECT_EQ(0, end(handle, result));
    }
    for (const auto& policy : {"pwquality", "pwhistory"})
    {
        for (const auto allowed : {true, false})
        {
            std::ofstream(pamDirectory + "/kompli-validation")
                << "password " << (std::string(policy) == "pwquality" ? "requisite" : "required") << " pam_" << (allowed ? "permit" : "deny")
                << ".so\n"
                   "password sufficient pam_permit.so\n"
                   "password required pam_deny.so\n";
            void* handle = nullptr;
            ASSERT_EQ(0, start("kompli-validation", "kompli-nonexistent-fixture", &conversation, pamDirectory.c_str(), &handle));
            const auto result = password(handle, 0);
            EXPECT_EQ(allowed, result == 0) << policy;
            EXPECT_EQ(0, end(handle, result));
        }
    }
}

TEST_F(PasswordPolicyOptionTest, RealFaillockThresholdAndSuccessfulAccountReset)
{
    if (geteuid() != 0)
    {
        GTEST_SKIP() << "Isolated root-account faillock test requires root";
    }
    auto library = std::unique_ptr<void, int (*)(void*)>(dlopen("libpam.so.0", RTLD_NOW), dlclose);
    ASSERT_NE(nullptr, library.get());
    using Start = int (*)(const char*, const char*, const void*, const char*, void**);
    using Operation = int (*)(void*, int);
    const auto start = reinterpret_cast<Start>(dlsym(library.get(), "pam_start_confdir"));
    const auto authenticate = reinterpret_cast<Operation>(dlsym(library.get(), "pam_authenticate"));
    const auto account = reinterpret_cast<Operation>(dlsym(library.get(), "pam_acct_mgmt"));
    const auto end = reinterpret_cast<Operation>(dlsym(library.get(), "pam_end"));
    ASSERT_NE(nullptr, start);
    const auto tally = context.GetTempdirPath() + "/isolated-tally";
    ASSERT_EQ(0, mkdir(tally.c_str(), 0700));
    const auto settings = context.MakeTempfile("deny = 3\nunlock_time = 0\neven_deny_root\nroot_unlock_time = 0\ndir = " + tally + "\n");
    struct Conversation
    {
        int (*callback)(int, const void**, void***, void*);
        void* data;
    } conversation = {[](int, const void**, void***, void*) { return 19; }, nullptr};
    const auto attempt = [&](bool correct) {
        std::ofstream(pamDirectory + "/kompli-real-faillock") << "auth requisite pam_faillock.so preauth conf=" + settings +
                                                                     "\n"
                                                                     "auth [success=2 default=ignore] pam_" +
                                                                     std::string(correct ? "permit" : "deny") +
                                                                     ".so\n"
                                                                     "auth required pam_faillock.so authfail conf=" +
                                                                     settings +
                                                                     "\n"
                                                                     "auth requisite pam_deny.so\n"
                                                                     "auth required pam_permit.so\n"
                                                                     "account required pam_permit.so\n"
                                                                     "account required pam_faillock.so conf=" +
                                                                     settings + "\n";
        void* handle = nullptr;
        EXPECT_EQ(0, start("kompli-real-faillock", "root", &conversation, pamDirectory.c_str(), &handle));
        if (!handle)
        {
            return false;
        }
        const auto result = authenticate(handle, 0);
        if (result == 0)
        {
            EXPECT_EQ(0, account(handle, 0));
        }
        EXPECT_EQ(0, end(handle, result));
        return result == 0;
    };
    for (int round = 0; round < 2; ++round)
    {
        EXPECT_FALSE(attempt(false));
        EXPECT_FALSE(attempt(false));
        EXPECT_TRUE(attempt(true));
    }
    EXPECT_FALSE(attempt(false));
    EXPECT_FALSE(attempt(false));
    EXPECT_FALSE(attempt(false));
    EXPECT_FALSE(attempt(true));
}

TEST_F(PasswordPolicyOptionTest, RealHistoryAndWeakQualityInIsolatedFilesystem)
{
    if (geteuid() != 0)
    {
        GTEST_SKIP() << "Isolated synthetic passwd/shadow tests require chroot privilege";
    }
    auto library = std::unique_ptr<void, int (*)(void*)>(dlopen("libpam.so.0", RTLD_NOW | RTLD_GLOBAL), dlclose);
    ASSERT_NE(nullptr, library.get());
    auto cryptLibrary = std::unique_ptr<void, int (*)(void*)>(dlopen("libcrypt.so.1", RTLD_NOW | RTLD_GLOBAL), dlclose);
    ASSERT_NE(nullptr, cryptLibrary.get());
    using Crypt = char* (*)(const char*, const char*);
    const auto crypt = reinterpret_cast<Crypt>(dlsym(cryptLibrary.get(), "crypt"));
    ASSERT_NE(nullptr, crypt);
    const std::string oldHash = crypt("HistoryOld_A91!_unique", "$6$kompliunit$");
    const auto fixture = context.GetTempdirPath() + "/synthetic-system";
    ASSERT_EQ(0, mkdir(fixture.c_str(), 0700));
    ASSERT_EQ(0, mkdir((fixture + "/etc").c_str(), 0755));
    ASSERT_EQ(0, mkdir((fixture + "/etc/security").c_str(), 0700));
    ASSERT_EQ(0, mkdir((fixture + "/pam").c_str(), 0755));
    std::ofstream(fixture + "/etc/passwd") << "root:x:0:0:synthetic:/root:/bin/sh\n";
    std::ofstream(fixture + "/etc/shadow") << "root:" << oldHash << ":20000:0:99999:7:::\n";
    std::ofstream(fixture + "/etc/nsswitch.conf") << "passwd: files\nshadow: files\n";
    std::string hashes;
    for (int index = 0; index < 25; ++index)
    {
        const auto token = "StoredPast_" + std::to_string(index) + "_A9!unique";
        hashes += (hashes.empty() ? "" : ",") + std::string(crypt(token.c_str(), "$6$kompliunit$"));
    }
    std::ofstream(fixture + "/etc/security/opasswd") << "root:0:25:" << hashes << "\n";
    ASSERT_EQ(0, chmod((fixture + "/etc/shadow").c_str(), 0600));
    ASSERT_EQ(0, chmod((fixture + "/etc/security/opasswd").c_str(), 0600));
    const auto source = context.MakeTempfile(
        "extern int pam_set_item(void *, int, const void *);\n"
        "int pam_sm_chauthtok(void *p, int flags, int argc, const char **argv) {\n"
        " return (flags & 0x2000) && argc == 1 ? pam_set_item(p, 6, argv[0]) : 0; }\n");
    const auto compiled = fixture + "/token.so";
    const auto command = "clang -x c -shared -fPIC '" + source + "' -o '" + compiled + "'";
    ASSERT_EQ(0, system(command.c_str()));
    const auto copy = [&](const std::string& sourcePath, const std::string& name) {
        std::ifstream input(sourcePath, std::ios::binary);
        std::ofstream output(fixture + "/" + name, std::ios::binary);
        output << input.rdbuf();
        return input.good() && output.good();
    };
    std::string modules = "/lib/x86_64-linux-gnu/security";
    if (access((modules + "/pam_pwhistory.so").c_str(), R_OK) != 0)
    {
        GTEST_SKIP() << "System pwhistory module is unavailable";
    }
    auto history = std::unique_ptr<void, int (*)(void*)>(dlopen((modules + "/pam_pwhistory.so").c_str(), RTLD_NOW | RTLD_GLOBAL), dlclose);
    ASSERT_NE(nullptr, history.get());
    ASSERT_TRUE(copy(modules + "/pam_pwhistory.so", "history.so"));
    ASSERT_TRUE(copy(modules + "/pam_permit.so", "permit.so"));
    const char* extracted = getenv("KOMPLI_PAM_TEST_LIBRARIES");
    std::unique_ptr<void, int (*)(void*)> crack(nullptr, dlclose);
    std::unique_ptr<void, int (*)(void*)> qualityLibrary(nullptr, dlclose);
    if (extracted)
    {
        const std::string path = extracted;
        crack.reset(dlopen((path + "/libcrack.so.2").c_str(), RTLD_NOW | RTLD_GLOBAL));
        qualityLibrary.reset(dlopen((path + "/libpwquality.so.1").c_str(), RTLD_NOW | RTLD_GLOBAL));
        ASSERT_NE(nullptr, crack.get()) << dlerror();
        ASSERT_NE(nullptr, qualityLibrary.get()) << dlerror();
        ASSERT_TRUE(copy(path + "/security/pam_pwquality.so", "quality.so"));
    }
    using Start = int (*)(const char*, const char*, const void*, const char*, void**);
    using Operation = int (*)(void*, int);
    const auto start = reinterpret_cast<Start>(dlsym(library.get(), "pam_start_confdir"));
    const auto password = reinterpret_cast<Operation>(dlsym(library.get(), "pam_chauthtok"));
    const auto end = reinterpret_cast<Operation>(dlsym(library.get(), "pam_end"));
    ASSERT_NE(nullptr, start);
    for (const auto& scenario : std::vector<std::pair<std::string, bool>>{
             {"history-old", false}, {"history-retained", false}, {"history-new", true}, {"quality-weak", false}, {"quality-strong", true}})
    {
        const bool quality = scenario.first.find("quality-") == 0;
        if (quality && !extracted)
        {
            continue;
        }
        const auto token = scenario.first == "history-old" ?
                               "HistoryOld_A91!_unique" :
                               (scenario.first == "history-retained" ? "StoredPast_5_A9!unique" :
                                                                       (scenario.first == "quality-weak" ? "ShortA9!pass" : "DifferentNew_b7$Pass"));
        std::ofstream(fixture + "/pam/kompli-password")
            << "password required /token.so " + std::string(token) + "\npassword required /" +
                   (quality ? std::string("quality.so minlen=14 dictcheck=0 enforce_for_root use_authtok retry=1") :
                              std::string("history.so remember=24 use_authtok enforce_for_root retry=1")) +
                   "\npassword required /permit.so\n";
        const auto child = fork();
        ASSERT_GE(child, 0);
        if (child == 0)
        {
            if (chroot(fixture.c_str()) != 0 || chdir("/") != 0)
            {
                _exit(40);
            }
            struct Conversation
            {
                int (*callback)(int, const void**, void***, void*);
                void* data;
            } conversation = {[](int count, const void** messages, void*** responses, void* data) {
                                  struct Message
                                  {
                                      int style;
                                      const char* text;
                                  };
                                  struct Response
                                  {
                                      char* text;
                                      int code;
                                  };
                                  auto reply = static_cast<Response*>(calloc(static_cast<size_t>(count), sizeof(Response)));
                                  if (!reply)
                                      return 5;
                                  for (int index = 0; index < count; ++index)
                                  {
                                      if (static_cast<const Message*>(messages[index])->style == 1)
                                      {
                                          reply[index].text = strdup(static_cast<const char*>(data));
                                      }
                                  }
                                  *responses = reinterpret_cast<void**>(reply);
                                  return 0;
                              },
                const_cast<char*>(token)};
            void* handle = nullptr;
            if (start("kompli-password", "root", &conversation, "/pam", &handle) != 0)
            {
                _exit(41);
            }
            const auto result = password(handle, 0);
            end(handle, result);
            _exit((result == 0) == scenario.second ? 0 : 100 + result);
        }
        int status = 0;
        ASSERT_EQ(child, waitpid(child, &status, 0));
        EXPECT_TRUE(WIFEXITED(status));
        EXPECT_EQ(0, WEXITSTATUS(status)) << scenario.first;
    }
    EXPECT_EQ(0U, Read(fixture + "/etc/security/opasswd")->find("root:0:24:"));
    if (!extracted)
        GTEST_SKIP() << "History was exercised; pwquality needs KOMPLI_PAM_TEST_LIBRARIES or extracted test dependencies";
}

TEST_F(PasswordPolicyOptionTest, DoesNotEnableMissingModules)
{
    std::ofstream(pam) << "# pam_pwquality.so\npassword required pam_unix.so\n";
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, ENOTSUP);
    ExpectFile("# password policy\nminlen = 8\n");
}

TEST_F(PasswordPolicyOptionTest, ReadsAuthselectSymlinksButNeverWritesThem)
{
    const auto target = context.MakeTempfile("password requisite pam_pwquality.so\n");
    ASSERT_EQ(0, unlink(pam.c_str()));
    ASSERT_EQ(0, symlink(target.c_str(), pam.c_str()));
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
    EXPECT_EQ(Read(target).Value(), "password requisite pam_pwquality.so\n");
}

TEST_F(PasswordPolicyOptionTest, ChecksLegacyPamConfForConflictingOverrides)
{
    std::ofstream(context.GetSpecialFilePath("/etc/pam.conf")) << "login password requisite pam_pwquality.so minlen=8\n";
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, ENOTSUP);
    ExpectFile("# password policy\nminlen = 8\n");
}

TEST_F(PasswordPolicyOptionTest, FailsClosedOnUnreadablePamConfiguration)
{
    EXPECT_CALL(context, GetFileContents(pam)).WillRepeatedly(Return(Error("Unreadable PAM file", EACCES)));
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, EACCES);
    ExpectFile("# password policy\nminlen = 8\n");
}

TEST_F(PasswordPolicyOptionTest, RequiresExistingConfiguration)
{
    ASSERT_EQ(0, unlink(config.c_str()));
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, ENOENT);
    EXPECT_EQ(-1, access(config.c_str(), F_OK));
}

TEST_F(PasswordPolicyOptionTest, RefusesSymlinkedConfiguration)
{
    const auto target = context.MakeTempfile("minlen = 8\n");
    ASSERT_EQ(0, unlink(config.c_str()));
    ASSERT_EQ(0, symlink(target.c_str(), config.c_str()));
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(Read(target).Value(), "minlen = 8\n");
}

TEST_F(PasswordPolicyOptionTest, RefusesHardlinkedConfiguration)
{
    ASSERT_EQ(0, link(config.c_str(), (config + ".link").c_str()));
    EXPECT_FALSE(RemediatePasswordPolicyOption(params, indicators, context).HasValue());
    ExpectFile("# password policy\nminlen = 8\n");
}

TEST_F(PasswordPolicyOptionTest, RollsBackFailedPostAudit)
{
    int calls = 0;
    EXPECT_CALL(context, GetFileContents(config)).WillRepeatedly(Invoke([&](const std::string& path) -> Result<std::string> {
        if (++calls == 3)
        {
            return std::string("minlen = 6\n");
        }
        return Read(path);
    }));
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
    ExpectFile("# password policy\nminlen = 8\n");
}

TEST_F(PasswordPolicyOptionTest, RollsBackPostAuditReadErrors)
{
    int calls = 0;
    EXPECT_CALL(context, GetFileContents(config)).WillRepeatedly(Invoke([&](const std::string& path) -> Result<std::string> {
        if (++calls == 3)
        {
            return Error("Verification read failed", EIO);
        }
        return Read(path);
    }));
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, EIO);
    ExpectFile("# password policy\nminlen = 8\n");
}

TEST_F(PasswordPolicyOptionTest, ReportsRollbackFailureWithoutFollowingReplacementSymlink)
{
    const auto target = context.MakeTempfile("administrator replacement\n");
    int calls = 0;
    EXPECT_CALL(context, GetFileContents(config)).WillRepeatedly(Invoke([&](const std::string& path) -> Result<std::string> {
        if (++calls == 3)
        {
            EXPECT_EQ(0, unlink(config.c_str()));
            EXPECT_EQ(0, symlink(target.c_str(), config.c_str()));
            return Error("Verification failed", EIO);
        }
        return Read(path);
    }));
    auto result = RemediatePasswordPolicyOption(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_NE(result.Error().message.find("rollback failed"), std::string::npos);
    EXPECT_EQ(Read(target).Value(), "administrator replacement\n");
}

TEST_F(PasswordPolicyOptionTest, GeneratedAuditGuardSkipsAlreadyCompliantRulesWithoutWeakeningSettings)
{
    const auto marker = context.MakeTempfile("unchanged\n");
    ASSERT_EQ(0, chmod(marker.c_str(), 0600));
    const auto verification = "{\"not\":{\"not\":{\"FilePermissions\":{\"path\":\"" + marker + "\",\"mask\":\"0177\"}}}}";
    const std::string writer = "{\"PasswordPolicyOption\":{\"policy\":\"pwquality\",\"option\":\"minlen\",\"value\":\"14\"}}";
    auto json = JsonWrapper::FromString("{\"anyOf\":[" + verification + ",{\"allOf\":[" + writer + "," + verification + "]}]}");
    ASSERT_TRUE(json.HasValue());
    const ParameterMap parameters;
    Evaluator evaluator("test", json_value_get_object(json->get()), parameters, context);
    auto result = evaluator.ExecuteRemediation();
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
    ExpectFile("# password policy\nminlen = 8\n");
}

TEST_F(PasswordPolicyOptionTest, GeneratedPostAuditDoesNotRemediateOtherChecksOrClaimRuleSuccess)
{
    const auto marker = context.MakeTempfile("unchanged\n");
    ASSERT_EQ(0, chmod(marker.c_str(), 0644));
    const auto verification = "{\"not\":{\"not\":{\"FilePermissions\":{\"path\":\"" + marker + "\",\"mask\":\"0177\"}}}}";
    const std::string writer = "{\"PasswordPolicyOption\":{\"policy\":\"pwquality\",\"option\":\"minlen\",\"value\":\"14\"}}";
    auto json = JsonWrapper::FromString("{\"anyOf\":[" + verification + ",{\"allOf\":[" + writer + "," + verification + "]}]}");
    ASSERT_TRUE(json.HasValue());
    const ParameterMap parameters;
    Evaluator evaluator("test", json_value_get_object(json->get()), parameters, context);
    auto result = evaluator.ExecuteRemediation();
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
    ExpectFile("# password policy\nminlen = 14\n");
    struct stat metadata;
    ASSERT_EQ(0, stat(marker.c_str(), &metadata));
    EXPECT_EQ(metadata.st_mode & 0777U, 0644U);
}
