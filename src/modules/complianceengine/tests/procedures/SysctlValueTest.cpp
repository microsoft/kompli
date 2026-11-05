// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "CommonUtils.h"
#include "MockContext.h"

#include <SysctlValue.h>
#include <algorithm>
#include <dirent.h>
#include <fstream>
#include <gtest/gtest.h>
#include <iterator>
#include <string.h>
#include <string>
#include <unistd.h>
#include <vector>

using ComplianceEngine::AuditSysctlValue;
using ComplianceEngine::CompactListFormatter;
using ComplianceEngine::Error;
using ComplianceEngine::IndicatorsTree;
using ComplianceEngine::Pattern;
using ComplianceEngine::RemediateSysctlValue;
using ComplianceEngine::Result;
using ComplianceEngine::Status;
using ComplianceEngine::SysctlValueParams;
using ::testing::Return;

static const std::string systemdSysctlCat = "/lib/systemd/systemd-sysctl --cat-config";
static const std::string systemdSysctlVersion = "/lib/systemd/systemd-sysctl --version";
static const std::string systemdUsrSysctlCat = "/usr/lib/systemd/systemd-sysctl --cat-config";
static const std::string systemdUsrSysctlVersion = "/usr/lib/systemd/systemd-sysctl --version";
static const std::string sysctlIpForward0 = "net.ipv4.ip_forward = 0";
static const std::string sysctlIpForward1 = "net.ipv4.ip_forward = 1";
static const std::string sysctlIpForward0Comment = "                          # net.ipv4.ip_forward = 0";

struct SysctlNameValue
{
    std::string name;
    std::string value;
    SysctlNameValue(std::string a_name, std::string a_value)
        : name(a_name),
          value(a_value)
    {
    }
    std::string CfgOutput() const
    {
        auto fname = name;
        std::replace(fname.begin(), fname.end(), '.', '/');
        fname = std::string("# /etc/") + fname + ".conf\n";
        auto nameEqVal = name + " = " + value + "\n";
        return fname + nameEqVal;
    }
};

// sysctl names that should be matchec correctly using regexp in ensureSysctl
static const std::vector<SysctlNameValue> unsuportedSysctlTests = {
    // This is sysctl with multiline output as stated in SysctlNameValue.value string, currenlty due to regex limitation we can handle it
    SysctlNameValue(std::string("fs.binfmt_misc.python3/10"),
        std::string("enabled\ninterpreter /usr/bin/python3.10\nflags:\noffset 0\nmagic 6f0d0d0a\n")),
};

static const std::vector<SysctlNameValue> cisSsysctlNames = {
    SysctlNameValue(std::string("net.ipv4.conf.all.accept_redirects"), std::string("0")),
    SysctlNameValue(std::string("net.ipv4.conf.all.accept_source_route"), std::string("0")),
    SysctlNameValue(std::string("net.ipv4.conf.all.log_martians"), std::string("1")),
    SysctlNameValue(std::string("net.ipv4.conf.all.rp_filter"), std::string("1")),
    SysctlNameValue(std::string("net.ipv4.conf.all.secure_redirects"), std::string("0")),
    SysctlNameValue(std::string("net.ipv4.conf.all.send_redirects"), std::string("0")),
    SysctlNameValue(std::string("net.ipv4.conf.default.accept_redirects"), std::string("0")),
    SysctlNameValue(std::string("net.ipv4.conf.default.accept_source_route"), std::string("0")),
    SysctlNameValue(std::string("net.ipv4.conf.default.log_martians"), std::string("1")),
    SysctlNameValue(std::string("net.ipv4.conf.default.rp_filter"), std::string("1")),
    SysctlNameValue(std::string("net.ipv4.conf.default.secure_redirects"), std::string("0")),
    SysctlNameValue(std::string("net.ipv4.conf.default.send_redirects"), std::string("0")),
    SysctlNameValue(std::string("net.ipv4.icmp_echo_ignore_broadcasts"), std::string("1")),
    SysctlNameValue(std::string("net.ipv4.icmp_ignore_bogus_error_responses"), std::string("1")),
    SysctlNameValue(std::string("net.ipv4.ip_forward"), std::string("0")),
    SysctlNameValue(std::string("net.ipv4.tcp_syncookies"), std::string("1")),
    SysctlNameValue(std::string("net.ipv6.conf.all.accept_ra"), std::string("0")),
    SysctlNameValue(std::string("net.ipv6.conf.all.accept_redirects"), std::string("0")),
    SysctlNameValue(std::string("net.ipv6.conf.all.accept_source_route"), std::string("0")),
    SysctlNameValue(std::string("net.ipv6.conf.all.forwarding"), std::string("0")),
    SysctlNameValue(std::string("net.ipv6.conf.default.accept_ra"), std::string("0")),
    SysctlNameValue(std::string("net.ipv6.conf.default.accept_redirects"), std::string("0")),
    SysctlNameValue(std::string("net.ipv6.conf.default.accept_source_route"), std::string("0")),
};

static const char sysctlIpForward1Then0Than1Than0[] =
    "net.ipv4.ip_forward = 1\n"
    "net.ipv4.ip_forward = 0\n"
    "net.ipv4.ip_forward = 1\n"
    "net.ipv4.ip_forward = 0";

static const char emptyOutput[] = "";

static const char sysctlIpForward0FilenameExtraSpaces[] =
    ""
    "# /etc/sysctl.d/foo.conf\n"
    "     net.ipv4.ip_forward    =          0     \n"
    "     \n";

static const char sysctlIpForward0FilenameTabs[] =
    ""
    "# /etc/sysctl.d/foo.conf\n"
    " \t net.ipv4.ip_forward    =\t0\t     \n"
    "     \n";

static const char sysctlIpForward1Then0Than1Than0WithFilenames[] =
    "# /etc/sysctl.d/fwd_1.conf\n"
    "   net.ipv4.ip_forward = 1\n"
    "# /etc/sysctl.d/fwd_0.conf\n"
    "   net.ipv4.ip_forward = 0\n"
    "# /etc/sysctl.d/fwd_1_v2.conf\n"
    "   net.ipv4.ip_forward = 1\n"
    "# /etc/sysctl.d/fwd_0_v2.conf\n"
    "   net.ipv4.ip_forward = 0\n";

namespace
{
Result<std::string> ReadTestFile(const std::string& path)
{
    std::ifstream input(path);
    if (!input.is_open())
    {
        return Error("Failed to read test file", errno);
    }
    return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}
} // anonymous namespace

class SysctlValueTest : public ::testing::Test
{
    struct LengthComparator
    {
        bool operator()(const std::string& lhs, const std::string& rhs) const
        {
            if (lhs.size() == rhs.size())
            { // If lengths are equal, sort lexicographically
                return lhs < rhs;
            }
            return lhs.size() > rhs.size(); // Sort by length, longest first
        }
    };

protected:
    MockContext mContext;
    IndicatorsTree mIndicators;
    CompactListFormatter mFormatter;

    void SetUp() override
    {
        mIndicators.Push("SysctlValue");
    }
};

class LegacySysctlValueTest : public SysctlValueTest
{
protected:
    std::vector<std::string> directories;
    SysctlValueParams params;

    void SetUp() override
    {
        SysctlValueTest::SetUp();
        const std::vector<std::string> locations = {"/etc/sysctl.d", "/run/sysctl.d", "/usr/local/lib/sysctl.d", "/usr/lib/sysctl.d", "/lib/sysctl.d"};
        for (size_t i = 0; i < locations.size(); ++i)
        {
            const auto directory = mContext.GetTempdirPath() + "/sysctl-" + std::to_string(i);
            ASSERT_EQ(0, mkdir(directory.c_str(), 0700));
            directories.push_back(directory);
            mContext.SetSpecialFilePath(locations[i], directory);
        }
        params.sysctlName = "net.ipv4.ip_forward";
        params.value = Pattern::Make("0").Value();
        EXPECT_CALL(mContext, GetFileContents(testing::_)).WillRepeatedly(testing::Invoke(ReadTestFile));
        EXPECT_CALL(mContext, GetFileContents("/proc/sys/net/ipv4/ip_forward")).WillRepeatedly(Return(Result<std::string>("0\n")));
        EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlVersion)).WillRepeatedly(Return(Result<std::string>("systemd 228")));
        EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlCat))
            .WillRepeatedly(Return(Result<std::string>(Error("systemd-sysctl: unrecognized option '--cat-config'", EIO))));
    }

    std::string Write(size_t directory, const std::string& name, const std::string& contents)
    {
        const auto path = directories.at(directory) + "/" + name;
        std::ofstream(path) << contents;
        return path;
    }
};

TEST_F(LegacySysctlValueTest, ReadsConfigurationOnOlderSystemd)
{
    Write(0, "90-custom.conf", sysctlIpForward0);
    auto result = AuditSysctlValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());
}

TEST_F(LegacySysctlValueTest, HighestPriorityDirectoryMasksSameBasename)
{
    Write(0, "90-custom.conf", sysctlIpForward0);
    Write(1, "90-custom.conf", sysctlIpForward1);
    Write(2, "90-custom.conf", sysctlIpForward1);
    Write(3, "90-custom.conf", sysctlIpForward1);
    Write(4, "90-custom.conf", sysctlIpForward1);
    auto result = AuditSysctlValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());
}

TEST_F(LegacySysctlValueTest, RunDirectoryOverridesVendorWithSameName)
{
    Write(1, "90-custom.conf", sysctlIpForward0);
    Write(2, "90-custom.conf", sysctlIpForward1);
    auto result = AuditSysctlValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());
}

TEST_F(LegacySysctlValueTest, FilenameOrderAppliesAcrossDirectories)
{
    Write(0, "10-first.conf", sysctlIpForward1);
    Write(4, "99-last.conf", sysctlIpForward0);
    auto result = AuditSysctlValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());
}

TEST_F(LegacySysctlValueTest, NullSymlinkMasksVendorFile)
{
    Write(0, "50-custom.conf", sysctlIpForward0);
    Write(3, "99-vendor.conf", sysctlIpForward1);
    ASSERT_EQ(0, symlink("/dev/null", (directories[0] + "/99-vendor.conf").c_str()));
    auto result = AuditSysctlValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());
}

TEST_F(LegacySysctlValueTest, ExistingSysctlConfSymlinkIsRead)
{
    const auto legacy = mContext.MakeTempfile(sysctlIpForward0);
    ASSERT_EQ(0, symlink(legacy.c_str(), (directories[0] + "/99-sysctl.conf").c_str()));
    auto result = AuditSysctlValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());
}

TEST_F(LegacySysctlValueTest, ManagedPersistenceOverridesStockLateSortingFiles)
{
    const auto legacy = mContext.MakeTempfile(sysctlIpForward1);
    ASSERT_EQ(0, symlink(legacy.c_str(), (directories[0] + "/99-sysctl.conf").c_str()));
    Write(0, "99-cloudimg-ipv6.conf", sysctlIpForward1);
    const auto managed = directories[0] + "/99-zz-kompli-net.ipv4.ip_forward.conf";
    mContext.SetSpecialFilePath("/etc/sysctl.d/99-zz-kompli-net.ipv4.ip_forward.conf", managed);
    auto result = RemediateSysctlValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(Status::Compliant, result.Value());
    EXPECT_EQ(0, access(managed.c_str(), F_OK));
}

TEST_F(LegacySysctlValueTest, MissingPersistentValueIsNotCompliant)
{
    auto result = AuditSysctlValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::NonCompliant, result.Value());
}

TEST_F(LegacySysctlValueTest, DoesNotMaskPermissionFailuresAsLegacyCompatibility)
{
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlCat)).WillOnce(Return(Result<std::string>(Error("permission denied --cat-config", EACCES))));
    auto result = AuditSysctlValue(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EACCES, result.Error().code);
}

TEST_F(LegacySysctlValueTest, PropagatesUnreadableSource)
{
    const auto file = Write(0, "90-custom.conf", sysctlIpForward0);
    EXPECT_CALL(mContext, GetFileContents(file)).WillOnce(Return(Result<std::string>(Error("unreadable", EACCES))));
    auto result = AuditSysctlValue(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EACCES, result.Error().code);
}

TEST_F(LegacySysctlValueTest, RefusesNonregularSource)
{
    ASSERT_EQ(0, mkdir((directories[0] + "/90-directory.conf").c_str(), 0700));
    auto result = AuditSysctlValue(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EINVAL, result.Error().code);
}

TEST_F(SysctlValueTest, HappyPathSysctlValueEqualConfigurationNoOverride)
{
    auto sysctlName = std::string("net.ipv4.ip_forward");
    auto sysctlSlashedName = sysctlName;
    std::replace(sysctlSlashedName.begin(), sysctlSlashedName.end(), '.', '/');
    EXPECT_CALL(mContext, GetFileContents("/proc/sys/" + sysctlSlashedName)).WillRepeatedly(Return(Result<std::string>("0\n")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlVersion)).WillRepeatedly(Return(Result<std::string>("")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlCat)).WillRepeatedly(Return(Result<std::string>(sysctlIpForward0)));
    SysctlValueParams params;
    params.sysctlName = sysctlName;
    params.value = Pattern::Make("0").Value();

    auto result = AuditSysctlValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(SysctlValueTest, RuntimeOnlySkipsConfigFileCheck)
{
    // When runtimeOnly is true, a correct runtime value is sufficient and the
    // stored configuration (systemd-sysctl) must NOT be consulted.
    auto sysctlName = std::string("net.ipv4.ip_forward");
    auto sysctlSlashedName = sysctlName;
    std::replace(sysctlSlashedName.begin(), sysctlSlashedName.end(), '.', '/');
    EXPECT_CALL(mContext, GetFileContents("/proc/sys/" + sysctlSlashedName)).WillRepeatedly(Return(Result<std::string>("0\n")));
    // The stored-config path must never be reached.
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlVersion)).Times(0);
    EXPECT_CALL(mContext, ExecuteCommand(systemdUsrSysctlVersion)).Times(0);
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlCat)).Times(0);
    EXPECT_CALL(mContext, ExecuteCommand(systemdUsrSysctlCat)).Times(0);
    SysctlValueParams params;
    params.sysctlName = sysctlName;
    params.value = Pattern::Make("0").Value();
    params.runtimeOnly = true;

    auto result = AuditSysctlValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(SysctlValueTest, RemediateRuntimeOnlyLiteral)
{
    const auto runtimePath = mContext.MakeTempfile("1\n");
    mContext.SetSpecialFilePath("/proc/sys/net/ipv4/ip_forward", runtimePath);
    EXPECT_CALL(mContext, GetFileContents(runtimePath)).WillRepeatedly(::testing::Invoke([runtimePath](const std::string&) {
        return ReadTestFile(runtimePath);
    }));

    SysctlValueParams params;
    params.sysctlName = "net.ipv4.ip_forward";
    params.value = Pattern::Make("0").Value();
    params.runtimeOnly = true;

    auto result = RemediateSysctlValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);

    auto contents = ReadTestFile(runtimePath);
    ASSERT_TRUE(contents.HasValue());
    EXPECT_EQ(contents.Value(), "0");
}

TEST_F(SysctlValueTest, RemediateRuntimeOnlyAnchoredLiteral)
{
    const auto runtimePath = mContext.MakeTempfile("1\n");
    mContext.SetSpecialFilePath("/proc/sys/net/ipv4/ip_forward", runtimePath);
    EXPECT_CALL(mContext, GetFileContents(runtimePath)).WillRepeatedly(::testing::Invoke([runtimePath](const std::string&) {
        return ReadTestFile(runtimePath);
    }));

    SysctlValueParams params;
    params.sysctlName = "net.ipv4.ip_forward";
    params.value = Pattern::Make("^0$").Value();
    params.runtimeOnly = true;

    auto result = RemediateSysctlValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(SysctlValueTest, RemediateRejectsRegexValue)
{
    SysctlValueParams params;
    params.sysctlName = "net.ipv4.ip_forward";
    params.value = Pattern::Make("[01]").Value();
    params.runtimeOnly = true;

    auto result = RemediateSysctlValue(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, ENOTSUP);
}

TEST_F(SysctlValueTest, RemediateRejectsNonDottedPersistentName)
{
    SysctlValueParams params;
    params.sysctlName = "net/ipv4/ip_forward";
    params.value = Pattern::Make("0").Value();
    params.runtimeOnly = false;

    auto result = RemediateSysctlValue(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, ENOTSUP);
}

class SysctlValueRemediationTest : public SysctlValueTest
{
protected:
    std::string runtimePath;
    std::string configPath;
    std::string laterConfiguration;
    SysctlValueParams params;

    void SetUp() override
    {
        SysctlValueTest::SetUp();
        runtimePath = mContext.MakeTempfile("1\n");
        configPath = mContext.GetTempdirPath() + "/99-zz-kompli-net.ipv4.ip_forward.conf";
        mContext.SetSpecialFilePath("/proc/sys/net/ipv4/ip_forward", runtimePath);
        mContext.SetSpecialFilePath("/etc/sysctl.d/99-zz-kompli-net.ipv4.ip_forward.conf", configPath);
        EXPECT_CALL(mContext, GetFileContents(runtimePath)).WillRepeatedly(::testing::Invoke([this](const std::string&) {
            return ReadTestFile(runtimePath);
        }));
        EXPECT_CALL(mContext, GetFileContents(configPath)).WillRepeatedly(::testing::Invoke([this](const std::string&) {
            return ReadTestFile(configPath);
        }));
        EXPECT_CALL(mContext, GetFileContents("/etc/default/ufw")).WillRepeatedly(Return(Error("No UFW configuration", ENOENT)));
        EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlVersion)).WillRepeatedly(Return(std::string()));
        EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlCat)).WillRepeatedly(::testing::Invoke([this](const std::string&) -> Result<std::string> {
            auto contents = ReadTestFile(configPath);
            return (contents.HasValue() ? contents.Value() : std::string()) + laterConfiguration;
        }));
        params.sysctlName = "net.ipv4.ip_forward";
        params.value = Pattern::Make("^0$").Value();
    }

    void ExpectFile(const std::string& path, const std::string& expected)
    {
        auto contents = ReadTestFile(path);
        ASSERT_TRUE(contents.HasValue());
        EXPECT_EQ(contents.Value(), expected);
    }
};

TEST_F(SysctlValueRemediationTest, CreatesPersistentConfigurationAndConverges)
{
    auto result = RemediateSysctlValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
    ExpectFile(runtimePath, "0");
    ExpectFile(configPath, "# Managed by kompli\nnet.ipv4.ip_forward = 0\n");
    struct stat metadata;
    ASSERT_EQ(0, stat(configPath.c_str(), &metadata));
    EXPECT_EQ(metadata.st_mode & 0777U, 0644U);
    auto audit = AuditSysctlValue(params, mIndicators, mContext);
    ASSERT_TRUE(audit.HasValue());
    EXPECT_EQ(audit.Value(), Status::Compliant);
}

TEST_F(SysctlValueRemediationTest, RepairsPersistenceOnlyWithoutRewritingRuntime)
{
    std::ofstream(runtimePath) << "0\n";
    auto result = RemediateSysctlValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
    ExpectFile(runtimePath, "0\n");
    ExpectFile(configPath, "# Managed by kompli\nnet.ipv4.ip_forward = 0\n");
}

TEST_F(SysctlValueRemediationTest, ReplacesExistingManagedConfigurationPreservingMode)
{
    std::ofstream(configPath) << "# old managed content\nnet.ipv4.ip_forward = 1\n";
    ASSERT_EQ(0, chmod(configPath.c_str(), 0600));
    auto result = RemediateSysctlValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
    ExpectFile(configPath, "# Managed by kompli\nnet.ipv4.ip_forward = 0\n");
    struct stat metadata;
    ASSERT_EQ(0, stat(configPath.c_str(), &metadata));
    EXPECT_EQ(metadata.st_mode & 0777U, 0600U);
}

TEST_F(SysctlValueRemediationTest, SecondRunDoesNotReplaceManagedFile)
{
    auto first = RemediateSysctlValue(params, mIndicators, mContext);
    ASSERT_TRUE(first.HasValue());
    ASSERT_EQ(first.Value(), Status::Compliant);
    struct stat before;
    ASSERT_EQ(0, stat(configPath.c_str(), &before));
    auto second = RemediateSysctlValue(params, mIndicators, mContext);
    ASSERT_TRUE(second.HasValue());
    EXPECT_EQ(second.Value(), Status::Compliant);
    struct stat after;
    ASSERT_EQ(0, stat(configPath.c_str(), &after));
    EXPECT_EQ(before.st_ino, after.st_ino);
    EXPECT_EQ(before.st_mtim.tv_sec, after.st_mtim.tv_sec);
    EXPECT_EQ(before.st_mtim.tv_nsec, after.st_mtim.tv_nsec);
}

TEST_F(SysctlValueRemediationTest, LaterPrecedenceConflictRestoresRuntimeAndRemovesCreatedFile)
{
    laterConfiguration = "\n# /etc/sysctl.d/zz-administrator.conf\nnet.ipv4.ip_forward = 1\n";
    auto result = RemediateSysctlValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
    ExpectFile(runtimePath, "1\n");
    EXPECT_EQ(-1, access(configPath.c_str(), F_OK));
    EXPECT_EQ(errno, ENOENT);
}

TEST_F(SysctlValueRemediationTest, LaterPrecedenceConflictRestoresExistingManagedFile)
{
    const std::string original = "# existing managed content\nnet.ipv4.ip_forward = 1\n";
    std::ofstream(configPath) << original;
    laterConfiguration = "\nnet.ipv4.ip_forward = 1\n";
    auto result = RemediateSysctlValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
    ExpectFile(runtimePath, "1\n");
    ExpectFile(configPath, original);
}

TEST_F(SysctlValueRemediationTest, RuntimeWriteFailureRollsBackPersistentCreation)
{
    const auto target = mContext.MakeTempfile("1\n");
    ASSERT_EQ(0, unlink(runtimePath.c_str()));
    ASSERT_EQ(0, symlink(target.c_str(), runtimePath.c_str()));
    auto result = RemediateSysctlValue(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_NE(result.Error().message.find("rollback failed"), std::string::npos);
    ExpectFile(target, "1\n");
    EXPECT_EQ(-1, access(configPath.c_str(), F_OK));
}

TEST_F(SysctlValueRemediationTest, RefusesSymlinkedConfigurationDirectory)
{
    const auto parent = mContext.GetTempdirPath() + "/linked-sysctl.d";
    ASSERT_EQ(0, symlink(mContext.GetTempdirPath().c_str(), parent.c_str()));
    mContext.SetSpecialFilePath("/etc/sysctl.d/99-zz-kompli-net.ipv4.ip_forward.conf", parent + "/new.conf");
    auto result = RemediateSysctlValue(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    ExpectFile(runtimePath, "1\n");
    EXPECT_EQ(-1, access((mContext.GetTempdirPath() + "/new.conf").c_str(), F_OK));
}

TEST_F(SysctlValueRemediationTest, DoesNotChangeUnrelatedManagedKeys)
{
    const auto unrelated = mContext.GetTempdirPath() + "/99-zz-kompli-net.ipv4.tcp_syncookies.conf";
    std::ofstream(unrelated) << "net.ipv4.tcp_syncookies = 1\n";
    auto result = RemediateSysctlValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
    ExpectFile(unrelated, "net.ipv4.tcp_syncookies = 1\n");
}

TEST_F(SysctlValueRemediationTest, RollbackDoesNotDeleteReplacedManagedFile)
{
    const auto replacement = mContext.MakeTempfile("# concurrently replaced\n");
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlCat)).WillRepeatedly(::testing::Invoke([&](const std::string&) -> Result<std::string> {
        EXPECT_EQ(0, rename(replacement.c_str(), configPath.c_str()));
        return std::string("net.ipv4.ip_forward = 1\n");
    }));
    auto result = RemediateSysctlValue(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_NE(result.Error().message.find("changed before rollback"), std::string::npos);
    ExpectFile(runtimePath, "1\n");
    ExpectFile(configPath, "# concurrently replaced\n");
}

TEST_F(SysctlValueRemediationTest, VerificationErrorRestoresBothStates)
{
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlVersion)).WillRepeatedly(Return(Error("Unavailable", ENOENT)));
    EXPECT_CALL(mContext, ExecuteCommand(systemdUsrSysctlVersion)).WillRepeatedly(Return(Error("Unavailable", ENOENT)));
    auto result = RemediateSysctlValue(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, ENOENT);
    ExpectFile(runtimePath, "1\n");
    EXPECT_EQ(-1, access(configPath.c_str(), F_OK));
}

TEST_F(SysctlValueRemediationTest, RefusesSymlinkedManagedConfiguration)
{
    const auto target = mContext.MakeTempfile("unrelated\n");
    ASSERT_EQ(0, symlink(target.c_str(), configPath.c_str()));
    auto result = RemediateSysctlValue(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    ExpectFile(target, "unrelated\n");
    ExpectFile(runtimePath, "1\n");
}

TEST_F(SysctlValueRemediationTest, RefusesHardlinkedManagedConfiguration)
{
    const auto target = mContext.MakeTempfile("unrelated\n");
    ASSERT_EQ(0, link(target.c_str(), configPath.c_str()));
    auto result = RemediateSysctlValue(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    ExpectFile(target, "unrelated\n");
    ExpectFile(runtimePath, "1\n");
}

TEST_F(SysctlValueRemediationTest, PersistentWriteFailureDoesNotChangeRuntime)
{
    mContext.SetSpecialFilePath("/etc/sysctl.d/99-zz-kompli-net.ipv4.ip_forward.conf", mContext.GetTempdirPath() + "/absent/config.conf");
    auto result = RemediateSysctlValue(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, ENOENT);
    ExpectFile(runtimePath, "1\n");
}

TEST_F(SysctlValueRemediationTest, MissingRuntimeKeyRemainsNotApplicable)
{
    EXPECT_CALL(mContext, GetFileContents(runtimePath)).WillRepeatedly(Return(Error("Missing sysctl", ENOENT)));
    auto result = RemediateSysctlValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NotApplicable);
    EXPECT_EQ(-1, access(configPath.c_str(), F_OK));
}

TEST_F(SysctlValueRemediationTest, RejectsPersistentCommentValuesBeforeMutation)
{
    for (const auto& value : {"0#comment", "0;comment", "0\n1"})
    {
        params.value = Pattern::Make(value).Value();
        auto result = RemediateSysctlValue(params, mIndicators, mContext);
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ(result.Error().code, ENOTSUP);
    }
    ExpectFile(runtimePath, "1\n");
    EXPECT_EQ(-1, access(configPath.c_str(), F_OK));
}

TEST_F(SysctlValueTest, RuntimeOnlyStillEnforcesRuntimeValue)
{
    // runtimeOnly=true skips only the stored-config check, not the runtime check:
    // a wrong runtime value is still NonCompliant, and the stored config is not consulted.
    auto sysctlName = std::string("net.ipv4.ip_forward");
    auto sysctlSlashedName = sysctlName;
    std::replace(sysctlSlashedName.begin(), sysctlSlashedName.end(), '.', '/');
    EXPECT_CALL(mContext, GetFileContents("/proc/sys/" + sysctlSlashedName)).WillRepeatedly(Return(Result<std::string>("1\n")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlVersion)).Times(0);
    EXPECT_CALL(mContext, ExecuteCommand(systemdUsrSysctlVersion)).Times(0);
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlCat)).Times(0);
    EXPECT_CALL(mContext, ExecuteCommand(systemdUsrSysctlCat)).Times(0);
    SysctlValueParams params;
    params.sysctlName = sysctlName;
    params.value = Pattern::Make("0").Value();
    params.runtimeOnly = true;

    auto result = AuditSysctlValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(SysctlValueTest, HappyPathAlternativeSystemdSysctlLocation)
{
    auto sysctlName = std::string("net.ipv4.ip_forward");
    auto sysctlSlashedName = sysctlName;
    std::replace(sysctlSlashedName.begin(), sysctlSlashedName.end(), '.', '/');
    EXPECT_CALL(mContext, GetFileContents("/proc/sys/" + sysctlSlashedName)).WillRepeatedly(Return(Result<std::string>("0\n")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlVersion)).WillRepeatedly(Return(Error("Missing")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdUsrSysctlVersion)).WillRepeatedly(Return(Result<std::string>("")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdUsrSysctlCat)).WillRepeatedly(Return(Result<std::string>(sysctlIpForward0)));
    SysctlValueParams params;
    params.sysctlName = sysctlName;
    params.value = Pattern::Make("0").Value();

    auto result = AuditSysctlValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(SysctlValueTest, UnHappyPathSysctlValueConfigurationEqualEmptyOuput)
{
    auto sysctlName = std::string("net.ipv4.ip_forward");
    auto sysctlSlashedName = sysctlName;
    std::replace(sysctlSlashedName.begin(), sysctlSlashedName.end(), '.', '/');
    EXPECT_CALL(mContext, GetFileContents("/proc/sys/" + sysctlSlashedName)).WillRepeatedly(Return(Result<std::string>("0\n")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlVersion)).WillRepeatedly(Return(Result<std::string>("")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlCat)).WillRepeatedly(Return(Result<std::string>(emptyOutput)));
    EXPECT_CALL(mContext, GetFileContents("/etc/default/ufw")).WillRepeatedly(Return(Result<std::string>(Error("No such file or directory", -1))));
    SysctlValueParams params;
    params.sysctlName = sysctlName;
    params.value = Pattern::Make("0").Value();

    auto result = AuditSysctlValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(SysctlValueTest, HappyPathSysctlValueEqualConfigurationOverrideLastOneWins)
{
    auto sysctlName = std::string("net.ipv4.ip_forward");
    auto sysctlSlashedName = sysctlName;
    std::replace(sysctlSlashedName.begin(), sysctlSlashedName.end(), '.', '/');
    EXPECT_CALL(mContext, GetFileContents("/proc/sys/" + sysctlSlashedName)).WillRepeatedly(Return(Result<std::string>("0\n")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlVersion)).WillRepeatedly(Return(Result<std::string>("")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlCat)).WillRepeatedly(Return(Result<std::string>(sysctlIpForward1Then0Than1Than0)));
    SysctlValueParams params;
    params.sysctlName = sysctlName;
    params.value = Pattern::Make("0").Value();

    auto result = AuditSysctlValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(SysctlValueTest, UnHappyPathSysctlValueEqualConfigurationComment)
{
    auto sysctlName = std::string("net.ipv4.ip_forward");
    auto sysctlSlashedName = sysctlName;
    std::replace(sysctlSlashedName.begin(), sysctlSlashedName.end(), '.', '/');
    EXPECT_CALL(mContext, GetFileContents("/proc/sys/" + sysctlSlashedName)).WillRepeatedly(Return(Result<std::string>("0\n")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlVersion)).WillRepeatedly(Return(Result<std::string>("")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlCat)).WillRepeatedly(Return(Result<std::string>(sysctlIpForward0Comment)));
    EXPECT_CALL(mContext, GetFileContents("/etc/default/ufw")).WillRepeatedly(Return(Result<std::string>(Error("No such file or directory", -1))));
    SysctlValueParams params;
    params.sysctlName = sysctlName;
    params.value = Pattern::Make("0").Value();

    auto result = AuditSysctlValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(SysctlValueTest, UnHappyPathSysctlValueNotEqual)
{
    auto sysctlName = std::string("net.ipv4.ip_forward");
    auto sysctlSlashedName = sysctlName;
    std::replace(sysctlSlashedName.begin(), sysctlSlashedName.end(), '.', '/');
    EXPECT_CALL(mContext, GetFileContents("/proc/sys/" + sysctlSlashedName)).WillRepeatedly(Return(Result<std::string>("0\n")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlVersion)).WillRepeatedly(Return(Result<std::string>("")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlCat)).WillRepeatedly(Return(Result<std::string>(sysctlIpForward1)));
    SysctlValueParams params;
    params.sysctlName = sysctlName;
    params.value = Pattern::Make("0").Value();

    auto result = AuditSysctlValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(SysctlValueTest, UnHappyPathSysctlValueEqualConfiruationOverride)
{
    auto sysctlName = std::string("net.ipv4.ip_forward");
    auto sysctlSlashedName = sysctlName;
    std::replace(sysctlSlashedName.begin(), sysctlSlashedName.end(), '.', '/');
    EXPECT_CALL(mContext, GetFileContents("/proc/sys/" + sysctlSlashedName)).WillRepeatedly(Return(Result<std::string>("0\n")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlVersion)).WillRepeatedly(Return(Result<std::string>("")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlCat)).WillRepeatedly(Return(Result<std::string>(sysctlIpForward1)));
    SysctlValueParams params;
    params.sysctlName = sysctlName;
    params.value = Pattern::Make("0").Value();

    auto result = AuditSysctlValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

// Regexp value tests
TEST_F(SysctlValueTest, HappyPathSysctlValueRegexpDotEqualConfiruationNoOverride)
{
    auto sysctlName = std::string("net.ipv4.ip_forward");
    auto sysctlSlashedName = sysctlName;
    std::replace(sysctlSlashedName.begin(), sysctlSlashedName.end(), '.', '/');
    EXPECT_CALL(mContext, GetFileContents("/proc/sys/" + sysctlSlashedName)).WillRepeatedly(Return(Result<std::string>("0\n")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlVersion)).WillRepeatedly(Return(Result<std::string>("")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlCat)).WillRepeatedly(Return(Result<std::string>(sysctlIpForward0)));
    SysctlValueParams params;
    params.sysctlName = sysctlName;
    params.value = Pattern::Make(".").Value();

    auto result = AuditSysctlValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(SysctlValueTest, HappyPathSysctlValueRegexpRangeEqualConfiruationNoOverride)
{
    auto sysctlName = std::string("net.ipv4.ip_forward");
    auto sysctlSlashedName = sysctlName;
    std::replace(sysctlSlashedName.begin(), sysctlSlashedName.end(), '.', '/');
    EXPECT_CALL(mContext, GetFileContents("/proc/sys/" + sysctlSlashedName)).WillRepeatedly(Return(Result<std::string>("0\n")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlVersion)).WillRepeatedly(Return(Result<std::string>("")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlCat)).WillRepeatedly(Return(Result<std::string>(sysctlIpForward0)));
    SysctlValueParams params;
    params.sysctlName = sysctlName;
    params.value = Pattern::Make("[0]").Value();

    auto result = AuditSysctlValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(SysctlValueTest, UnHappyPathSysctlValueRegexpRangeEqualConfiruationNoOverride)
{
    auto sysctlName = std::string("net.ipv4.ip_forward");
    auto sysctlSlashedName = sysctlName;
    std::replace(sysctlSlashedName.begin(), sysctlSlashedName.end(), '.', '/');
    EXPECT_CALL(mContext, GetFileContents("/proc/sys/" + sysctlSlashedName)).WillRepeatedly(Return(Result<std::string>("0\n")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlVersion)).WillRepeatedly(Return(Result<std::string>("")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlCat)).WillRepeatedly(Return(Result<std::string>(sysctlIpForward1)));
    SysctlValueParams params;
    params.sysctlName = sysctlName;
    params.value = Pattern::Make("[0]").Value();

    auto result = AuditSysctlValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(SysctlValueTest, UnHappyPathSysctlValueRegexpRangeNotEqual)
{
    auto sysctlName = std::string("net.ipv4.ip_forward");
    auto sysctlSlashedName = sysctlName;
    std::replace(sysctlSlashedName.begin(), sysctlSlashedName.end(), '.', '/');
    EXPECT_CALL(mContext, GetFileContents("/proc/sys/" + sysctlSlashedName)).WillRepeatedly(Return(Result<std::string>("1\n")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlVersion)).WillRepeatedly(Return(Result<std::string>("")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlCat)).WillRepeatedly(Return(Result<std::string>(sysctlIpForward0)));
    SysctlValueParams params;
    params.sysctlName = sysctlName;
    params.value = Pattern::Make("[0]").Value();

    auto result = AuditSysctlValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(SysctlValueTest, UnHappyPathSysctlValueEqualConfiruationNotEqualTabs)
{
    auto sysctlName = std::string("net.ipv4.ip_forward");
    auto sysctlSlashedName = sysctlName;
    std::replace(sysctlSlashedName.begin(), sysctlSlashedName.end(), '.', '/');
    EXPECT_CALL(mContext, GetFileContents("/proc/sys/" + sysctlSlashedName)).WillRepeatedly(Return(Result<std::string>("1\n")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlVersion)).WillRepeatedly(Return(Result<std::string>("")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlCat)).WillRepeatedly(Return(Result<std::string>(sysctlIpForward0FilenameTabs)));
    SysctlValueParams params;
    params.sysctlName = sysctlName;
    params.value = Pattern::Make("1").Value();

    auto result = AuditSysctlValue(params, mIndicators, mContext);
    ASSERT_EQ(mFormatter.Format(mIndicators).Value(),
        std::string("[Compliant] Correct value for 'net.ipv4.ip_forward' in runtime configuration\n[NonCompliant] Expected 'net.ipv4.ip_forward' got "
                    "'0' found in: '/etc/sysctl.d/foo.conf'\n"));
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(SysctlValueTest, UnHappyPathSysctlValueEqualConfiruationNotEqualExtraSpacesFilenameReportCheck)
{
    auto sysctlName = std::string("net.ipv4.ip_forward");
    auto sysctlSlashedName = sysctlName;
    std::replace(sysctlSlashedName.begin(), sysctlSlashedName.end(), '.', '/');
    EXPECT_CALL(mContext, GetFileContents("/proc/sys/" + sysctlSlashedName)).WillRepeatedly(Return(Result<std::string>("1\n")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlVersion)).WillRepeatedly(Return(Result<std::string>("")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlCat)).WillRepeatedly(Return(Result<std::string>(sysctlIpForward0FilenameExtraSpaces)));
    SysctlValueParams params;
    params.sysctlName = sysctlName;
    params.value = Pattern::Make("1").Value();

    auto result = AuditSysctlValue(params, mIndicators, mContext);
    ASSERT_EQ(mFormatter.Format(mIndicators).Value(),
        std::string("[Compliant] Correct value for 'net.ipv4.ip_forward' in runtime configuration\n[NonCompliant] Expected 'net.ipv4.ip_forward' got "
                    "'0' found in: '/etc/sysctl.d/foo.conf'\n"));
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(SysctlValueTest, HappyPathSysctlValueEqualConfiruationOverrideLastOneWinsWithFilename)
{
    auto sysctlName = std::string("net.ipv4.ip_forward");
    auto sysctlSlashedName = sysctlName;
    std::replace(sysctlSlashedName.begin(), sysctlSlashedName.end(), '.', '/');
    EXPECT_CALL(mContext, GetFileContents("/proc/sys/" + sysctlSlashedName)).WillRepeatedly(Return(Result<std::string>("1\n")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlVersion)).WillRepeatedly(Return(Result<std::string>("")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlCat)).WillRepeatedly(Return(Result<std::string>(sysctlIpForward1Then0Than1Than0WithFilenames)));
    SysctlValueParams params;
    params.sysctlName = sysctlName;
    params.value = Pattern::Make("1").Value();

    auto result = AuditSysctlValue(params, mIndicators, mContext);

    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
    ASSERT_EQ(mFormatter.Format(mIndicators).Value(),
        std::string("[Compliant] Correct value for 'net.ipv4.ip_forward' in runtime configuration\n[NonCompliant] Expected 'net.ipv4.ip_forward' got "
                    "'0' found in: '/etc/sysctl.d/fwd_0_v2.conf'\n"));
}

TEST_F(SysctlValueTest, HappyPathValidateCisSysctls)
{
    for (size_t i = 0; i < cisSsysctlNames.size(); i++)
    {
        auto sysctlName = cisSsysctlNames[i].name;
        auto value = cisSsysctlNames[i].value;
        auto cfgOuput = cisSsysctlNames[i].CfgOutput();

        auto sysctlSlashedName = sysctlName;
        std::replace(sysctlSlashedName.begin(), sysctlSlashedName.end(), '.', '/');
        EXPECT_CALL(mContext, GetFileContents("/proc/sys/" + sysctlSlashedName)).WillRepeatedly(Return(Result<std::string>(value + "\n")));
        EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlVersion)).WillRepeatedly(Return(Result<std::string>("")));
        EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlCat)).WillRepeatedly(Return(Result<std::string>(cfgOuput.c_str())));
        SysctlValueParams params;
        params.sysctlName = sysctlName;
        params.value = Pattern::Make(value).Value();

        auto result = AuditSysctlValue(params, mIndicators, mContext);

        ASSERT_TRUE(result.HasValue()) << "HappyPathValidateSysctlNameAndValues FAILED: nr " << i << " name '" << sysctlName << "'";
        ASSERT_EQ(result.Value(), Status::Compliant) << "HappyPathValidateSysctlNameAndValues FAILED: nr " << i << " name '" << sysctlName << "'";
        ;
    }
}

TEST_F(SysctlValueTest, UnhappyPathSysctlMultilineOutput)
{
    SysctlNameValue sysctlNameValue(std::string("fs.binfmt_misc.python3/10"),
        std::string("enabled\ninterpreter /usr/bin/python3.10\nflags:\noffset 0\nmagic 6f0d0d0a\n"));

    auto sysctlName = sysctlNameValue.name;
    auto value = sysctlNameValue.value;
    auto cfgOuput = sysctlNameValue.CfgOutput();
    auto sysctlSlashedName = sysctlName;
    std::replace(sysctlSlashedName.begin(), sysctlSlashedName.end(), '.', '/');
    EXPECT_CALL(mContext, GetFileContents("/proc/sys/" + sysctlSlashedName)).WillRepeatedly(Return(Result<std::string>(value + "\n")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlVersion)).WillRepeatedly(Return(Result<std::string>("")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlCat)).WillRepeatedly(Return(Result<std::string>(cfgOuput.c_str())));
    SysctlValueParams params;
    params.sysctlName = sysctlName;
    params.value = Pattern::Make(value).Value();

    auto result = AuditSysctlValue(params, mIndicators, mContext);

    ASSERT_TRUE(result.HasValue()) << "HappyPathValidateSysctlNameAndValues FAILED: nr "
                                   << " name '" << sysctlName << "'";
    ASSERT_EQ(result.Value(), Status::NonCompliant) << "HappyPathValidateSysctlNameAndValues FAILED: nr "
                                                    << " name '" << sysctlName << "'";
    ;
}

TEST_F(SysctlValueTest, UfwDefaultsFileMissing)
{
    auto sysctlName = std::string("net.ipv4.ip_forward");
    auto sysctlSlashedName = sysctlName;
    std::replace(sysctlSlashedName.begin(), sysctlSlashedName.end(), '.', '/');
    EXPECT_CALL(mContext, GetFileContents("/proc/sys/" + sysctlSlashedName)).WillRepeatedly(Return(Result<std::string>("1\n")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlVersion)).WillRepeatedly(Return(Result<std::string>("")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlCat)).WillRepeatedly(Return(Result<std::string>(emptyOutput)));
    EXPECT_CALL(mContext, GetFileContents("/etc/default/ufw")).WillRepeatedly(Return(Result<std::string>(Error("No such file or directory", -1))));

    SysctlValueParams params;
    params.sysctlName = sysctlName;
    params.value = Pattern::Make("1").Value();
    auto result = AuditSysctlValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
    ASSERT_TRUE(mFormatter.Format(mIndicators).Value().find("Failed to read /etc/default/ufw") != std::string::npos);
}

TEST_F(SysctlValueTest, UfwDefaultsFileNoIptSysctl)
{
    auto sysctlName = std::string("net.ipv4.ip_forward");
    auto sysctlSlashedName = sysctlName;
    std::replace(sysctlSlashedName.begin(), sysctlSlashedName.end(), '.', '/');
    EXPECT_CALL(mContext, GetFileContents("/proc/sys/" + sysctlSlashedName)).WillRepeatedly(Return(Result<std::string>("1\n")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlVersion)).WillRepeatedly(Return(Result<std::string>("")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlCat)).WillRepeatedly(Return(Result<std::string>(emptyOutput)));
    EXPECT_CALL(mContext, GetFileContents("/etc/default/ufw")).WillRepeatedly(Return(Result<std::string>("# No IPT_SYSCTL here\nFOO=bar\n")));

    SysctlValueParams params;
    params.sysctlName = sysctlName;
    params.value = Pattern::Make("1").Value();
    auto result = AuditSysctlValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
    ASSERT_TRUE(mFormatter.Format(mIndicators).Value().find("Failed to find IPT_SYSCTL") != std::string::npos);
}

TEST_F(SysctlValueTest, UfwSysctlFileMissing)
{
    auto sysctlName = std::string("net.ipv4.ip_forward");
    auto sysctlSlashedName = sysctlName;
    std::replace(sysctlSlashedName.begin(), sysctlSlashedName.end(), '.', '/');
    EXPECT_CALL(mContext, GetFileContents("/proc/sys/" + sysctlSlashedName)).WillRepeatedly(Return(Result<std::string>("1\n")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlVersion)).WillRepeatedly(Return(Result<std::string>("")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlCat)).WillRepeatedly(Return(Result<std::string>(emptyOutput)));
    EXPECT_CALL(mContext, GetFileContents("/etc/default/ufw")).WillRepeatedly(Return(Result<std::string>("IPT_SYSCTL=/tmp/ufw-sysctl.conf\n")));
    EXPECT_CALL(mContext, GetFileContents("/tmp/ufw-sysctl.conf")).WillRepeatedly(Return(Result<std::string>(Error("No such file or directory", -1))));

    SysctlValueParams params;
    params.sysctlName = sysctlName;
    params.value = Pattern::Make("1").Value();
    auto result = AuditSysctlValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
    ASSERT_TRUE(mFormatter.Format(mIndicators).Value().find("Failed to read ufw sysctl config file") != std::string::npos);
}

TEST_F(SysctlValueTest, UfwSysctlFileValueMatches)
{
    auto sysctlName = std::string("net.ipv4.ip_forward");
    auto sysctlSlashedName = sysctlName;
    std::replace(sysctlSlashedName.begin(), sysctlSlashedName.end(), '.', '/');
    EXPECT_CALL(mContext, GetFileContents("/proc/sys/" + sysctlSlashedName)).WillRepeatedly(Return(Result<std::string>("1\n")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlVersion)).WillRepeatedly(Return(Result<std::string>("")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlCat)).WillRepeatedly(Return(Result<std::string>(emptyOutput)));
    EXPECT_CALL(mContext, GetFileContents("/etc/default/ufw")).WillRepeatedly(Return(Result<std::string>("IPT_SYSCTL=/tmp/ufw-sysctl.conf\n")));
    EXPECT_CALL(mContext, GetFileContents("/tmp/ufw-sysctl.conf")).WillRepeatedly(Return(Result<std::string>("net/ipv4/ip_forward=1\n")));

    SysctlValueParams params;
    params.sysctlName = sysctlName;
    params.value = Pattern::Make("1").Value();
    auto result = AuditSysctlValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
    ASSERT_TRUE(mFormatter.Format(mIndicators).Value().find("in UFW configuration") != std::string::npos);
}

TEST_F(SysctlValueTest, UfwSysctlFileValueDoesNotMatch)
{
    auto sysctlName = std::string("net.ipv4.ip_forward");
    auto sysctlSlashedName = sysctlName;
    std::replace(sysctlSlashedName.begin(), sysctlSlashedName.end(), '.', '/');
    EXPECT_CALL(mContext, GetFileContents("/proc/sys/" + sysctlSlashedName)).WillRepeatedly(Return(Result<std::string>("1\n")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlVersion)).WillRepeatedly(Return(Result<std::string>("")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlCat)).WillRepeatedly(Return(Result<std::string>(emptyOutput)));
    EXPECT_CALL(mContext, GetFileContents("/etc/default/ufw")).WillRepeatedly(Return(Result<std::string>("IPT_SYSCTL=/tmp/ufw-sysctl.conf\n")));
    EXPECT_CALL(mContext, GetFileContents("/tmp/ufw-sysctl.conf")).WillRepeatedly(Return(Result<std::string>("net/ipv4/ip_forward=0\n")));

    SysctlValueParams params;
    params.sysctlName = sysctlName;
    params.value = Pattern::Make("1").Value();
    auto result = AuditSysctlValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
    ASSERT_TRUE(mFormatter.Format(mIndicators).Value().find("got '0' in UFW configuration") != std::string::npos);
}

// Security tests for path traversal prevention

TEST_F(SysctlValueTest, SecurityRejectsSysctlNameWithPathTraversal)
{
    // Attempt path traversal via sysctl name: ../../../etc/passwd
    SysctlValueParams params;
    params.sysctlName = "../../../etc/passwd";
    params.value = Pattern::Make(".*").Value();

    auto result = AuditSysctlValue(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    ASSERT_EQ(result.Error().code, EINVAL);
    ASSERT_TRUE(result.Error().message.find("Invalid sysctl name") != std::string::npos);
}

TEST_F(SysctlValueTest, SecurityRejectsSysctlNameWithDoubleDot)
{
    // Attempt path traversal via embedded double dots
    SysctlValueParams params;
    params.sysctlName = "net..ipv4.ip_forward";
    params.value = Pattern::Make("0").Value();

    auto result = AuditSysctlValue(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    ASSERT_EQ(result.Error().code, EINVAL);
}

TEST_F(SysctlValueTest, SecurityRejectsEmptySysctlName)
{
    SysctlValueParams params;
    params.sysctlName = "";
    params.value = Pattern::Make("0").Value();

    auto result = AuditSysctlValue(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    ASSERT_EQ(result.Error().code, EINVAL);
}

TEST_F(SysctlValueTest, SecurityRejectsSysctlNameWithSlashAndDoubleDot)
{
    // Reject path traversal via slash + double dot (e.g. net/ipv4/../etc/passwd)
    // Note: bare slashes alone are permitted for names like fs.binfmt_misc.python3/10
    SysctlValueParams params;
    params.sysctlName = "net/ipv4/../etc/passwd";
    params.value = Pattern::Make("0").Value();

    auto result = AuditSysctlValue(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    ASSERT_EQ(result.Error().code, EINVAL);
}

TEST_F(SysctlValueTest, SecurityRejectsSysctlNameWithShellMetachars)
{
    // Reject names with shell metacharacters
    SysctlValueParams params;
    params.sysctlName = "net.ipv4.ip_forward;rm -rf /";
    params.value = Pattern::Make("0").Value();

    auto result = AuditSysctlValue(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    ASSERT_EQ(result.Error().code, EINVAL);
}

TEST_F(SysctlValueTest, SecurityRejectsUfwSysctlFileWithPathTraversal)
{
    auto sysctlName = std::string("net.ipv4.ip_forward");
    auto sysctlSlashedName = sysctlName;
    std::replace(sysctlSlashedName.begin(), sysctlSlashedName.end(), '.', '/');
    EXPECT_CALL(mContext, GetFileContents("/proc/sys/" + sysctlSlashedName)).WillRepeatedly(Return(Result<std::string>("1\n")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlVersion)).WillRepeatedly(Return(Result<std::string>("")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlCat)).WillRepeatedly(Return(Result<std::string>(emptyOutput)));
    // Malicious IPT_SYSCTL value with path traversal
    EXPECT_CALL(mContext, GetFileContents("/etc/default/ufw")).WillRepeatedly(Return(Result<std::string>("IPT_SYSCTL=/../../../etc/shadow\n")));

    SysctlValueParams params;
    params.sysctlName = sysctlName;
    params.value = Pattern::Make("1").Value();
    auto result = AuditSysctlValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
    ASSERT_TRUE(mFormatter.Format(mIndicators).Value().find("Invalid sysctl file path") != std::string::npos);
}

TEST_F(SysctlValueTest, SecurityRejectsUfwSysctlFileWithRelativePath)
{
    auto sysctlName = std::string("net.ipv4.ip_forward");
    auto sysctlSlashedName = sysctlName;
    std::replace(sysctlSlashedName.begin(), sysctlSlashedName.end(), '.', '/');
    EXPECT_CALL(mContext, GetFileContents("/proc/sys/" + sysctlSlashedName)).WillRepeatedly(Return(Result<std::string>("1\n")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlVersion)).WillRepeatedly(Return(Result<std::string>("")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlCat)).WillRepeatedly(Return(Result<std::string>(emptyOutput)));
    // Relative path instead of absolute
    EXPECT_CALL(mContext, GetFileContents("/etc/default/ufw")).WillRepeatedly(Return(Result<std::string>("IPT_SYSCTL=etc/ufw/sysctl.conf\n")));

    SysctlValueParams params;
    params.sysctlName = sysctlName;
    params.value = Pattern::Make("1").Value();
    auto result = AuditSysctlValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
    ASSERT_TRUE(mFormatter.Format(mIndicators).Value().find("Invalid sysctl file path") != std::string::npos);
}

TEST_F(SysctlValueTest, SecurityAcceptsValidSysctlName)
{
    // Valid sysctl name with alphanumeric, dots, underscores, and hyphens
    auto sysctlName = std::string("net.ipv4.conf.eth-0.accept_redirects");
    auto sysctlSlashedName = sysctlName;
    std::replace(sysctlSlashedName.begin(), sysctlSlashedName.end(), '.', '/');
    EXPECT_CALL(mContext, GetFileContents("/proc/sys/" + sysctlSlashedName)).WillRepeatedly(Return(Result<std::string>("0\n")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlVersion)).WillRepeatedly(Return(Result<std::string>("")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlCat)).WillRepeatedly(Return(Result<std::string>("net.ipv4.conf.eth-0.accept_redirects = 0")));

    SysctlValueParams params;
    params.sysctlName = sysctlName;
    params.value = Pattern::Make("0").Value();

    auto result = AuditSysctlValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(SysctlValueTest, RuntimeValueEmptyStringIsNonCompliant)
{
    // GetFileContents returning an empty string (no trailing newline) triggers UB via
    // *rbegin() on an empty std::string in unpatched code; the fix guards with !empty().
    // The empty value does not match the expected pattern, so the result is NonCompliant.
    auto sysctlName = std::string("net.ipv4.ip_forward");
    auto sysctlSlashedName = sysctlName;
    std::replace(sysctlSlashedName.begin(), sysctlSlashedName.end(), '.', '/');
    EXPECT_CALL(mContext, GetFileContents("/proc/sys/" + sysctlSlashedName)).WillRepeatedly(Return(Result<std::string>("")));

    SysctlValueParams params;
    params.sysctlName = sysctlName;
    params.value = Pattern::Make("0").Value();

    auto result = AuditSysctlValue(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(SysctlValueTest, SystemdSysctlNotFoundAtEitherLocation)
{
    // When neither systemd-sysctl location responds, the procedure must return an Error
    // rather than silently reporting Compliant or NonCompliant.
    auto sysctlName = std::string("net.ipv4.ip_forward");
    auto sysctlSlashedName = sysctlName;
    std::replace(sysctlSlashedName.begin(), sysctlSlashedName.end(), '.', '/');
    EXPECT_CALL(mContext, GetFileContents("/proc/sys/" + sysctlSlashedName)).WillRepeatedly(Return(Result<std::string>("0\n")));
    EXPECT_CALL(mContext, ExecuteCommand(systemdSysctlVersion)).WillRepeatedly(Return(Result<std::string>(Error("not found", ENOENT))));
    EXPECT_CALL(mContext, ExecuteCommand(systemdUsrSysctlVersion)).WillRepeatedly(Return(Result<std::string>(Error("not found", ENOENT))));

    SysctlValueParams params;
    params.sysctlName = sysctlName;
    params.value = Pattern::Make("0").Value();

    auto result = AuditSysctlValue(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    ASSERT_EQ(result.Error().code, ENOENT);
}
