// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "CommonUtils.h"
#include "MockContext.h"

#include <JsonWrapper.h>
#include <PackageInstalled.h>
#include <cstdlib>
#include <dirent.h>
#include <fstream>
#include <gtest/gtest.h>
#include <linux/limits.h>
#include <parson.h>
#include <string>
#include <unistd.h>

using Kompli::AuditPackageInstalled;
using Kompli::CompactListFormatter;
using Kompli::Error;
using Kompli::IndicatorsTree;
using Kompli::PackageInstalledParams;
using Kompli::PackageManagerType;
using Kompli::Result;
using Kompli::Status;

using testing::HasSubstr;
using testing::Return;

static const std::string rpmCommand = "rpm -qa --qf='%{NAME} %{EVR}\n'";
static const std::string rpmWithPackageOutput = "package1 1.0.0-1\npackage2 2.1.0-2\nsample-package 3.1.4-5\nmysql-server 5.7.32-1\npackage5 1.5.0-3\n";
static const std::string rpmWithoutPackageOutput = "package1 1.0.0\npackage2 2.1.0\nother-package 4:4.0.0\npackage5 1:1.5.0\n";

static const std::string dpkgCommand = "dpkg -l";
static const std::string dpkgWithPackageOutput =
    "Desired=Unknown/Install/Remove/Purge/Hold\n"
    "| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend\n"
    "|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)\n"
    "||/ Name                      Version                  Architecture Description\n"
    "+++-=========================-========================-============-===============================\n"
    "ii  package1                  1.2.3-4                  amd64        Package 1 description\n"
    "ii  package2:amd64            2:2.0.0-1                amd64        Package 2 description\n"
    "ii  sample-package            3.1.4-2                  amd64        Sample package description\n"
    "rc  removed-package           1.0.0-1                  amd64        Removed package\n"
    "ii  mysql-server              5.7.32-1                 amd64        MySQL server package\n";

static const std::string dpkgWithoutPackageOutput =
    "Desired=Unknown/Install/Remove/Purge/Hold\n"
    "| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend\n"
    "|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)\n"
    "||/ Name                      Version                  Architecture Description\n"
    "+++-=========================-========================-============-===============================\n"
    "ii  package1                  1.2.3-4                  amd64        Package 1 description\n"
    "ii  package2                  2.0.0-1                  amd64        Package 2 description\n"
    "rc  removed-package           1.0.0-1                  amd64        Removed package\n"
    "ii  mysql-server              5.7.32-1                 amd64        MySQL server package\n";

// Package manager detection commands
static const std::string dpkgDetectCommand = "dpkg -l dpkg";
static const std::string rpmDetectCommand = "rpm -q rpm";
static const std::string dpkgDetectOutput =
    "Desired=Unknown/Install/Remove/Purge/Hold\n"
    "| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend\n"
    "|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)\n"
    "||/ Name                      Version                  Architecture Description\n"
    "+++-=========================-========================-============-===============================\n"
    "ii  dpkg                      1.19.7                   amd64        Debian package management system\n";
static const std::string rpmDetectOutput = "rpm-4.14.2.1-1.el8\n";

class PackageInstalledTest : public ::testing::Test
{
protected:
    std::string cacheFile;
    MockContext mContext;
    CompactListFormatter mFormatter;
    IndicatorsTree mIndicators;

    void SetUp() override
    {
        cacheFile = mContext.GetStatePath() + "/ComplianceEnginePackageCache";
        mIndicators.Push("PackageInstalled");
    }

    void CreateCacheFile(const std::string& packageManager, time_t timestamp, const std::vector<std::pair<std::string, std::string>>& packages)
    {
        std::ofstream cache(cacheFile);
        ASSERT_TRUE(cache.is_open());
        cache << "# PackageCache " << packageManager << "@" << timestamp << std::endl;
        for (const auto& pkg : packages)
        {
            cache << pkg.first << " " << pkg.second << std::endl;
        }
        cache.close();
    }

    PackageInstalledParams LatestParams(const std::string& name = "sample-package")
    {
        PackageInstalledParams params;
        params.packageName = name;
        params.packageManager = PackageManagerType::DPKG;
        params.latestPackageVersion = true;
        return params;
    }

    void ExpectCandidate(const std::string& installed, const std::string& candidate, const std::string& name = "sample-package")
    {
        CreateCacheFile("dpkg", time(nullptr), {{name, installed}});
        EXPECT_CALL(mContext, ExecuteCommand("LC_ALL=C apt-cache policy -- \"" + name + "\""))
            .WillOnce(Return(Result<std::string>(name + ":\n  Installed: " + installed + "\n  Candidate: " + candidate + "\n  Version table:\n")));
    }
};

TEST_F(PackageInstalledTest, DetectDpkgPackageManager)
{
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr(dpkgDetectCommand))).WillRepeatedly(Return(Result<std::string>(dpkgDetectOutput)));
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr(rpmDetectCommand))).WillRepeatedly(Return(Result<std::string>(Error("Command failed", 1))));
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr(dpkgCommand))).WillRepeatedly(Return(Result<std::string>(dpkgWithPackageOutput)));

    PackageInstalledParams params;
    params.packageName = "sample-package";

    auto result = AuditPackageInstalled(params, mIndicators, mContext);

    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
    ASSERT_TRUE(mFormatter.Format(mIndicators).Value().find("sample-package") != std::string::npos);
}

TEST_F(PackageInstalledTest, DetectRpmPackageManager)
{
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr(dpkgDetectCommand))).WillRepeatedly(Return(Result<std::string>(Error("Command failed", 1))));
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr(rpmDetectCommand))).WillRepeatedly(Return(Result<std::string>(rpmDetectOutput)));
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr(rpmCommand))).WillRepeatedly(Return(Result<std::string>(rpmWithPackageOutput)));

    PackageInstalledParams params;
    params.packageName = "sample-package";

    auto result = AuditPackageInstalled(params, mIndicators, mContext);

    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
    ASSERT_TRUE(mFormatter.Format(mIndicators).Value().find("sample-package") != std::string::npos);
}

TEST_F(PackageInstalledTest, NoPackageManagerDetected)
{
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr(dpkgDetectCommand))).WillRepeatedly(Return(Result<std::string>(Error("Command failed", 1))));
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr(rpmDetectCommand))).WillRepeatedly(Return(Result<std::string>(Error("Command failed", 1))));

    PackageInstalledParams params;
    params.packageName = "sample-package";

    auto result = AuditPackageInstalled(params, mIndicators, mContext);

    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NotApplicable);
}

TEST_F(PackageInstalledTest, SpecifiedPackageManagerOverridesDetection)
{
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr(dpkgDetectCommand))).WillRepeatedly(Return(Result<std::string>(Error("Command failed", 1))));
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr(rpmDetectCommand))).WillRepeatedly(Return(Result<std::string>(Error("Command failed", 1))));
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr(rpmCommand))).WillRepeatedly(Return(Result<std::string>(rpmWithPackageOutput)));

    PackageInstalledParams params;
    params.packageName = "sample-package";
    params.packageManager = PackageManagerType::RPM;

    auto result = AuditPackageInstalled(params, mIndicators, mContext);

    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(PackageInstalledTest, RpmPackageExists)
{
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr(rpmCommand))).WillRepeatedly(Return(Result<std::string>(rpmWithPackageOutput)));
    PackageInstalledParams params;
    params.packageName = "sample-package";
    params.packageManager = PackageManagerType::RPM;

    auto result = AuditPackageInstalled(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(PackageInstalledTest, RpmPackageDoesNotExist)
{
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr(rpmCommand))).WillRepeatedly(Return(Result<std::string>(rpmWithoutPackageOutput)));
    PackageInstalledParams params;
    params.packageName = "sample-package";
    params.packageManager = PackageManagerType::RPM;

    auto result = AuditPackageInstalled(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(PackageInstalledTest, DpkgPackageExists)
{
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr(dpkgCommand))).WillRepeatedly(Return(Result<std::string>(dpkgWithPackageOutput)));
    PackageInstalledParams params;
    params.packageName = "sample-package";
    params.packageManager = PackageManagerType::DPKG;

    auto result = AuditPackageInstalled(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(PackageInstalledTest, DpkgPackageDoesNotExist)
{
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr(dpkgCommand))).WillRepeatedly(Return(Result<std::string>(dpkgWithoutPackageOutput)));
    PackageInstalledParams params;
    params.packageName = "sample-package";
    params.packageManager = PackageManagerType::DPKG;

    auto result = AuditPackageInstalled(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(PackageInstalledTest, RpmCommandFails)
{
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr(rpmCommand))).WillRepeatedly(Return(Result<std::string>(Error("Command failed", 1))));
    PackageInstalledParams params;
    params.packageName = "sample-package";
    params.packageManager = PackageManagerType::RPM;

    auto result = AuditPackageInstalled(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    ASSERT_TRUE(result.Error().message.find("Failed to get installed packages") != std::string::npos);
}

TEST_F(PackageInstalledTest, DpkgCommandFails)
{
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr(dpkgCommand))).WillRepeatedly(Return(Result<std::string>(Error("Command failed", 1))));
    PackageInstalledParams params;
    params.packageName = "sample-package";
    params.packageManager = PackageManagerType::DPKG;

    auto result = AuditPackageInstalled(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    ASSERT_TRUE(result.Error().message.find("Failed to get installed packages") != std::string::npos);
}

TEST_F(PackageInstalledTest, UseCacheWhenAvailable)
{
    time_t now = time(nullptr);
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr(rpmCommand))).Times(0); // it should never be called
    CreateCacheFile("rpm", now, {{"package1", "1.0.0-1"}, {"package2", "2.1.0-2"}, {"sample-package", "3.1.4-5"}, {"mysql-server", "5.7.32-1"}});

    PackageInstalledParams params;
    params.packageName = "sample-package";
    params.packageManager = PackageManagerType::RPM;

    auto result = AuditPackageInstalled(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(PackageInstalledTest, UseStaleCache)
{
    time_t staleTime = time(nullptr) - 4000; // Over PACKAGELIST_TTL (3000)
    CreateCacheFile("rpm", staleTime,
        {{"sample-package", "3.1.4-5"}, {"package1", "1.0.0-1"}, {"package2", "2.1.0-2"}, {"old-package", "0.9.0-1"}, {"mysql-server", "5.7.32-1"}});

    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr(rpmCommand))).WillRepeatedly(Return(Result<std::string>(Error("Command failed", 1))));
    PackageInstalledParams params;
    params.packageName = "sample-package";
    params.packageManager = PackageManagerType::RPM;

    auto result = AuditPackageInstalled(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(PackageInstalledTest, RefreshStaleCache)
{
    time_t staleTime = time(nullptr) - 4000; // Over PACKAGELIST_TTL (3000)
    CreateCacheFile("rpm", staleTime, {{"package1", "1.0.0-1"}, {"package2", "2.1.0-2"}, {"old-package", "0.9.0-1"}, {"mysql-server", "5.7.32-1"}});

    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr(rpmCommand))).WillRepeatedly(Return(Result<std::string>(rpmWithPackageOutput)));

    PackageInstalledParams params;
    params.packageName = "sample-package";
    params.packageManager = PackageManagerType::RPM;

    auto result = AuditPackageInstalled(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(PackageInstalledTest, PackageManagerMismatch)
{
    time_t now = time(nullptr);
    CreateCacheFile("dpkg", now, {{"package1", "1.2.3-4"}, {"package2", "2.0.0-1"}, {"sample-package", "3.1.4-2"}, {"mysql-server", "5.7.32-1"}});

    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr(rpmCommand))).WillRepeatedly(Return(Result<std::string>(rpmWithPackageOutput)));

    PackageInstalledParams params;
    params.packageName = "sample-package";
    params.packageManager = PackageManagerType::RPM; // Mismatch with cache

    auto result = AuditPackageInstalled(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(PackageInstalledTest, InvalidCacheFormat)
{
    std::ofstream cache(cacheFile);
    ASSERT_TRUE(cache.is_open());
    cache << "This is not a valid cache file format" << std::endl;
    cache.close();

    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr(rpmCommand))).WillRepeatedly(Return(Result<std::string>(rpmWithPackageOutput)));

    PackageInstalledParams params;
    params.packageName = "sample-package";
    params.packageManager = PackageManagerType::RPM;

    auto result = AuditPackageInstalled(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(PackageInstalledTest, CacheWithInvalidTimestamp)
{
    std::ofstream cache(cacheFile);
    ASSERT_TRUE(cache.is_open());
    cache << "# PackageCache rpm@notanumber" << std::endl;
    cache << "package1 1.0.0" << std::endl;
    cache << "sample-package 3.1.4" << std::endl;
    cache.close();

    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr(rpmCommand))).WillRepeatedly(Return(Result<std::string>(rpmWithPackageOutput)));

    PackageInstalledParams params;
    params.packageName = "sample-package";
    params.packageManager = PackageManagerType::RPM;

    auto result = AuditPackageInstalled(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(PackageInstalledTest, CacheTooStale)
{
    time_t veryStaleTime = time(nullptr) - 13000; // Over PACKAGELIST_STALE_TTL (12600)
    CreateCacheFile("rpm", veryStaleTime,
        {{"package1", "1.0.0-1"}, {"package2", "2.1.0-2"}, {"sample-package", "3.1.4-5"}, {"mysql-server", "5.7.32-1"}});

    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr(rpmCommand))).WillRepeatedly(Return(Result<std::string>(rpmWithPackageOutput)));

    PackageInstalledParams params;
    params.packageName = "sample-package";
    params.packageManager = PackageManagerType::RPM;

    auto result = AuditPackageInstalled(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(PackageInstalledTest, CachePathBroken)
{
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr(dpkgCommand))).WillRepeatedly(Return(Result<std::string>(dpkgWithPackageOutput)));

    PackageInstalledParams params;
    params.packageName = "sample-package";
    params.packageManager = PackageManagerType::DPKG;

    auto result = AuditPackageInstalled(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

// Version checking tests
TEST_F(PackageInstalledTest, MinVersionRequiredAndMet_Rpm)
{
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr(rpmCommand))).WillRepeatedly(Return(Result<std::string>(rpmWithPackageOutput)));

    PackageInstalledParams params;
    params.packageName = "sample-package";
    params.packageManager = PackageManagerType::RPM;
    params.minPackageVersion = "3.0.0-1"; // Required version is less than installed 3.1.4-5

    auto result = AuditPackageInstalled(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(PackageInstalledTest, MinVersionRequiredAndNotMet_Rpm)
{
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr(rpmCommand))).WillRepeatedly(Return(Result<std::string>(rpmWithPackageOutput)));

    PackageInstalledParams params;
    params.packageName = "sample-package";
    params.packageManager = PackageManagerType::RPM;
    params.minPackageVersion = "4.0.0-1"; // Required version is greater than installed 3.1.4-5

    auto result = AuditPackageInstalled(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(PackageInstalledTest, MinVersionRequiredExactMatch_Rpm)
{
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr(rpmCommand))).WillRepeatedly(Return(Result<std::string>(rpmWithPackageOutput)));

    PackageInstalledParams params;
    params.packageName = "sample-package";
    params.packageManager = PackageManagerType::RPM;
    params.minPackageVersion = "3.1.4-5"; // Exact match with installed version including release

    auto result = AuditPackageInstalled(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(PackageInstalledTest, MinVersionRequiredAndMet_Dpkg)
{
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr(dpkgCommand))).WillRepeatedly(Return(Result<std::string>(dpkgWithPackageOutput)));

    PackageInstalledParams params;
    params.packageName = "sample-package";
    params.packageManager = PackageManagerType::DPKG;
    params.minPackageVersion = "3.0.0-1"; // Required version is less than installed 3.1.4-2

    auto result = AuditPackageInstalled(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(PackageInstalledTest, MinVersionRequiredAndNotMet_Dpkg)
{
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr(dpkgCommand))).WillRepeatedly(Return(Result<std::string>(dpkgWithPackageOutput)));

    PackageInstalledParams params;
    params.packageName = "sample-package";
    params.packageManager = PackageManagerType::DPKG;
    params.minPackageVersion = "4.0.0-1"; // Required version is greater than installed 3.1.4-2

    auto result = AuditPackageInstalled(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(PackageInstalledTest, MinVersionRequiredExactMatch_Dpkg)
{
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr(dpkgCommand))).WillRepeatedly(Return(Result<std::string>(dpkgWithPackageOutput)));

    PackageInstalledParams params;
    params.packageName = "sample-package";
    params.packageManager = PackageManagerType::DPKG;
    params.minPackageVersion = "3.1.4-2"; // Exact match with installed version

    auto result = AuditPackageInstalled(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(PackageInstalledTest, PackageNotInstalledWithMinVersion)
{
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr(rpmCommand))).WillRepeatedly(Return(Result<std::string>(rpmWithoutPackageOutput)));

    PackageInstalledParams params;
    params.packageName = "sample-package";
    params.packageManager = PackageManagerType::RPM;
    params.minPackageVersion = "1.0.0-1";

    auto result = AuditPackageInstalled(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
    // Should indicate package not installed, not version mismatch
}

TEST_F(PackageInstalledTest, ComplexVersionComparison_Rpm)
{
    // Test with more complex version strings
    std::string complexRpmOutput = "package1 1.0.0-1\ncomplex-package 2.4.1-rc3\nmysql-server 8.0.25-1\npackage5 1.5.0-3\n";
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr(rpmCommand))).WillRepeatedly(Return(Result<std::string>(complexRpmOutput)));

    PackageInstalledParams params;
    params.packageName = "complex-package";
    params.packageManager = PackageManagerType::RPM;
    params.minPackageVersion = "2.4.0-1"; // Should be satisfied by 2.4.1-rc3

    auto result = AuditPackageInstalled(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(PackageInstalledTest, ComplexVersionComparisonFails_Rpm)
{
    // Test with more complex version strings
    std::string complexRpmOutput = "package1 1.0.0-1\ncomplex-package 2.3.5-beta\nmysql-server 8.0.25-1\npackage5 1.5.0-3\n";
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr(rpmCommand))).WillRepeatedly(Return(Result<std::string>(complexRpmOutput)));

    PackageInstalledParams params;
    params.packageName = "complex-package";
    params.packageManager = PackageManagerType::RPM;
    params.minPackageVersion = "2.4.0-1"; // Should not be satisfied by 2.3.5-beta

    auto result = AuditPackageInstalled(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(PackageInstalledTest, VersionComparisonWithCache)
{
    time_t now = time(nullptr);
    CreateCacheFile("rpm", now, {{"package1", "1.0.0-1"}, {"version-test", "2.5.1-2"}, {"mysql-server", "5.7.32-1"}});

    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr(rpmCommand))).Times(0); // Should use cache

    PackageInstalledParams params;
    params.packageName = "version-test";
    params.packageManager = PackageManagerType::RPM;
    params.minPackageVersion = "2.5.0-1"; // Should be satisfied by cached 2.5.1-2

    auto result = AuditPackageInstalled(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(PackageInstalledTest, VersionComparisonWithCacheFails)
{
    time_t now = time(nullptr);
    CreateCacheFile("rpm", now, {{"package1", "1.0.0-1"}, {"version-test", "2.4.9-1"}, {"mysql-server", "5.7.32-1"}});

    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr(rpmCommand))).Times(0); // Should use cache

    PackageInstalledParams params;
    params.packageName = "version-test";
    params.packageManager = PackageManagerType::RPM;
    params.minPackageVersion = "2.5.0-1"; // Should not be satisfied by cached 2.4.9-1

    auto result = AuditPackageInstalled(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(PackageInstalledTest, EmptyMinVersionIsIgnored)
{
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr(rpmCommand))).WillRepeatedly(Return(Result<std::string>(rpmWithPackageOutput)));

    PackageInstalledParams params;
    params.packageName = "sample-package";
    params.packageManager = PackageManagerType::RPM;
    params.minPackageVersion = ""; // Empty version should be ignored

    auto result = AuditPackageInstalled(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(PackageInstalledTest, NumericVersionComparison)
{
    std::string numericVersionOutput = "numeric1 1.2.3-1\nnumeric2 1.10.0-2\nnumeric3 2.0.0-1\npackage5 1.5.0-3\n";
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr(rpmCommand))).WillRepeatedly(Return(Result<std::string>(numericVersionOutput)));

    // Test that 1.10.0-2 > 1.2.3-1 (numeric comparison, not string comparison)
    PackageInstalledParams params;
    params.packageName = "numeric2";
    params.packageManager = PackageManagerType::RPM;
    params.minPackageVersion = "1.9.0-1"; // Should be satisfied by 1.10.0-2

    auto result = AuditPackageInstalled(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(PackageInstalledTest, MixedAlphanumericVersionComparison)
{
    // Test mixed alphanumeric version comparison
    std::string mixedVersionOutput = "mixed1 1.0a-1\nmixed2 1.0b-1\nmixed3 1.0.1-2\npackage5 1.5.0-3\n";
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr(rpmCommand))).WillRepeatedly(Return(Result<std::string>(mixedVersionOutput)));

    // Test that 1.0.1-2 > 1.0b-1 (numeric part comes before alphabetic)
    PackageInstalledParams params;
    params.packageName = "mixed3";
    params.packageManager = PackageManagerType::RPM;
    params.minPackageVersion = "1.0b-1"; // Should be satisfied by 1.0.1-2

    auto result = AuditPackageInstalled(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(PackageInstalledTest, AlphaOnlyVersionComparison)
{
    // Test mixed alphanumeric version comparison
    std::string mixedVersionOutput = "mixed1 1.0a-1\nmixed2 1.0b-1\nmixed3 1.0.1-2\npackage5 1.5.0-3\nalpha 1.beta.3-5";
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr(rpmCommand))).WillRepeatedly(Return(Result<std::string>(mixedVersionOutput)));

    // Test that 1.beta.3-5 > 1.alpha.0-1 (beta > alpha alphabetically)
    PackageInstalledParams params;
    params.packageName = "alpha";
    params.packageManager = PackageManagerType::RPM;
    params.minPackageVersion = "1.alpha.0-1";

    auto result = AuditPackageInstalled(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(PackageInstalledTest, LongerVersionComparison)
{
    // Test mixed alphanumeric version comparison
    std::string mixedVersionOutput = "mixed1 1.0a-1\nmixed2 1.0b-1\nmixed3 1.0.1-2\npackage5 1.5.0-3\nalpha 1.beta.3.7.1-5";
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr(rpmCommand))).WillRepeatedly(Return(Result<std::string>(mixedVersionOutput)));

    // Test that 1.beta.3-5 > 1.alpha.0-1 (beta > alpha alphabetically)
    PackageInstalledParams params;
    params.packageName = "alpha";
    params.packageManager = PackageManagerType::RPM;
    params.minPackageVersion = "1.beta.3.7-1";

    auto result = AuditPackageInstalled(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(PackageInstalledTest, EpochVersionComparison_Rpm)
{
    // Test epoch version comparison - epoch takes precedence over version and release
    std::string epochVersionOutput =
        "package1 1.0.0-1\nepoch-package 2:1.0.0-1\nepoch-package2 1:2.0.0-1\nno-epoch-package 3.0.0-1\npackage5 1.5.0-3\n";
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr(rpmCommand))).WillRepeatedly(Return(Result<std::string>(epochVersionOutput)));

    // Test that epoch:version-release comparison works correctly
    // epoch-package has epoch 2, so 2:1.0.0-1 should be greater than 1:2.0.0-1
    PackageInstalledParams params;
    params.packageName = "epoch-package";
    params.packageManager = PackageManagerType::RPM;
    params.minPackageVersion = "1:2.0.0-1"; // Should be satisfied by 2:1.0.0-1 (higher epoch)

    auto result = AuditPackageInstalled(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(PackageInstalledTest, EpochVersionComparisonFails_Rpm)
{
    // Test epoch version comparison where requirement is not met
    std::string epochVersionOutput =
        "package1 1.0.0-1\nepoch-package 1:1.0.0-1\nepoch-package2 2:2.0.0-1\nno-epoch-package 3.0.0-1\npackage5 1.5.0-3\n";
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr(rpmCommand))).WillRepeatedly(Return(Result<std::string>(epochVersionOutput)));

    // Test that epoch:version-release comparison fails when required epoch is higher
    PackageInstalledParams params;
    params.packageName = "epoch-package";
    params.packageManager = PackageManagerType::RPM;
    params.minPackageVersion = "2:1.0.0-1"; // Should not be satisfied by 1:1.0.0-1 (lower epoch)

    auto result = AuditPackageInstalled(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(PackageInstalledTest, MixedEpochAndNoEpochComparison_Rpm)
{
    // Test comparison between packages with epoch and without epoch
    std::string mixedEpochOutput = "package1 1.0.0-1\nwith-epoch 1:1.0.0-1\nwithout-epoch 2.0.0-1\npackage5 1.5.0-3\n";
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr(rpmCommand))).WillRepeatedly(Return(Result<std::string>(mixedEpochOutput)));

    // Test that package with epoch 1: is greater than package without epoch (implicit epoch 0)
    PackageInstalledParams params;
    params.packageName = "with-epoch";
    params.packageManager = PackageManagerType::RPM;
    params.minPackageVersion = "2.0.0-1"; // Should be satisfied by 1:1.0.0-1 (epoch 1 > implicit epoch 0)

    auto result = AuditPackageInstalled(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(PackageInstalledTest, LatestVersionBelowCandidate)
{
    ExpectCandidate("3.1.4-2", "3.1.4-3");
    EXPECT_CALL(mContext, ExecuteCommand("dpkg --compare-versions \"3.1.4-2\" ge \"3.1.4-3\"; printf '%s' \"$?\""))
        .WillOnce(Return(Result<std::string>("1")));
    auto result = AuditPackageInstalled(LatestParams(), mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
    EXPECT_THAT(mFormatter.Format(mIndicators).Value(), HasSubstr("APT candidate 3.1.4-3"));
}

TEST_F(PackageInstalledTest, LatestVersionMeetsCandidateAndReusesCache)
{
    ExpectCandidate("3.1.4-2", "3.1.4-2");
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr("dpkg --compare-versions"))).Times(2).WillRepeatedly(Return(Result<std::string>("0")));
    for (int i = 0; i < 2; ++i)
    {
        auto result = AuditPackageInstalled(LatestParams(), mIndicators, mContext);
        ASSERT_TRUE(result.HasValue());
        EXPECT_EQ(result.Value(), Status::Compliant);
    }
}

TEST_F(PackageInstalledTest, LatestVersionWithoutCandidate)
{
    ExpectCandidate("3.1.4-2", "(none)");
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr("dpkg --compare-versions"))).Times(0);
    auto result = AuditPackageInstalled(LatestParams(), mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(PackageInstalledTest, LatestVersionMissingPackage)
{
    CreateCacheFile("dpkg", time(nullptr), {{"other-package", "1.0"}});
    EXPECT_CALL(mContext, ExecuteCommand(testing::_)).Times(0);
    auto result = AuditPackageInstalled(LatestParams(), mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(PackageInstalledTest, LatestVersionPackageRemovedSinceCache)
{
    ExpectCandidate("(none)", "3.1.4-2");
    auto result = AuditPackageInstalled(LatestParams(), mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(PackageInstalledTest, LatestVersionAutodetectsDpkgFromCache)
{
    ExpectCandidate("3.1.4-2", "3.1.4-2");
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr("dpkg --compare-versions"))).WillOnce(Return(Result<std::string>("0")));
    auto params = LatestParams();
    params.packageManager = PackageManagerType::Autodetect;
    auto result = AuditPackageInstalled(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(PackageInstalledTest, LatestVersionRejectsRpm)
{
    auto params = LatestParams();
    params.packageManager = PackageManagerType::RPM;
    EXPECT_CALL(mContext, ExecuteCommand(testing::_)).Times(0);
    auto result = AuditPackageInstalled(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, EINVAL);
}

TEST_F(PackageInstalledTest, LatestVersionAptFailure)
{
    CreateCacheFile("dpkg", time(nullptr), {{"sample-package", "3.1.4-2"}});
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr("apt-cache policy"))).WillOnce(Return(Result<std::string>(Error("apt-cache unavailable", 127))));
    auto result = AuditPackageInstalled(LatestParams(), mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_THAT(result.Error().message, HasSubstr("apt-cache unavailable"));
}

TEST_F(PackageInstalledTest, LatestVersionInvalidPolicy)
{
    CreateCacheFile("dpkg", time(nullptr), {{"sample-package", "3.1.4-2"}});
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr("apt-cache policy")))
        .WillOnce(Return(Result<std::string>("sample-package:\n  Installed: 3.1.4-2\n")));
    auto result = AuditPackageInstalled(LatestParams(), mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_THAT(result.Error().message, HasSubstr("Invalid APT policy"));
}

TEST_F(PackageInstalledTest, LatestVersionAmbiguousPolicy)
{
    CreateCacheFile("dpkg", time(nullptr), {{"sample-package", "3.1.4-2"}});
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr("apt-cache policy")))
        .WillOnce(Return(Result<std::string>("sample-package:\n  Installed: 3.1.4-2\n  Candidate: 3.1.4-2\nother:\n  Installed: 1\n  Candidate: 2\n")));
    auto result = AuditPackageInstalled(LatestParams(), mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_THAT(result.Error().message, HasSubstr("Ambiguous APT policy"));
}

TEST_F(PackageInstalledTest, LatestVersionComparisonFailure)
{
    ExpectCandidate("3.1.4-2", "invalid-version");
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr("dpkg --compare-versions"))).WillOnce(Return(Result<std::string>("2")));
    auto result = AuditPackageInstalled(LatestParams(), mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_THAT(result.Error().message, HasSubstr("exit status 2"));
}

TEST_F(PackageInstalledTest, LatestVersionComparisonCommandFailure)
{
    ExpectCandidate("3.1.4-2", "3.1.4-3");
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr("dpkg --compare-versions"))).WillOnce(Return(Result<std::string>(Error("command failed"))));
    auto result = AuditPackageInstalled(LatestParams(), mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_THAT(result.Error().message, HasSubstr("Failed to compare dpkg versions"));
}

TEST_F(PackageInstalledTest, LatestVersionDoesNotReuseStaleCacheOnRefreshFailure)
{
    CreateCacheFile("dpkg", time(nullptr) - 4000, {{"sample-package", "3.1.4-2"}});
    EXPECT_CALL(mContext, ExecuteCommand(dpkgCommand)).WillOnce(Return(Result<std::string>(Error("dpkg unavailable"))));
    auto result = AuditPackageInstalled(LatestParams(), mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_THAT(result.Error().message, HasSubstr("Failed to get installed packages"));
}

TEST_F(PackageInstalledTest, LatestVersionRefreshesExpiredCandidate)
{
    CreateCacheFile("dpkg", time(nullptr) - 4000, {{"sample-package", "3.1.4-2"}});
    {
        std::ofstream cache(cacheFile, std::ios::app);
        cache << "# Candidate sample-package 3.1.4-2\n";
    }
    EXPECT_CALL(mContext, ExecuteCommand(dpkgCommand)).WillOnce(Return(Result<std::string>(dpkgWithPackageOutput)));
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr("apt-cache policy")))
        .WillOnce(Return(Result<std::string>("sample-package:\n  Installed: 3.1.4-2\n  Candidate: 3.1.4-3\n")));
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr("dpkg --compare-versions"))).WillOnce(Return(Result<std::string>("1")));
    auto result = AuditPackageInstalled(LatestParams(), mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(PackageInstalledTest, LatestVersionAlsoEnforcesMinimumVersion)
{
    ExpectCandidate("3.1.4-2", "3.1.4-2");
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr("dpkg --compare-versions"))).WillOnce(Return(Result<std::string>("0")));
    auto params = LatestParams();
    params.minPackageVersion = "4.0";
    auto result = AuditPackageInstalled(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(PackageInstalledTest, LatestVersionHeldArchitectureQualifiedPackage)
{
    EXPECT_CALL(mContext, ExecuteCommand(dpkgCommand))
        .WillOnce(Return(Result<std::string>("+++-====\nhi  sample-package:amd64 3.1.4-2 amd64 Held package\n")));
    EXPECT_CALL(mContext, ExecuteCommand("LC_ALL=C apt-cache policy -- \"sample-package:amd64\""))
        .WillOnce(Return(Result<std::string>("sample-package:amd64:\n  Installed: 3.1.4-2\n  Candidate: 3.1.4-3\n")));
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr("dpkg --compare-versions"))).WillOnce(Return(Result<std::string>("1")));
    auto result = AuditPackageInstalled(LatestParams("sample-package:amd64"), mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(PackageInstalledTest, LatestVersionUsesNativeDebianOrdering)
{
    if (access("/usr/bin/dpkg", X_OK) != 0)
    {
        GTEST_SKIP() << "dpkg is not installed";
    }
    const std::vector<std::tuple<std::string, std::string, Status>> cases = {
        {"1.0~rc1-1", "1.0-1", Status::NonCompliant},
        {"1:1.0-1", "2.0-1", Status::Compliant},
        {"1.0-1", "1.0-1+b1", Status::NonCompliant},
        {"1.0-2", "1.0-1", Status::Compliant},
    };
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr("dpkg --compare-versions"))).WillRepeatedly([](const std::string& cmd) -> Result<std::string> {
        char* output = nullptr;
        int status = ::ExecuteCommand(nullptr, cmd.c_str(), false, false, 0, 0, &output, nullptr, nullptr);
        std::string text = output ? output : "";
        std::free(output);
        if (status != 0)
        {
            return Error("Failed to execute dpkg", status);
        }
        return text;
    });
    for (const auto& entry : cases)
    {
        SCOPED_TRACE(std::get<0>(entry) + " vs " + std::get<1>(entry));
        ExpectCandidate(std::get<0>(entry), std::get<1>(entry));
        auto result = AuditPackageInstalled(LatestParams(), mIndicators, mContext);
        ASSERT_TRUE(result.HasValue());
        EXPECT_EQ(result.Value(), std::get<2>(entry));
    }
}

TEST_F(PackageInstalledTest, LatestVersionArchitectureAlias)
{
    EXPECT_CALL(mContext, ExecuteCommand(dpkgCommand)).WillOnce(Return(Result<std::string>(dpkgWithPackageOutput)));
    EXPECT_CALL(mContext, ExecuteCommand("LC_ALL=C apt-cache policy -- \"sample-package:amd64\""))
        .WillOnce(Return(Result<std::string>("sample-package:\n  Installed: 3.1.4-2\n  Candidate: 3.1.4-2\n")));
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr("dpkg --compare-versions"))).WillOnce(Return(Result<std::string>("0")));
    auto result = AuditPackageInstalled(LatestParams("sample-package:amd64"), mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(PackageInstalledTest, LatestVersionFourPayloadsThroughEvaluator)
{
    const std::vector<std::string> packages = {"libpam-runtime", "libpam-modules", "libpam-pwquality", "cracklib-runtime"};
    EXPECT_CALL(mContext, ExecuteCommand(HasSubstr("dpkg --compare-versions"))).Times(4).WillRepeatedly(Return(Result<std::string>("1")));
    const std::map<std::string, std::string> parameters;
    for (const auto& package : packages)
    {
        SCOPED_TRACE(package);
        ExpectCandidate("1.0-1", "1.0-2", package);
        auto json = Kompli::JsonWrapper::FromString("{\"PackageInstalled\":{\"packageName\":\"" + package +
                                                    "\",\"packageManager\":\"dpkg\",\"latestPackageVersion\":\"true\"}}");
        ASSERT_TRUE(json.HasValue());
        Kompli::Evaluator evaluator(package, json_value_get_object(json->get()), parameters, mContext);
        auto result = evaluator.ExecuteAudit(mFormatter);
        ASSERT_TRUE(result.HasValue());
        EXPECT_EQ(result.Value().status, Status::NonCompliant);
    }
}
