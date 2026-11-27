// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "MCInterface.h"

#include <CommonUtils.h>
#include <DistributionInfo.h>
#include <Engine.h>
#include <Mmi.h>
#include <fstream>
#include <gtest/gtest.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <version.h>

using namespace std;
using Kompli::DistributionInfo;

class ComplianceEngineTest : public ::testing::Test
{
protected:
    MMI_HANDLE mHandle = nullptr;
    static const unsigned int cMaxPayloadSize = 100;
    void SetUp() override
    {
        KompliInitialize(nullptr);
        mHandle = KompliMmiOpen("test", cMaxPayloadSize);
    }

    void TearDown() override
    {
        KompliMmiClose(mHandle);
        KompliShutdown();
    }
};

TEST_F(ComplianceEngineTest, ComplianceEngineMmiOpen_1)
{
    ASSERT_NE(mHandle, nullptr);
}

TEST_F(ComplianceEngineTest, ComplianceEngineMmiGetInfo_InvalidArguments_1)
{
    int payloadSizeBytes = 0;
    ASSERT_NE(MMI_OK, KompliMmiGetInfo("test", nullptr, &payloadSizeBytes));
}

TEST_F(ComplianceEngineTest, ComplianceEngineMmiGetInfo_InvalidArguments_2)
{
    char* payload = nullptr;
    ASSERT_NE(MMI_OK, KompliMmiGetInfo("test", &payload, nullptr));
}

TEST_F(ComplianceEngineTest, ComplianceEngineMmiGetInfo_1)
{
    char* payload = nullptr;
    int payloadSizeBytes = 0;
    ASSERT_EQ(MMI_OK, KompliMmiGetInfo("test", &payload, &payloadSizeBytes));
    KompliMmiFree(payload);
}

TEST_F(ComplianceEngineTest, ComplianceEngineMmiSet_InvalidArguments_1)
{
    auto payload = std::string("\"eyJhdWRpdCI6eyJhbnlPZiI6W119fQ=="); // {"audit":{"anyOf":[]}} in base64
    ASSERT_NE(MMI_OK, KompliMmiSet(nullptr, "ComplianceEngine", "procedureX", payload.c_str(), static_cast<int>(payload.size())));
}

TEST_F(ComplianceEngineTest, ComplianceEngineMmiSet_InvalidArguments_2)
{
    auto payload = std::string("\"eyJhdWRpdCI6eyJhbnlPZiI6W119fQ==\""); // {"audit":{"anyOf":[]}} in base64
    ASSERT_NE(MMI_OK, KompliMmiSet(mHandle, nullptr, "procedureX", payload.c_str(), static_cast<int>(payload.size())));
}

TEST_F(ComplianceEngineTest, ComplianceEngineMmiSet_InvalidArguments_3)
{
    auto payload = std::string("\"eyJhdWRpdCI6eyJhbnlPZiI6W119fQ==\""); // {"audit":{"anyOf":[]}} in base64
    ASSERT_NE(MMI_OK, KompliMmiSet(mHandle, "wrong module name", "procedureX", payload.c_str(), static_cast<int>(payload.size())));
}

TEST_F(ComplianceEngineTest, ComplianceEngineMmiSet_InvalidArguments_4)
{
    auto payload = std::string("\"eyJhdWRpdCI6eyJhbnlPZiI6W119fQ==\""); // {"audit":{"anyOf":[]}} in base64
    ASSERT_NE(MMI_OK, KompliMmiSet(mHandle, "ComplianceEngine", nullptr, payload.c_str(), static_cast<int>(payload.size())));
}

TEST_F(ComplianceEngineTest, ComplianceEngineMmiSet_InvalidArguments_5)
{
    auto payload = std::string("\"eyJhdWRpdCI6eyJhbnlPZiI6W119fQ==\""); // {"audit":{"anyOf":[]}} in base64
    ASSERT_NE(MMI_OK, KompliMmiSet(mHandle, "ComplianceEngine", "procedureX", nullptr, static_cast<int>(payload.size())));
}

TEST_F(ComplianceEngineTest, ComplianceEngineMmiSet_InvalidArguments_6)
{
    auto payload = std::string("\"eyJhdWRpdCI6eyJhbnlPZiI6W119fQ==\""); // {"audit":{"anyOf":[]}} in base64
    ASSERT_NE(MMI_OK, KompliMmiSet(mHandle, "ComplianceEngine", "procedureX", payload.c_str(), -1));
}

TEST_F(ComplianceEngineTest, ComplianceEngineMmiSet_SetProcedure_1)
{
    auto payload = std::string("\"eyJhdWRpdCI6eyJhbnlPZiI6W119fQ==\""); // {"audit":{"anyOf":[]}} in base64
    ASSERT_EQ(MMI_OK, KompliMmiSet(mHandle, "ComplianceEngine", "procedureX", payload.c_str(), static_cast<int>(payload.size())));
}

TEST_F(ComplianceEngineTest, ComplianceEngineMmiSet_SetProcedure_2)
{
    auto procedurePayload =
        std::string("\"eyJhdWRpdCI6eyJhbnlPZiI6W3sicW0/Ijp7fX1dfX0K\""); // '{"audit":{"anyOf":[{"qm?":{}}]}}' in base64, verify that '/' is properly de-escaped
    ASSERT_EQ(MMI_OK, KompliMmiSet(mHandle, "ComplianceEngine", "procedureX", procedurePayload.c_str(), static_cast<int>(procedurePayload.size())));
}

TEST_F(ComplianceEngineTest, ComplianceEngineMmiGet_InvalidArguments_1)
{
    char* payload = nullptr;
    int payloadSizeBytes = 0;
    ASSERT_NE(MMI_OK, KompliMmiGet(nullptr, "ComplianceEngine", "auditX", &payload, &payloadSizeBytes));
}

TEST_F(ComplianceEngineTest, ComplianceEngineMmiGet_InvalidArguments_2)
{
    char* payload = nullptr;
    int payloadSizeBytes = 0;
    ASSERT_NE(MMI_OK, KompliMmiGet(mHandle, nullptr, "auditX", &payload, &payloadSizeBytes));
}

TEST_F(ComplianceEngineTest, ComplianceEngineMmiGet_InvalidArguments_3)
{
    char* payload = nullptr;
    int payloadSizeBytes = 0;
    auto result = KompliMmiGet(mHandle, "ComplianceEngine", "auditX", &payload, &payloadSizeBytes);
    ASSERT_EQ(result, MMI_OK);
    ASSERT_NE(payload, nullptr);
    ASSERT_TRUE(std::string(payload).find("Rule not found") != std::string::npos);
    KompliMmiFree(payload);
}

TEST_F(ComplianceEngineTest, ComplianceEngineMmiGet_InvalidArguments_4)
{
    char* payload = nullptr;
    int payloadSizeBytes = 0;
    ASSERT_NE(MMI_OK, KompliMmiGet(mHandle, "ComplianceEngine", nullptr, &payload, &payloadSizeBytes));
}

TEST_F(ComplianceEngineTest, ComplianceEngineMmiGet_InvalidArguments_5)
{
    int payloadSizeBytes = 0;
    ASSERT_NE(MMI_OK, KompliMmiGet(mHandle, "ComplianceEngine", "auditX", nullptr, &payloadSizeBytes));
}

TEST_F(ComplianceEngineTest, ComplianceEngineMmiGet_InvalidArguments_6)
{
    char* payload = nullptr;
    ASSERT_NE(MMI_OK, KompliMmiGet(mHandle, "ComplianceEngine", "auditX", &payload, nullptr));
}

TEST_F(ComplianceEngineTest, ComplianceEngineMmiGet_1)
{
    auto procedurePayload = std::string("\"eyJhdWRpdCI6eyJhbnlPZiI6W119fQ==\""); // {"audit":{"anyOf":[]}} in base64
    ASSERT_EQ(MMI_OK, KompliMmiSet(mHandle, "ComplianceEngine", "procedureX", procedurePayload.c_str(), static_cast<int>(procedurePayload.size())));
    char* payload = nullptr;
    int payloadSizeBytes = 0;
    ASSERT_EQ(MMI_OK, KompliMmiGet(mHandle, "ComplianceEngine", "auditX", &payload, &payloadSizeBytes));
    ASSERT_NE(payload, nullptr);
    EXPECT_NE(0, strncmp(payload, "\"PASS", 5));
    KompliMmiFree(payload);
}

TEST_F(ComplianceEngineTest, ComplianceEngineMmiGet_2)
{
    auto procedurePayload = std::string("\"eyJhdWRpdCI6eyJhbGxPZiI6W119fQ==\""); // {"audit":{"allOf":[]}} in base64
    ASSERT_EQ(MMI_OK, KompliMmiSet(mHandle, "ComplianceEngine", "procedureX", procedurePayload.c_str(), static_cast<int>(procedurePayload.size())));
    char* payload = nullptr;
    int payloadSizeBytes = 0;
    ASSERT_EQ(MMI_OK, KompliMmiGet(mHandle, "ComplianceEngine", "auditX", &payload, &payloadSizeBytes));
    ASSERT_NE(payload, nullptr);
    ASSERT_TRUE(payloadSizeBytes >= 5);
    EXPECT_EQ(0, strncmp(payload, "\"PASS", 5));
    KompliMmiFree(payload);
}

TEST_F(ComplianceEngineTest, ValidatePayload_1)
{
    ASSERT_EQ(EINVAL, KompliCheckApplicability(nullptr, "/cis/ubuntu/22.04/v1.1.1/x/y/z", nullptr));
    ASSERT_EQ(EINVAL, KompliCheckApplicability(mHandle, nullptr, nullptr));
}

TEST_F(ComplianceEngineTest, ValidatePayload_2)
{
    ASSERT_EQ(EINVAL, KompliCheckApplicability(mHandle, "/cis/foo/bar/v1.1.1/x/y/z", nullptr));
}

TEST_F(ComplianceEngineTest, ValidatePayload_3)
{
    auto& engine = *reinterpret_cast<Kompli::Engine*>(mHandle);
    auto osRelease = engine.GetDistributionInfo();
    ASSERT_TRUE(osRelease.HasValue());
    std::string payloadKey = std::string("/cis/") + to_string(osRelease->distribution) + "/" + osRelease->version + "/v1.1.1/x/y/z";
    ASSERT_EQ(0, KompliCheckApplicability(mHandle, payloadKey.c_str(), nullptr));
}

TEST_F(ComplianceEngineTest, ValidatePayload_OverrideFile)
{
    if (0 != getuid())
    {
        GTEST_SKIP() << "This test suite requires root privileges or fakeroot";
    }

    struct stat st;
    auto status = stat(DistributionInfo::cDefaultOverrideFilePath, &st);
    if ((0 == status) || (ENOENT != errno))
    {
        GTEST_SKIP() << "This test suite modifies the override file which is already present";
    }

    bool createdDir = false;
    struct stat dirSt;
    if (0 != stat("/etc/kompli", &dirSt))
    {
        createdDir = (0 == mkdir("/etc/kompli", 0755));
    }

    std::ofstream overrideFile(DistributionInfo::cDefaultOverrideFilePath);
    if (!overrideFile.is_open())
    {
        if (createdDir)
        {
            rmdir("/etc/kompli");
        }
        GTEST_SKIP() << "Cannot create override file (insufficient permissions or missing directory)";
    }
    overrideFile << "OS=Linux ARCH=x86_64 DISTRO=ol VERSION=foo\n";
    overrideFile.flush();
    overrideFile.close();
    KompliShutdown();
    auto handle = KompliMmiOpen("test", cMaxPayloadSize);
    EXPECT_EQ(0, remove(DistributionInfo::cDefaultOverrideFilePath));
    if (createdDir)
    {
        rmdir("/etc/kompli");
    }
    ASSERT_NE(nullptr, handle);
    auto& engine = *reinterpret_cast<Kompli::Engine*>(handle);
    auto osRelease = engine.GetDistributionInfo();
    ASSERT_TRUE(osRelease.HasValue());
    EXPECT_EQ(0, KompliCheckApplicability(handle, "/cis/ol/foo/v2.0.1/x/y/z", nullptr));
    KompliMmiClose(handle);
}
