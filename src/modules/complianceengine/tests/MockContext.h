// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ContextInterface.h"
#include "TemporaryDirectory.h"

#include <cstdio>
#include <fstream>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <iostream>
#include <map>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

struct MockContext : public ComplianceEngine::ContextInterface
{
    MOCK_METHOD(ComplianceEngine::Result<std::string>, ExecuteCommand, (const std::string& cmd), (const, override));
    MOCK_METHOD(ComplianceEngine::Result<std::string>, GetFileContents, (const std::string& filePath), (const, override));
    MOCK_METHOD(ComplianceEngine::Result<std::vector<ComplianceEngine::InterfaceInfo>>, GetNetworkInterfaces, (), (const, override));

    ComplianceEngine::Result<std::string> GetRunningKernelRelease() const override
    {
        return mRunningKernelRelease;
    }

    // Overrides the value returned by GetRunningKernelRelease(); pass an Error to simulate
    // uname() failing.
    void SetRunningKernelRelease(ComplianceEngine::Result<std::string> release)
    {
        mRunningKernelRelease = std::move(release);
    }

    ComplianceEngine::Telemetry& GetTelemetry() override
    {
        return mTelemetry;
    }

    OsConfigLogHandle GetLogHandle() const override
    {
        return mLogHandle;
    }

    void SetLogHandle(OsConfigLogHandle logHandle)
    {
        mLogHandle = logHandle;
    }

    MockContext()
        : mTempOwner(CreateTempdir()),
          mTempdir(mTempOwner.Path())
    {
        mTempRootDir = mTempdir + "/rootfs";
        ::mkdir(mTempRootDir.c_str(), 0755);

        std::string mCachePath = mTempdir + "/fsscanner-cache";
        std::string mLockfilePath = mTempdir + "/fsscanner-lock";
        mFsScannerp =
            std::unique_ptr<ComplianceEngine::FilesystemScanner>(new ComplianceEngine::FilesystemScanner(mTempRootDir, mCachePath, mLockfilePath, 60, 120, 10));
    }

    ~MockContext() override
    {
        if (!mTempOwner.Remove())
        {
            std::cerr << "Failed to remove temporary directory: " << mTempdir << std::endl;
        }
    }

    std::string MakeTempfile(const std::string& content, const std::string& extension = "")
    {
        std::string filename = mTempdir + "/" + std::to_string(++mTempfileCount) + extension;
        std::ofstream file(filename);
        file << content;
        return filename;
    }

    std::string GetTempdirPath() const
    {
        return mTempdir;
    }

    std::string GetSpecialFilePath(const std::string& path) const override
    {
        auto it = mSpecialFilesMap.find(path);
        if (it != mSpecialFilesMap.end())
        {
            return it->second;
        }

        return path;
    }

    void SetSpecialFilePath(const std::string& path, const std::string& overridden)
    {
        mSpecialFilesMap[path] = overridden;
    }

    ComplianceEngine::FilesystemScanner& GetFilesystemScanner() override
    {
        return *mFsScannerp;
    }

    std::string GetFilesystemScannerRoot() const
    {
        return mTempRootDir;
    }

    std::string GetStatePath() const override
    {
        return mTempdir;
    }

private:
    // throws as it's used by the constructor
    static ComplianceEngine::Detail::TemporaryDirectory CreateTempdir()
    {
        auto result = ComplianceEngine::Detail::TemporaryDirectory::Make("ComplianceEngineTest");
        if (!result.HasValue())
        {
            throw std::runtime_error(result.Error().message);
        }
        return std::move(result).Value();
    }

    ComplianceEngine::Detail::TemporaryDirectory mTempOwner;
    std::string mTempdir;
    std::string mTempRootDir;
    std::size_t mTempfileCount{0};
    std::map<std::string, std::string> mSpecialFilesMap;
    std::unique_ptr<ComplianceEngine::FilesystemScanner> mFsScannerp;
    ComplianceEngine::Result<std::string> mRunningKernelRelease{std::string("5.15.test")};
    OsConfigLogHandle mLogHandle{nullptr};
    ComplianceEngine::Telemetry mTelemetry{-1};
};
