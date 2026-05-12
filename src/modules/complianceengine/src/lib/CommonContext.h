// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_COMMONCONTEXT_H
#define COMPLIANCEENGINE_COMMONCONTEXT_H

#include "ContextInterface.h"
#include "Logging.h"
#include "Result.h"
#include "Telemetry.h"

#include <memory>
#include <sstream>
#include <string>
#include <vector>

namespace ComplianceEngine
{

class CommonContext : public ContextInterface
{
public:
    CommonContext(OsConfigLogHandle log, const std::string& statePath, const int fd = -1)
        : mLog(log),
          mStatePath(statePath),
          mTelemetry(fd),
          mFsScanner("/", mStatePath + "/" + sFsCachePath, sLockPath, sSoftTimeout, sHardTimeout, sScanWaitTime)
    {
    }
    ~CommonContext() override;
    CommonContext(const CommonContext&) = delete;
    CommonContext& operator=(const CommonContext&) = delete;
    CommonContext(CommonContext&&) = delete;
    CommonContext& operator=(CommonContext&&) = delete;

    Result<std::string> ExecuteCommand(const std::string& cmd) const override;
    Result<std::string> GetFileContents(const std::string& filePath) const override;
    Result<std::vector<InterfaceInfo>> GetNetworkInterfaces() const override;
    Result<std::string> GetRunningKernelRelease() const override;

    Telemetry& GetTelemetry() override
    {
        return mTelemetry;
    }
    OsConfigLogHandle GetLogHandle() const override
    {
        return mLog;
    }

    std::string GetSpecialFilePath(const std::string& path) const override;
    FilesystemScanner& GetFilesystemScanner() override
    {
        return mFsScanner;
    }

    std::string GetStatePath() const override
    {
        return mStatePath;
    }

private:
    static constexpr char sFsCachePath[] = "ComplianceEngineFSCache";
    static constexpr char sLockPath[] = "/run/complianceengine-fsscanner.lock";
    static constexpr int sSoftTimeout = 3600;
    static constexpr int sHardTimeout = 86400;
    static constexpr int sScanWaitTime = 30;

    OsConfigLogHandle mLog;
    std::string mStatePath;
    Telemetry mTelemetry;
    FilesystemScanner mFsScanner;
};
} // namespace ComplianceEngine
#endif // COMPLIANCEENGINE_COMMONCONTEXT_H
