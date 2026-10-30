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
    // Native seam pass-throughs for fault-injection lambdas. These take only
    // native syscall arguments; they do not extract from a typed owner.
    int RealOpenNativePath(const char* path, int flags) const
    {
        return ContextInterface::OpenNativePath(path, flags);
    }
    int RealOpenNativeAt(int directory, const char* path, int flags) const
    {
        return ContextInterface::OpenNativeAt(directory, path, flags);
    }
    int RealStatFileDescriptor(int fd, struct stat* metadata) const
    {
        return ContextInterface::StatFileDescriptor(fd, metadata);
    }
    ssize_t RealReadFileDescriptor(int fd, void* buffer, std::size_t size) const
    {
        return ContextInterface::ReadFileDescriptor(fd, buffer, size);
    }
    int RealCloseFileDescriptor(int fd) const
    {
        return ContextInterface::CloseFileDescriptor(fd);
    }
    int RealDuplicateDescriptor(int fd) const
    {
        return ContextInterface::DuplicateDescriptor(fd);
    }
    pid_t RealNativeProcessId() const
    {
        return ContextInterface::NativeProcessId();
    }
    pid_t RealNativeThreadId() const
    {
        return ContextInterface::NativeThreadId();
    }
    MOCK_METHOD(ComplianceEngine::Result<std::string>, ExecuteCommand, (const std::string& cmd), (const, override));
    MOCK_METHOD(ComplianceEngine::Result<std::string>, GetFileContents, (const std::string& filePath), (const, override));
    MOCK_METHOD(int, OpenNativePath, (const char* path, int flags), (const, override));
    MOCK_METHOD(int, OpenNativeAt, (int directory, const char* path, int flags), (const, override));
    MOCK_METHOD(int, StatFileDescriptor, (int descriptor, struct stat* metadata), (const, override));
    MOCK_METHOD(int, StatFilesystemDescriptor, (int descriptor, struct statfs* metadata), (const, override));
    MOCK_METHOD(ssize_t, ReadFileDescriptor, (int descriptor, void* buffer, std::size_t size), (const, override));
    MOCK_METHOD(ssize_t, ReadLinkDescriptor, (int descriptor, char* buffer, std::size_t size), (const, override));
    MOCK_METHOD(int, StatusFlagsDescriptor, (int descriptor), (const, override));
    MOCK_METHOD(int, DescriptorFlagsDescriptor, (int descriptor), (const, override));
    MOCK_METHOD(int, DuplicateDescriptor, (int descriptor), (const, override));
    MOCK_METHOD(DIR*, FdOpenDirectory, (int descriptor), (const, override));
    MOCK_METHOD(int, CloseFileDescriptor, (int descriptor), (const, override));
    MOCK_METHOD(int, ChownPinnedFileDescriptor, (int descriptor, uid_t owner, gid_t group), (const, override));
    MOCK_METHOD(int, ChmodPinnedAlias, (int procfsDirectory, const char* decimalAlias, mode_t mode), (const, override));
    MOCK_METHOD(pid_t, NativeProcessId, (), (const, override));
    MOCK_METHOD(pid_t, NativeThreadId, (), (const, override));
    MOCK_METHOD(DIR*, OpenDirectory, (const char* path), (const, override));
    MOCK_METHOD(struct dirent*, ReadDirectory, (DIR * directory), (const, override));
    MOCK_METHOD(int, CloseDirectory, (DIR * directory), (const, override));
    MOCK_METHOD(int, StatPath, (const char* path, struct stat* metadata), (const, override));
    MOCK_METHOD(int, LstatPath, (const char* path, struct stat* metadata), (const, override));
    MOCK_METHOD(struct group*, GetGroupById, (gid_t id), (const, override));
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
        ON_CALL(*this, NativeProcessId()).WillByDefault([this] { return ContextInterface::NativeProcessId(); });
        ON_CALL(*this, NativeThreadId()).WillByDefault([this] { return ContextInterface::NativeThreadId(); });
        ON_CALL(*this, OpenNativePath(testing::_, testing::_)).WillByDefault([this](const char* path, int flags) {
            return ContextInterface::OpenNativePath(path, flags);
        });
        ON_CALL(*this, OpenNativeAt(testing::_, testing::_, testing::_)).WillByDefault([this](int directory, const char* path, int flags) {
            return ContextInterface::OpenNativeAt(directory, path, flags);
        });
        ON_CALL(*this, StatFileDescriptor(testing::_, testing::_)).WillByDefault([this](int descriptor, struct stat* metadata) {
            return ContextInterface::StatFileDescriptor(descriptor, metadata);
        });
        ON_CALL(*this, StatFilesystemDescriptor(testing::_, testing::_)).WillByDefault([this](int descriptor, struct statfs* metadata) {
            return ContextInterface::StatFilesystemDescriptor(descriptor, metadata);
        });
        ON_CALL(*this, ReadLinkDescriptor(testing::_, testing::_, testing::_)).WillByDefault([this](int descriptor, char* buffer, std::size_t size) {
            return ContextInterface::ReadLinkDescriptor(descriptor, buffer, size);
        });
        ON_CALL(*this, StatusFlagsDescriptor(testing::_)).WillByDefault([this](int descriptor) {
            return ContextInterface::StatusFlagsDescriptor(descriptor);
        });
        ON_CALL(*this, DescriptorFlagsDescriptor(testing::_)).WillByDefault([this](int descriptor) {
            return ContextInterface::DescriptorFlagsDescriptor(descriptor);
        });
        ON_CALL(*this, DuplicateDescriptor(testing::_)).WillByDefault([this](int descriptor) {
            return ContextInterface::DuplicateDescriptor(descriptor);
        });
        ON_CALL(*this, FdOpenDirectory(testing::_)).WillByDefault([this](int descriptor) { return ContextInterface::FdOpenDirectory(descriptor); });
        ON_CALL(*this, ReadFileDescriptor(testing::_, testing::_, testing::_)).WillByDefault([this](int descriptor, void* buffer, std::size_t size) {
            return ContextInterface::ReadFileDescriptor(descriptor, buffer, size);
        });
        ON_CALL(*this, CloseFileDescriptor(testing::_)).WillByDefault([this](int descriptor) {
            return ContextInterface::CloseFileDescriptor(descriptor);
        });
        ON_CALL(*this, ChownPinnedFileDescriptor(testing::_, testing::_, testing::_)).WillByDefault([this](int descriptor, uid_t owner, gid_t group) {
            return ContextInterface::ChownPinnedFileDescriptor(descriptor, owner, group);
        });
        ON_CALL(*this, ChmodPinnedAlias(testing::_, testing::_, testing::_)).WillByDefault([this](int procfsDirectory, const char* decimalAlias, mode_t mode) {
            return ContextInterface::ChmodPinnedAlias(procfsDirectory, decimalAlias, mode);
        });
        ON_CALL(*this, OpenDirectory(testing::_)).WillByDefault([this](const char* path) { return ContextInterface::OpenDirectory(path); });
        ON_CALL(*this, ReadDirectory(testing::_)).WillByDefault([this](DIR* directory) { return ContextInterface::ReadDirectory(directory); });
        ON_CALL(*this, CloseDirectory(testing::_)).WillByDefault([this](DIR* directory) { return ContextInterface::CloseDirectory(directory); });
        ON_CALL(*this, StatPath(testing::_, testing::_)).WillByDefault([this](const char* path, struct stat* metadata) {
            return ContextInterface::StatPath(path, metadata);
        });
        ON_CALL(*this, LstatPath(testing::_, testing::_)).WillByDefault([this](const char* path, struct stat* metadata) {
            return ContextInterface::LstatPath(path, metadata);
        });
        ON_CALL(*this, GetGroupById(testing::_)).WillByDefault([this](gid_t id) { return ContextInterface::GetGroupById(id); });
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
    static ComplianceEngine::TemporaryDirectory CreateTempdir()
    {
        auto result = ComplianceEngine::TemporaryDirectory::Make("ComplianceEngineTest");
        if (!result.HasValue())
        {
            throw std::runtime_error(result.Error().message);
        }
        return std::move(result).Value();
    }

    ComplianceEngine::TemporaryDirectory mTempOwner;
    std::string mTempdir;
    std::string mTempRootDir;
    std::size_t mTempfileCount{0};
    std::map<std::string, std::string> mSpecialFilesMap;
    std::unique_ptr<ComplianceEngine::FilesystemScanner> mFsScannerp;
    ComplianceEngine::Result<std::string> mRunningKernelRelease{std::string("5.15.test")};
    OsConfigLogHandle mLogHandle{nullptr};
    ComplianceEngine::Telemetry mTelemetry{-1};
};
