// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ContextInterface.h"
#include "TemporaryDirectory.h"

#include <cerrno>
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

// Convert a real native close into the typed, code-only mock seam.
inline ComplianceEngine::Result<void> NativeCloseResult(int status) noexcept
{
    if (status != 0)
    {
        const int saved = errno ? errno : EIO;
        return ComplianceEngine::Error(saved);
    }
    return ComplianceEngine::Result<void>::Success();
}

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
    // Needed by the readlink buffer-size tests, which must assert the size
    // Path requests while still performing the real read.
    ssize_t RealReadLinkDescriptor(int fd, char* buffer, std::size_t size) const
    {
        return ContextInterface::ReadLinkDescriptor(fd, buffer, size);
    }
    ComplianceEngine::Result<void> RealCloseFileDescriptor(int fd) const
    {
        return ContextInterface::CloseFileDescriptor(fd);
    }
    int RealDuplicateDescriptor(int fd) const
    {
        return ContextInterface::DuplicateDescriptor(fd);
    }
    int RealChownPinnedFileDescriptor(int descriptor, uid_t owner, gid_t group) const
    {
        return ContextInterface::ChownPinnedFileDescriptor(descriptor, owner, group);
    }
    int RealChmodPinnedAlias(int procfsDirectory, const char* decimalAlias, mode_t mode) const
    {
        return ContextInterface::ChmodPinnedAlias(procfsDirectory, decimalAlias, mode);
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
    MOCK_METHOD(int, OpenNativePath, (const char* path, int flags), (const, noexcept, override));
    MOCK_METHOD(int, OpenNativeAt, (int directory, const char* path, int flags), (const, noexcept, override));
    MOCK_METHOD(int, StatFileDescriptor, (int descriptor, struct stat* metadata), (const, noexcept, override));
    MOCK_METHOD(int, StatFilesystemDescriptor, (int descriptor, struct statfs* metadata), (const, noexcept, override));
    MOCK_METHOD(ssize_t, ReadFileDescriptor, (int descriptor, void* buffer, std::size_t size), (const, noexcept, override));
    MOCK_METHOD(ssize_t, ReadLinkDescriptor, (int descriptor, char* buffer, std::size_t size), (const, noexcept, override));
    MOCK_METHOD(int, StatusFlagsDescriptor, (int descriptor), (const, noexcept, override));
    MOCK_METHOD(int, DescriptorFlagsDescriptor, (int descriptor), (const, noexcept, override));
    MOCK_METHOD(int, DuplicateDescriptor, (int descriptor), (const, noexcept, override));
    MOCK_METHOD(DIR*, FdOpenDirectory, (int descriptor), (const, noexcept, override));
    MOCK_METHOD(ComplianceEngine::Result<void>, CloseFileDescriptor, (int descriptor), (const, noexcept, override));
    MOCK_METHOD(int, ChownPinnedFileDescriptor, (int descriptor, uid_t owner, gid_t group), (const, noexcept, override));
    MOCK_METHOD(int, ChmodPinnedAlias, (int procfsDirectory, const char* decimalAlias, mode_t mode), (const, noexcept, override));
    MOCK_METHOD(pid_t, NativeProcessId, (), (const, noexcept, override));
    MOCK_METHOD(pid_t, NativeThreadId, (), (const, noexcept, override));
    MOCK_METHOD(DIR*, OpenDirectory, (const char* path), (const, noexcept, override));
    MOCK_METHOD(struct dirent*, ReadDirectory, (DIR * directory), (const, noexcept, override));
    MOCK_METHOD(ComplianceEngine::Result<void>, CloseDirectory, (DIR * directory), (const, noexcept, override));
    MOCK_METHOD(int, StatPath, (const char* path, struct stat* metadata), (const, noexcept, override));
    MOCK_METHOD(int, LstatPath, (const char* path, struct stat* metadata), (const, noexcept, override));
    MOCK_METHOD(struct group*, GetGroupById, (gid_t id), (const, noexcept, override));
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

    OsConfigLogHandle GetLogHandle() const noexcept override
    {
        return mLogHandle;
    }

    void SetLogHandle(OsConfigLogHandle logHandle)
    {
        mLogHandle = logHandle;
    }

    // Test-only context limit. Lowering below currently owned pins blocks
    // further acquisition until enough owners are closed; existing owners
    // retain their charges. Values above 256 cannot raise production capacity.
    void SetManagedDescriptorAllowanceForTesting(std::size_t limit) noexcept
    {
        mTestDescriptorAllowance = limit;
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

    // --- Incidental-native-call helpers -------------------------------------
    //
    // gMock warns "Uninteresting mock function call" for any mocked call that
    // isn't covered by an EXPECT_CALL, even when ON_CALL supplies its default
    // action (see testing/MockContext.h ON_CALL block above). Most native
    // seams below are plumbing a test doesn't care about -- declare them
    // explicitly as allowed with `Times(AnyNumber())` so a real fixture can
    // run under `testing::StrictMock<MockContext>`. Call the helper(s) this
    // fixture needs from SetUp() (or at the top of an individual test),
    // before any test-specific EXPECT_CALL on the same seam: gMock matches
    // the newest expectation first, so a later, more specific EXPECT_CALL
    // still takes priority over these catch-alls. Do not call the helper for
    // a group whose seam a particular test already constrains with its own
    // EXPECT_CALL (exact count, Times(0), or an InSequence step) -- that
    // would silently convert an argument-mismatched "unexpected call"
    // failure into a pass. Group by what the call represents, not just by
    // mocked signature, so a caller can allow identity/bootstrap noise while
    // still holding e.g. close-once behavior to an exact expectation.
    //
    // ChownPinnedFileDescriptor/ChmodPinnedAlias deliberately have no allow-
    // helper here: they perform the ownership/mode mutation that remediation
    // tests exist to verify (count, uid/gid/mode, and -- via fstat/fstatat
    // on the call arguments -- the exact target file). A fixture that
    // reaches these seams must declare its own EXPECT_CALL (exact count or
    // Times(0)) rather than get a catch-all that would hide an
    // argument-mismatched or mistargeted mutation. Use RealChownPinnedFileDescriptor/
    // RealChmodPinnedAlias (declared at the top of this struct with the
    // other Real* pass-throughs) to delegate a verified call to the real
    // syscall from inside that EXPECT_CALL's side effect.

    // getpid()/gettid() calls used only to resolve the verified /proc/self
    // procfs pin; never the property under test.
    void AllowProcfsBootstrap()
    {
        EXPECT_CALL(*this, NativeProcessId()).Times(testing::AnyNumber());
        EXPECT_CALL(*this, NativeThreadId()).Times(testing::AnyNumber());
    }

    // open()/openat() calls that acquire a root pin or a child descriptor;
    // incidental setup for tests that aren't checking open() arguments or
    // open-call counts themselves.
    void AllowNativeOpen()
    {
        EXPECT_CALL(*this, OpenNativePath(testing::_, testing::_)).Times(testing::AnyNumber());
        EXPECT_CALL(*this, OpenNativeAt(testing::_, testing::_, testing::_)).Times(testing::AnyNumber());
    }

    // fstat()/fstatfs()/fcntl(F_GETFL|F_GETFD)/readlinkat() calls that
    // inspect an already-open descriptor (type, filesystem, flags, link
    // target); incidental unless the test is exercising that inspection.
    void AllowDescriptorInspection()
    {
        EXPECT_CALL(*this, StatFileDescriptor(testing::_, testing::_)).Times(testing::AnyNumber());
        EXPECT_CALL(*this, StatFilesystemDescriptor(testing::_, testing::_)).Times(testing::AnyNumber());
        EXPECT_CALL(*this, StatusFlagsDescriptor(testing::_)).Times(testing::AnyNumber());
        EXPECT_CALL(*this, DescriptorFlagsDescriptor(testing::_)).Times(testing::AnyNumber());
        EXPECT_CALL(*this, ReadLinkDescriptor(testing::_, testing::_, testing::_)).Times(testing::AnyNumber());
    }

    // read() calls against an already-open descriptor; incidental unless the
    // test is exercising read content/retry/short-read behavior itself.
    void AllowFileRead()
    {
        EXPECT_CALL(*this, ReadFileDescriptor(testing::_, testing::_, testing::_)).Times(testing::AnyNumber());
    }

    // close() calls on a file descriptor; incidental RAII cleanup unless the
    // test is specifically exercising close-once/no-retry/close-failure
    // behavior, which should keep its own exact expectation instead.
    void AllowDescriptorClose()
    {
        EXPECT_CALL(*this, CloseFileDescriptor(testing::_)).Times(testing::AnyNumber());
    }

    // fdopendir()/readdir()/closedir() calls; incidental unless the test is
    // exercising directory enumeration order, pagination, or cursor-close
    // behavior itself.
    void AllowDirectoryEnumeration()
    {
        EXPECT_CALL(*this, FdOpenDirectory(testing::_)).Times(testing::AnyNumber());
        EXPECT_CALL(*this, ReadDirectory(testing::_)).Times(testing::AnyNumber());
        EXPECT_CALL(*this, CloseDirectory(testing::_)).Times(testing::AnyNumber());
    }

    // getgrgid() calls; incidental unless the test is exercising group-name
    // resolution itself.
    void AllowIdentityLookup()
    {
        EXPECT_CALL(*this, GetGroupById(testing::_)).Times(testing::AnyNumber());
    }

    // Convenience: every group above. Only use this when a fixture/test has
    // no specific EXPECT_CALL on any of these seams; otherwise call the
    // narrower per-seam-group helpers and skip the group(s) that overlap a
    // specific expectation (see the per-seam helpers' comments above).
    void AllowIncidentalNativeAccess()
    {
        AllowProcfsBootstrap();
        AllowNativeOpen();
        AllowDescriptorInspection();
        AllowFileRead();
        AllowDescriptorClose();
        AllowDirectoryEnumeration();
        AllowIdentityLookup();
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

protected:
    std::size_t ManagedDescriptorAllowance() const noexcept override
    {
        return mTestDescriptorAllowance;
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
    std::size_t mTestDescriptorAllowance = 256;
    std::map<std::string, std::string> mSpecialFilesMap;
    std::unique_ptr<ComplianceEngine::FilesystemScanner> mFsScannerp;
    ComplianceEngine::Result<std::string> mRunningKernelRelease{std::string("5.15.test")};
    OsConfigLogHandle mLogHandle{nullptr};
    ComplianceEngine::Telemetry mTelemetry{-1};
};
