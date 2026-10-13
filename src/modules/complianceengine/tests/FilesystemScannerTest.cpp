// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "FilesystemScanner.h"

#include "MockContext.h"
#include "ScopeGuard.h"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <gtest/gtest.h>
#include <iterator>
#include <string>
#include <sys/file.h>
#include <sys/inotify.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

using ComplianceEngine::Error;
using ComplianceEngine::FilesystemScanner;
using ComplianceEngine::Result;

namespace
{
void TouchFile(const std::string& path)
{
    std::ofstream ofs(path.c_str());
    ofs << "data";
    ofs.close();
}

pid_t WaitForScannerPid(const std::string& path, pid_t previousPid = -1)
{
    for (int attempt = 0; attempt < 300; ++attempt)
    {
        std::ifstream lockFile(path.c_str());
        pid_t scannerPid = -1;
        if ((lockFile >> scannerPid) && (scannerPid > 0) && (scannerPid != previousPid))
        {
            return scannerPid;
        }
        ::usleep(10 * 1000);
    }
    return -1;
}
} // namespace

class FilesystemScannerTest : public ::testing::Test
{
protected:
    std::string rootDir;
    std::string cachePath;
    std::string lockPath;
    MockContext mContext;

    void SetUp() override
    {
        rootDir = mContext.GetTempdirPath() + "/filesystem-scanner";
        ASSERT_EQ(0, ::mkdir(rootDir.c_str(), 0700));
        // create some files
        ::mkdir((rootDir + "/sub").c_str(), 0755);
        TouchFile(rootDir + "/a.txt");
        TouchFile(rootDir + "/sub/b.txt");
        cachePath = rootDir + "/cache.txt"; // place cache within temp dir
        lockPath = rootDir + "/lock.lck";
    }
};

TEST_F(FilesystemScannerTest, InitialCacheBuildWaitsAndSucceeds)
{
    // soft=5, hard=10, wait=3 seconds (ample time for small scan)
    FilesystemScanner scanner(rootDir, cachePath, lockPath, 5, 10, 3);
    auto res = scanner.GetFullFilesystem();
    // First call may return either value (if background finished within wait) or error
    if (!res)
    {
        // If error due to background not done yet, call again after short sleep
        ::usleep(400 * 1000); // 400ms
        res = scanner.GetFullFilesystem();
    }
    ASSERT_TRUE(res) << "Cache should be available after wait window: " << (res ? "" : res.Error().message);
    ASSERT_GT(res.Value()->entries.size(), 0u);
}

TEST_F(FilesystemScannerTest, RecordsExactTreeMetadataWithoutFollowingInteriorSymlink)
{
    const std::string targetDir = rootDir + "/target";
    const std::string targetFile = targetDir + "/target.txt";
    const std::string linkPath = rootDir + "/target-link";
    ASSERT_EQ(0, ::mkdir(targetDir.c_str(), 0700));
    TouchFile(targetFile);
    ASSERT_EQ(0, ::symlink(targetDir.c_str(), linkPath.c_str()));

    const std::string externalCache = mContext.GetTempdirPath() + "/exact-tree-cache";
    const std::string externalLock = mContext.GetTempdirPath() + "/exact-tree-lock";
    FilesystemScanner scanner(rootDir, externalCache, externalLock, 60, 120, 10);
    auto result = scanner.GetFullFilesystem();

    ASSERT_TRUE(result.HasValue()) << (result.HasValue() ? "" : result.Error().message);
    std::vector<std::string> paths;
    for (const auto& entry : result.Value()->entries)
    {
        paths.push_back(entry.first);
    }
    const std::vector<std::string> expected = {
        rootDir + "/a.txt",
        rootDir + "/sub",
        rootDir + "/sub/b.txt",
        targetDir,
        linkPath,
        targetFile,
    };
    EXPECT_EQ(expected, paths);

    EXPECT_TRUE(S_ISREG(result.Value()->entries.at(rootDir + "/a.txt").st.st_mode));
    EXPECT_TRUE(S_ISDIR(result.Value()->entries.at(rootDir + "/sub").st.st_mode));
    EXPECT_TRUE(S_ISREG(result.Value()->entries.at(rootDir + "/sub/b.txt").st.st_mode));
    EXPECT_TRUE(S_ISLNK(result.Value()->entries.at(linkPath).st.st_mode));
}

TEST_F(FilesystemScannerTest, BackgroundScanLeavesNoChild)
{
    {
        FilesystemScanner scanner(rootDir, cachePath, lockPath, 5, 10, 3);
        auto res = scanner.GetFullFilesystem();
        ASSERT_TRUE(res);
    }

    ::usleep(100 * 1000);
    EXPECT_EQ(::waitpid(-1, nullptr, WNOHANG), -1);
    EXPECT_EQ(errno, ECHILD);
}

TEST_F(FilesystemScannerTest, BackgroundScanOutlivesLaunchingProcess)
{
    pid_t launcherPid = ::fork();
    ASSERT_GE(launcherPid, 0);
    if (launcherPid == 0)
    {
        FilesystemScanner scanner(rootDir, cachePath, lockPath, 5, 10, 0);
        (void)scanner.GetFullFilesystem();
        _exit(0);
    }

    int launcherStatus = 0;
    ASSERT_EQ(::waitpid(launcherPid, &launcherStatus, 0), launcherPid);
    ASSERT_TRUE(WIFEXITED(launcherStatus));
    ASSERT_EQ(WEXITSTATUS(launcherStatus), 0);

    for (int attempt = 0; (attempt < 30) && (::access(cachePath.c_str(), F_OK) != 0); ++attempt)
    {
        ::usleep(100 * 1000);
    }
    EXPECT_EQ(::access(cachePath.c_str(), F_OK), 0);
}

TEST_F(FilesystemScannerTest, KilledBackgroundScanIsReplaced)
{
    const std::string externalCache = mContext.GetTempdirPath() + "/killed-scan-cache";
    const std::string externalLock = mContext.GetTempdirPath() + "/killed-scan-lock";
    const std::string temporaryCache = externalCache + ".tmp";
    // Hold the first worker after its successful walk, while it still owns the lock.
    ASSERT_EQ(::mkfifo(temporaryCache.c_str(), 0600), 0);
    pid_t activeWorker = -1;
    int lockFd = -1;
    ScopeGuard cleanup([&] {
        if (activeWorker > 0)
        {
            ::kill(activeWorker, SIGKILL);
        }
        // Unblock a worker whose PID was not observed before an assertion failed.
        const int reader = ::open(temporaryCache.c_str(), O_RDONLY | O_NONBLOCK);
        const auto waitUntilReleased = [&]() {
            for (int attempt = 0; attempt < 300; ++attempt)
            {
                const int probe = ::open(externalLock.c_str(), O_RDONLY);
                if (probe >= 0)
                {
                    const bool released = (::flock(probe, LOCK_EX | LOCK_NB) == 0);
                    if (released)
                    {
                        ::flock(probe, LOCK_UN);
                    }
                    ::close(probe);
                    if (released)
                    {
                        return true;
                    }
                }
                ::usleep(10 * 1000);
            }
            return false;
        };
        const bool released = waitUntilReleased();
        if (!released)
        {
            ADD_FAILURE() << "Scanner lock remained held during FIFO cleanup";
        }
        if (reader >= 0 && released)
        {
            ::close(reader);
        }
        if (lockFd >= 0)
        {
            ::close(lockFd);
        }
        if (released)
        {
            ::unlink(temporaryCache.c_str());
        }
    });
    FilesystemScanner scanner(rootDir, externalCache, externalLock, 5, 10, 0);
    ASSERT_FALSE(scanner.GetFullFilesystem());

    pid_t firstScannerPid = WaitForScannerPid(externalLock);
    ASSERT_GT(firstScannerPid, 0);
    activeWorker = firstScannerPid;
    ASSERT_EQ(::kill(firstScannerPid, SIGKILL), 0);
    activeWorker = -1;

    lockFd = ::open(externalLock.c_str(), O_RDONLY);
    ASSERT_GE(lockFd, 0);
    const auto waitForLockRelease = [&]() {
        for (int attempt = 0; attempt < 300; ++attempt)
        {
            if (::flock(lockFd, LOCK_EX | LOCK_NB) == 0)
            {
                ::flock(lockFd, LOCK_UN);
                return true;
            }
            ::usleep(10 * 1000);
        }
        return false;
    };
    ASSERT_TRUE(waitForLockRelease());

    ASSERT_FALSE(scanner.GetFullFilesystem());
    pid_t replacementScannerPid = WaitForScannerPid(externalLock, firstScannerPid);
    ASSERT_GT(replacementScannerPid, 0);
    activeWorker = replacementScannerPid;
    EXPECT_NE(replacementScannerPid, firstScannerPid);
    EXPECT_EQ(::kill(replacementScannerPid, 0), 0);
    ASSERT_EQ(::kill(replacementScannerPid, SIGKILL), 0);
    activeWorker = -1;
    ASSERT_TRUE(waitForLockRelease());
    ASSERT_EQ(::close(lockFd), 0);
    lockFd = -1;
    ASSERT_EQ(::unlink(temporaryCache.c_str()), 0);
    cleanup.Dismiss();

    FilesystemScanner waitingScanner(rootDir, externalCache, externalLock, 5, 10, 3);
    auto result = waitingScanner.GetFullFilesystem();
    ASSERT_TRUE(result.HasValue()) << (result.HasValue() ? "" : result.Error().message);
    EXPECT_NE(result.Value()->entries.find(rootDir + "/a.txt"), result.Value()->entries.end());
}

TEST_F(FilesystemScannerTest, SoftTimeoutTriggersBackgroundButReturnsData)
{
    FilesystemScanner scanner(rootDir, cachePath, lockPath, 1, 100, 0); // short soft timeout
    // Build cache
    auto res = scanner.GetFullFilesystem();
    if (!res)
    {
        ::usleep(300 * 1000);
        res = scanner.GetFullFilesystem();
    }
    ASSERT_TRUE(res);
    auto firstEnd = res.Value()->scan_end_time;
    ASSERT_GT(firstEnd, 0);
    // Wait past soft timeout but before hard
    ::sleep(2);
    auto res2 = scanner.GetFullFilesystem();
    ASSERT_TRUE(res2);                                // soft timeout returns stale data
    EXPECT_EQ(res2.Value()->scan_end_time, firstEnd); // cache unchanged yet
}

TEST_F(FilesystemScannerTest, HardTimeoutCausesErrorUntilRefreshFinishes)
{
    FilesystemScanner scanner(rootDir, cachePath, lockPath, 1, 2, 0); // soft=1, hard=2
    auto res = scanner.GetFullFilesystem();
    if (!res)
    {
        ::usleep(500 * 1000);
        res = scanner.GetFullFilesystem();
    }
    ASSERT_TRUE(res);
    ::sleep(3); // exceed hard timeout
    auto res2 = scanner.GetFullFilesystem();
    ASSERT_FALSE(res2); // should be error due to hard timeout and no wait
    // Give background scan time to complete
    ::usleep(400 * 1000);
    auto res3 = scanner.GetFullFilesystem();
    ASSERT_TRUE(res3); // new cache available
    EXPECT_NE(res3.Value()->scan_end_time, res.Value()->scan_end_time);
}

TEST_F(FilesystemScannerTest, HardTimeoutWithWaitMayReturnFreshCache)
{
    FilesystemScanner scanner(rootDir, cachePath, lockPath, 1, 2, 2); // wait up to 2s
    auto res = scanner.GetFullFilesystem();
    if (!res)
    {
        ::usleep(400 * 1000);
        res = scanner.GetFullFilesystem();
    }
    ASSERT_TRUE(res);
    auto oldEnd = res.Value()->scan_end_time;
    ::sleep(3); // exceed hard timeout
    auto res2 = scanner.GetFullFilesystem();
    if (!res2)
    {
        // wait path failed to obtain new cache in time
        ::usleep(800 * 1000);
        res2 = scanner.GetFullFilesystem();
    }
    ASSERT_TRUE(res2);
    EXPECT_NE(oldEnd, res2.Value()->scan_end_time);
}

TEST_F(FilesystemScannerTest, LoadCacheSkipsOverHardTimeout)
{
    // Keep the initial cache comfortably below the soft timeout. With a
    // short timeout, whole-second timestamps can make a fresh cache look
    // soft-expired and start a refresh that races with the stale-header write.
    FilesystemScanner scanner(rootDir, cachePath, lockPath, 3600, 7200, 0);
    // Build initial cache
    auto res = scanner.GetFullFilesystem();
    if (!res)
    {
        ::usleep(300 * 1000);
        res = scanner.GetFullFilesystem();
    }
    ASSERT_TRUE(res);
    std::ifstream cache(cachePath.c_str());
    ASSERT_TRUE(cache.is_open());
    std::string originalHeader;
    std::string originalEntry;
    ASSERT_TRUE(static_cast<bool>(std::getline(cache, originalHeader)));
    ASSERT_TRUE(static_cast<bool>(std::getline(cache, originalEntry)));
    cache.close();

    // Manually modify header to simulate old cache beyond hard timeout
    {
        std::ofstream ofs(cachePath.c_str(), std::ios::out | std::ios::trunc);
        long oldStart = (long)::time(nullptr) - 10000;
        long oldEnd = oldStart - 1; // ensure earlier
        ofs << "# FilesystemScanCache-V1 " << oldStart << ' ' << oldEnd << "\n";
        ofs << originalEntry << "\n";
        ASSERT_TRUE(ofs.good());
        ofs.close();
    }
    // Second scanner to test LoadCache rejection
    FilesystemScanner scanner2(rootDir, cachePath, lockPath, 3600, 7200, 0);
    auto res2 = scanner2.GetFullFilesystem();
    ASSERT_FALSE(res2);
    EXPECT_EQ(res2.Error().message, "filesystem cache unavailable; background scan started");
}

TEST_F(FilesystemScannerTest, LegacyCacheFormatStillLoads)
{
    // Manually create a legacy-format cache file (same format as current) with a couple entries
    // This ensures that changes to internal storage (vector -> map) did not alter on-disk parsing assumptions.
    FilesystemScanner scanner(rootDir, cachePath, lockPath, 5, 10, 1);
    // Craft cache file with start/end times that are fresh
    time_t now = ::time(nullptr);
    {
        std::ofstream ofs(cachePath.c_str(), std::ios::out | std::ios::trunc);
        ofs << "# FilesystemScanCache-V1 " << static_cast<long>(now - 1) << ' ' << static_cast<long>(now - 1) << "\n";
        // Two fake entries rooted at test root; use current stat info from rootDir
        struct stat stRoot;
        ASSERT_EQ(::lstat(rootDir.c_str(), &stRoot), 0);
        ofs << rootDir << ' ' << static_cast<unsigned long long>(stRoot.st_dev) << ' ' << static_cast<unsigned long long>(stRoot.st_ino) << ' '
            << static_cast<unsigned>(stRoot.st_mode) << ' ' << static_cast<unsigned>(stRoot.st_nlink) << ' ' << static_cast<long long>(stRoot.st_uid)
            << ' ' << static_cast<long>(stRoot.st_gid) << ' ' << static_cast<long long>(stRoot.st_size) << ' ' << static_cast<long>(stRoot.st_blksize)
            << ' ' << static_cast<long long>(stRoot.st_blocks) << "\n";
        // Add a dummy child path entry referencing same stats (acceptable for test purpose)
        ofs << rootDir << "/dummy" << ' ' << static_cast<unsigned long long>(stRoot.st_dev) << ' ' << static_cast<unsigned long long>(stRoot.st_ino)
            << ' ' << static_cast<unsigned>(stRoot.st_mode) << ' ' << static_cast<unsigned>(stRoot.st_nlink) << ' '
            << static_cast<long long>(stRoot.st_uid) << ' ' << static_cast<long>(stRoot.st_gid) << ' ' << static_cast<long long>(stRoot.st_size) << ' '
            << static_cast<long>(stRoot.st_blksize) << ' ' << static_cast<long long>(stRoot.st_blocks) << "\n";
    }
    auto res = scanner.GetFullFilesystem();
    if (!res)
    {
        // Allow background wait window
        ::usleep(300 * 1000);
        res = scanner.GetFullFilesystem();
    }
    ASSERT_TRUE(res);
    // Expect at least the two synthetic entries to be recognized.
    size_t found = 0;
    for (const auto& kv : res.Value()->entries)
    {
        if (kv.first == rootDir || kv.first == rootDir + "/dummy")
        {
            ++found;
        }
    }
    EXPECT_EQ(found, (size_t)2);
}

TEST_F(FilesystemScannerTest, MalformedCacheRowsAreNotLoadedAsEntries)
{
    const time_t now = ::time(nullptr);
    struct stat rootStatus;
    ASSERT_EQ(0, ::lstat(rootDir.c_str(), &rootStatus));
    {
        std::ofstream cache(cachePath.c_str(), std::ios::out | std::ios::trunc);
        cache << "# FilesystemScanCache-V1 " << static_cast<long>(now - 1) << ' ' << static_cast<long>(now - 1) << "\n";
        cache << rootDir + "/valid" << ' ' << static_cast<unsigned long long>(rootStatus.st_dev) << ' ' << static_cast<unsigned long long>(rootStatus.st_ino)
              << ' ' << static_cast<unsigned>(rootStatus.st_mode) << ' ' << static_cast<unsigned>(rootStatus.st_nlink) << ' '
              << static_cast<long long>(rootStatus.st_uid) << ' ' << static_cast<long>(rootStatus.st_gid) << ' ' << static_cast<long long>(rootStatus.st_size)
              << ' ' << static_cast<long>(rootStatus.st_blksize) << ' ' << static_cast<long long>(rootStatus.st_blocks) << "\n";
        cache << rootDir + "/malformed"
              << " missing fields\n";
    }

    FilesystemScanner scanner(rootDir, cachePath, lockPath, 60, 120, 1);
    const auto result = scanner.GetFullFilesystem();

    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(1u, result.Value()->entries.size());
    EXPECT_EQ(rootDir + "/valid", result.Value()->entries.begin()->first);
}

TEST_F(FilesystemScannerTest, PartialScanDoesNotReplaceExistingCache)
{
    const std::string filePath = rootDir + "/a.txt";
    ASSERT_EQ(0, ::mkdir((rootDir + "/sub/next").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((rootDir + "/sub/next/last").c_str(), 0700));
    const int notificationFd = ::inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    ASSERT_GE(notificationFd, 0);
    ScopeGuard closeNotification([&] { ::close(notificationFd); });
    ASSERT_GE(::inotify_add_watch(notificationFd, (rootDir + "/sub/next").c_str(), IN_OPEN), 0);
    struct stat metadata;
    ASSERT_EQ(0, ::lstat(filePath.c_str(), &metadata));
    const time_t cacheTime = ::time(nullptr) + 1;
    const std::string header = "# FilesystemScanCache-V1 " + std::to_string(static_cast<long>(cacheTime)) + " " + std::to_string(static_cast<long>(cacheTime));
    const std::string entry = filePath + " " + std::to_string(static_cast<unsigned long long>(metadata.st_dev)) + " " +
                              std::to_string(static_cast<unsigned long long>(metadata.st_ino)) + " " +
                              std::to_string(static_cast<unsigned>(metadata.st_mode)) + " " + std::to_string(static_cast<unsigned>(metadata.st_nlink)) +
                              " " + std::to_string(static_cast<long long>(metadata.st_uid)) + " " + std::to_string(static_cast<long>(metadata.st_gid)) +
                              " " + std::to_string(static_cast<long long>(metadata.st_size)) + " " +
                              std::to_string(static_cast<long>(metadata.st_blksize)) + " " + std::to_string(static_cast<long long>(metadata.st_blocks));
    {
        std::ofstream cache(cachePath.c_str());
        cache << header << '\n' << entry << '\n';
        ASSERT_TRUE(cache.good());
    }
    std::ifstream originalCache(cachePath.c_str(), std::ios::binary);
    ASSERT_TRUE(originalCache.is_open());
    const std::string original((std::istreambuf_iterator<char>(originalCache)), std::istreambuf_iterator<char>());

    FilesystemScanner scanner(rootDir, cachePath, lockPath, 2, 3600, 0);
    auto result = scanner.GetFullFilesystem();
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value()->entries.size(), 1u);

    ::sleep(4);
    struct rlimit originalLimit;
    ASSERT_EQ(0, ::getrlimit(RLIMIT_NOFILE, &originalLimit));
    ASSERT_GE(originalLimit.rlim_cur, 4u);
    struct rlimit limited = originalLimit;
    // The scan child closes inherited descriptors: its lock and three directory opens exhaust this limit.
    limited.rlim_cur = 4;
    {
        struct RestoreLimit
        {
            const struct rlimit& original;
            ~RestoreLimit()
            {
                ::setrlimit(RLIMIT_NOFILE, &original);
            }
        } restore{originalLimit};
        ASSERT_EQ(0, ::setrlimit(RLIMIT_NOFILE, &limited));
        result = scanner.GetFullFilesystem();
    }
    struct rlimit restored;
    ASSERT_EQ(0, ::getrlimit(RLIMIT_NOFILE, &restored));
    ASSERT_EQ(originalLimit.rlim_cur, restored.rlim_cur);
    ASSERT_TRUE(result.HasValue());

    ASSERT_GT(WaitForScannerPid(lockPath), 0);
    const int lockFd = ::open(lockPath.c_str(), O_RDONLY);
    ASSERT_GE(lockFd, 0);
    bool finished = false;
    for (int attempt = 0; attempt < 300; ++attempt)
    {
        if (::flock(lockFd, LOCK_EX | LOCK_NB) == 0)
        {
            finished = true;
            ASSERT_EQ(0, ::flock(lockFd, LOCK_UN));
            break;
        }
        ::usleep(10 * 1000);
    }
    ASSERT_EQ(0, ::close(lockFd));
    ASSERT_TRUE(finished);

    alignas(struct inotify_event) char events[4096];
    const ssize_t eventBytes = ::read(notificationFd, events, sizeof(events));
    ASSERT_GT(eventBytes, 0) << "The scanner did not open the interior directory";
    bool visitedInterior = false;
    for (ssize_t offset = 0; offset < eventBytes;)
    {
        const auto* event = reinterpret_cast<const struct inotify_event*>(events + offset);
        visitedInterior |= (event->mask & IN_OPEN) != 0;
        offset += sizeof(*event) + event->len;
    }
    ASSERT_TRUE(visitedInterior);

    std::ifstream cache(cachePath.c_str(), std::ios::binary);
    ASSERT_TRUE(cache.is_open());
    const std::string after((std::istreambuf_iterator<char>(cache)), std::istreambuf_iterator<char>());
    EXPECT_EQ(after, original);
}
