// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "FilesystemScanner.h"
#include "TemporaryDirectory.h"

#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstddef>
#include <cstdlib>
#include <fstream>
#include <gtest/gtest.h>
#include <new>
#include <string>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>

using Kompli::FilesystemScanner;
using Kompli::TemporaryDirectory;

namespace
{
// Sticky allocation-fault injector. Plain process-wide globals, not thread_local, so that
// fork() (which copies the whole address space of the single, forking thread) gives each
// descendant process its own independent copy of this state: once armed with N, attempt N
// and every later counted attempt throws std::bad_alloc, in that process, until disarmed.
// Both operator new and operator new[] count, because std::filebuf allocates its buffer
// with new[]. The test process stays single-threaded before forking, so a plain global is
// sufficient and clearer than thread_local here.
bool g_allocationFaultArmed = false;
std::size_t g_allocationFaultTarget = 0;
std::size_t g_allocationAttempts = 0;

void ArmAllocationFault(std::size_t attemptNumber)
{
    g_allocationAttempts = 0;
    g_allocationFaultTarget = attemptNumber;
    g_allocationFaultArmed = true;
}

void DisarmAllocationFault()
{
    g_allocationFaultArmed = false;
}

// Forwards to malloc/free (not ::operator new/delete) so that replacing the global
// allocation functions stays ASan-compatible: ASan intercepts malloc/free themselves
// (ahead of libc, by load order), so heap tracking still applies even though this
// replacement also takes priority over ASan's own operator new. See
// ResultAllocationTest.cpp for the full rationale.
void* AllocateBytes(std::size_t bytes)
{
    if (bytes == 0)
    {
        bytes = 1;
    }
    for (;;)
    {
        if (void* ptr = std::malloc(bytes))
        {
            return ptr;
        }
        std::new_handler handler = std::get_new_handler();
        if (!handler)
        {
            throw std::bad_alloc();
        }
        handler();
    }
}

void* CountedAllocate(std::size_t bytes)
{
    if (g_allocationFaultArmed)
    {
        ++g_allocationAttempts;
        if (g_allocationAttempts >= g_allocationFaultTarget)
        {
            throw std::bad_alloc();
        }
    }
    return AllocateBytes(bytes);
}

void TouchFile(const std::string& path)
{
    std::ofstream ofs(path.c_str());
    ofs << "data";
}

// FileLock::Make (FilesystemScanner.cpp) writes the scanner's pid into the lock file; see
// FilesystemScannerTest.cpp's WaitForScannerPid for the same read pattern. Returns -1 if
// unavailable.
pid_t ReadScannerPidFromLock(const std::string& lockPath)
{
    std::ifstream lockFile(lockPath.c_str());
    pid_t pid = -1;
    if ((lockFile >> pid) && (pid > 0))
    {
        return pid;
    }
    return -1;
}
} // namespace

void* operator new(std::size_t bytes)
{
    return CountedAllocate(bytes);
}

void* operator new[](std::size_t bytes)
{
    return CountedAllocate(bytes);
}

void operator delete(void* ptr) noexcept
{
    std::free(ptr);
}

void operator delete(void* ptr, std::size_t) noexcept
{
    std::free(ptr);
}

void operator delete[](void* ptr) noexcept
{
    std::free(ptr);
}

void operator delete[](void* ptr, std::size_t) noexcept
{
    std::free(ptr);
}

// An exception escaping the forked scanner grandchild must never resume host
// (caller/engine) code. This executable holds only this case, so the replaced global
// operators and the sticky injector cannot affect any other test.
//
// Coverage claim: a sticky allocation failure is started at each allocation attempt of the
// scanner's successful path, in order (N = 1, 2, ...). Allocation points reached only on
// other paths (for example the lock-contention Error messages) are not claimed. The
// property under test is that no sentinel status (42 or 43) ever appears -- i.e. no forked
// scanner process ever unwinds an uncaught exception, or returns normally, into the copied
// engine/host stack frames above it. A scanner that hits the injected fault is expected to
// exit with status 1 (an existing explicit _exit(1) path, or the child-process exception
// boundary); that status is not attributed to any particular guard. If a library silently
// absorbed a failure and the scan still succeeded, the sweep would simply end earlier; it
// still requires at least one prior exit of 1, so the sweep reached the scanner body.
TEST(FilesystemScannerAllocationTest, ScannerProcessExitsOnAllocationFailureAtEveryPoint)
{
    // Setup, once. The detached scanner is re-parented to this process when the
    // intermediate child exits (which BackgroundScan already waits for), so the test can
    // reap it.
    ASSERT_EQ(0, ::prctl(PR_SET_CHILD_SUBREAPER, 1));

    auto tempDirResult = TemporaryDirectory::Make("filesystem-scanner-allocation-test");
    ASSERT_TRUE(tempDirResult.HasValue()) << tempDirResult.Error().message;
    TemporaryDirectory tempDir = std::move(tempDirResult).Value();
    const std::string root = tempDir.Path();

    ASSERT_EQ(0, ::mkdir((root + "/sub").c_str(), 0700));
    TouchFile(root + "/a.txt");
    TouchFile(root + "/sub/b.txt");

    const std::string cachePath = root + "/cache.txt";
    // Longer than libstdc++'s 15-character small-string buffer, so FileLock's path copy
    // allocates.
    const std::string lockPath = root + "/filesystem-scanner-allocation-test.lock";
    ASSERT_GT(lockPath.size(), 15u);

    const pid_t testPid = ::getpid();
    const std::size_t bound = 10000;
    std::size_t successfulAttempt = 0;
    bool sawFaultExit = false;

    for (std::size_t attempt = 1; attempt <= bound; ++attempt)
    {
        // Remove any lock file left by the previous iteration's scanner (already reaped
        // above) so that a PID read from it below can only come from the scanner started
        // in this iteration, never a stale PID reused by an unrelated process.
        if ((::unlink(lockPath.c_str()) != 0) && (errno != ENOENT))
        {
            FAIL() << "attempt " << attempt << ": failed to remove stale lock file (errno " << errno << ")";
        }

        FilesystemScanner scanner(root, cachePath, lockPath, /*softTimeoutSeconds=*/60, /*hardTimeoutSeconds=*/120, /*waitTimeoutSeconds=*/0);
        ArmAllocationFault(attempt);
        bool caughtInSelf = false;
        try
        {
            (void)scanner.GetFullFilesystem();
        }
        catch (...)
        {
            if (::getpid() != testPid)
            {
                _exit(42); // Sentinel: a scanner process unwound an exception into this caught frame.
            }
            caughtInSelf = true;
            DisarmAllocationFault();
        }
        if (::getpid() != testPid)
        {
            _exit(43); // Sentinel: a scanner process returned normally into caller code.
        }
        DisarmAllocationFault(); // Idempotent; also covers the no-exception path.

        int status = 0;
        pid_t reaped = -1;
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
        for (;;)
        {
            reaped = ::waitpid(-1, &status, WNOHANG);
            if (reaped > 0)
            {
                break;
            }
            if (reaped < 0)
            {
                if (errno == EINTR)
                {
                    continue;
                }
                ASSERT_EQ(ECHILD, errno) << "attempt " << attempt << ": unexpected waitpid() failure";
                ASSERT_TRUE(caughtInSelf) << "attempt " << attempt
                                          << ": no scanner process existed to reap, "
                                             "but GetFullFilesystem() did not throw in this process either";
                break;
            }
            if (std::chrono::steady_clock::now() >= deadline)
            {
                pid_t strandedPid = ReadScannerPidFromLock(lockPath);
                int verifyStatus = 0;
                // WNOHANG here proves strandedPid is a live child of this process before we
                // consider signaling it: a stale/reused pid from a previous iteration's lock
                // file would not be our child, and waitpid() would fail instead of returning 0.
                pid_t verifyResult = (strandedPid > 0) ? ::waitpid(strandedPid, &verifyStatus, WNOHANG) : -1;
                if ((strandedPid > 0) && (verifyResult == 0))
                {
                    ::kill(strandedPid, SIGKILL);
                    int reapStatus = 0;
                    pid_t finalReap = -1;
                    do
                    {
                        finalReap = ::waitpid(strandedPid, &reapStatus, 0);
                    } while ((finalReap < 0) && (errno == EINTR));
                    FAIL() << "attempt " << attempt << ": scanner pid " << strandedPid << " did not exit within the reap deadline; killed it";
                }
                else if ((strandedPid > 0) && (verifyResult == strandedPid))
                {
                    // It exited right at the deadline and this waitpid() call already reaped
                    // it: treat it as a normal reap instead of signaling anything.
                    reaped = strandedPid;
                    status = verifyStatus;
                    break;
                }
                else
                {
                    FAIL() << "attempt " << attempt << ": timed out waiting to reap the scanner (lock file pid " << strandedPid
                           << "); not signaling an unverified/unknown process";
                }
            }
            ::usleep(1000);
        }

        if (reaped < 0)
        {
            // No child existed: valid only when the fault fired in this process before the
            // first fork() (for example during BackgroundScan's tmpPath concatenation).
            continue;
        }

        ASSERT_TRUE(WIFEXITED(status)) << "attempt " << attempt << ": scanner did not exit normally, raw status " << status;
        const int exitStatus = WEXITSTATUS(status);
        ASSERT_NE(42, exitStatus) << "attempt " << attempt << ": scanner unwound an uncaught exception into caller code";
        ASSERT_NE(43, exitStatus) << "attempt " << attempt << ": scanner returned normally into caller code";

        if (exitStatus == 0)
        {
            ASSERT_TRUE(std::ifstream(cachePath.c_str()).good()) << "attempt " << attempt << ": scanner exited 0 but did not publish a readable cache";
            successfulAttempt = attempt;
            break;
        }

        ASSERT_EQ(1, exitStatus) << "attempt " << attempt << ": scanner exited with an unexpected status";
        sawFaultExit = true;
    }

    ASSERT_GT(successfulAttempt, 0u) << "sweep reached the bound (" << bound << ") without a successful scan";
    ASSERT_LT(successfulAttempt, bound);
    ASSERT_TRUE(sawFaultExit) << "sweep never observed a scanner exit of 1 before the first success at N=" << successfulAttempt;
}
