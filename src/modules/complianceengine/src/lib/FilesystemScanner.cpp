// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "FilesystemScanner.h"

#include "FileLock.hpp"
#include "Optional.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fstream>
#include <limits.h>
#include <memory>
#include <signal.h>
#include <sstream>
#include <stack>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace ComplianceEngine
{
static void ScanDirRecursive(const std::string& dir, dev_t rootDev, std::map<std::string, FilesystemScanner::FSEntry>& entries);
pid_t BackgroundScan(const std::string& root, const std::string& cachePath, const std::string& lockPath);

static void CloseInheritedFileDescriptors()
{
#ifdef SYS_close_range
    if (::syscall(SYS_close_range, 0U, UINT_MAX, 0U) == 0)
    {
        return;
    }
#endif
    long maxFileDescriptor = ::sysconf(_SC_OPEN_MAX);
    if (maxFileDescriptor < 0)
    {
        maxFileDescriptor = 1024;
    }
    for (int fileDescriptor = 0; fileDescriptor < maxFileDescriptor; ++fileDescriptor)
    {
        ::close(fileDescriptor);
    }
}

FilesystemScanner::FilesystemScanner(std::string rootDir, std::string cachePath, std::string lockPath, time_t softTimeoutSeconds,
    time_t hardTimeoutSeconds, time_t waitTimeoutSeconds)
    : root(std::move(rootDir)),
      cachePath(std::move(cachePath)),
      lockPath(std::move(lockPath)),
      m_softTimeout(softTimeoutSeconds),
      m_hardTimeout(hardTimeoutSeconds),
      m_waitTimeout(waitTimeoutSeconds)
{
    if ((0 == m_hardTimeout) || (0 == m_softTimeout) || (m_hardTimeout < m_softTimeout))
    {
        throw std::runtime_error("Invalid timeout configuration: hard must be >= soft and both > 0");
    }
}

Result<std::shared_ptr<const FilesystemScanner::FSCache>> FilesystemScanner::GetFullFilesystem()
{
    // Ensure we have a cache (may trigger background build + optional wait).
    if (!m_cache)
    {
        if (!LoadCache())
        {
            BackgroundScan(root, cachePath, lockPath);
            if (m_waitTimeout > 0)
            {
                time_t startWait = ::time(nullptr);
                while ((::time(nullptr) - startWait) < m_waitTimeout)
                {
                    if (LoadCache())
                    {
                        break;
                    }
                    ::usleep(200 * 1000);
                }
            }
            if (!m_cache)
            {
                return ComplianceEngine::Error("filesystem cache unavailable; background scan started");
            }
        }
    }
    time_t now = ::time(nullptr);
    time_t age = 0;
    if (m_cache->scan_end_time > 0)
    {
        age = now - m_cache->scan_end_time;
    }
    bool softExpired = (m_softTimeout > 0 && age >= m_softTimeout);
    bool hardExpired = (m_hardTimeout > 0 && age >= m_hardTimeout);

    if (hardExpired)
    {
        BackgroundScan(root, cachePath, lockPath);
        if (m_waitTimeout > 0)
        {
            time_t startWait = ::time(nullptr);
            while ((::time(nullptr) - startWait) < m_waitTimeout)
            {
                if (LoadCache() && (now = ::time(nullptr), (now - m_cache->scan_end_time) < m_hardTimeout))
                {
                    return Result<std::shared_ptr<const FSCache>>(std::static_pointer_cast<const FSCache>(m_cache));
                }
                ::sleep(m_waitTimeout / 10);
            }
        }
        m_cache.reset();
        return ComplianceEngine::Error("filesystem cache expired (hard timeout); refresh started");
    }

    if (softExpired)
    {
        // Return current (stale) data and refresh in the background (only launch once)
        BackgroundScan(root, cachePath, lockPath);
        return Result<std::shared_ptr<const FSCache>>(std::static_pointer_cast<const FSCache>(m_cache));
    }

    return Result<std::shared_ptr<const FSCache>>(std::static_pointer_cast<const FSCache>(m_cache));
}

// Depth-first recursive directory scanner with lexicographically sorted sibling traversal.
// Filesystem recursion with boundary detection: if st_dev differs from rootDev and
// the target filesystem type is in a disallowed set (proc, devfs/devpts/devtmpfs variants,
// nfs*, fuse*), the directory entry is recorded but not traversed.
static void ScanDirRecursive(const std::string& dir, dev_t rootDev, std::map<std::string, FilesystemScanner::FSEntry>& entries)
{
    DIR* d = ::opendir(dir.c_str());
    if (!d)
    {
        return; // ignore unreadable dirs
    }
    auto dirDeleter = std::unique_ptr<DIR, int (*)(DIR*)>(d, ::closedir);
    struct dirent* de = nullptr;
    while ((de = ::readdir(d)) != nullptr)
    {
        if (de->d_name[0] == '.' && (de->d_name[1] == '\0' || (de->d_name[1] == '.' && de->d_name[2] == '\0')))
        {
            continue;
        }
        const char* name = de->d_name;
        std::string fullPath = dir;
        if (!fullPath.empty() && fullPath.back() != '/')
        {
            fullPath.push_back('/');
        }
        fullPath += name;
        struct stat st;
        if (::lstat(fullPath.c_str(), &st) != 0)
        {
            continue;
        }
        entries.insert(std::make_pair(fullPath, FilesystemScanner::FSEntry{st}));
        if (S_ISDIR(st.st_mode))
        {
            bool traverse = true;
            if (st.st_dev != rootDev)
            {
                struct statfs sfs;
                if (::statfs(fullPath.c_str(), &sfs) == 0)
                {
                    // Magic numbers for filesystems to skip recursion into when crossing boundary
                    switch (static_cast<unsigned long>(sfs.f_type))
                    {
                        case 0x9fa0:     /* PROC_SUPER_MAGIC (procfs) */
                        case 0x1373:     /* DEVFS_SUPER_MAGIC (legacy devfs) */
                        case 0x1cd1:     /* DEVPTS_SUPER_MAGIC (devpts) */
                        case 0x62656572: /* SYSFS_MAGIC (sysfs) */
                        case 0x01021994: /* TMPFS_MAGIC (devtmpfs often appears as tmpfs) */
                        case 0x6969:     /* NFS_SUPER_MAGIC (all nfs variants share) */
                        case 0x65735546: /* FUSE_SUPER_MAGIC (fuse) */
                            traverse = false;
                            break;
                        default:
                            break;
                    }
                }
            }
            if (traverse)
            {
                ScanDirRecursive(fullPath, st.st_dev, entries);
            }
        }
    }
}

pid_t BackgroundScan(const std::string& root, const std::string& cachePath, const std::string& lockPath)
{
    std::string tmpPath = cachePath + ".tmp";
    pid_t pid = ::fork();
    if (pid < 0)
    {
        return pid;
    }
    if (pid == 0)
    {
        if (::setsid() < 0)
        {
            _exit(1);
        }

        pid_t scannerPid = ::fork();
        if (scannerPid < 0)
        {
            _exit(1);
        }
        if (scannerPid > 0)
        {
            _exit(0);
        }

        CloseInheritedFileDescriptors();
        (void)::chdir("/");

        auto lockResult = FileLock::Make(lockPath);
        if (!lockResult.HasValue())
        {
            // Unable to obtain lock (either open or flock failure, likely another process scanning).
            _exit(0);
        }
        FileLock lock = std::move(lockResult.Value());

        time_t start = ::time(nullptr);
        std::shared_ptr<FilesystemScanner::FSCache> cache((FilesystemScanner::FSCache*)nullptr);
        try
        {
            cache.reset(new FilesystemScanner::FSCache());
        }
        catch (...)
        {
            _exit(1);
        }
        cache->scan_start_time = start;
        // Determine root device for boundary detection
        struct stat rootSt;
        if (::lstat(root.c_str(), &rootSt) != 0)
        {
            _exit(1);
        }
        ScanDirRecursive(root, rootSt.st_dev, cache->entries);
        time_t end = ::time(nullptr);
        cache->scan_end_time = end;
        // Build and atomically replace cache file.

        std::ofstream ofs(tmpPath.c_str(), std::ios::out | std::ios::trunc);
        if (!ofs.is_open())
        {
            _exit(1);
        }
        ofs << "# FilesystemScanCache-V1 " << static_cast<long>(start) << ' ' << static_cast<long>(end) << '\n';
        for (const auto& kv : cache->entries)
        {
            const auto& path = kv.first;
            const auto& st = kv.second.st;
            ofs << path << ' ' << static_cast<unsigned long long>(st.st_dev) << ' ' << static_cast<unsigned long long>(st.st_ino) << ' '
                << static_cast<unsigned>(st.st_mode) << ' ' << static_cast<unsigned>(st.st_nlink) << ' ' << static_cast<long long>(st.st_uid) << ' '
                << static_cast<long>(st.st_gid) << ' ' << static_cast<long long>(st.st_size) << ' ' << static_cast<long>(st.st_blksize) << ' '
                << static_cast<long long>(st.st_blocks) << '\n';
        }
        ofs.flush();
        ofs.close();

        ::unlink(cachePath.c_str());
        ::rename(tmpPath.c_str(), cachePath.c_str());
        _exit(0);
    }

    pid_t waitResult = -1;
    do
    {
        waitResult = ::waitpid(pid, nullptr, 0);
    } while ((waitResult < 0) && (errno == EINTR));
    return pid;
}

bool FilesystemScanner::LoadCache()
{
    std::ifstream ifs(cachePath.c_str());
    if (!ifs.is_open())
    {
        return false;
    }
    std::string header;
    if (!std::getline(ifs, header))
    {
        return false;
    }
    std::istringstream hs(header);
    std::string hash, magic;
    long start = 0, end = 0;
    if (!(hs >> hash >> magic >> start >> end))
    {
        return false;
    }
    if (hash != "#" || magic != "FilesystemScanCache-V1")
    {
        return false;
    }
    // Skip loading if cache already beyond hard timeout age.
    if (m_hardTimeout > 0)
    {
        time_t now = ::time(nullptr);
        if (end > 0 && (now - end) >= m_hardTimeout)
        {
            return false;
        }
    }
    std::shared_ptr<FSCache> cache((FSCache*)nullptr);
    try
    {
        cache.reset(new FSCache());
    }
    catch (...)
    {
        return false;
    }
    cache->scan_start_time = start;
    cache->scan_end_time = end;
    std::string line;
    while (std::getline(ifs, line))
    {
        if (line.empty())
        {
            continue;
        }
        std::istringstream ls(line);
        std::string name;
        unsigned long long dev = 0, ino = 0;
        unsigned mode = 0, nlink = 0;
        long long uid = 0, size = 0, blocks = 0;
        long gid = 0, blksize = 0;
        if (!(ls >> name >> dev >> ino >> mode >> nlink >> uid >> gid >> size >> blksize >> blocks))
        {
            continue; // malformed
        }
        struct stat st;
        st.st_dev = static_cast<dev_t>(dev);
        st.st_ino = static_cast<ino_t>(ino);
        st.st_mode = static_cast<mode_t>(mode);
        st.st_nlink = static_cast<nlink_t>(nlink);
        st.st_uid = static_cast<uid_t>(uid);
        st.st_gid = static_cast<gid_t>(gid);
        st.st_size = static_cast<off_t>(size);
        st.st_blksize = static_cast<blksize_t>(blksize);
        st.st_blocks = static_cast<blkcnt_t>(blocks);
        cache->entries.insert(std::make_pair(std::move(name), FSEntry{st}));
    }
    if (!cache->entries.empty())
    {
        m_cache = cache;
        return true;
    }
    return false;
}

} // namespace ComplianceEngine
