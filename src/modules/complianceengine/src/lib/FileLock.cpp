// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "FileLock.hpp"

#include <cstdio>
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>

namespace ComplianceEngine
{
FileLock::FileLock(const std::string& path)
    : mPath(path)
{
}

Result<FileLock> FileLock::Make(const std::string& path, bool blocking)
{
    FileLock fl(path);
    fl.mFd = ::open(path.c_str(), O_RDWR | O_CREAT, 0644);
    if (fl.mFd < 0)
    {
        return ComplianceEngine::Error("failed to open lock file");
    }
    const int operation = LOCK_EX | (blocking ? 0 : LOCK_NB);
    if (::flock(fl.mFd, operation) != 0)
    {
        ::close(fl.mFd);
        fl.mFd = -1;
        return ComplianceEngine::Error("another process holds lock");
    }
    if (::ftruncate(fl.mFd, 0) == 0)
    {
        char pidBuf[64];
        int len = std::snprintf(pidBuf, sizeof(pidBuf), "%ld\n", (long)::getpid());
        if (len > 0)
        {
            (void)::write(fl.mFd, pidBuf, static_cast<size_t>(len));
            ::lseek(fl.mFd, 0, SEEK_SET);
        }
    }
    return Result<FileLock>(std::move(fl));
}

FileLock::~FileLock()
{
    if (mFd >= 0)
    {
        ::flock(mFd, LOCK_UN);
        ::close(mFd);
        mFd = -1;
    }
}

FileLock::FileLock(FileLock&& other) noexcept
    : mPath(std::move(other.mPath)),
      mFd(other.mFd)
{
    other.mFd = -1;
}

FileLock& FileLock::operator=(FileLock&& other) noexcept
{
    if (this != &other)
    {
        if (mFd >= 0)
        {
            ::flock(mFd, LOCK_UN);
            ::close(mFd);
        }
        mPath = std::move(other.mPath);
        mFd = other.mFd;
        other.mFd = -1;
    }
    return *this;
}

} // namespace ComplianceEngine
