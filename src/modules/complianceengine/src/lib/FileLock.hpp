// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_FILELOCK_HPP
#define COMPLIANCEENGINE_FILELOCK_HPP

#include "Result.h"

#include <string>

namespace ComplianceEngine
{
// A cross-process exclusive, non-blocking file lock backed by flock(2).
// Extracted from FilesystemScanner's original private helper so other
// components (e.g. komplid's remediation serialization) can reuse the same
// implementation instead of duplicating it. Move-only; the lock is released
// (and the backing fd closed) when the FileLock is destroyed.
class FileLock
{
public:
    // Attempts to create (if missing) and acquire an exclusive lock on
    // `path`. When `blocking` is false (the default), returns Error
    // immediately if another process already holds the lock; when true,
    // waits until the lock becomes available. Returns Error if the file
    // cannot be opened.
    static Result<FileLock> Make(const std::string& path, bool blocking = false);

    ~FileLock();

    FileLock(const FileLock&) = delete;
    FileLock& operator=(const FileLock&) = delete;
    FileLock(FileLock&& other) noexcept;
    FileLock& operator=(FileLock&& other) noexcept;

private:
    explicit FileLock(const std::string& path);

    std::string mPath;
    int mFd = -1;
};

} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_FILELOCK_HPP
