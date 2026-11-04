// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_FILESYSTEM_PROCFS_DESCRIPTOR_ACCESS_HPP
#define COMPLIANCEENGINE_FILESYSTEM_PROCFS_DESCRIPTOR_ACCESS_HPP

#include "Descriptor.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <sys/stat.h>

namespace ComplianceEngine
{
namespace Filesystem
{
namespace Detail
{
// One scoped, context- and current-task-bound session for verified
// /proc/self/task/<tid>/{fd,fdinfo} access. Only the native ContextInterface
// boundary can consume its roles. Callers synchronize against external
// close/dup2/reuse; PID/TID checks do not freeze the task's fd table.
class ProcfsDescriptorAccess
{
public:
    Result<bool> Open();
    void Close() noexcept;
    Result<std::uint64_t> ReadMountId(const Descriptor& descriptor, std::size_t byteCap) const;

private:
    friend class ::ComplianceEngine::ContextInterface;
    friend class ::ComplianceEngine::Filesystem::Detail::Handle;
    friend class ::ComplianceEngine::Filesystem::Path;
    friend class ::ComplianceEngine::Tests::DescriptorTestAccess;
    explicit ProcfsDescriptorAccess(const ContextInterface& context);
    ProcfsDescriptorAccess(const ContextInterface&&) = delete;
    static bool IsProcfsDirectory(const ContextInterface& context, const Descriptor& descriptor);
    bool VerifyRole(const ContextInterface& context, bool information) const;
    // Bootstrap owners are disposed during Open to keep the peak descriptor
    // count bounded; disposal failures are diagnostic-only. Ordinary callers
    // cannot replace role pins.
    Descriptor proc, self, pid, task, tid, fd, fdinfo;
    pid_t mPid = 0, mTid = 0;
    bool mVerified = false;
    struct stat mFdIdentity = {}, mFdinfoIdentity = {};
};

Result<std::uint64_t> ParseMountId(const std::string& fdinfo);
} // namespace Detail
} // namespace Filesystem
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_FILESYSTEM_PROCFS_DESCRIPTOR_ACCESS_HPP
