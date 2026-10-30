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
// One scoped, context-bound session for verified /proc/self/fd and fdinfo
// access. Only the native ContextInterface boundary can consume its roles.
class ProcfsDescriptorAccess
{
public:
    explicit ProcfsDescriptorAccess(const ContextInterface& context);
    ProcfsDescriptorAccess(const ContextInterface&&) = delete;
    Result<bool> Open();
    Result<bool> Close();
    Result<std::uint64_t> ReadMountId(const Descriptor& descriptor, std::size_t byteCap) const;
    const Descriptor& ProcDirectory() const noexcept
    {
        return proc;
    }
    const Descriptor& FdDirectory() const noexcept
    {
        return fd;
    }
    const Descriptor& FdinfoDirectory() const noexcept
    {
        return fdinfo;
    }

private:
    friend class ::ComplianceEngine::ContextInterface;
    bool VerifyRole(const ContextInterface& context, bool information) const;
    // Only Open() fills the role owners after verifying /proc/self against
    // the current PID. Ordinary callers cannot replace or swap these pins.
    Descriptor proc, self, pid, fd, fdinfo;
    bool mVerified = false;
    struct stat mFdIdentity = {}, mFdinfoIdentity = {};
};

Result<std::uint64_t> ParseMountId(const std::string& fdinfo);
} // namespace Detail
} // namespace Filesystem
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_FILESYSTEM_PROCFS_DESCRIPTOR_ACCESS_HPP
