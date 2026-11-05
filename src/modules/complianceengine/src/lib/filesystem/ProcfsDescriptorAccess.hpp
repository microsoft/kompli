// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_FILESYSTEM_PROCFS_DESCRIPTOR_ACCESS_HPP
#define COMPLIANCEENGINE_FILESYSTEM_PROCFS_DESCRIPTOR_ACCESS_HPP

#include "Descriptor.hpp"

#include <array>
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
    ProcfsDescriptorAccess() = delete;
    ProcfsDescriptorAccess(const ProcfsDescriptorAccess&) = delete;
    ProcfsDescriptorAccess& operator=(const ProcfsDescriptorAccess&) = delete;
    ProcfsDescriptorAccess(ProcfsDescriptorAccess&&) noexcept = default;
    ProcfsDescriptorAccess& operator=(ProcfsDescriptorAccess&&) & noexcept = default;
    ~ProcfsDescriptorAccess() noexcept = default;
    Result<std::uint64_t> ReadMountId(const Descriptor& descriptor, std::size_t byteCap) const;

private:
    friend class ::ComplianceEngine::ContextInterface;
    friend class ::ComplianceEngine::Filesystem::Detail::Handle;
    friend class ::ComplianceEngine::Filesystem::Path;
    friend class ::ComplianceEngine::Tests::DescriptorTestAccess;
    static Result<ProcfsDescriptorAccess> Open(const ContextInterface& context);
    static Result<ProcfsDescriptorAccess> Open(const ContextInterface&&) = delete;
    enum class Role
    {
        Fd,
        Fdinfo
    };
    using Roles = std::array<Descriptor, 2>;
    struct VerifiedBindings
    {
        pid_t pid;
        pid_t tid;
        struct stat fdIdentity;
        struct stat fdinfoIdentity;
    };
    ProcfsDescriptorAccess(const ContextInterface& context, Roles roles, VerifiedBindings bindings) noexcept;
    static bool IsProcfsDirectory(const ContextInterface& context, const Descriptor& descriptor);
    void RequireRolesOwned() const;
    bool VerifyRole(const ContextInterface& context, bool information) const;
    const ContextInterface* mContext;
    Roles mRoles;
    VerifiedBindings mBindings;
};

Result<std::uint64_t> ParseMountId(const std::string& fdinfo);
} // namespace Detail
} // namespace Filesystem
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_FILESYSTEM_PROCFS_DESCRIPTOR_ACCESS_HPP
