// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_FILESYSTEM_PROCFS_DESCRIPTOR_ACCESS_HPP
#define COMPLIANCEENGINE_FILESYSTEM_PROCFS_DESCRIPTOR_ACCESS_HPP

#include "Descriptor.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
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

private:
    friend class ::ComplianceEngine::ContextInterface;
    friend class ::ComplianceEngine::Filesystem::Detail::Handle;
    friend class ::ComplianceEngine::Filesystem::Path;
    friend class ::ComplianceEngine::Tests::DescriptorTestAccess;
    static Result<ProcfsDescriptorAccess> Make(const ContextInterface& context);
    static Result<ProcfsDescriptorAccess> Make(const ContextInterface&&) = delete;
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
    // A temporary context would dangle past construction: this session
    // retains the context reference for its own lifetime (see mContext below).
    ProcfsDescriptorAccess(const ContextInterface&&, Roles, VerifiedBindings) = delete;
    // Only ContextInterface's native-dispatch boundary (OpenFdinfo/OpenAlias/
    // OpenPinAlias/ChmodAlias) calls this, after it has already rejected a
    // moved-from target and the specific moved-from role it is about to use;
    // VerifyRole itself never touches a raw descriptor integer, only
    // verified native operations through `context`.
    // VerifyRole only uses context transiently (identity pointer compare plus
    // CurrentProcessId/CurrentThreadId/StatFile, all synchronous); it does
    // not retain it, so no deleted rvalue overload applies here.
    bool VerifyRole(const ContextInterface& context, Role role) const;
    // Only Path/Handle's acquisition internals and the test-access friend may
    // read a verified fdinfo mount ID; an unvalidated byte cap must never
    // reach here from outside those acceptance points (see Path::Make's
    // ResolverLimits validation and FilesystemCollection's request validation).
    Result<std::uint64_t> ReadMountId(const Descriptor& descriptor, std::size_t byteCap) const;
    // Bundles the verified fd/fdinfo roles with the identity snapshot taken
    // during their single stat each; Make()'s caller needs both for VerifiedBindings.
    struct RetainedRoles
    {
        Roles roles;
        struct stat fdIdentity;
        struct stat fdinfoIdentity;
    };
    // Transient use only (StatFilesystem/StatFile); not retained, so no
    // deleted rvalue overload applies here.
    static bool IsProcfsDirectory(const ContextInterface& context, const Descriptor& descriptor);
    static Result<Descriptor> OpenVerifiedSelf(const ContextInterface& context, pid_t pid);
    // The returned Descriptor retains whichever context opened it (via
    // OpenAbsolutePin/OpenAt): a temporary argument here would dangle in the
    // caller.
    static Result<Descriptor> OpenVerifiedSelf(const ContextInterface&&, pid_t) = delete;
    static Result<Descriptor> OpenVerifiedTid(const ContextInterface& context, pid_t pid, pid_t tid);
    static Result<Descriptor> OpenVerifiedTid(const ContextInterface&&, pid_t, pid_t) = delete;
    static Result<RetainedRoles> OpenVerifiedRoles(const ContextInterface& context, const Descriptor& taskDirectory, pid_t pid, pid_t tid);
    static Result<RetainedRoles> OpenVerifiedRoles(const ContextInterface&&, const Descriptor&, pid_t, pid_t) = delete;
    // Transient use only (the synchronous ReadFile loop); the returned
    // std::uint64_t carries no reference, so no deleted rvalue overload
    // applies here.
    static Result<std::uint64_t> ReadMountIdBytes(const ContextInterface& context, const Descriptor& info, std::size_t byteCap);
    std::reference_wrapper<const ContextInterface> mContext;
    Roles mRoles;
    VerifiedBindings mBindings;
};
} // namespace Detail
} // namespace Filesystem
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_FILESYSTEM_PROCFS_DESCRIPTOR_ACCESS_HPP
