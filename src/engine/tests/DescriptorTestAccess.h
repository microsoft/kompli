// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_TESTS_DESCRIPTOR_TEST_ACCESS_H
#define COMPLIANCEENGINE_TESTS_DESCRIPTOR_TEST_ACCESS_H

#include <ContextInterface.h>
#include <filesystem/Descriptor.hpp>
#include <filesystem/FTWDirectoryCursor.hpp>
#include <filesystem/Pin.hpp>
#include <filesystem/ProcfsDescriptorAccess.hpp>
#include <stdexcept>
#include <type_traits>
#include <utility>

namespace ComplianceEngine
{
namespace Tests
{
// Defined only in tests. Production has no public bridge to typed operations.
class DescriptorTestAccess
{
    using Descriptor = Filesystem::Detail::Descriptor;
    using Procfs = Filesystem::Detail::ProcfsDescriptorAccess;
    using Cursor = Filesystem::FTW::Detail::DirectoryCursor;
    using Profile = ContextInterface::OpenProfile;

    // Friend-context SFINAE for retained-context constructors/factories that
    // are only reachable through this class's own friendship (Descriptor and
    // ProcfsDescriptorAccess both declare DescriptorTestAccess a friend).
    // Each decltype() below is lexically inside this friend class, so access
    // control for the named private member is checked with *this* class's
    // friendship, not an ordinary caller's -- unlike the DENY_* probes in
    // DescriptorAccessCompileTest.cpp, which run outside every friend and so
    // cannot distinguish "ill-formed: no access" from "ill-formed: deleted".
    // The exposed `*Lvalue` constant is therefore a positive control proving
    // the probe really sees friend access (it must be true); the matching
    // `*Rvalue` constant proves the deleted `const ContextInterface&&`
    // overload is still rejected even under that same friend access (use of
    // a deleted function is ill-formed even unevaluated, so this remains a
    // genuine SFINAE substitution failure, not merely an access failure).
    template <typename T, typename = decltype(Descriptor(std::declval<T>(), 0))>
    static std::true_type ProbeDescriptorCtor(int);
    template <typename T>
    static std::false_type ProbeDescriptorCtor(...);
    template <typename T, typename = decltype(Procfs(std::declval<T>(), std::declval<Procfs::Roles>(), std::declval<Procfs::VerifiedBindings>()))>
    static std::true_type ProbeProcfsCtor(int);
    template <typename T>
    static std::false_type ProbeProcfsCtor(...);
    template <typename T, typename = decltype(Procfs::OpenVerifiedSelf(std::declval<T>(), pid_t{}))>
    static std::true_type ProbeOpenVerifiedSelf(int);
    template <typename T>
    static std::false_type ProbeOpenVerifiedSelf(...);
    template <typename T, typename = decltype(Procfs::OpenVerifiedTid(std::declval<T>(), pid_t{}, pid_t{}))>
    static std::true_type ProbeOpenVerifiedTid(int);
    template <typename T>
    static std::false_type ProbeOpenVerifiedTid(...);
    template <typename T, typename = decltype(Procfs::OpenVerifiedRoles(std::declval<T>(), std::declval<const Descriptor&>(), pid_t{}, pid_t{}))>
    static std::true_type ProbeOpenVerifiedRoles(int);
    template <typename T>
    static std::false_type ProbeOpenVerifiedRoles(...);
    // ContextInterface::OpenProcfsSelf/OpenVerifiedAt are themselves `const&`-qualified
    // members that return a Descriptor retaining `*this`; the probe below calls them
    // directly on T (lvalue vs. rvalue ContextInterface), mirroring the static factories above.
    template <typename T, typename = decltype(std::declval<T>().OpenProcfsSelf(std::declval<const Descriptor&>()))>
    static std::true_type ProbeOpenProcfsSelf(int);
    template <typename T>
    static std::false_type ProbeOpenProcfsSelf(...);
    template <typename T, typename = decltype(std::declval<T>().OpenVerifiedAt(std::declval<const Descriptor&>(), std::declval<const char*>(), Profile::PinChild))>
    static std::true_type ProbeOpenVerifiedAt(int);
    template <typename T>
    static std::false_type ProbeOpenVerifiedAt(...);

public:
    static constexpr bool DescriptorCtorLvalue = decltype(ProbeDescriptorCtor<const ContextInterface&>(0))::value;
    static constexpr bool DescriptorCtorRvalue = decltype(ProbeDescriptorCtor<const ContextInterface&&>(0))::value;
    static constexpr bool ProcfsCtorLvalue = decltype(ProbeProcfsCtor<const ContextInterface&>(0))::value;
    static constexpr bool ProcfsCtorRvalue = decltype(ProbeProcfsCtor<const ContextInterface&&>(0))::value;
    static constexpr bool OpenVerifiedSelfLvalue = decltype(ProbeOpenVerifiedSelf<const ContextInterface&>(0))::value;
    static constexpr bool OpenVerifiedSelfRvalue = decltype(ProbeOpenVerifiedSelf<const ContextInterface&&>(0))::value;
    static constexpr bool OpenVerifiedTidLvalue = decltype(ProbeOpenVerifiedTid<const ContextInterface&>(0))::value;
    static constexpr bool OpenVerifiedTidRvalue = decltype(ProbeOpenVerifiedTid<const ContextInterface&&>(0))::value;
    static constexpr bool OpenVerifiedRolesLvalue = decltype(ProbeOpenVerifiedRoles<const ContextInterface&>(0))::value;
    static constexpr bool OpenVerifiedRolesRvalue = decltype(ProbeOpenVerifiedRoles<const ContextInterface&&>(0))::value;
    static constexpr bool OpenProcfsSelfLvalue = decltype(ProbeOpenProcfsSelf<const ContextInterface&>(0))::value;
    static constexpr bool OpenProcfsSelfRvalue = decltype(ProbeOpenProcfsSelf<const ContextInterface&&>(0))::value;
    static constexpr bool OpenVerifiedAtLvalue = decltype(ProbeOpenVerifiedAt<const ContextInterface&>(0))::value;
    static constexpr bool OpenVerifiedAtRvalue = decltype(ProbeOpenVerifiedAt<const ContextInterface&&>(0))::value;

    // Keep every context-retaining result tied to a caller-owned lvalue.
    static Result<Descriptor> OpenAbsolutePin(const ContextInterface& context, const char* path)
    {
        return context.OpenAbsolutePin(path);
    }
    static Result<Descriptor> OpenAbsolutePin(const ContextInterface&&, const char*) = delete;
    static Result<Descriptor> OpenAt(const ContextInterface& context, const Descriptor& directory, const char* name, Profile profile)
    {
        return context.OpenAt(directory, name, profile);
    }
    static Result<Descriptor> OpenAt(const ContextInterface&&, const Descriptor&, const char*, Profile) = delete;
    static Result<Descriptor> OpenFdinfo(const ContextInterface& context, const Procfs& procfs, const Descriptor& target)
    {
        return context.OpenFdinfo(procfs, target);
    }
    static Result<Descriptor> OpenFdinfo(const ContextInterface&&, const Procfs&, const Descriptor&) = delete;
    static Result<Descriptor> OpenAlias(const ContextInterface& context, const Procfs& procfs, const Descriptor& target, Filesystem::Type directory)
    {
        return context.OpenAlias(procfs, target, directory);
    }
    static Result<Descriptor> OpenAlias(const ContextInterface&&, const Procfs&, const Descriptor&, Filesystem::Type) = delete;
    static Result<Descriptor> OpenPinAlias(const ContextInterface& context, const Procfs& procfs, const Descriptor& target, Filesystem::Type directory)
    {
        return context.OpenPinAlias(procfs, target, directory);
    }
    static Result<Descriptor> OpenPinAlias(const ContextInterface&&, const Procfs&, const Descriptor&, Filesystem::Type) = delete;
    static Result<Descriptor> Duplicate(const ContextInterface& context, const Descriptor& source)
    {
        return context.Duplicate(source);
    }
    static Result<Descriptor> Duplicate(const ContextInterface&&, const Descriptor&) = delete;
    static int StatFile(const ContextInterface& context, const Descriptor& owner, struct stat* metadata)
    {
        return context.StatFile(owner, metadata);
    }
    static int StatFilesystem(const ContextInterface& context, const Descriptor& owner, struct statfs* metadata)
    {
        return context.StatFilesystem(owner, metadata);
    }
    static ssize_t ReadFile(const ContextInterface& context, const Descriptor& owner, void* buffer, std::size_t size)
    {
        return context.ReadFile(owner, buffer, size);
    }
    static ssize_t ReadLink(const ContextInterface& context, const Descriptor& owner, char* buffer, std::size_t size)
    {
        return context.ReadLink(owner, buffer, size);
    }
    static int StatusFlags(const ContextInterface& context, const Descriptor& owner)
    {
        return context.StatusFlags(owner);
    }
    static int DescriptorFlags(const ContextInterface& context, const Descriptor& owner)
    {
        return context.DescriptorFlags(owner);
    }
    static int ChownPinned(const ContextInterface& context, const Descriptor& owner, uid_t user, gid_t group)
    {
        return context.ChownPinned(owner, user, group);
    }
    static int ChmodAlias(const ContextInterface& context, const Procfs& procfs, const Descriptor& owner, mode_t mode)
    {
        return context.ChmodAlias(procfs, owner, mode);
    }
    static Result<Cursor> OpenDirectoryCursor(const ContextInterface& context, Descriptor&& owner)
    {
        return context.OpenDirectoryCursor(std::move(owner));
    }
    static Result<Cursor> OpenDirectoryCursor(const ContextInterface&&, Descriptor&&) = delete;
    // This test-only native-access adapter is checked; internal disposal is not.
    static Result<void> CloseOwnedDescriptor(const ContextInterface& context, Descriptor& owner)
    {
        if (ConsumedDescriptor(owner) < 0)
            throw std::logic_error("Descriptor: use after move (no ownership)");
        return context.CloseOwnedDescriptor(owner);
    }
    static constexpr bool InternalCloseIsNoexcept() noexcept
    {
        return noexcept(std::declval<const ContextInterface&>().CloseOwnedDescriptor(std::declval<Descriptor&>()));
    }
    static Result<void> CloseInternally(const ContextInterface& context, Descriptor& owner) noexcept
    {
        return context.CloseOwnedDescriptor(owner);
    }
    static Result<pid_t> CurrentProcessId(const ContextInterface& context)
    {
        return context.CurrentProcessId();
    }
    static Result<pid_t> CurrentThreadId(const ContextInterface& context)
    {
        return context.CurrentThreadId();
    }
    static Result<Procfs> ProcfsAccess(const ContextInterface& context)
    {
        return Procfs::Make(context);
    }
    static Result<Procfs> ProcfsAccess(const ContextInterface&&) = delete;
    static Result<std::uint64_t> ReadMountId(const Procfs& procfs, const Descriptor& descriptor, std::size_t byteCap)
    {
        return procfs.ReadMountId(descriptor, byteCap);
    }
    static void Dispose(Descriptor& owner) noexcept
    {
        Descriptor retired(std::move(owner)); // RAII lifetime boundary in tests only.
    }
    static int ConsumedDescriptor(const Descriptor& descriptor) noexcept
    {
        return descriptor.mDescriptor;
    }
    static int ConsumedProcfsRole(const Procfs& procfs, std::size_t index) noexcept
    {
        return procfs.mRoles[index].mDescriptor;
    }
};
} // namespace Tests
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_TESTS_DESCRIPTOR_TEST_ACCESS_H
