// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// C1 (Descriptor layer): Descriptor, ProcfsDescriptorAccess and the
// ContextInterface native boundary (minus the cursor seams, which are C4 --
// see FTWAccessCompileTest.cpp). Split from the former monolithic
// DescriptorAccessCompileTest.cpp (see PinAccessCompileTest.cpp,
// PathAccessCompileTest.cpp and FTWAccessCompileTest.cpp for the other
// layers); shared detection idioms live in AccessCompileTestSupport.h.

#include <AccessCompileTestSupport.h>
#include <ContextInterface.h>
#include <DescriptorTestAccess.h>
#include <MockContext.h>
#include <cstddef>
#include <filesystem/Descriptor.hpp>
#include <filesystem/FilesystemType.hpp>
#include <filesystem/ProcfsDescriptorAccess.hpp>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace
{
using ComplianceEngine::ContextInterface;
using ComplianceEngine::Filesystem::Type;
using ComplianceEngine::Filesystem::Detail::Descriptor;
using Procfs = ComplianceEngine::Filesystem::Detail::ProcfsDescriptorAccess;
using Profile = ContextInterface::OpenProfile;

static_assert(noexcept(std::declval<const ContextInterface&>().GetLogHandle()), "Logging access is nonthrowing");
static_assert(ComplianceEngine::Tests::DescriptorTestAccess::InternalCloseIsNoexcept(), "Private internal owner disposal is nonthrowing");
static_assert(!noexcept(ComplianceEngine::Tests::DescriptorTestAccess::CloseOwnedDescriptor(std::declval<const ContextInterface&>(), std::declval<Descriptor&>())),
    "Checked test native access can reject a consumed owner with logic_error");
static_assert(noexcept(std::declval<const MockContext&>().OpenNativePath("/", 0)), "Native open seam is nonthrowing");
static_assert(noexcept(std::declval<const MockContext&>().ReadNativeDescriptor(0, nullptr, 0)), "Native read seam is nonthrowing");
static_assert(noexcept(std::declval<const MockContext&>().CloseNativeDescriptor(0)), "Native close seam is nonthrowing");
static_assert(std::is_same<decltype(std::declval<const MockContext&>().CloseNativeDescriptor(0)), ComplianceEngine::Result<void>>::value,
    "Native descriptor close carries typed success or error");

DENY_CONTEXT_CALL(EmptyDescriptor, .EmptyDescriptor())
DENY_CONTEXT_CALL(HasValue, .HasValue())
DENY_CONTEXT_CALL(OpenAbsolutePin, .OpenAbsolutePin("/"))
DENY_CONTEXT_CALL(OpenAt, .OpenAt(std::declval<const Descriptor&>(), "child", Profile::PinChild))
DENY_CONTEXT_CALL(OpenFdinfo, .OpenFdinfo(std::declval<const Procfs&>(), std::declval<const Descriptor&>()))
DENY_CONTEXT_CALL(OpenAlias, .OpenAlias(std::declval<const Procfs&>(), std::declval<const Descriptor&>(), Type::RegularFile))
DENY_CONTEXT_CALL(OpenPinAlias, .OpenPinAlias(std::declval<const Procfs&>(), std::declval<const Descriptor&>(), Type::RegularFile))
DENY_CONTEXT_CALL(Duplicate, .Duplicate(std::declval<const Descriptor&>()))
DENY_CONTEXT_CALL(StatFile, .StatFile(std::declval<const Descriptor&>(), std::declval<struct stat*>()))
DENY_CONTEXT_CALL(StatFilesystem, .StatFilesystem(std::declval<const Descriptor&>(), std::declval<struct statfs*>()))
DENY_CONTEXT_CALL(ReadFile, .ReadFile(std::declval<const Descriptor&>(), std::declval<void*>(), std::size_t{}))
DENY_CONTEXT_CALL(ReadLink, .ReadLink(std::declval<const Descriptor&>(), std::declval<char*>(), std::size_t{}))
DENY_CONTEXT_CALL(StatusFlags, .StatusFlags(std::declval<const Descriptor&>()))
DENY_CONTEXT_CALL(DescriptorFlags, .DescriptorFlags(std::declval<const Descriptor&>()))
DENY_CONTEXT_CALL(ChownPinned, .ChownPinned(std::declval<const Descriptor&>(), uid_t{}, gid_t{}))
DENY_CONTEXT_CALL(ChmodAlias, .ChmodAlias(std::declval<const Procfs&>(), std::declval<const Descriptor&>(), mode_t{}))
DENY_CONTEXT_CALL(CloseOwnedDescriptor, .CloseOwnedDescriptor(std::declval<Descriptor&>()))
DENY_CONTEXT_CALL(CurrentProcessId, .CurrentProcessId())
DENY_CONTEXT_CALL(CurrentThreadId, .CurrentThreadId())
DENY_CONTEXT_CALL(OpenProcfsSelf, .OpenProcfsSelf(std::declval<const Descriptor&>()))
DENY_CONTEXT_CALL(OpenVerifiedAt, .OpenVerifiedAt(std::declval<const Descriptor&>(), "child", Profile::PinChild))
DENY_CONTEXT_CALL(ReserveManagedDescriptor, .ReserveManagedDescriptor())
DENY_CONTEXT_CALL(ReleaseManagedDescriptor, .ReleaseManagedDescriptor())
DENY_CONTEXT_CALL(OpenNativePath, .OpenNativePath("/", int{}))
DENY_CONTEXT_CALL(OpenNativeAt, .OpenNativeAt(int{}, "child", int{}))
DENY_CONTEXT_CALL(StatNativeDescriptor, .StatNativeDescriptor(int{}, std::declval<struct stat*>()))
DENY_CONTEXT_CALL(StatFilesystemDescriptor, .StatFilesystemDescriptor(int{}, std::declval<struct statfs*>()))
DENY_CONTEXT_CALL(ReadNativeDescriptor, .ReadNativeDescriptor(int{}, std::declval<void*>(), std::size_t{}))
DENY_CONTEXT_CALL(ReadLinkDescriptor, .ReadLinkDescriptor(int{}, std::declval<char*>(), std::size_t{}))
DENY_CONTEXT_CALL(StatusFlagsDescriptor, .StatusFlagsDescriptor(int{}))
DENY_CONTEXT_CALL(DescriptorFlagsDescriptor, .DescriptorFlagsDescriptor(int{}))
DENY_CONTEXT_CALL(DuplicateDescriptor, .DuplicateDescriptor(int{}))
DENY_CONTEXT_CALL(CloseNativeDescriptor, .CloseNativeDescriptor(int{}))
DENY_CONTEXT_CALL(ChownPinnedFileDescriptor, .ChownPinnedFileDescriptor(int{}, uid_t{}, gid_t{}))
DENY_CONTEXT_CALL(ChmodPinnedAlias, .ChmodPinnedAlias(int{}, "0", mode_t{}))
DENY_CONTEXT_CALL(NativeProcessId, .NativeProcessId())
DENY_CONTEXT_CALL(NativeThreadId, .NativeThreadId())
#undef DENY_CONTEXT_CALL

DENY_HELPER_CALL(IsProcfsDirectory, Detail::ProcfsDescriptorAccess, (std::declval<const ContextInterface&>(), std::declval<const Descriptor&>()))
DENY_HELPER_CALL(OpenVerifiedSelf, Detail::ProcfsDescriptorAccess, (std::declval<const ContextInterface&>(), pid_t{}))
DENY_HELPER_CALL(OpenVerifiedTid, Detail::ProcfsDescriptorAccess, (std::declval<const ContextInterface&>(), pid_t{}, pid_t{}))
DENY_HELPER_CALL(OpenVerifiedRoles, Detail::ProcfsDescriptorAccess, (std::declval<const ContextInterface&>(), std::declval<const Descriptor&>(), pid_t{}, pid_t{}))
DENY_HELPER_CALL(ReadMountIdBytes, Detail::ProcfsDescriptorAccess, (std::declval<const ContextInterface&>(), std::declval<const Descriptor&>(), std::size_t{}))
#undef DENY_HELPER_CALL

// Friend-context coverage for the private constructors/factories above that
// retain their `const ContextInterface&` argument (directly, or via a
// returned/stored owner): DescriptorTestAccess is a friend of Descriptor and
// ProcfsDescriptorAccess, so its exposed traits evaluate access with that
// friendship, unlike the DENY_HELPER_CALL probes above (which run outside
// every friend and so cannot tell "no access" apart from "deleted"). Each
// `*Lvalue` assertion is a positive control proving the probe really ran
// with friend access (not merely always-false); each `*Rvalue` assertion
// proves the matching deleted `const ContextInterface&&` overload is still
// rejected under that same access.
using TestAccess = ComplianceEngine::Tests::DescriptorTestAccess;
static_assert(TestAccess::DescriptorCtorLvalue, "Friend access must see Descriptor's private lvalue-context constructor as callable");
static_assert(!TestAccess::DescriptorCtorRvalue, "Descriptor's deleted rvalue-context constructor must stay rejected under friend access");
static_assert(TestAccess::ProcfsCtorLvalue, "Friend access must see ProcfsDescriptorAccess's private lvalue-context constructor as callable");
static_assert(!TestAccess::ProcfsCtorRvalue, "ProcfsDescriptorAccess's deleted rvalue-context constructor must stay rejected under friend access");
static_assert(TestAccess::OpenVerifiedSelfLvalue, "Friend access must see OpenVerifiedSelf's lvalue-context overload as callable");
static_assert(!TestAccess::OpenVerifiedSelfRvalue, "OpenVerifiedSelf's deleted rvalue-context overload must stay rejected under friend access");
static_assert(TestAccess::OpenVerifiedTidLvalue, "Friend access must see OpenVerifiedTid's lvalue-context overload as callable");
static_assert(!TestAccess::OpenVerifiedTidRvalue, "OpenVerifiedTid's deleted rvalue-context overload must stay rejected under friend access");
static_assert(TestAccess::OpenVerifiedRolesLvalue, "Friend access must see OpenVerifiedRoles's lvalue-context overload as callable");
static_assert(!TestAccess::OpenVerifiedRolesRvalue, "OpenVerifiedRoles's deleted rvalue-context overload must stay rejected under friend access");
static_assert(TestAccess::OpenProcfsSelfLvalue, "Friend access must see ContextInterface::OpenProcfsSelf's lvalue-context overload as callable");
static_assert(!TestAccess::OpenProcfsSelfRvalue,
    "ContextInterface::OpenProcfsSelf's deleted rvalue-context overload must stay rejected under friend access");
static_assert(TestAccess::OpenVerifiedAtLvalue, "Friend access must see ContextInterface::OpenVerifiedAt's lvalue-context overload as callable");
static_assert(!TestAccess::OpenVerifiedAtRvalue,
    "ContextInterface::OpenVerifiedAt's deleted rvalue-context overload must stay rejected under friend access");

// ReleaseOwned is a private non-static member of Descriptor (unlike
// RequireOwned, a .cpp-local anonymous-namespace function with no class
// membership at all, so there is nothing named on Descriptor to deny).
template <typename T, typename = void>
struct CanReleaseOwned : std::false_type
{
};
template <typename T>
struct CanReleaseOwned<T, typename Void<decltype(std::declval<T&>().ReleaseOwned())>::type> : std::true_type
{
};
static_assert(!CanReleaseOwned<Descriptor>::value, "ReleaseOwned must be Descriptor-private");

// ReadMountId is a private non-static member of ProcfsDescriptorAccess,
// callable only through its friend boundary (ContextInterface, Pin, Path,
// and the test-access friend), not by an ordinary caller holding a session
// by const reference.
#define DENY_PROCFS_MEMBER_CALL(name, arguments)                                                                                                       \
    template <typename T, typename = void>                                                                                                             \
    struct CanProcfsMember##name : std::false_type                                                                                                     \
    {                                                                                                                                                  \
    };                                                                                                                                                 \
    template <typename T>                                                                                                                              \
    struct CanProcfsMember##name<T, typename Void<decltype(std::declval<const T&>().name arguments)>::type> : std::true_type                           \
    {                                                                                                                                                  \
    };                                                                                                                                                 \
    static_assert(!CanProcfsMember##name<Procfs>::value, #name " must be ProcfsDescriptorAccess-private");

DENY_PROCFS_MEMBER_CALL(ReadMountId, (std::declval<const Descriptor&>(), std::size_t{}))
#undef DENY_PROCFS_MEMBER_CALL
// VerifyRole's own Role parameter is itself a private nested enum, the same
// obstacle ResolveInput's InputRole poses for Path (see PathAccessCompileTest.cpp):
// taking its address proves privacy without spelling Role.
DENY_PRIVATE_MEMBER_ADDRESS(VerifyRole, Procfs)

using Access = ComplianceEngine::Tests::DescriptorTestAccess;
CHECK_CONTEXT_FACTORY(OpenAbsolutePin, (std::declval<T>(), "/"))
CHECK_CONTEXT_FACTORY(OpenAt, (std::declval<T>(), std::declval<const Descriptor&>(), "child", Profile::PinChild))
CHECK_CONTEXT_FACTORY(OpenFdinfo, (std::declval<T>(), std::declval<const Procfs&>(), std::declval<const Descriptor&>()))
CHECK_CONTEXT_FACTORY(OpenAlias, (std::declval<T>(), std::declval<const Procfs&>(), std::declval<const Descriptor&>(), Type::RegularFile))
CHECK_CONTEXT_FACTORY(OpenPinAlias, (std::declval<T>(), std::declval<const Procfs&>(), std::declval<const Descriptor&>(), Type::RegularFile))
CHECK_CONTEXT_FACTORY(Duplicate, (std::declval<T>(), std::declval<const Descriptor&>()))
CHECK_CONTEXT_FACTORY(ProcfsAccess, (std::declval<T>()))
#undef CHECK_CONTEXT_FACTORY

template <typename T, typename = void>
struct CanConstructProcfs : std::false_type
{
};
template <typename T>
struct CanConstructProcfs<T, typename Void<decltype(T(std::declval<const ContextInterface&>()))>::type> : std::true_type
{
};
static_assert(!CanConstructProcfs<Procfs>::value, "Ordinary callers cannot create verified procfs authority");
static_assert(!std::is_constructible<Procfs, const ContextInterface&&>::value, "Temporary contexts cannot create verified procfs authority");
// Make is Procfs's own private factory, named directly rather than through
// construction syntax: the call form proves privacy without the ambiguity a
// member-pointer would hit against the overload set's deleted rvalue
// overload (decltype(&T::Make) cannot resolve between the two overloads).
template <typename T, typename = void>
struct CanCallProcfsMake : std::false_type
{
};
template <typename T>
struct CanCallProcfsMake<T, typename Void<decltype(T::Make(std::declval<const ContextInterface&>()))>::type> : std::true_type
{
};
static_assert(!CanCallProcfsMake<Procfs>::value, "Make must be ProcfsDescriptorAccess-private");
static_assert(std::is_nothrow_move_constructible<Procfs>::value && std::is_nothrow_move_assignable<Procfs>::value,
    "ProcfsDescriptorAccess move cannot throw (reference_wrapper context member)");

using D = ComplianceEngine::Filesystem::Detail::Descriptor;
static_assert(!std::is_copy_constructible<D>::value && !std::is_copy_assignable<D>::value, "Descriptor is unique");
static_assert(std::is_nothrow_move_constructible<D>::value && std::is_nothrow_move_assignable<D>::value, "Descriptor move cannot throw");
static_assert(std::is_assignable<D&, D&&>::value && !std::is_assignable<D&&, D&&>::value && std::is_nothrow_move_assignable<D>::value,
    "Descriptor assignment requires an lvalue and cannot throw");
static_assert(std::is_nothrow_destructible<D>::value, "Descriptor cleanup is diagnostic-only RAII");
static_assert(!std::is_default_constructible<D>::value && !std::is_copy_constructible<D>::value && std::is_nothrow_move_constructible<D>::value,
    "Descriptor has one owner or is consumed");
template <typename T, typename = void>
struct CanDescriptorHasValue : std::false_type
{
};
template <typename T>
struct CanDescriptorHasValue<T, typename Void<decltype(std::declval<T&>().HasValue())>::type> : std::true_type
{
};
static_assert(!CanDescriptorHasValue<D>::value, "No empty Descriptor API");
static_assert(!CanCloseComponent<D>::value, "Unique owners cannot explicitly close");
static_assert(std::is_nothrow_destructible<D>::value, "Owner disposal is noexcept");
static_assert(!std::is_constructible<D, const ContextInterface&, int>::value, "Native adoption is private to the verified boundary");
template <typename T, typename = void>
struct CanRawGet : std::false_type
{
};
template <typename T>
struct CanRawGet<T, typename Void<decltype(std::declval<T&>().Get())>::type> : std::true_type
{
};
template <typename T, typename = void>
struct CanRawRelease : std::false_type
{
};
template <typename T>
struct CanRawRelease<T, typename Void<decltype(std::declval<T&>().Release())>::type> : std::true_type
{
};
static_assert(!CanRawGet<D>::value && !CanRawRelease<D>::value, "No public native descriptor accessor");

} // namespace
