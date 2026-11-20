// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <ContextInterface.h>
#include <DescriptorTestAccess.h>
#include <MockContext.h>
#include <PathTestAccess.h>
#include <cstddef>
#include <filesystem/Descriptor.hpp>
#include <filesystem/FilesystemCollection.hpp>
#include <filesystem/LinesRange.hpp>
#include <filesystem/Path.hpp>
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
using Handle = ComplianceEngine::Filesystem::Detail::Handle;
using Profile = ContextInterface::OpenProfile;

static_assert(noexcept(std::declval<const ContextInterface&>().GetLogHandle()), "Logging access is nonthrowing");
static_assert(ComplianceEngine::Tests::DescriptorTestAccess::InternalCloseIsNoexcept(), "Private internal owner disposal is nonthrowing");
static_assert(!noexcept(ComplianceEngine::Tests::DescriptorTestAccess::CloseOwnedDescriptor(std::declval<const ContextInterface&>(), std::declval<Descriptor&>())),
    "Checked test native access can reject a consumed owner with logic_error");
static_assert(noexcept(std::declval<const MockContext&>().OpenNativePath("/", 0)), "Native open seam is nonthrowing");
static_assert(noexcept(std::declval<const MockContext&>().ReadFileDescriptor(0, nullptr, 0)), "Native read seam is nonthrowing");
static_assert(noexcept(std::declval<const MockContext&>().CloseFileDescriptor(0)), "Native close seam is nonthrowing");
static_assert(noexcept(std::declval<const MockContext&>().CloseDirectory(nullptr)), "Native cursor close seam is nonthrowing");
static_assert(std::is_same<decltype(std::declval<const MockContext&>().CloseFileDescriptor(0)), ComplianceEngine::Result<void>>::value,
    "Native descriptor close carries typed success or error");
static_assert(std::is_same<decltype(std::declval<const MockContext&>().CloseDirectory(nullptr)), ComplianceEngine::Result<void>>::value,
    "Native directory close carries typed success or error");

// These unevaluated C++11 expressions are outside every wrapper and test friend.
// Private typed authority and protected native overrides must not be callable.
template <typename...>
struct Void
{
    using type = void;
};

#define DENY_CONTEXT_CALL(name, expression)                                                                                                            \
    template <typename T, typename = void>                                                                                                             \
    struct Can##name : std::false_type                                                                                                                 \
    {                                                                                                                                                  \
    };                                                                                                                                                 \
    template <typename T>                                                                                                                              \
    struct Can##name<T, typename Void<decltype(std::declval<T&>() expression)>::type> : std::true_type                                                 \
    {                                                                                                                                                  \
    };                                                                                                                                                 \
    static_assert(!Can##name<const ContextInterface>::value, #name " must not be accessible to ordinary callers");

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
DENY_CONTEXT_CALL(OpenDirectoryCursor, .OpenDirectoryCursor(std::declval<Descriptor&&>()))
DENY_CONTEXT_CALL(CloseOwnedDescriptor, .CloseOwnedDescriptor(std::declval<Descriptor&>()))
DENY_CONTEXT_CALL(CurrentProcessId, .CurrentProcessId())
DENY_CONTEXT_CALL(CurrentThreadId, .CurrentThreadId())
DENY_CONTEXT_CALL(OpenProcfsSelf, .OpenProcfsSelf(std::declval<const Descriptor&>()))
DENY_CONTEXT_CALL(OpenVerifiedAt, .OpenVerifiedAt(std::declval<const Descriptor&>(), "child", Profile::PinChild))
DENY_CONTEXT_CALL(CloseOwnedDirectoryCursor, .CloseOwnedDirectoryCursor(std::declval<DIR*>()))
DENY_CONTEXT_CALL(ReserveManagedDescriptor, .ReserveManagedDescriptor())
DENY_CONTEXT_CALL(ReleaseManagedDescriptor, .ReleaseManagedDescriptor())
DENY_CONTEXT_CALL(OpenNativePath, .OpenNativePath("/", int{}))
DENY_CONTEXT_CALL(OpenNativeAt, .OpenNativeAt(int{}, "child", int{}))
DENY_CONTEXT_CALL(StatFileDescriptor, .StatFileDescriptor(int{}, std::declval<struct stat*>()))
DENY_CONTEXT_CALL(StatFilesystemDescriptor, .StatFilesystemDescriptor(int{}, std::declval<struct statfs*>()))
DENY_CONTEXT_CALL(ReadFileDescriptor, .ReadFileDescriptor(int{}, std::declval<void*>(), std::size_t{}))
DENY_CONTEXT_CALL(ReadLinkDescriptor, .ReadLinkDescriptor(int{}, std::declval<char*>(), std::size_t{}))
DENY_CONTEXT_CALL(StatusFlagsDescriptor, .StatusFlagsDescriptor(int{}))
DENY_CONTEXT_CALL(DescriptorFlagsDescriptor, .DescriptorFlagsDescriptor(int{}))
DENY_CONTEXT_CALL(DuplicateDescriptor, .DuplicateDescriptor(int{}))
DENY_CONTEXT_CALL(FdOpenDirectory, .FdOpenDirectory(int{}))
DENY_CONTEXT_CALL(CloseFileDescriptor, .CloseFileDescriptor(int{}))
DENY_CONTEXT_CALL(ChownPinnedFileDescriptor, .ChownPinnedFileDescriptor(int{}, uid_t{}, gid_t{}))
DENY_CONTEXT_CALL(ChmodPinnedAlias, .ChmodPinnedAlias(int{}, "0", mode_t{}))
DENY_CONTEXT_CALL(NativeProcessId, .NativeProcessId())
DENY_CONTEXT_CALL(NativeThreadId, .NativeThreadId())
#undef DENY_CONTEXT_CALL

// The implementation helpers are private to the owning wrappers, even if an
// ordinary caller is handed a Descriptor and a verified procfs session.
#define DENY_HELPER_CALL(name, wrapper, arguments)                                                                                                     \
    template <typename T, typename = void>                                                                                                             \
    struct CanHelper##name : std::false_type                                                                                                           \
    {                                                                                                                                                  \
    };                                                                                                                                                 \
    template <typename T>                                                                                                                              \
    struct CanHelper##name<T, typename Void<decltype(T::name arguments)>::type> : std::true_type                                                       \
    {                                                                                                                                                  \
    };                                                                                                                                                 \
    static_assert(!CanHelper##name<ComplianceEngine::Filesystem::wrapper>::value, #name " must be wrapper-private");

DENY_HELPER_CALL(ActivateReadOnly, Detail::Handle,
    (std::declval<const ContextInterface&>(), std::declval<const Descriptor&>(), std::declval<const struct stat&>(), Type::RegularFile))
DENY_HELPER_CALL(OpenAndVerifyAlias, Detail::Handle,
    (std::declval<const ContextInterface&>(), std::declval<const Procfs&>(), std::declval<const Descriptor&>(), std::declval<const struct stat&>(), Type::RegularFile))
DENY_HELPER_CALL(AcquirePinnedObject, Detail::Handle,
    (std::declval<const ContextInterface&>(), std::declval<Descriptor>(), std::size_t{}, std::declval<const char*>()))
DENY_HELPER_CALL(ReadPinnedLink, Path, (std::declval<const Descriptor&>(), std::size_t{}))
DENY_HELPER_CALL(ReadVerifiedLinkText, Path, (std::declval<const Descriptor&>(), std::declval<const struct stat&>(), std::size_t{}))
// Handle::Impl/Path::Impl/ProcfsDescriptorAccess::Impl do not exist as
// wrapper types (no CanNameImpl target exists for any of these classes;
// see below); each helper below is a direct private static member of its
// narrowest friended owner, covered here individually.
DENY_HELPER_CALL(Inspect, Detail::Handle, (std::declval<const Handle&>()))
DENY_HELPER_CALL(SetModeWithProcfs, Detail::Handle, (std::declval<const Handle&>(), std::declval<const Procfs&>(), mode_t{}))
DENY_HELPER_CALL(PinProcessRoot, Detail::Handle, (std::declval<const ContextInterface&>(), std::declval<ComplianceEngine::Filesystem::PrefixLimits>()))
DENY_HELPER_CALL(MakeRootComponent, Path, (std::declval<ComplianceEngine::Filesystem::Detail::Handle>()))
DENY_HELPER_CALL(SameAcquisition, Path::Component,
    (std::declval<const ComplianceEngine::Filesystem::Path::Component&>(), std::declval<const ComplianceEngine::Filesystem::Path::Component&>()))
DENY_HELPER_CALL(LookupNameBytes, Path::Component, (std::declval<const ComplianceEngine::Filesystem::Path::Component&>()))
DENY_HELPER_CALL(EffectiveNameBytes, Path::Component, (std::declval<const ComplianceEngine::Filesystem::Path::Component&>()))
DENY_HELPER_CALL(LookupName, Path::Component, (std::declval<const ComplianceEngine::Filesystem::Path::Component&>()))
DENY_HELPER_CALL(EffectiveName, Path::Component, (std::declval<const ComplianceEngine::Filesystem::Path::Component&>()))
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
// Path::ResolveInput's own parameter list names Path::InputRole, itself a
// private nested enum: no external expression can spell the matching call
// overload, so DENY_HELPER_CALL's call-syntax detection does not apply here.
// Taking the member's address only needs its name, not its parameter types,
// and forming the address of a private member still triggers access control
// in an unevaluated SFINAE context, so this proves privacy without ever
// spelling InputRole.
#define DENY_PRIVATE_MEMBER_ADDRESS(name, Owner)                                                                                                       \
    template <typename T, typename = void>                                                                                                             \
    struct CanName##name : std::false_type                                                                                                             \
    {                                                                                                                                                  \
    };                                                                                                                                                 \
    template <typename T>                                                                                                                              \
    struct CanName##name<T, typename Void<decltype(&T::name)>::type> : std::true_type                                                                  \
    {                                                                                                                                                  \
    };                                                                                                                                                 \
    static_assert(!CanName##name<Owner>::value, #name " must be " #Owner "-private");

DENY_PRIVATE_MEMBER_ADDRESS(ResolveInput, ComplianceEngine::Filesystem::Path)
#undef DENY_PRIVATE_MEMBER_ADDRESS
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

// ReadMountId and VerifyRole are private non-static members of
// ProcfsDescriptorAccess, callable only through its friend boundary
// (ContextInterface, Handle, Path, and the test-access friend), not by an
// ordinary caller holding a session by const reference.
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
// obstacle ResolveInput's InputRole posed above: taking its address proves
// privacy without spelling Role.
#define DENY_PRIVATE_MEMBER_ADDRESS(name, Owner)                                                                                                       \
    template <typename T, typename = void>                                                                                                             \
    struct CanName##name : std::false_type                                                                                                             \
    {                                                                                                                                                  \
    };                                                                                                                                                 \
    template <typename T>                                                                                                                              \
    struct CanName##name<T, typename Void<decltype(&T::name)>::type> : std::true_type                                                                  \
    {                                                                                                                                                  \
    };                                                                                                                                                 \
    static_assert(!CanName##name<Owner>::value, #name " must be " #Owner "-private");

DENY_PRIVATE_MEMBER_ADDRESS(VerifyRole, Procfs)
#undef DENY_PRIVATE_MEMBER_ADDRESS

using Access = ComplianceEngine::Tests::DescriptorTestAccess;
// The bridge must not erase the context factory lvalue requirement through
// a const base reference. Check both base and actual concrete MockContext.
#define CHECK_CONTEXT_FACTORY(name, arguments)                                                                                                         \
    template <typename T, typename = void>                                                                                                             \
    struct CanBridge##name : std::false_type                                                                                                           \
    {                                                                                                                                                  \
    };                                                                                                                                                 \
    template <typename T>                                                                                                                              \
    struct CanBridge##name<T, typename Void<decltype(Access::name arguments)>::type> : std::true_type                                                  \
    {                                                                                                                                                  \
    };                                                                                                                                                 \
    static_assert(CanBridge##name<ContextInterface&>::value && CanBridge##name<const ContextInterface&>::value, #name " must accept base lvalues");    \
    static_assert(CanBridge##name<MockContext&>::value && CanBridge##name<const MockContext&>::value, #name " must accept concrete lvalues");          \
    static_assert(!CanBridge##name<ContextInterface&&>::value && !CanBridge##name<const ContextInterface&&>::value,                                    \
        #name " must reject base temporaries");                                                                                                        \
    static_assert(!CanBridge##name<MockContext&&>::value && !CanBridge##name<const MockContext&&>::value, #name " must reject concrete temporaries");

CHECK_CONTEXT_FACTORY(OpenAbsolutePin, (std::declval<T>(), "/"))
CHECK_CONTEXT_FACTORY(OpenAt, (std::declval<T>(), std::declval<const Descriptor&>(), "child", Profile::PinChild))
CHECK_CONTEXT_FACTORY(OpenFdinfo, (std::declval<T>(), std::declval<const Procfs&>(), std::declval<const Descriptor&>()))
CHECK_CONTEXT_FACTORY(OpenAlias, (std::declval<T>(), std::declval<const Procfs&>(), std::declval<const Descriptor&>(), Type::RegularFile))
CHECK_CONTEXT_FACTORY(OpenPinAlias, (std::declval<T>(), std::declval<const Procfs&>(), std::declval<const Descriptor&>(), Type::RegularFile))
CHECK_CONTEXT_FACTORY(Duplicate, (std::declval<T>(), std::declval<const Descriptor&>()))
CHECK_CONTEXT_FACTORY(OpenDirectoryCursor, (std::declval<T>(), std::declval<Descriptor&&>()))
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
} // namespace

namespace
{
using C = ComplianceEngine::Filesystem::Path::Component;
using D = ComplianceEngine::Filesystem::Detail::Descriptor;
using M = ComplianceEngine::Filesystem::Metadata;
using H = ComplianceEngine::Filesystem::Detail::Handle;
static_assert(!std::is_default_constructible<C>::value, "Component requires a complete acquisition");
static_assert(std::is_nothrow_copy_constructible<C>::value && std::is_nothrow_copy_assignable<C>::value, "Shared acquisition copy cannot throw");
static_assert(std::is_nothrow_move_constructible<C>::value && std::is_nothrow_move_assignable<C>::value, "Move-as-copy cannot throw");
static_assert(!std::is_copy_constructible<D>::value && !std::is_copy_assignable<D>::value, "Descriptor is unique");
static_assert(std::is_nothrow_move_constructible<D>::value && std::is_nothrow_move_assignable<D>::value, "Descriptor move cannot throw");
static_assert(std::is_same<decltype(std::declval<const C&>().Metadata()), M>::value, "Acquisition metadata owns its provenance");
static_assert(!noexcept(std::declval<const C&>().Metadata()), "Copying names may allocate");
static_assert(std::is_same<decltype(std::declval<const ComplianceEngine::Filesystem::Path&>().Limits()), ComplianceEngine::Filesystem::ResolverLimits>::value,
    "Limits are a value");
using R = ComplianceEngine::Filesystem::ReadableFile;
using Cursor = ComplianceEngine::Filesystem::FTW::Detail::DirectoryCursor;
using P = ComplianceEngine::Filesystem::Path;
using Lines = ComplianceEngine::Filesystem::LinesRange;
static_assert(std::is_assignable<D&, D&&>::value && !std::is_assignable<D&&, D&&>::value && std::is_nothrow_move_assignable<D>::value,
    "Descriptor assignment requires an lvalue and cannot throw");
static_assert(std::is_assignable<R&, R&&>::value && !std::is_assignable<R&&, R&&>::value && std::is_nothrow_move_assignable<R>::value,
    "Reader assignment requires an lvalue and cannot throw");
static_assert(std::is_assignable<Cursor&, Cursor&&>::value && !std::is_assignable<Cursor&&, Cursor&&>::value && std::is_nothrow_move_assignable<Cursor>::value,
    "Cursor assignment requires an lvalue and cannot throw");
static_assert(std::is_nothrow_move_constructible<Cursor>::value, "Cursor move construction cannot throw (reference_wrapper context member)");
static_assert(std::is_assignable<P&, P&&>::value && !std::is_assignable<P&&, P&&>::value && std::is_nothrow_move_assignable<P>::value,
    "Path assignment requires an lvalue and cannot throw");
static_assert(!std::is_convertible<ComplianceEngine::Filesystem::LookupMountId, ComplianceEngine::Filesystem::TargetMountId>::value,
    "Lookup and target mounts are distinct");
static_assert(!std::is_convertible<ComplianceEngine::Filesystem::UserId, ComplianceEngine::Filesystem::GroupId>::value,
    "Ownership arguments are distinct");
static_assert(std::is_nothrow_destructible<D>::value, "Descriptor cleanup is diagnostic-only RAII");
template <typename T, typename = void>
struct CanCloseComponent : std::false_type
{
};
template <typename T>
struct CanCloseComponent<T, typename Void<decltype(std::declval<T&>().Close())>::type> : std::true_type
{
};
template <typename T, typename = void>
struct CanTestComponentValue : std::false_type
{
};
template <typename T>
struct CanTestComponentValue<T, typename Void<decltype(std::declval<T&>().HasValue())>::type> : std::true_type
{
};
template <typename T, typename = void>
struct CanBorrowPin : std::false_type
{
};
template <typename T>
struct CanBorrowPin<T, typename Void<decltype(std::declval<T&>().Pin())>::type> : std::true_type
{
};
static_assert(!CanCloseComponent<C>::value && !CanTestComponentValue<C>::value && !CanBorrowPin<C>::value,
    "Shared acquisition never exposes empty state, native pin or checked close");
static_assert(std::is_same<decltype(std::declval<const P&>().Root()), C>::value && std::is_same<decltype(std::declval<const P&>().Leaf()), C>::value,
    "Path gives owning pin values");
// ADR-0048 Decision 2: a moved-from Path diagnoses with std::logic_error
// before any other validation or native dispatch, so these six accessors
// (noexcept before ADR-0048) cannot stay noexcept -- a noexcept function that
// throws terminates the process.
static_assert(!noexcept(std::declval<const P&>().Root()) && !noexcept(std::declval<const P&>().Leaf()) && !noexcept(std::declval<const P&>().Size()) &&
                  !noexcept(std::declval<const P&>().RetainedDescriptors()) && !noexcept(std::declval<const P&>().Limits()) &&
                  !noexcept(std::declval<const P&>().Context()),
    "A moved-from Path's checked accessors cannot be noexcept (ADR-0048)");
using Step = P::Step;
static_assert(!std::is_default_constructible<P>::value && !std::is_copy_constructible<P>::value && std::is_nothrow_move_constructible<P>::value &&
                  std::is_nothrow_move_assignable<P>::value,
    "Path always owns a nonempty snapshot even after moving");
static_assert(!std::is_default_constructible<Step>::value && !std::is_copy_constructible<Step>::value &&
                  std::is_nothrow_move_constructible<Step>::value && std::is_nothrow_move_assignable<Step>::value,
    "A delta owns its pins, including after moving");
static_assert(std::is_same<decltype(std::declval<const Step&>().Target()), C>::value && std::is_same<decltype(std::declval<const Step&>().Metadata()), M>::value,
    "Step publishes owned components and detached facts");
// ADR-0048 Decision 2: a moved-from Step diagnoses the same way; Target and
// RetainedDescriptors were noexcept before ADR-0048 and cannot stay so.
static_assert(!noexcept(std::declval<const Step&>().Target()) && !noexcept(std::declval<const Step&>().RetainedDescriptors()),
    "A moved-from Step's checked accessors cannot be noexcept (ADR-0048)");
static_assert(std::is_same<decltype(std::declval<const P&>().Resolve(std::string{}, P::Policy{})), ComplianceEngine::Result<ComplianceEngine::Variant<Step, P::RejectionReason>>>::value,
    "Resolve returns an owning delta or a rejection");
static_assert(std::is_same<decltype(std::declval<P&>().Apply(std::declval<Step&&>())), ComplianceEngine::Result<Step>>::value &&
                  std::is_same<decltype(std::declval<P&>().Freeze()), ComplianceEngine::Result<bool>>::value,
    "Mutators operate on an lvalue Path");
#define DENY_PATH_MEMBER(name, expression)                                                                                                             \
    template <typename T, typename = void>                                                                                                             \
    struct Can##name : std::false_type                                                                                                                 \
    {                                                                                                                                                  \
    };                                                                                                                                                 \
    template <typename T>                                                                                                                              \
    struct Can##name<T, typename Void<decltype(std::declval<T>() expression)>::type> : std::true_type                                                  \
    {                                                                                                                                                  \
    };                                                                                                                                                 \
    static_assert(!Can##name<P&>::value, #name " is not public");
DENY_PATH_MEMBER(Push, .Push(std::string{}, P::Policy{}))
DENY_PATH_MEMBER(Pop, .Pop())
DENY_PATH_MEMBER(AcquireChild, .AcquireChild(std::string{}, P::Policy{}))
DENY_PATH_MEMBER(IsFrozen, .IsFrozen())
DENY_PATH_MEMBER(Components, .Components())
DENY_PATH_MEMBER(Pin, .Pin())
// LookupName/ToString are private outside the PathTestAccess friend.
DENY_PATH_MEMBER(LookupName, .LookupName())
DENY_PATH_MEMBER(ToString, .ToString())
#undef DENY_PATH_MEMBER
template <typename T, typename = void>
struct CanFreeze : std::false_type
{
};
template <typename T>
struct CanFreeze<T, typename Void<decltype(std::declval<T>().Freeze())>::type> : std::true_type
{
};
template <typename T, typename = void>
struct CanApply : std::false_type
{
};
template <typename T>
struct CanApply<T, typename Void<decltype(std::declval<T>().Apply(std::declval<Step&&>()))>::type> : std::true_type
{
};
static_assert(CanFreeze<P&>::value && !CanFreeze<P&&>::value && CanApply<P&>::value && !CanApply<P&&>::value, "Path mutation requires an lvalue owner");
template <typename T, typename = void>
struct CanMake : std::false_type
{
};
template <typename T>
struct CanMake<T, typename Void<decltype(P::Make(std::declval<T>(), std::string{}, P::Policy{}, ComplianceEngine::Filesystem::ResolverLimits{}))>::type>
    : std::true_type
{
};
static_assert(CanMake<const ContextInterface&>::value && !CanMake<const ContextInterface&&>::value, "A Path cannot retain a temporary context");
// LinesRange::Make retains the context through the ReadableFile/Descriptor it
// activates; both overloads must reject a temporary the same way Path::Make does.
template <typename T, typename = void>
struct CanMakeLines : std::false_type
{
};
template <typename T>
struct CanMakeLines<T, typename Void<decltype(Lines::Make(std::declval<T>(), std::string{}))>::type> : std::true_type
{
};
template <typename T, typename = void>
struct CanMakeLinesWithPolicy : std::false_type
{
};
template <typename T>
struct CanMakeLinesWithPolicy<T, typename Void<decltype(Lines::Make(std::declval<T>(), std::string{}, Lines::Policy{}))>::type> : std::true_type
{
};
static_assert(CanMakeLines<const ContextInterface&>::value && !CanMakeLines<const ContextInterface&&>::value,
    "A LinesRange cannot retain a temporary context (path-only overload)");
static_assert(CanMakeLinesWithPolicy<const ContextInterface&>::value && !CanMakeLinesWithPolicy<const ContextInterface&&>::value,
    "A LinesRange cannot retain a temporary context (path+policy overload)");
// LinesRange::Iterator is move-only and single-pass; every observed use
// increments or assigns an lvalue (range-for, LinesRangeTest). &-qualifying
// operator++ and operator=(Iterator&&) removes only the dangling
// `auto& it = ++range.begin();` form -- the lvalue forms stay well-formed.
template <typename T, typename = void>
struct CanIncrementIterator : std::false_type
{
};
template <typename T>
struct CanIncrementIterator<T, typename Void<decltype(++std::declval<T>())>::type> : std::true_type
{
};
static_assert(CanIncrementIterator<Lines::Iterator&>::value, "An lvalue LinesRange::Iterator can be incremented");
static_assert(!CanIncrementIterator<Lines::Iterator&&>::value, "A temporary LinesRange::Iterator cannot be incremented");
template <typename T, typename = void>
struct CanMoveAssignIntoIterator : std::false_type
{
};
template <typename T>
struct CanMoveAssignIntoIterator<T, typename Void<decltype(std::declval<T>() = std::declval<Lines::Iterator&&>())>::type> : std::true_type
{
};
static_assert(CanMoveAssignIntoIterator<Lines::Iterator&>::value, "An lvalue LinesRange::Iterator accepts move assignment");
static_assert(!CanMoveAssignIntoIterator<Lines::Iterator&&>::value, "A temporary LinesRange::Iterator cannot be the target of move assignment");
// FilesystemCollectionEntry::operator=(FilesystemCollectionEntry&&)
// is &-qualified the same way, for the same reason -- no observed caller
// assigns into a temporary, and a borrowed *this could otherwise dangle.
using Entry = ComplianceEngine::Filesystem::FilesystemCollectionEntry;
template <typename T, typename = void>
struct CanMoveAssignIntoEntry : std::false_type
{
};
template <typename T>
struct CanMoveAssignIntoEntry<T, typename Void<decltype(std::declval<T>() = std::declval<Entry&&>())>::type> : std::true_type
{
};
static_assert(CanMoveAssignIntoEntry<Entry&>::value, "An lvalue FilesystemCollectionEntry accepts move assignment");
static_assert(!CanMoveAssignIntoEntry<Entry&&>::value, "A temporary FilesystemCollectionEntry cannot be the target of move assignment");
// FilesystemCollectionEntry completes its rule of five (destructor
// `= default`); it stays move-only and nonthrowing to move or assign.
static_assert(!std::is_copy_constructible<Entry>::value && !std::is_copy_assignable<Entry>::value, "FilesystemCollectionEntry is move-only");
static_assert(std::is_nothrow_move_constructible<Entry>::value && std::is_nothrow_move_assignable<Entry>::value,
    "FilesystemCollectionEntry moves without throwing");
// OwnComponent is callable only by the traversal code that produces
// entries (FTW::FileRange, including its nested State), never by an
// ordinary caller holding a FilesystemCollectionEntry.
template <typename T, typename = void>
struct CanOwnComponent : std::false_type
{
};
template <typename T>
struct CanOwnComponent<T, typename Void<decltype(std::declval<T&>().OwnComponent(std::declval<C>()))>::type> : std::true_type
{
};
static_assert(!CanOwnComponent<Entry>::value, "OwnComponent must be traversal-private");
// Handle and Path::Component each merge their two OpenReadOnly
// overloads into one, defaulting the Policy, so both call forms below name
// the same declaration.
static_assert(std::is_same<decltype(std::declval<const H&>().OpenReadOnly()), ComplianceEngine::Result<R>>::value &&
                  std::is_same<decltype(std::declval<const H&>().OpenReadOnly(R::Policy{})), ComplianceEngine::Result<R>>::value,
    "Handle::OpenReadOnly is one overload with a default Policy");
static_assert(std::is_same<decltype(std::declval<const C&>().OpenReadOnly()), ComplianceEngine::Result<R>>::value &&
                  std::is_same<decltype(std::declval<const C&>().OpenReadOnly(R::Policy{})), ComplianceEngine::Result<R>>::value,
    "Path::Component::OpenReadOnly is one overload with a default Policy");
// Path::LookupName()/ToString() are private, no production caller
// (logging included); the bounded-authority PathTestAccess friend is the
// only caller left, so these are checked through it, not through P directly.
static_assert(std::is_same<decltype(ComplianceEngine::Tests::PathTestAccess::LookupName(std::declval<const P&>())), std::string>::value &&
                  std::is_same<decltype(ComplianceEngine::Tests::PathTestAccess::ToString(std::declval<const P&>())), std::string>::value,
    "Names are returned by owning value, not borrowed storage");
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
static_assert(!CanCloseComponent<D>::value && !CanCloseComponent<H>::value, "Unique owners cannot explicitly close");
static_assert(std::is_nothrow_destructible<D>::value && std::is_nothrow_destructible<H>::value && std::is_nothrow_destructible<C>::value,
    "Owner disposal is noexcept");
static_assert(std::is_nothrow_move_constructible<H>::value && std::is_nothrow_move_assignable<H>::value, "Handle transfers without copying names");
static_assert(std::is_same<decltype(std::declval<const H&>().Metadata()), M>::value && !noexcept(std::declval<const H&>().Metadata()) &&
                  std::is_same<decltype(std::declval<const Step&>().Metadata()), M>::value && !noexcept(std::declval<const Step&>().Metadata()),
    "Handle and Step produce owning fallible metadata copies");
static_assert(!std::is_default_constructible<M>::value, "Metadata cannot be fabricated");
static_assert(!std::is_constructible<ComplianceEngine::Filesystem::LookupMountId, std::uint64_t>::value &&
                  !std::is_constructible<ComplianceEngine::Filesystem::TargetMountId, std::uint64_t>::value,
    "Mount provenance is sealed");
static_assert(std::is_constructible<ComplianceEngine::Filesystem::UserId, uid_t>::value &&
                  std::is_constructible<ComplianceEngine::Filesystem::GroupId, gid_t>::value &&
                  !std::is_convertible<uid_t, ComplianceEngine::Filesystem::UserId>::value &&
                  !std::is_convertible<gid_t, ComplianceEngine::Filesystem::GroupId>::value,
    "Caller-supplied identity is explicit");
static_assert(!std::is_constructible<ComplianceEngine::Filesystem::Detail::LookupSpelling, std::string>::value &&
                  !std::is_constructible<ComplianceEngine::Filesystem::Detail::EffectiveSpelling, std::string>::value,
    "Acquisition names are sealed");
static_assert(!std::is_convertible<ComplianceEngine::Filesystem::LookupMountId, ComplianceEngine::Filesystem::TargetMountId>::value &&
                  !std::is_convertible<ComplianceEngine::Filesystem::Detail::LookupSpelling, ComplianceEngine::Filesystem::Detail::EffectiveSpelling>::value,
    "Lookup and target roles cannot be interchanged");
template <typename T, typename = void>
struct CanOpenChildren : std::false_type
{
};
template <typename T>
struct CanOpenChildren<T, typename Void<decltype(std::declval<T&>().OpenChildren())>::type> : std::true_type
{
};
template <typename T, typename = void>
struct CanOldAcquired : std::false_type
{
};
template <typename T>
struct CanOldAcquired<T, typename Void<decltype(std::declval<T&>().Acquired())>::type> : std::true_type
{
};
template <typename T, typename = void>
struct CanOldLookup : std::false_type
{
};
template <typename T>
struct CanOldLookup<T, typename Void<decltype(std::declval<T&>().LookupName())>::type> : std::true_type
{
};
template <typename T, typename = void>
struct CanOldEffective : std::false_type
{
};
template <typename T>
struct CanOldEffective<T, typename Void<decltype(std::declval<T&>().EffectiveName())>::type> : std::true_type
{
};
// No class in this module defines a struct/class named Impl (see the
// DENY_HELPER_CALL entries above for Descriptor's, Handle's, Path's,
// Path::Component's, and ProcfsDescriptorAccess's private members).
// DirectoryCursor's own helper, OpenChildren, is a plain private static
// member declared directly on DirectoryCursor, checked the same way below.
template <typename T, typename = void>
struct CanHelperOpenChildren : std::false_type
{
};
template <typename T>
struct CanHelperOpenChildren<T, typename Void<decltype(T::OpenChildren(std::declval<C>()))>::type> : std::true_type
{
};
static_assert(!CanOpenChildren<C>::value && !CanOpenChildren<H>::value, "Directory enumeration is FTW-only");
static_assert(!CanOldAcquired<C>::value && !CanOldAcquired<H>::value && !CanOldAcquired<Step>::value, "No duplicate observation API");
static_assert(!CanOldLookup<C>::value && !CanOldLookup<H>::value && !CanOldEffective<C>::value && !CanOldEffective<H>::value,
    "Acquisition names live in immutable metadata");
static_assert(!CanHelperOpenChildren<Cursor>::value, "OpenChildren must be wrapper-private");
static_assert(!std::is_constructible<D, const ContextInterface&, int>::value && !std::is_constructible<H, D&&>::value,
    "Native adoption is private to the verified boundary");
static_assert(!std::is_constructible<M, ComplianceEngine::Filesystem::Type, const struct stat&, ComplianceEngine::Filesystem::LookupMountId, ComplianceEngine::Filesystem::TargetMountId,
                  ComplianceEngine::Filesystem::Detail::LookupSpelling, ComplianceEngine::Filesystem::Detail::EffectiveSpelling>::value,
    "Raw callers cannot mint an acquisition observation");
// Non-const data members: provenance stays sealed by private constructors and
// friendship, not by const members, so these seven types keep assignment and
// move without throwing.
static_assert(std::is_copy_assignable<ComplianceEngine::Filesystem::LookupMountId>::value &&
                  std::is_copy_assignable<ComplianceEngine::Filesystem::TargetMountId>::value &&
                  std::is_copy_assignable<ComplianceEngine::Filesystem::UserId>::value && std::is_copy_assignable<ComplianceEngine::Filesystem::GroupId>::value &&
                  std::is_copy_assignable<ComplianceEngine::Filesystem::Detail::LookupSpelling>::value &&
                  std::is_copy_assignable<ComplianceEngine::Filesystem::Detail::EffectiveSpelling>::value && std::is_copy_assignable<M>::value,
    "Identity and names are copy/move assignable, not const-sealed");
static_assert(std::is_nothrow_move_constructible<ComplianceEngine::Filesystem::LookupMountId>::value &&
                  std::is_nothrow_move_assignable<ComplianceEngine::Filesystem::LookupMountId>::value &&
                  std::is_nothrow_move_constructible<ComplianceEngine::Filesystem::TargetMountId>::value &&
                  std::is_nothrow_move_assignable<ComplianceEngine::Filesystem::TargetMountId>::value &&
                  std::is_nothrow_move_constructible<ComplianceEngine::Filesystem::UserId>::value &&
                  std::is_nothrow_move_assignable<ComplianceEngine::Filesystem::UserId>::value &&
                  std::is_nothrow_move_constructible<ComplianceEngine::Filesystem::GroupId>::value &&
                  std::is_nothrow_move_assignable<ComplianceEngine::Filesystem::GroupId>::value &&
                  std::is_nothrow_move_constructible<ComplianceEngine::Filesystem::Detail::LookupSpelling>::value &&
                  std::is_nothrow_move_assignable<ComplianceEngine::Filesystem::Detail::LookupSpelling>::value &&
                  std::is_nothrow_move_constructible<ComplianceEngine::Filesystem::Detail::EffectiveSpelling>::value &&
                  std::is_nothrow_move_assignable<ComplianceEngine::Filesystem::Detail::EffectiveSpelling>::value &&
                  std::is_nothrow_move_constructible<M>::value && std::is_nothrow_move_assignable<M>::value,
    "Provenance wrappers and Metadata move without allocating or throwing");
using LookupSpellingT = ComplianceEngine::Filesystem::Detail::LookupSpelling;
using EffectiveSpellingT = ComplianceEngine::Filesystem::Detail::EffectiveSpelling;
using LookupMountIdT = ComplianceEngine::Filesystem::LookupMountId;
using TargetMountIdT = ComplianceEngine::Filesystem::TargetMountId;
using UserIdT = ComplianceEngine::Filesystem::UserId;
using GroupIdT = ComplianceEngine::Filesystem::GroupId;
static_assert(std::is_same<decltype(std::declval<const LookupSpellingT&>().Value()), std::string>::value &&
                  std::is_same<decltype(std::declval<const EffectiveSpellingT&>().Value()), std::string>::value &&
                  std::is_same<decltype(std::declval<const M&>().LookupName()), std::string>::value &&
                  std::is_same<decltype(std::declval<const M&>().EffectiveName()), std::string>::value,
    "Spelling and metadata name getters return an owning std::string, not a reference");
static_assert(!noexcept(std::declval<const LookupSpellingT&>().Value()) && !noexcept(std::declval<const EffectiveSpellingT&>().Value()) &&
                  !noexcept(std::declval<const M&>().LookupName()) && !noexcept(std::declval<const M&>().EffectiveName()),
    "Name getters may allocate, so they are not noexcept");
static_assert(
    noexcept(std::declval<const LookupMountIdT&>().Value()) && noexcept(std::declval<const TargetMountIdT&>().Value()) && noexcept(
        std::declval<const UserIdT&>()
            .Value()) && noexcept(std::declval<const GroupIdT&>()
                                      .Value()) && noexcept(std::declval<const M&>()
                                                                .FileType()) && noexcept(std::declval<const M&>()
                                                                                             .Stat()) && noexcept(std::declval<const M&>()
                                                                                                                      .LookupMount()) && noexcept(std::declval<const M&>()
                                                                                                                                                      .TargetMount()),
    "Integer and scalar getters cannot throw");
template <typename T, typename = void>
struct CanRawValueField : std::false_type
{
};
template <typename T>
struct CanRawValueField<T, typename Void<decltype(std::declval<T&>().value)>::type> : std::true_type
{
};
static_assert(!CanRawValueField<LookupMountIdT>::value && !CanRawValueField<TargetMountIdT>::value && !CanRawValueField<UserIdT>::value &&
                  !CanRawValueField<GroupIdT>::value && !CanRawValueField<LookupSpellingT>::value && !CanRawValueField<EffectiveSpellingT>::value,
    "No public raw .value field remains on any provenance wrapper");
template <typename T, typename = void>
struct CanRawTypeField : std::false_type
{
};
template <typename T>
struct CanRawTypeField<T, typename Void<decltype(std::declval<T&>().type)>::type> : std::true_type
{
};
static_assert(!CanRawTypeField<M>::value, "No public raw .type field remains on Metadata");
template <typename T, typename = void>
struct CanRawMetadataField : std::false_type
{
};
template <typename T>
struct CanRawMetadataField<T, typename Void<decltype(std::declval<T&>().metadata)>::type> : std::true_type
{
};
static_assert(!CanRawMetadataField<M>::value, "No public raw .metadata field remains on Metadata");
template <typename T, typename = void>
struct CanRawLookupNameField : std::false_type
{
};
template <typename T>
struct CanRawLookupNameField<T, typename Void<decltype(std::declval<T&>().lookupName)>::type> : std::true_type
{
};
static_assert(!CanRawLookupNameField<M>::value, "No public raw .lookupName field remains on Metadata");
template <typename T, typename = void>
struct CanRawEffectiveNameField : std::false_type
{
};
template <typename T>
struct CanRawEffectiveNameField<T, typename Void<decltype(std::declval<T&>().effectiveName)>::type> : std::true_type
{
};
static_assert(!CanRawEffectiveNameField<M>::value, "No public raw .effectiveName field remains on Metadata");
template <typename T, typename = void>
struct CanRawLookupMountField : std::false_type
{
};
template <typename T>
struct CanRawLookupMountField<T, typename Void<decltype(std::declval<T&>().lookupMount)>::type> : std::true_type
{
};
static_assert(!CanRawLookupMountField<M>::value, "No public raw .lookupMount field remains on Metadata");
template <typename T, typename = void>
struct CanRawTargetMountField : std::false_type
{
};
template <typename T>
struct CanRawTargetMountField<T, typename Void<decltype(std::declval<T&>().targetMount)>::type> : std::true_type
{
};
static_assert(!CanRawTargetMountField<M>::value, "No public raw .targetMount field remains on Metadata");
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
