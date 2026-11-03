// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <ContextInterface.h>
#include <DescriptorTestAccess.h>
#include <MockContext.h>
#include <cstddef>
#include <filesystem/Descriptor.hpp>
#include <filesystem/ProcfsDescriptorAccess.hpp>
#include <type_traits>
#include <utility>

namespace
{
using ComplianceEngine::ContextInterface;
using ComplianceEngine::Filesystem::Detail::Descriptor;
using Procfs = ComplianceEngine::Filesystem::Detail::ProcfsDescriptorAccess;
using Profile = ContextInterface::OpenProfile;

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
DENY_CONTEXT_CALL(OpenAbsolutePin, .OpenAbsolutePin("/"))
DENY_CONTEXT_CALL(OpenAt, .OpenAt(std::declval<const Descriptor&>(), "child", Profile::PinChild))
DENY_CONTEXT_CALL(OpenFdinfo, .OpenFdinfo(std::declval<const Procfs&>(), std::declval<const Descriptor&>()))
DENY_CONTEXT_CALL(OpenAlias, .OpenAlias(std::declval<const Procfs&>(), std::declval<const Descriptor&>(), false))
DENY_CONTEXT_CALL(OpenPinAlias, .OpenPinAlias(std::declval<const Procfs&>(), std::declval<const Descriptor&>(), false))
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
DENY_CONTEXT_CALL(OpenVerifiedAt, .OpenVerifiedAt(std::declval<const Descriptor&>(), "child", Profile::PinChild, ContextInterface::CloseDiagnostic::Descriptor))
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

DENY_HELPER_CALL(ActivateReadOnly, Handle,
    (std::declval<const ContextInterface&>(), std::declval<const Descriptor&>(), std::declval<const struct stat&>(), false, std::size_t{}))
DENY_HELPER_CALL(ActivateReadOnlyImpl, Handle,
    (std::declval<const ContextInterface&>(), std::declval<const Descriptor&>(), std::declval<const struct stat&>(), false, std::size_t{},
        std::declval<const std::uint64_t*>()))
DENY_HELPER_CALL(OpenAndVerifyAlias, Handle,
    (std::declval<const ContextInterface&>(), std::declval<const Procfs&>(), std::declval<const Descriptor&>(), std::declval<Descriptor&>(),
        std::declval<const struct stat&>(), false, std::size_t{}, std::declval<const std::uint64_t*>()))
DENY_HELPER_CALL(ReadPinnedLink, Path, (std::declval<const Descriptor&>(), std::size_t{}, std::size_t{}))
DENY_HELPER_CALL(ReadVerifiedLinkText, Path,
    (std::declval<const Descriptor&>(), std::declval<const struct stat&>(), std::declval<const Procfs&>(), std::size_t{}, std::size_t{}))
#undef DENY_HELPER_CALL

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

CHECK_CONTEXT_FACTORY(EmptyDescriptor, (std::declval<T>()))
CHECK_CONTEXT_FACTORY(OpenAbsolutePin, (std::declval<T>(), "/"))
CHECK_CONTEXT_FACTORY(OpenAt, (std::declval<T>(), std::declval<const Descriptor&>(), "child", Profile::PinChild))
CHECK_CONTEXT_FACTORY(OpenFdinfo, (std::declval<T>(), std::declval<const Procfs&>(), std::declval<const Descriptor&>()))
CHECK_CONTEXT_FACTORY(OpenAlias, (std::declval<T>(), std::declval<const Procfs&>(), std::declval<const Descriptor&>(), false))
CHECK_CONTEXT_FACTORY(OpenPinAlias, (std::declval<T>(), std::declval<const Procfs&>(), std::declval<const Descriptor&>(), false))
CHECK_CONTEXT_FACTORY(Duplicate, (std::declval<T>(), std::declval<const Descriptor&>()))
CHECK_CONTEXT_FACTORY(OpenDirectoryCursor, (std::declval<T>(), std::declval<Descriptor&&>()))
CHECK_CONTEXT_FACTORY(ProcfsAccess, (std::declval<T>()))
CHECK_CONTEXT_FACTORY(ActivateReadOnly, (std::declval<T>(), std::declval<const Descriptor&>(), std::declval<const struct stat&>(), false, std::size_t{}))
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
} // namespace
