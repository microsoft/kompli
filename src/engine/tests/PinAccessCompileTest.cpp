// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// C2 (Pin layer): Pin, Metadata and the provenance value types it owns
// (LookupMountId/TargetMountId/UserId/GroupId/LookupSpelling/EffectiveSpelling),
// plus ReadableFile. Split from the former monolithic
// DescriptorAccessCompileTest.cpp (see DescriptorAccessCompileTest.cpp for
// C1, PathAccessCompileTest.cpp for C3 and FTWAccessCompileTest.cpp for C4);
// shared detection idioms live in AccessCompileTestSupport.h.

#include <AccessCompileTestSupport.h>
#include <ContextInterface.h>
#include <cstddef>
#include <cstdint>
#include <filesystem/Descriptor.hpp>
#include <filesystem/Pin.hpp>
#include <filesystem/ProcfsDescriptorAccess.hpp>
#include <filesystem/ReadableFile.hpp>
#include <string>
#include <type_traits>
#include <utility>

namespace
{
using ComplianceEngine::ContextInterface;
using ComplianceEngine::Filesystem::Type;
using ComplianceEngine::Filesystem::Detail::Descriptor;
using Procfs = ComplianceEngine::Filesystem::Detail::ProcfsDescriptorAccess;
using Pin = ComplianceEngine::Filesystem::Detail::Pin;
using D = ComplianceEngine::Filesystem::Detail::Descriptor;
using M = ComplianceEngine::Filesystem::Metadata;
using R = ComplianceEngine::Filesystem::ReadableFile;

// Pin's own private helpers: each dispatches through ContextInterface's
// friend-gated native surface, so it stays a member of Pin (or a nested type
// it returns), not a free function.
DENY_HELPER_CALL(ActivateReadOnly, Detail::Pin,
    (std::declval<const ContextInterface&>(), std::declval<const Descriptor&>(), std::declval<const struct stat&>(), Type::RegularFile))
DENY_HELPER_CALL(OpenAndVerifyAlias, Detail::Pin,
    (std::declval<const ContextInterface&>(), std::declval<const Procfs&>(), std::declval<const Descriptor&>(), std::declval<const struct stat&>(), Type::RegularFile))
DENY_HELPER_CALL(AcquirePinnedObject, Detail::Pin,
    (std::declval<const ContextInterface&>(), std::declval<Descriptor>(), std::size_t{}, std::declval<const char*>()))
// No class in this module defines a struct/class named Impl: Pin::Impl does
// not exist as a wrapper type (no CanNameImpl target exists); each helper
// below is a direct private static member of Pin, covered here individually.
DENY_HELPER_CALL(Inspect, Detail::Pin, (std::declval<const Pin&>()))
DENY_HELPER_CALL(SetModeWithProcfs, Detail::Pin, (std::declval<const Pin&>(), std::declval<const Procfs&>(), mode_t{}))
DENY_HELPER_CALL(PinProcessRoot, Detail::Pin, (std::declval<const ContextInterface&>(), std::declval<ComplianceEngine::Filesystem::PrefixLimits>()))
#undef DENY_HELPER_CALL

static_assert(std::is_assignable<R&, R&&>::value && !std::is_assignable<R&&, R&&>::value && std::is_nothrow_move_assignable<R>::value,
    "Reader assignment requires an lvalue and cannot throw");
static_assert(!std::is_convertible<ComplianceEngine::Filesystem::LookupMountId, ComplianceEngine::Filesystem::TargetMountId>::value,
    "Lookup and target mounts are distinct");
static_assert(!std::is_convertible<ComplianceEngine::Filesystem::UserId, ComplianceEngine::Filesystem::GroupId>::value,
    "Ownership arguments are distinct");
// Pin merges its two OpenReadOnly overloads into one, defaulting the Policy,
// so both call forms below name the same declaration.
static_assert(std::is_same<decltype(std::declval<const Pin&>().OpenReadOnly()), ComplianceEngine::Result<R>>::value &&
                  std::is_same<decltype(std::declval<const Pin&>().OpenReadOnly(R::Policy{})), ComplianceEngine::Result<R>>::value,
    "Pin::OpenReadOnly is one overload with a default Policy");
static_assert(!CanCloseComponent<Pin>::value, "Unique owners cannot explicitly close");
static_assert(std::is_nothrow_destructible<Pin>::value, "Owner disposal is noexcept");
static_assert(std::is_nothrow_move_constructible<Pin>::value && std::is_nothrow_move_assignable<Pin>::value, "Pin transfers without copying names");
static_assert(std::is_same<decltype(std::declval<const Pin&>().Metadata()), M>::value && !noexcept(std::declval<const Pin&>().Metadata()),
    "Pin produces an owning fallible metadata copy");
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
static_assert(!CanOpenChildren<Pin>::value, "Directory enumeration is FTW-only, not reachable from Pin");
static_assert(!CanOldAcquired<Pin>::value, "No duplicate observation API on Pin");
static_assert(!CanOldLookup<Pin>::value && !CanOldEffective<Pin>::value, "Acquisition names live in immutable metadata, not on Pin");
static_assert(!std::is_constructible<Pin, D&&>::value, "Native adoption is private to the verified boundary");
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

} // namespace
