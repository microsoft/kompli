// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Path layer: Path, Path::Component, Path::Step and LinesRange. Split
// from the former monolithic DescriptorAccessCompileTest.cpp (see
// DescriptorAccessCompileTest.cpp for the Descriptor layer,
// PinAccessCompileTest.cpp for the Pin layer and FTWAccessCompileTest.cpp
// for the FTW layer); shared detection idioms live in
// AccessCompileTestSupport.h. No legacy context API absence assertions
// were present in the original file to carry here.

#include <AccessCompileTestSupport.h>
#include <ContextInterface.h>
#include <PathTestAccess.h>
#include <filesystem/LinesRange.hpp>
#include <filesystem/Path.hpp>
#include <filesystem/ReadableFile.hpp>
#include <string>
#include <type_traits>
#include <utility>

namespace
{
using ComplianceEngine::ContextInterface;
using C = ComplianceEngine::Filesystem::Path::Component;
using M = ComplianceEngine::Filesystem::Metadata;
using R = ComplianceEngine::Filesystem::ReadableFile;
using P = ComplianceEngine::Filesystem::Path;
using Lines = ComplianceEngine::Filesystem::LinesRange;
using Step = P::Step;

// Path's own private helpers: each dispatches through ContextInterface's
// friend-gated native surface, so it stays a member of Path (or a nested
// type it returns), not a free function.
DENY_HELPER_CALL(ReadPinnedLink, Path, (std::declval<const ComplianceEngine::Filesystem::Detail::Descriptor&>(), std::size_t{}))
DENY_HELPER_CALL(ReadVerifiedLinkText, Path,
    (std::declval<const ComplianceEngine::Filesystem::Detail::Descriptor&>(), std::declval<const struct stat&>(), std::size_t{}))
DENY_HELPER_CALL(MakeRootComponent, Path, (std::declval<ComplianceEngine::Filesystem::Detail::Pin>()))
DENY_HELPER_CALL(SameAcquisition, Path::Component, (std::declval<const C&>(), std::declval<const C&>()))
DENY_HELPER_CALL(LookupNameBytes, Path::Component, (std::declval<const C&>()))
DENY_HELPER_CALL(EffectiveNameBytes, Path::Component, (std::declval<const C&>()))
DENY_HELPER_CALL(LookupName, Path::Component, (std::declval<const C&>()))
DENY_HELPER_CALL(EffectiveName, Path::Component, (std::declval<const C&>()))
#undef DENY_HELPER_CALL
// Path::ResolveInput's own parameter list names Path::InputRole, itself a
// private nested enum: no external expression can spell the matching call
// overload, so DENY_HELPER_CALL's call-syntax detection does not apply here.
// Taking the member's address only needs its name, not its parameter types,
// and forming the address of a private member still triggers access control
// in an unevaluated SFINAE context, so this proves privacy without ever
// spelling InputRole.
DENY_PRIVATE_MEMBER_ADDRESS(ResolveInput, P)

static_assert(!std::is_default_constructible<C>::value, "Component requires a complete acquisition");
static_assert(std::is_nothrow_copy_constructible<C>::value && std::is_nothrow_copy_assignable<C>::value, "Shared acquisition copy cannot throw");
static_assert(std::is_nothrow_move_constructible<C>::value && std::is_nothrow_move_assignable<C>::value, "Move-as-copy cannot throw");
static_assert(std::is_same<decltype(std::declval<const C&>().Metadata()), M>::value, "Acquisition metadata owns its provenance");
static_assert(!noexcept(std::declval<const C&>().Metadata()), "Copying names may allocate");
static_assert(std::is_same<decltype(std::declval<const P&>().Limits()), ComplianceEngine::Filesystem::ResolverLimits>::value, "Limits are a value");
static_assert(std::is_assignable<P&, P&&>::value && !std::is_assignable<P&&, P&&>::value && std::is_nothrow_move_assignable<P>::value,
    "Path assignment requires an lvalue and cannot throw");
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
// A moved-from Path is consumed: every state-reading operation checks
// liveness first and throws std::logic_error before any other validation
// or native dispatch, so these six accessors (noexcept previously) cannot
// stay noexcept -- a noexcept function that throws terminates the process.
static_assert(!noexcept(std::declval<const P&>().Root()) && !noexcept(std::declval<const P&>().Leaf()) && !noexcept(std::declval<const P&>().Size()) &&
                  !noexcept(std::declval<const P&>().RetainedDescriptors()) && !noexcept(std::declval<const P&>().Limits()) &&
                  !noexcept(std::declval<const P&>().Context()),
    "A moved-from Path's checked accessors cannot be noexcept");
static_assert(!std::is_default_constructible<P>::value && !std::is_copy_constructible<P>::value && std::is_nothrow_move_constructible<P>::value &&
                  std::is_nothrow_move_assignable<P>::value,
    "Path always owns a nonempty snapshot even after moving");
static_assert(!std::is_default_constructible<Step>::value && !std::is_copy_constructible<Step>::value &&
                  std::is_nothrow_move_constructible<Step>::value && std::is_nothrow_move_assignable<Step>::value,
    "A delta owns its pins, including after moving");
static_assert(std::is_same<decltype(std::declval<const Step&>().Target()), C>::value && std::is_same<decltype(std::declval<const Step&>().Metadata()), M>::value,
    "Step publishes owned components and detached facts");
// A moved-from Step is consumed the same way: every state-reading operation
// checks liveness first and throws std::logic_error, so Target and
// RetainedDescriptors, noexcept before this rule applied, cannot stay so.
static_assert(!noexcept(std::declval<const Step&>().Target()) && !noexcept(std::declval<const Step&>().RetainedDescriptors()),
    "A moved-from Step's checked accessors cannot be noexcept");
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
// Path::Component each merge its two OpenReadOnly overloads into one,
// defaulting the Policy, so both call forms below name the same declaration.
static_assert(std::is_same<decltype(std::declval<const C&>().OpenReadOnly()), ComplianceEngine::Result<R>>::value &&
                  std::is_same<decltype(std::declval<const C&>().OpenReadOnly(R::Policy{})), ComplianceEngine::Result<R>>::value,
    "Path::Component::OpenReadOnly is one overload with a default Policy");
// Path::LookupName()/ToString() are private, no production caller
// (logging included); the bounded-authority PathTestAccess friend is the
// only caller left, so these are checked through it, not through P directly.
static_assert(std::is_same<decltype(ComplianceEngine::Tests::PathTestAccess::LookupName(std::declval<const P&>())), std::string>::value &&
                  std::is_same<decltype(ComplianceEngine::Tests::PathTestAccess::ToString(std::declval<const P&>())), std::string>::value,
    "Names are returned by owning value, not borrowed storage");
static_assert(std::is_nothrow_destructible<C>::value, "Owner disposal is noexcept");
static_assert(std::is_same<decltype(std::declval<const Step&>().Metadata()), M>::value && !noexcept(std::declval<const Step&>().Metadata()),
    "Step produces an owning fallible metadata copy");
static_assert(!CanOpenChildren<C>::value, "Directory enumeration is FTW-only, not reachable from Path::Component");
static_assert(!CanOldAcquired<C>::value && !CanOldAcquired<Step>::value, "No duplicate observation API on Path::Component/Path::Step");
static_assert(!CanOldLookup<C>::value && !CanOldEffective<C>::value, "Acquisition names live in immutable metadata, not on Path::Component");

} // namespace
