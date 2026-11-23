// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// C4 (FTW layer): DirectoryCursor and the FilesystemCollection/FTW traversal
// surface (FilesystemCollectionEntry), plus the ContextInterface cursor
// seams (OpenDirectoryCursor/CloseOwnedDirectoryCursor/FdOpenDirectory/
// CloseDirectory). Split from the former monolithic
// DescriptorAccessCompileTest.cpp (see DescriptorAccessCompileTest.cpp for
// C1, PinAccessCompileTest.cpp for C2 and PathAccessCompileTest.cpp for C3);
// shared detection idioms live in AccessCompileTestSupport.h.

#include <AccessCompileTestSupport.h>
#include <ContextInterface.h>
#include <DirectoryCursorTestAccess.h>
#include <MockContext.h>
#include <filesystem/Descriptor.hpp>
#include <filesystem/FTWDirectoryCursor.hpp>
#include <filesystem/FilesystemCollection.hpp>
#include <type_traits>
#include <utility>

namespace
{
using ComplianceEngine::ContextInterface;
using ComplianceEngine::Filesystem::Detail::Descriptor;
using C = ComplianceEngine::Filesystem::Path::Component;
using Cursor = ComplianceEngine::Filesystem::FTW::Detail::DirectoryCursor;
using Entry = ComplianceEngine::Filesystem::FilesystemCollectionEntry;

static_assert(noexcept(std::declval<const MockContext&>().CloseDirectory(nullptr)), "Native cursor close seam is nonthrowing");
static_assert(std::is_same<decltype(std::declval<const MockContext&>().CloseDirectory(nullptr)), ComplianceEngine::Result<void>>::value,
    "Native directory close carries typed success or error");

DENY_CONTEXT_CALL(OpenDirectoryCursor, .OpenDirectoryCursor(std::declval<Descriptor&&>()))
DENY_CONTEXT_CALL(CloseOwnedDirectoryCursor, .CloseOwnedDirectoryCursor(std::declval<DIR*>()))
DENY_CONTEXT_CALL(FdOpenDirectory, .FdOpenDirectory(int{}))
#undef DENY_CONTEXT_CALL

using Access = ComplianceEngine::Tests::DirectoryCursorTestAccess;
CHECK_CONTEXT_FACTORY(OpenDirectoryCursor, (std::declval<T>(), std::declval<Descriptor&&>()))
#undef CHECK_CONTEXT_FACTORY

static_assert(std::is_assignable<Cursor&, Cursor&&>::value && !std::is_assignable<Cursor&&, Cursor&&>::value && std::is_nothrow_move_assignable<Cursor>::value,
    "Cursor assignment requires an lvalue and cannot throw");
static_assert(std::is_nothrow_move_constructible<Cursor>::value, "Cursor move construction cannot throw (reference_wrapper context member)");
// FilesystemCollectionEntry::operator=(FilesystemCollectionEntry&&) is
// &-qualified -- no observed caller assigns into a temporary, and a
// borrowed *this could otherwise dangle.
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
// No class in this module defines a struct/class named Impl: DirectoryCursor's
// own helper, OpenChildren, is a plain private static member declared
// directly on DirectoryCursor, checked here individually (no CanNameImpl
// target exists for it).
template <typename T, typename = void>
struct CanHelperOpenChildren : std::false_type
{
};
template <typename T>
struct CanHelperOpenChildren<T, typename Void<decltype(T::OpenChildren(std::declval<C>()))>::type> : std::true_type
{
};
static_assert(!CanHelperOpenChildren<Cursor>::value, "OpenChildren must be wrapper-private");

} // namespace
