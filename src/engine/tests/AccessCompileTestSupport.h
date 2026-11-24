// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_TESTS_ACCESS_COMPILE_TEST_SUPPORT_H
#define COMPLIANCEENGINE_TESTS_ACCESS_COMPILE_TEST_SUPPORT_H

#include <ContextInterface.h>
#include <type_traits>
#include <utility>

// Shared compile-time detection idioms for the layered
// Descriptor/Pin/Path/FTW access-compile-test suites
// (DescriptorAccessCompileTest.cpp, PinAccessCompileTest.cpp,
// PathAccessCompileTest.cpp, FTWAccessCompileTest.cpp). Each macro/template
// here is invoked from two or more of those files; a single copy here keeps
// every file's static_asserts about its own types without duplicating the
// idiom itself. This header has no filesystem-layer dependency beyond
// ContextInterface.h (Descriptor layer), so every layer may include it.

template <typename...>
struct Void
{
    using type = void;
};

// These unevaluated C++11 expressions are outside every wrapper and test friend.
// Private typed authority and protected native overrides must not be callable.
#define DENY_CONTEXT_CALL(name, expression)                                                                                                            \
    template <typename T, typename = void>                                                                                                             \
    struct Can##name : std::false_type                                                                                                                 \
    {                                                                                                                                                  \
    };                                                                                                                                                 \
    template <typename T>                                                                                                                              \
    struct Can##name<T, typename Void<decltype(std::declval<T&>() expression)>::type> : std::true_type                                                 \
    {                                                                                                                                                  \
    };                                                                                                                                                 \
    static_assert(!Can##name<const ComplianceEngine::ContextInterface>::value, #name " must not be accessible to ordinary callers");

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

// A private nested enum parameter (e.g. Path::InputRole, ProcfsDescriptorAccess::Role)
// blocks DENY_HELPER_CALL's call-syntax detection, since no external expression
// can spell the matching overload. Taking the member's address only needs its
// name, not its parameter types, and forming the address of a private member
// still triggers access control in an unevaluated SFINAE context, so this
// proves privacy without ever spelling the private parameter type.
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

// Close()/HasValue()/Pin() absence probes, reused across the Descriptor,
// Pin and Path::Component layers: each owner type denies the same
// generic member names, so the detector is shared instead of copied.
template <typename T, typename = void>
struct CanCloseComponent : std::false_type
{
};
template <typename T>
struct CanCloseComponent<T, typename Void<decltype(std::declval<T&>().Close())>::type> : std::true_type
{
};

// Old observation-API absence probes, reused across the Pin and
// Path::Component/Path::Step layers.
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

// Directory enumeration must be FTW-layer-only, not reachable from Pin or
// Path::Component.
template <typename T, typename = void>
struct CanOpenChildren : std::false_type
{
};
template <typename T>
struct CanOpenChildren<T, typename Void<decltype(std::declval<T&>().OpenChildren())>::type> : std::true_type
{
};

#endif // COMPLIANCEENGINE_TESTS_ACCESS_COMPILE_TEST_SUPPORT_H
