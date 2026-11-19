// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_TYPE_TRAITS_H
#define COMPLIANCEENGINE_TYPE_TRAITS_H

#include <cstddef>
#include <type_traits>

namespace ComplianceEngine
{
// Reusable C++11 pack helpers for type-safe storage and selection.
namespace TypeTraits
{
// Maximum of one or more size_t values, such as object sizes or alignments.
constexpr std::size_t Max(std::size_t value)
{
    return value;
}

template <typename... Rest>
constexpr std::size_t Max(std::size_t first, std::size_t second, Rest... rest)
{
    return Max(first < second ? second : first, rest...);
}

// True if every boolean in the pack is true; the empty pack is true.
template <bool... Values>
struct All;

template <>
struct All<> : std::true_type
{
};

template <bool First, bool... Rest>
struct All<First, Rest...> : std::integral_constant<bool, First && All<Rest...>::value>
{
};

// Number of types matching T after removing top-level cv qualifiers.
template <typename T, typename... Alternatives>
struct Count;

template <typename T>
struct Count<T> : std::integral_constant<std::size_t, 0>
{
};

template <typename T, typename First, typename... Rest>
struct Count<T, First, Rest...>
    : std::integral_constant<std::size_t, (std::is_same<typename std::remove_cv<T>::type, typename std::remove_cv<First>::type>::value ? 1 : 0) + Count<T, Rest...>::value>
{
};

// Pairwise distinct types ignoring top-level cv; the empty pack is unique.
template <typename... Alternatives>
struct Unique;

template <>
struct Unique<> : std::true_type
{
};

template <typename First, typename... Rest>
struct Unique<First, Rest...> : std::integral_constant<bool, (0 == Count<First, Rest...>::value) && Unique<Rest...>::value>
{
};

// First cv-insensitive match for T. Type retains the listed cv qualifiers;
// when absent, Type is void and Index is the number of listed types.
template <typename T, typename... Alternatives>
struct Find;

template <typename T>
struct Find<T>
{
    using Type = void;
    static constexpr std::size_t Index = 0;
};

template <typename T, typename First, typename... Rest>
struct Find<T, First, Rest...>
{
private:
    using Next = Find<T, Rest...>;
    static constexpr bool Match = std::is_same<typename std::remove_cv<T>::type, typename std::remove_cv<First>::type>::value;

public:
    using Type = typename std::conditional<Match, First, typename Next::Type>::type;
    static constexpr std::size_t Index = Match ? 0 : 1 + Next::Index;
};

// C++11 requires definitions when callers take the address or bind a reference.
template <typename T>
constexpr std::size_t Find<T>::Index;

template <typename T, typename First, typename... Rest>
constexpr std::size_t Find<T, First, Rest...>::Index;
} // namespace TypeTraits

template <typename T>
constexpr bool NoexceptCopyable() noexcept
{
    return std::is_nothrow_copy_constructible<T>::value;
}
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_TYPE_TRAITS_H
