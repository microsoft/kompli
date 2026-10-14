// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_RANGES_RANGE_HPP
#define COMPLIANCEENGINE_RANGES_RANGE_HPP

#include "View.hpp"

#include <memory>
#include <type_traits>

namespace ComplianceEngine
{
namespace Ranges
{
namespace Detail
{
template <typename...>
struct MakeVoid
{
    using type = void;
};

template <typename Collection, typename = void>
struct IsCollection : std::false_type
{
};

template <typename Collection>
struct IsCollection<Collection,
    typename MakeVoid<decltype(std::begin(std::declval<Collection&>())), decltype(std::end(std::declval<Collection&>())),
        decltype(++std::declval<decltype(std::begin(std::declval<Collection&>()))&>()), decltype(*std::declval<decltype(std::begin(std::declval<Collection&>()))&>()),
        decltype(static_cast<bool>(std::declval<decltype(std::begin(std::declval<Collection&>()))&>() != std::declval<decltype(std::end(std::declval<Collection&>()))&>())),
        typename std::iterator_traits<decltype(std::begin(std::declval<Collection&>()))>::value_type>::type> : std::true_type
{
};

template <typename T>
struct ElementResult
{
    using value_type = T;

    static Result<Optional<T>> Wrap(const T& value)
    {
        return Optional<T>(value);
    }
};

template <typename T>
struct ElementResult<Result<T>>
{
    using value_type = T;

    static Result<Optional<T>> Wrap(const Result<T>& value)
    {
        if (!value.HasValue())
        {
            return value.Error();
        }
        return Optional<T>(value.Value());
    }
};

template <typename Collection>
class CollectionSource
{
    using Iterator = decltype(std::begin(std::declval<Collection&>()));
    using Sentinel = decltype(std::end(std::declval<Collection&>()));
    using Element = typename std::iterator_traits<Iterator>::value_type;

    struct State
    {
        explicit State(Collection values)
            : collection(std::move(values))
        {
        }

        Collection collection;
        Optional<Iterator> current;
        Optional<Sentinel> end;
        bool advance = false;
    };

public:
    using value_type = typename ElementResult<Element>::value_type;

    explicit CollectionSource(Collection values)
        : mState(new State(std::move(values)))
    {
    }

    Result<Optional<value_type>> Next()
    {
        auto& state = *mState;
        if (!state.current.HasValue())
        {
            state.current = std::begin(state.collection);
            state.end = std::end(state.collection);
        }
        else if (state.advance)
        {
            ++state.current.Value();
        }
        if (!(state.current.Value() != state.end.Value()))
        {
            return Optional<value_type>();
        }
        state.advance = true;
        return ElementResult<Element>::Wrap(*state.current.Value());
    }

private:
    // Keep iterators and their owned collection together when the source moves.
    std::unique_ptr<State> mState;
};

template <typename Collection>
using EnableIfOwnedCollection =
    typename std::enable_if<IsCollection<typename std::decay<Collection>::type>::value && std::is_constructible<typename std::decay<Collection>::type, Collection&&>::value, int>::type;
} // namespace Detail

template <typename Collection, Detail::EnableIfOwnedCollection<Collection> = 0>
View<Detail::CollectionSource<typename std::decay<Collection>::type>> Range(Collection&& values)
{
    using Source = Detail::CollectionSource<typename std::decay<Collection>::type>;
    return View<Source>(Source(std::forward<Collection>(values)));
}
} // namespace Ranges
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_RANGES_RANGE_HPP
