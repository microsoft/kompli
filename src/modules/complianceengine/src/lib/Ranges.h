// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_RANGES_H
#define COMPLIANCEENGINE_RANGES_H

#include <Optional.h>
#include <Result.h>
#include <cstddef>
#include <iterator>
#include <limits>
#include <set>
#include <utility>
#include <vector>

namespace ComplianceEngine
{
namespace Ranges
{
namespace Detail
{
inline Result<std::size_t> IncrementCount(std::size_t count)
{
    if (std::numeric_limits<std::size_t>::max() == count)
    {
        return Error("Range count out of range", ERANGE);
    }
    return count + 1;
}
} // namespace Detail

// Sources return Result<Optional<T>>: a value, successful exhaustion, or an error.
template <typename Source>
class View
{
public:
    using value_type = typename Source::value_type;

    explicit View(Source source)
        : mSource(std::move(source))
    {
    }

    View(const View&) = delete;
    View& operator=(const View&) = delete;
    View(View&&) = default;
    View& operator=(View&&) = default;

    Result<Optional<value_type>> Next()
    {
        if (mStopped)
        {
            return Optional<value_type>();
        }
        auto next = mSource.Next();
        if ((!next.HasValue()) || (!next.Value().HasValue()))
        {
            mStopped = true;
        }
        return next;
    }

    class Iterator
    {
    public:
        using iterator_category = std::input_iterator_tag;
        using value_type = Result<typename Source::value_type>;
        using difference_type = std::ptrdiff_t;
        using pointer = const value_type*;
        using reference = const value_type&;

        Iterator() = default;
        explicit Iterator(View* view)
            : mView(view)
        {
            Advance();
        }

        reference operator*() const
        {
            return mCurrent.Value();
        }

        pointer operator->() const
        {
            return &mCurrent.Value();
        }

        Iterator& operator++()
        {
            Advance();
            return *this;
        }

        Iterator operator++(int)
        {
            auto previous = *this;
            Advance();
            return previous;
        }

        bool operator==(const Iterator& other) const
        {
            return mView == other.mView;
        }

        bool operator!=(const Iterator& other) const
        {
            return !(*this == other);
        }

    private:
        void Advance()
        {
            if (nullptr == mView)
            {
                return;
            }
            auto next = mView->Next();
            if (!next.HasValue())
            {
                mCurrent = value_type(next.Error());
            }
            else if (!next.Value().HasValue())
            {
                mCurrent.Reset();
                mView = nullptr;
            }
            else
            {
                mCurrent = value_type(std::move(next.Value()).Value());
            }
        }

        View* mView = nullptr;
        Optional<value_type> mCurrent;
    };

    Iterator begin() // NOLINT(*-identifier-naming)
    {
        return Iterator(this);
    }

    Iterator end() // NOLINT(*-identifier-naming)
    {
        return Iterator();
    }

private:
    Source mSource;
    bool mStopped = false;
};

namespace Detail
{
template <typename T>
class VectorSource
{
public:
    using value_type = T;

    explicit VectorSource(const std::vector<T>& values)
        : mBorrowed(&values)
    {
    }

    explicit VectorSource(std::vector<T>&& values)
        : mOwned(std::move(values))
    {
    }

    Result<Optional<T>> Next()
    {
        const auto& values = (nullptr == mBorrowed) ? mOwned : *mBorrowed;
        if (values.size() == mIndex)
        {
            return Optional<T>();
        }
        return Optional<T>(values[mIndex++]);
    }

private:
    std::vector<T> mOwned;
    const std::vector<T>* mBorrowed = nullptr;
    std::size_t mIndex = 0;
};

template <typename Source>
class BorrowedSource
{
public:
    using value_type = typename Source::value_type;

    explicit BorrowedSource(View<Source>& source)
        : mSource(source)
    {
    }

    Result<Optional<value_type>> Next()
    {
        return mSource.Next();
    }

private:
    View<Source>& mSource;
};

template <typename Source>
class UniqueSource
{
public:
    using value_type = typename Source::value_type;

    explicit UniqueSource(Source source)
        : mSource(std::move(source))
    {
    }

    Result<Optional<value_type>> Next()
    {
        for (;;)
        {
            auto next = mSource.Next();
            if (!next.HasValue())
            {
                return next.Error();
            }
            if (!next.Value().HasValue())
            {
                return Optional<value_type>();
            }
            if (mSeen.insert(next.Value().Value()).second)
            {
                return next;
            }
        }
    }

private:
    Source mSource;
    std::set<value_type> mSeen;
};
} // namespace Detail

template <typename T>
View<Detail::VectorSource<T>> Range(const std::vector<T>& values)
{
    return View<Detail::VectorSource<T>>(Detail::VectorSource<T>(values));
}

template <typename T>
View<Detail::VectorSource<T>> Range(std::vector<T>&& values)
{
    return View<Detail::VectorSource<T>>(Detail::VectorSource<T>(std::move(values)));
}

template <typename T>
void Range(const std::vector<T>&&) = delete;

template <typename Source>
View<Detail::UniqueSource<View<Source>>> Unique(View<Source>&& source)
{
    return View<Detail::UniqueSource<View<Source>>>(Detail::UniqueSource<View<Source>>(std::move(source)));
}

template <typename Source>
View<Detail::UniqueSource<Detail::BorrowedSource<Source>>> Unique(View<Source>& source)
{
    using Borrowed = Detail::BorrowedSource<Source>;
    return View<Detail::UniqueSource<Borrowed>>(Detail::UniqueSource<Borrowed>(Borrowed(source)));
}

template <typename Source>
Result<std::size_t> Count(View<Source>& source)
{
    std::size_t count = 0;
    for (const auto& item : source)
    {
        if (!item.HasValue())
        {
            return item.Error();
        }
        auto incremented = Detail::IncrementCount(count);
        if (!incremented.HasValue())
        {
            return incremented.Error();
        }
        count = incremented.Value();
    }
    return count;
}

template <typename Source>
Result<std::size_t> Count(View<Source>&& source)
{
    return Count(source);
}
} // namespace Ranges
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_RANGES_H
