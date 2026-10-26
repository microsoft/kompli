// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_RANGES_VIEW_HPP
#define COMPLIANCEENGINE_RANGES_VIEW_HPP

#include <Optional.h>
#include <Result.h>
#include <cstddef>
#include <iterator>
#include <utility>

namespace ComplianceEngine
{
namespace Ranges
{
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

} // namespace Ranges
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_RANGES_VIEW_HPP
