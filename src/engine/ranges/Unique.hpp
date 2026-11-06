// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_RANGES_UNIQUE_HPP
#define COMPLIANCEENGINE_RANGES_UNIQUE_HPP

#include "View.hpp"

#include <set>

namespace ComplianceEngine
{
namespace Ranges
{
namespace Detail
{
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

template <typename Source>
View<Detail::UniqueSource<View<Source>>> Unique(View<Source> source)
{
    return View<Detail::UniqueSource<View<Source>>>(Detail::UniqueSource<View<Source>>(std::move(source)));
}

} // namespace Ranges
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_RANGES_UNIQUE_HPP
