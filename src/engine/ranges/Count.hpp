// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_RANGES_COUNT_HPP
#define COMPLIANCEENGINE_RANGES_COUNT_HPP

#include "View.hpp"

#include <cerrno>
#include <limits>

namespace ComplianceEngine
{
namespace Ranges
{
template <typename Source>
Result<std::size_t> Count(View<Source> source)
{
    std::size_t count = 0;
    for (const auto& item : source)
    {
        if (!item.HasValue())
        {
            return item.Error();
        }
        if (std::numeric_limits<std::size_t>::max() == count)
        {
            return Error("Range count out of range", ERANGE);
        }
        ++count;
    }
    return count;
}

} // namespace Ranges
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_RANGES_COUNT_HPP
