// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef KOMPLI_TYPE_TRAITS_H
#define KOMPLI_TYPE_TRAITS_H

#include <type_traits>

namespace Kompli
{
template <typename T>
constexpr bool NoexceptCopyable() noexcept
{
    return std::is_nothrow_copy_constructible<T>::value;
}

} // namespace Kompli

#endif // KOMPLI_TYPE_TRAITS_H
