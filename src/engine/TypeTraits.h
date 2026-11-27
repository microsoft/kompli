// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef KOMPLI_TYPE_TRAITS_H
#define KOMPLI_TYPE_TRAITS_H

#include <type_traits>

namespace Kompli
{
// Reusable C++11 type traits and conditional wrapper copy control.
namespace TypeTraits
{
// Conditional copy policy for raw-lifetime wrapper storage. StorageType owns
// payload-specific copying, Reset, and nonthrowing MoveFrom.
template <typename StorageType, bool Copyable>
class CopyStorage;

template <typename StorageType>
class CopyStorage<StorageType, true> : public StorageType
{
public:
    CopyStorage() = default;
    CopyStorage(const CopyStorage& other)
        : StorageType(other)
    {
    }
    CopyStorage& operator=(const CopyStorage& other)
    {
        if (this != &other)
        {
            CopyStorage copy(other);
            this->Reset();
            this->MoveFrom(copy);
        }
        return *this;
    }
};

template <typename StorageType>
class CopyStorage<StorageType, false> : public StorageType
{
public:
    CopyStorage() = default;
    CopyStorage(const CopyStorage&) = delete;
    CopyStorage& operator=(const CopyStorage&) = delete;
};
} // namespace TypeTraits

template <typename T>
constexpr bool NoexceptCopyable() noexcept
{
    return std::is_nothrow_copy_constructible<T>::value;
}

} // namespace Kompli

#endif // KOMPLI_TYPE_TRAITS_H
