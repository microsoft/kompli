// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef KOMPLI_OPTIONAL_H
#define KOMPLI_OPTIONAL_H

#include "TypeTraits.h"

#include <new>
#include <stdexcept>
#include <type_traits>
#include <utility>

namespace Kompli
{
namespace OptionalDetail
{
template <typename T>
class Storage
{
protected:
    alignas(T) char mBuffer[sizeof(T)];
    T* mValue = nullptr;

    Storage() = default;
    ~Storage()
    {
        Reset();
    }

    // Precondition: this storage is empty. Only publishes mValue once the
    // placement-new succeeds, so a throwing copy leaves this storage empty.
    void CopyFrom(const Storage& other)
    {
        if (nullptr != other.mValue)
        {
            mValue = ::new (static_cast<void*>(mBuffer)) T(*other.mValue);
        }
    }

    // Precondition: this storage is empty. Nonthrowing because Optional<T>
    // asserts T's move constructor and destructor are nonthrowing.
    void MoveFrom(Storage& other) noexcept
    {
        if (nullptr != other.mValue)
        {
            mValue = ::new (static_cast<void*>(mBuffer)) T(std::move(*other.mValue));
        }
        other.Reset();
    }

    void Reset() noexcept
    {
        if (nullptr != mValue)
        {
            mValue->~T();
        }
        mValue = nullptr;
    }
};

template <typename T, bool Copyable>
class CopyStorage;

template <typename T>
class CopyStorage<T, true> : public Storage<T>
{
public:
    CopyStorage() = default;
    CopyStorage(const CopyStorage& other)
    {
        this->CopyFrom(other);
    }
    CopyStorage& operator=(const CopyStorage& other)
    {
        if (this != &other)
        {
            CopyStorage copy(other); // May throw; *this stays untouched until here.
            this->Reset();
            this->MoveFrom(copy);
        }
        return *this;
    }
};

template <typename T>
class CopyStorage<T, false> : public Storage<T>
{
public:
    CopyStorage() = default;
    CopyStorage(const CopyStorage&) = delete;
    CopyStorage& operator=(const CopyStorage&) = delete;
};
} // namespace OptionalDetail

template <typename T>
class Optional : private OptionalDetail::CopyStorage<T, std::is_copy_constructible<T>::value>
{
    // Existing type guards first so void/reference report their own
    // message; destructor before move so a throwing destructor reports its
    // own message even if a compiler stops at the first failure.
    static_assert(!std::is_void<T>::value, "Optional cannot hold void");
    static_assert(!std::is_reference<T>::value, "Optional cannot hold references");
    static_assert(std::is_nothrow_destructible<T>::value, "Optional requires a nonthrowing destructor");
    static_assert(std::is_nothrow_move_constructible<T>::value, "Optional requires a nonthrowing move constructor");

public:
    Optional() = default;
    Optional(T value) noexcept
    {
        this->mValue = ::new (static_cast<void*>(this->mBuffer)) T(std::move(value));
    }

    ~Optional() = default;

    Optional(const Optional&) = default;

    Optional(Optional&& other) noexcept
    {
        this->MoveFrom(other);
    }

    Optional& operator=(const Optional&) = default;

    Optional& operator=(T value)
    {
        Reset();
        this->mValue = ::new (static_cast<void*>(this->mBuffer)) T(std::move(value));
        return *this;
    }

    Optional& operator=(Optional&& other) noexcept
    {
        if (this != &other)
        {
            Reset();
            this->MoveFrom(other);
        }
        return *this;
    }

    bool HasValue() const noexcept
    {
        return this->mValue != nullptr;
    }

    T ValueOr(T default_value) const& noexcept(NoexceptCopyable<T>())
    {
        if (nullptr == this->mValue)
        {
            return default_value;
        }

        return *this->mValue;
    }

    T ValueOr(T default_value) && noexcept
    {
        if (nullptr == this->mValue)
        {
            return default_value;
        }

        return std::move(*this->mValue);
    }

    const T& Value() const&
    {
        CheckValue();
        return *this->mValue;
    }

    const T& Value() const&& = delete;

    T Value() &&
    {
        CheckValue();
        return std::move(*this->mValue);
    }

    T& Value() &
    {
        CheckValue();
        return *this->mValue;
    }

    const T* operator->() const&
    {
        CheckValue();
        return this->mValue;
    }

    const T* operator->() const&& = delete;

    T* operator->() &
    {
        CheckValue();
        return this->mValue;
    }

    explicit operator bool() const noexcept
    {
        return HasValue();
    }

    void Reset() noexcept
    {
        OptionalDetail::CopyStorage<T, std::is_copy_constructible<T>::value>::Reset();
    }

private:
    void CheckValue() const
    {
        if (nullptr == this->mValue)
        {
            throw std::logic_error("Optional: unchecked access to Value");
        }
    }
};
} // namespace Kompli

#endif // KOMPLI_OPTIONAL_H
