// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_OPTIONAL_H
#define COMPLIANCEENGINE_OPTIONAL_H

#include "TypeTraits.h"

#include <new>
#include <stdexcept>
#include <type_traits>
#include <utility>

namespace ComplianceEngine
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

    void CopyFrom(const Storage& other)
    {
        if (nullptr != other.mValue)
        {
            mValue = ::new (static_cast<void*>(mBuffer)) T(*other.mValue);
        }
    }

    void Reset() noexcept(NoexceptDestructible<T>())
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
            this->Reset();
            this->CopyFrom(other);
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
    static_assert(!std::is_void<T>::value, "Optional cannot hold void");
    static_assert(!std::is_reference<T>::value, "Optional cannot hold references");

public:
    Optional() = default;
    Optional(T value)
    {
        this->mValue = ::new (static_cast<void*>(this->mBuffer)) T(std::move(value));
    }

    ~Optional() = default;

    Optional(const Optional&) = default;

    Optional(Optional&& other) noexcept(NoexceptMovable<T>())
    {
        if (nullptr != other.mValue)
        {
            this->mValue = ::new (static_cast<void*>(this->mBuffer)) T(std::move(*other.mValue));
        }
        other.Reset();
    }

    Optional& operator=(const Optional&) = default;

    Optional& operator=(T value)
    {
        Reset();
        this->mValue = ::new (static_cast<void*>(this->mBuffer)) T(std::move(value));
        return *this;
    }

    Optional& operator=(Optional&& other) noexcept(NoexceptMovable<T>())
    {
        if (this == &other)
        {
            return *this;
        }

        Reset();
        if (nullptr != other.mValue)
        {
            this->mValue = ::new (static_cast<void*>(this->mBuffer)) T(std::move(*other.mValue));
        }
        other.Reset();
        return *this;
    }

    bool HasValue() const
    {
        return this->mValue != nullptr;
    }

    T ValueOr(T default_value) const noexcept(NoexceptCopyable<T>())
    {
        if (nullptr == this->mValue)
        {
            return default_value;
        }

        return *this->mValue;
    }

    const T& Value() const&
    {
        CheckValue();
        return *this->mValue;
    }

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
        return this->mValue;
    }

    T* operator->() &
    {
        return this->mValue;
    }

    operator bool() const noexcept
    {
        return HasValue();
    }

    void Reset() noexcept(NoexceptDestructible<T>())
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
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_OPTIONAL_H
