// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_RESULT_H
#define COMPLIANCEENGINE_RESULT_H

#include "Optional.h"
#include "TypeTraits.h"

#include <cstddef>
#include <iosfwd>
#include <new>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>

namespace ComplianceEngine
{
struct Error
{
    int code = -1;
    std::string message;

    // Format code-only diagnostics with strerror at report time.
    explicit Error(int code) noexcept
        : code(code)
    {
    }
    Error(std::string message, int code)
        : code(code),
          message(std::move(message))
    {
    }
    Error(std::string message)
        : message(std::move(message))
    {
    }
    Error(const Error& other)
        : code(other.code),
          message(other.message)
    {
    }
    Error(Error&& other) noexcept
        : code(other.code),
          message(std::move(other.message))
    {
    }
    Error& operator=(const Error& other)
    {
        if (this == &other)
        {
            return *this;
        }

        code = other.code;
        message = other.message;
        return *this;
    }

    Error& operator=(Error&& other) noexcept
    {
        if (this == &other)
        {
            return *this;
        }

        code = other.code;
        message = std::move(other.message);
        return *this;
    }
    ~Error() = default;
};
static_assert(std::is_nothrow_move_constructible<Error>::value && std::is_nothrow_destructible<Error>::value,
    "Error must move and destroy without throwing");
std::ostream& operator<<(std::ostream& os, const ComplianceEngine::Error& error);

namespace
{
constexpr std::size_t Max(std::size_t a, std::size_t b)
{
    return (a < b) ? b : a;
}
} // anonymous namespace

namespace ResultDetail
{
template <typename T>
class Storage
{
protected:
    union Pointer
    {
        T* value;
        ComplianceEngine::Error* error;
    };

    enum class Tag
    {
        Value,
        Error,
        MovedFrom
    };

    alignas(Max(alignof(T), alignof(ComplianceEngine::Error))) char mBuffer[Max(sizeof(T), sizeof(ComplianceEngine::Error))];
    Tag mTag = Tag::MovedFrom;
    Pointer mPointer = {nullptr};

    Storage() = default;
    ~Storage()
    {
        Reset();
    }

    // Precondition: this storage is empty. Construct first, so mTag
    // publishes only once the placement-new succeeds. A moved-from other
    // leaves this storage moved-from too.
    void CopyFrom(const Storage& other)
    {
        if (other.mTag == Tag::Value)
        {
            mPointer.value = ::new (static_cast<void*>(mBuffer)) T(*other.mPointer.value);
            mTag = Tag::Value;
        }
        else if (other.mTag == Tag::Error)
        {
            mPointer.error = ::new (static_cast<void*>(mBuffer)) ComplianceEngine::Error(*other.mPointer.error);
            mTag = Tag::Error;
        }
    }

    // Precondition: this storage is empty. Nonthrowing because Result<T>
    // asserts T's move constructor and destructor are nonthrowing. A
    // moved-from other leaves this storage moved-from too; other ends up
    // moved-from either way, since Reset() now settles on that tag.
    void MoveFrom(Storage& other) noexcept
    {
        if (other.mTag == Tag::Value)
        {
            mPointer.value = ::new (static_cast<void*>(mBuffer)) T(std::move(*other.mPointer.value));
            mTag = Tag::Value;
        }
        else if (other.mTag == Tag::Error)
        {
            mPointer.error = ::new (static_cast<void*>(mBuffer)) ComplianceEngine::Error(std::move(*other.mPointer.error));
            mTag = Tag::Error;
        }
        other.Reset();
    }

    void Reset() noexcept
    {
        if (mTag == Tag::Value)
        {
            mPointer.value->~T();
        }
        else if (mTag == Tag::Error)
        {
            using Type = ComplianceEngine::Error;
            mPointer.error->~Type();
        }
        mPointer.value = nullptr;
        mTag = Tag::MovedFrom;
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
} // namespace ResultDetail

template <typename T>
class Result : private ResultDetail::CopyStorage<T, std::is_copy_constructible<T>::value>
{
    using Storage = ResultDetail::CopyStorage<T, std::is_copy_constructible<T>::value>;
    using Tag = typename ResultDetail::Storage<T>::Tag;

    // Existing type guards first so reference/Error-as-value report their
    // own message; destructor before move so a throwing destructor reports
    // its own message even if a compiler stops at the first failure.
    static_assert(!std::is_reference<T>::value, "Result cannot hold references");
    static_assert(!std::is_same<T, ComplianceEngine::Error>::value, "Result cannot hold Error as its value type");
    static_assert(std::is_nothrow_destructible<T>::value, "Result requires a nonthrowing destructor");
    static_assert(std::is_nothrow_move_constructible<T>::value, "Result requires a nonthrowing move constructor");

public:
    Result(T value)
    {
        this->mPointer.value = ::new (static_cast<void*>(this->mBuffer)) T(std::move(value));
        this->mTag = Tag::Value;
    }

    Result(ComplianceEngine::Error error)
    {
        this->mPointer.error = ::new (static_cast<void*>(this->mBuffer)) ComplianceEngine::Error(std::move(error));
        this->mTag = Tag::Error;
    }

    Result(const Result&) = default;

    Result(Result&& other) noexcept
    {
        this->MoveFrom(other);
    }

    ~Result() = default;

private:
    void Reset() noexcept
    {
        Storage::Reset();
    }

public:
    Result& operator=(const Result&) = default;

    Result& operator=(Result&& other) noexcept
    {
        if (this == &other)
        {
            return *this;
        }

        Reset();
        this->MoveFrom(other);
        return *this;
    }

    bool HasValue() const noexcept
    {
        return this->mTag == Tag::Value;
    }

    operator bool() const noexcept
    {
        return HasValue();
    }

    T ValueOr(T default_value) const& noexcept(NoexceptCopyable<T>())
    {
        if (this->mTag != Tag::Value)
        {
            return std::move(default_value);
        }

        return *this->mPointer.value;
    }

    T ValueOr(T default_value) && noexcept
    {
        if (this->mTag != Tag::Value)
        {
            return std::move(default_value);
        }

        return std::move(*this->mPointer.value);
    }

    const T& Value() const&
    {
        CheckValue();
        return *this->mPointer.value;
    }

    T Value() &&
    {
        CheckValue();
        return std::move(*this->mPointer.value);
    }

    T& Value() &
    {
        CheckValue();
        return *this->mPointer.value;
    }

    const T* operator->() const&
    {
        CheckValue();
        return this->mPointer.value;
    }

    T* operator->() &
    {
        CheckValue();
        return this->mPointer.value;
    }

    const ComplianceEngine::Error& Error() const&
    {
        CheckError();
        return *this->mPointer.error;
    }

    ComplianceEngine::Error Error() &&
    {
        CheckError();
        return std::move(*this->mPointer.error);
    }

    ComplianceEngine::Error& Error() &
    {
        CheckError();
        return *this->mPointer.error;
    }

private:
    void CheckError() const
    {
        if (this->mTag == Tag::MovedFrom)
        {
            throw std::logic_error("Result: use after move");
        }
        if (this->mTag != Tag::Error)
        {
            throw std::logic_error("Result: unchecked access to Error");
        }
    }
    void CheckValue() const
    {
        if (this->mTag == Tag::MovedFrom)
        {
            throw std::logic_error("Result: use after move");
        }
        if (this->mTag != Tag::Value)
        {
            throw std::logic_error("Result: unchecked access to Value");
        }
    }
};

template <>
class Result<void>
{
public:
    static Result Success() noexcept
    {
        return Result();
    }

    Result(const ComplianceEngine::Error& error)
        : mError(error)
    {
    }

    Result(ComplianceEngine::Error&& error) noexcept
        : mError(std::move(error))
    {
    }

    Result(const Result&) = default;
    Result& operator=(const Result&) = default;

    Result(Result&& other) noexcept
        : mError(std::move(other.mError)),
          mMovedFrom(other.mMovedFrom)
    {
        other.mMovedFrom = true;
    }

    Result& operator=(Result&& other) noexcept
    {
        if (this != &other)
        {
            mError = std::move(other.mError);
            mMovedFrom = other.mMovedFrom;
            other.mMovedFrom = true;
        }
        return *this;
    }

    bool HasValue() const noexcept
    {
        return !mMovedFrom && !mError.HasValue();
    }

    explicit operator bool() const noexcept
    {
        return HasValue();
    }

    const ComplianceEngine::Error& Error() const&
    {
        CheckError();
        return mError.Value();
    }

    ComplianceEngine::Error& Error() &
    {
        CheckError();
        return mError.Value();
    }

    ComplianceEngine::Error Error() &&
    {
        CheckError();
        return std::move(mError).Value();
    }

private:
    Result() noexcept = default;

    void CheckError() const
    {
        if (mMovedFrom)
        {
            throw std::logic_error("Result: use after move");
        }
        if (HasValue())
        {
            throw std::logic_error("Result: unchecked access to Error");
        }
    }

    Optional<ComplianceEngine::Error> mError;
    bool mMovedFrom = false;
};
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_RESULT_H
