// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef KOMPLI_RESULT_H
#define KOMPLI_RESULT_H

#include "TypeTraits.h"

#include <stdexcept>
#include <string>

namespace Kompli
{
struct Error
{
    int code = -1;
    std::string message;

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
std::ostream& operator<<(std::ostream& os, const Kompli::Error& error);

namespace
{
constexpr std::size_t Max(std::size_t a, std::size_t b)
{
    return (a < b) ? b : a;
}
} // anonymous namespace

template <typename T>
class Result
{
    // Tag::Empty marks storage that holds neither a T nor an Error (after
    // Reset(), e.g. a moved-from Result): it keeps Reset() idempotent
    // without a nullable pointer to guard against double-destruction.
    enum class Tag
    {
        Value,
        Error,
        Empty
    };

    alignas(Max(alignof(T), alignof(Kompli::Error))) char mBuffer[Max(sizeof(T), sizeof(Kompli::Error))];
    Tag mTag;

    // No pointer member caches the placement-new'd address: mBuffer's
    // address never moves, so these always re-derive it from mBuffer
    // instead of reusing a value computed before an earlier placement-new
    // of a different type at the same address. A cached self-pointer,
    // typed as whichever union arm was last active, let GCC Release (-O3)
    // carry a value loaded through the old arm's type across the
    // subsequent placement-new of the other type, mis-reading the new
    // object's leading bytes.
    T* ValuePtr() noexcept
    {
        return reinterpret_cast<T*>(mBuffer);
    }
    const T* ValuePtr() const noexcept
    {
        return reinterpret_cast<const T*>(mBuffer);
    }
    Kompli::Error* ErrorPtr() noexcept
    {
        return reinterpret_cast<Kompli::Error*>(mBuffer);
    }
    const Kompli::Error* ErrorPtr() const noexcept
    {
        return reinterpret_cast<const Kompli::Error*>(mBuffer);
    }

public:
    Result(T value)
        : mTag(Tag::Value)
    {
        new (mBuffer) T(std::move(value));
    }

    Result(Kompli::Error error)
        : mTag(Tag::Error)
    {
        new (mBuffer) Kompli::Error(std::move(error));
    }

    Result(const Result& other)
        : mTag(other.mTag)
    {
        if (Tag::Value == mTag)
        {
            new (mBuffer) T(*other.ValuePtr());
        }
        else if (Tag::Error == mTag)
        {
            new (mBuffer) Kompli::Error(*other.ErrorPtr());
        }
    }

    Result(Result&& other) noexcept(NoexceptMovable<T>())
        : mTag(other.mTag)
    {
        if (Tag::Value == mTag)
        {
            new (mBuffer) T(std::move(*other.ValuePtr()));
        }
        else if (Tag::Error == mTag)
        {
            new (mBuffer) Kompli::Error(std::move(*other.ErrorPtr()));
        }

        other.Reset();
    }

    ~Result()
    {
        Reset();
    }

private:
    void Reset() noexcept(NoexceptDestructible<T>())
    {
        if (Tag::Value == mTag)
        {
            ValuePtr()->~T();
        }
        else if (Tag::Error == mTag)
        {
            using Type = Kompli::Error;
            ErrorPtr()->~Type();
        }
        mTag = Tag::Empty;
    }

public:
    // Known exception-safety gap, to be fixed in a follow-up: both assignment
    // operators publish the source tag before placement-constructing the
    // payload. If the T or Error copy/move constructor throws, this Result
    // keeps a Value/Error tag over storage that holds no live object, and its
    // destructor then destroys unconstructed storage. The fix is to keep the
    // tag Empty until construction succeeds. Constructors are not affected:
    // a throwing constructor never runs ~Result.
    Result& operator=(const Result& other)
    {
        if (this == &other)
        {
            return *this;
        }

        Reset();
        mTag = other.mTag;
        if (Tag::Value == mTag)
        {
            new (mBuffer) T(*other.ValuePtr());
        }
        else if (Tag::Error == mTag)
        {
            new (mBuffer) Kompli::Error(*other.ErrorPtr());
        }

        return *this;
    }

    Result& operator=(Result&& other) noexcept(NoexceptMovable<T>())
    {
        if (this == &other)
        {
            return *this;
        }

        Reset();
        mTag = other.mTag;
        if (Tag::Value == mTag)
        {
            new (mBuffer) T(std::move(*other.ValuePtr()));
        }
        else if (Tag::Error == mTag)
        {
            new (mBuffer) Kompli::Error(std::move(*other.ErrorPtr()));
        }

        other.Reset();
        return *this;
    }

    bool HasValue() const noexcept
    {
        return mTag == Tag::Value;
    }

    operator bool() const noexcept
    {
        return HasValue();
    }

    T ValueOr(T default_value) const& noexcept(NoexceptCopyable<T>())
    {
        if (Tag::Value != mTag)
        {
            return std::move(default_value);
        }

        return *ValuePtr();
    }

    T ValueOr(T default_value) && noexcept(NoexceptMovable<T>())
    {
        if (Tag::Value != mTag)
        {
            return std::move(default_value);
        }

        return std::move(*ValuePtr());
    }

    const T& Value() const&
    {
        CheckValue();
        return *ValuePtr();
    }

    T Value() &&
    {
        CheckValue();
        return std::move(*ValuePtr());
    }

    T& Value() &
    {
        CheckValue();
        return *ValuePtr();
    }

    const T* operator->() const&
    {
        CheckValue();
        return ValuePtr();
    }

    T* operator->() &
    {
        CheckValue();
        return ValuePtr();
    }

    const Kompli::Error& Error() const&
    {
        CheckError();
        return *ErrorPtr();
    }

    Kompli::Error Error() &&
    {
        CheckError();
        return std::move(*ErrorPtr());
    }

    Kompli::Error& Error() &
    {
        CheckError();
        return *ErrorPtr();
    }

private:
    void CheckError() const
    {
        if (mTag != Tag::Error)
        {
            throw std::logic_error("Result: unchecked access to Error");
        }
    }
    void CheckValue() const
    {
        if (mTag != Tag::Value)
        {
            throw std::logic_error("Result: unchecked access to Value");
        }
    }
};
} // namespace Kompli

#endif // KOMPLI_RESULT_H
