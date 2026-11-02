// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_RANGES_PATH_COMPONENTS_HPP
#define COMPLIANCEENGINE_RANGES_PATH_COMPONENTS_HPP

#include <cstddef>
#include <iterator>
#include <string>

namespace ComplianceEngine
{
namespace Ranges
{
// Splits a borrowed path spelling, ignoring empty components between '/'.
// Does not validate absolute paths, dot components or embedded NUL bytes.
// The source string must outlive the range and its iterators; yielded strings
// own their component bytes independently of the source.
class PathComponents
{
public:
    class Iterator
    {
    public:
        using iterator_category = std::forward_iterator_tag;
        using value_type = std::string;
        using difference_type = std::ptrdiff_t;
        using pointer = void;
        using reference = value_type;

        Iterator() = default;

        reference operator*() const
        {
            return mPath->substr(mPosition, mEnd - mPosition);
        }

        Iterator& operator++()
        {
            SetPosition(mEnd);
            return *this;
        }

        Iterator operator++(int)
        {
            auto previous = *this;
            ++*this;
            return previous;
        }

        bool operator==(const Iterator& other) const
        {
            return mPath == other.mPath && mPosition == other.mPosition;
        }

        bool operator!=(const Iterator& other) const
        {
            return !(*this == other);
        }

    private:
        Iterator(const std::string& path, std::size_t position)
            : mPath(&path)
        {
            SetPosition(position);
        }

        void SetPosition(std::size_t position)
        {
            if (position >= mPath->size())
            {
                mPosition = mEnd = mPath->size();
                return;
            }
            mPosition = mPath->find_first_not_of('/', position);
            if (mPosition == std::string::npos)
            {
                mPosition = mEnd = mPath->size();
                return;
            }
            mEnd = mPath->find('/', mPosition);
            if (mEnd == std::string::npos)
                mEnd = mPath->size();
        }

        const std::string* mPath = nullptr;
        std::size_t mPosition = 0;
        std::size_t mEnd = 0;

        friend class PathComponents;
    };

    explicit PathComponents(const std::string& path, std::size_t start = 0)
        : mPath(path),
          mStart(start)
    {
    }

    PathComponents(std::string&&, std::size_t = 0) = delete;
    PathComponents(const std::string&&, std::size_t = 0) = delete;

    Iterator begin() const // NOLINT(*-identifier-naming)
    {
        return Iterator(mPath, mStart);
    }

    Iterator end() const // NOLINT(*-identifier-naming)
    {
        return Iterator(mPath, mPath.size());
    }

private:
    const std::string& mPath;
    std::size_t mStart;
};
} // namespace Ranges
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_RANGES_PATH_COMPONENTS_HPP
