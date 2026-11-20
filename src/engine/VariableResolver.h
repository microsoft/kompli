// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_VARIABLE_RESOLVER_H
#define COMPLIANCEENGINE_VARIABLE_RESOLVER_H

#include <Result.h>
#include <TypedComparison.h>
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <functional>
#include <map>
#include <ranges/View.hpp>
#include <string>
#include <vector>

namespace ComplianceEngine
{
namespace VariableResolution
{
struct ObjectItem
{
    std::map<std::string, std::vector<std::string>> fields;
};

struct ObjectCollection
{
    std::vector<ObjectItem> items;
    bool complete = false;
};

using CollectObject = std::function<Result<ObjectCollection>(const std::string&)>;

namespace Detail
{
class ObjectFieldSource
{
public:
    using value_type = std::string;

    ObjectFieldSource(const ObjectCollection& collection, std::string objectRef, std::string itemField)
        : mBorrowed(&collection),
          mObjectRef(std::move(objectRef)),
          mItemField(std::move(itemField))
    {
    }

    ObjectFieldSource(ObjectCollection&& collection, std::string objectRef, std::string itemField)
        : mOwned(std::move(collection)),
          mObjectRef(std::move(objectRef)),
          mItemField(std::move(itemField))
    {
    }

    Result<Optional<std::string>> Next()
    {
        const auto& collection = (nullptr == mBorrowed) ? mOwned : *mBorrowed;
        if (mObjectRef.empty() || mItemField.empty())
        {
            return Error("Object reference and field name must be nonempty", EINVAL);
        }
        if (!collection.complete)
        {
            return Error("Incomplete object collection: " + mObjectRef, EAGAIN);
        }
        if (collection.items.empty())
        {
            return Error("No items for object field resolution: " + mObjectRef, ENODATA);
        }
        if (collection.items.size() == mItem)
        {
            return Optional<std::string>();
        }
        const auto& item = collection.items[mItem];
        const auto field = item.fields.find(mItemField);
        if (field == item.fields.end() || field->second.empty())
        {
            return Error("Missing object field '" + mItemField + "' in " + mObjectRef, EINVAL);
        }
        auto value = Optional<std::string>(field->second[mValue++]);
        if (field->second.size() == mValue)
        {
            ++mItem;
            mValue = 0;
        }
        return value;
    }

private:
    ObjectCollection mOwned;
    const ObjectCollection* mBorrowed = nullptr;
    std::string mObjectRef;
    std::string mItemField;
    std::size_t mItem = 0;
    std::size_t mValue = 0;
};
} // namespace Detail

inline Ranges::View<Detail::ObjectFieldSource> ObjectFieldRange(const ObjectCollection& collection, const std::string& objectRef, const std::string& itemField)
{
    return Ranges::View<Detail::ObjectFieldSource>(Detail::ObjectFieldSource(collection, objectRef, itemField));
}

inline Ranges::View<Detail::ObjectFieldSource> ObjectFieldRange(ObjectCollection&& collection, const std::string& objectRef, const std::string& itemField)
{
    return Ranges::View<Detail::ObjectFieldSource>(Detail::ObjectFieldSource(std::move(collection), objectRef, itemField));
}

void ObjectFieldRange(const ObjectCollection&&, const std::string&, const std::string&) = delete;

inline Result<std::vector<std::string>> ExtractObjectFields(const ObjectCollection& collection, const std::string& objectRef, const std::string& itemField)
{
    auto range = ObjectFieldRange(collection, objectRef, itemField);
    std::vector<std::string> values;
    for (const auto& value : range)
    {
        if (!value.HasValue())
        {
            return value.Error();
        }
        values.push_back(value.Value());
    }
    return values;
}

inline Result<std::vector<std::string>> ResolveObjectFieldValues(const std::string& objectRef, const std::string& itemField, const CollectObject& collect)
{
    if (objectRef.empty() || itemField.empty() || !collect)
    {
        return Error("Object reference, field name and collector are required", EINVAL);
    }
    auto collected = collect(objectRef);
    if (!collected.HasValue())
    {
        return collected.Error();
    }
    return ExtractObjectFields(collected.Value(), objectRef, itemField);
}

inline Result<std::vector<long long>> IntegerValues(const std::vector<std::string>& values)
{
    std::vector<long long> parsed;
    parsed.reserve(values.size());
    for (const auto& value : values)
    {
        const size_t firstDigit = (!value.empty() && (value[0] == '-' || value[0] == '+')) ? 1 : 0;
        if (firstDigit == value.size() || value.find_first_not_of("0123456789", firstDigit) != std::string::npos)
        {
            return Error("Invalid variable integer value: " + value, EINVAL);
        }
        errno = 0;
        char* end = nullptr;
        const long long number = std::strtoll(value.c_str(), &end, 10);
        if (errno == ERANGE)
        {
            return Error("Variable integer value out of range: " + value, ERANGE);
        }
        if (end != value.c_str() + value.size())
        {
            return Error("Invalid variable integer value: " + value, EINVAL);
        }
        parsed.push_back(number);
    }
    return parsed;
}

inline Result<std::vector<std::string>> Split(const std::vector<std::string>& values, const std::string& delimiter)
{
    if (delimiter.empty())
    {
        return Error("Empty variable split delimiter", EINVAL);
    }
    std::vector<std::string> parts;
    for (const auto& value : values)
    {
        size_t start = 0;
        size_t end = value.find(delimiter);
        while (end != std::string::npos)
        {
            parts.push_back(value.substr(start, end - start));
            start = end + delimiter.size();
            end = value.find(delimiter, start);
        }
        parts.push_back(value.substr(start));
    }
    return parts;
}

} // namespace VariableResolution
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_VARIABLE_RESOLVER_H
