// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_OVAL_VARIABLE_RESOLVER_H
#define COMPLIANCEENGINE_OVAL_VARIABLE_RESOLVER_H

#include <Result.h>
#include <TypedComparison.h>
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace ComplianceEngine
{
namespace OvalVariable
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

inline Result<std::vector<std::string>> ExtractObjectFields(const ObjectCollection& collection, const std::string& objectRef, const std::string& itemField)
{
    if (objectRef.empty() || itemField.empty())
    {
        return Error("Invalid object_component reference or field", EINVAL);
    }
    if (!collection.complete)
    {
        return Error("Incomplete object collection: " + objectRef, EAGAIN);
    }
    if (collection.items.empty())
    {
        return Error("No items for object_component: " + objectRef, ENODATA);
    }

    std::vector<std::string> values;
    for (const auto& item : collection.items)
    {
        const auto field = item.fields.find(itemField);
        if (field == item.fields.end() || field->second.empty())
        {
            return Error("Missing object_component field '" + itemField + "' in " + objectRef, EINVAL);
        }
        values.insert(values.end(), field->second.begin(), field->second.end());
    }
    return values;
}

inline Result<std::vector<std::string>> ObjectComponent(const std::string& objectRef, const std::string& itemField, const CollectObject& collect)
{
    if (objectRef.empty() || itemField.empty() || !collect)
    {
        return Error("Invalid object_component reference, field or collector", EINVAL);
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
            return Error("Invalid OVAL integer value: " + value, EINVAL);
        }
        errno = 0;
        char* end = nullptr;
        const long long number = std::strtoll(value.c_str(), &end, 10);
        if (errno == ERANGE)
        {
            return Error("OVAL integer value out of range: " + value, ERANGE);
        }
        if (end != value.c_str() + value.size())
        {
            return Error("Invalid OVAL integer value: " + value, EINVAL);
        }
        parsed.push_back(number);
    }
    return parsed;
}

inline std::vector<std::string> Unique(const std::vector<std::string>& values)
{
    std::set<std::string> seen;
    std::vector<std::string> unique;
    for (const auto& value : values)
    {
        if (seen.insert(value).second)
        {
            unique.push_back(value);
        }
    }
    return unique;
}

inline Result<std::vector<std::string>> Split(const std::vector<std::string>& values, const std::string& delimiter)
{
    if (delimiter.empty())
    {
        return Error("Empty OVAL split delimiter", EINVAL);
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

template <typename T>
Result<long long> Count(const std::vector<T>& values)
{
    if (values.size() > static_cast<unsigned long long>(LLONG_MAX))
    {
        return Error("OVAL count out of range", ERANGE);
    }
    return static_cast<long long>(values.size());
}

template <typename T>
Result<bool> CompareCount(const std::vector<T>& values, long long expected, TypedComparisonOperation operation)
{
    auto count = Count(values);
    if (!count.HasValue())
    {
        return count.Error();
    }
    return CompareTyped(count.Value(), expected, operation);
}
} // namespace OvalVariable
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_OVAL_VARIABLE_RESOLVER_H
