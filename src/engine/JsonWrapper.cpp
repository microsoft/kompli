// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "JsonWrapper.h"

#include <Base64.h>
#include <parson.h>

namespace ComplianceEngine
{
namespace
{
bool ContainsNul(const std::string& input)
{
    if (input.find('\0') != std::string::npos)
    {
        return true;
    }

    bool inString = false;
    for (std::size_t index = 0; index < input.size(); ++index)
    {
        const char value = input[index];
        if (!inString)
        {
            inString = value == '"';
            continue;
        }
        if (value == '"')
        {
            inString = false;
            continue;
        }
        if (value != '\\' || ++index >= input.size())
        {
            continue;
        }
        if ((input[index] == 'u') && (index + 4 < input.size()) && (input.compare(index + 1, 4, "0000") == 0))
        {
            return true;
        }
    }
    return false;
}
} // namespace

Result<JsonWrapper> JsonWrapper::FromString(const char* input)
{
    if (nullptr == input)
    {
        return Error("Failed to parse JSON", EINVAL);
    }
    if (ContainsNul(input))
    {
        return Error("JSON input contains embedded NUL", EINVAL);
    }
    auto result = JsonWrapperPointerType(json_parse_string(input), &json_value_free);
    if (nullptr == result)
    {
        return Error("Failed to parse JSON", EINVAL);
    }

    return JsonWrapper(std::move(result));
}

Result<JsonWrapper> JsonWrapper::FromString(const std::string& input)
{
    if (ContainsNul(input))
    {
        return Error("JSON input contains embedded NUL", EINVAL);
    }
    auto result = JsonWrapperPointerType(json_parse_string(input.c_str()), &json_value_free);
    if (nullptr == result)
    {
        return Error("Failed to parse JSON", EINVAL);
    }

    return JsonWrapper(std::move(result));
}

Result<JsonWrapper> JsonWrapper::FromBase64(const std::string& input)
{
    const auto decodedString = Base64Decode(input);
    if (!decodedString.HasValue())
    {
        return decodedString.Error();
    }

    return FromString(decodedString.Value());
}

Result<JsonWrapper> JsonWrapper::FromJsonString(const std::string& input)
{
    if (input.find('\0') != std::string::npos)
    {
        return Error("JSON string contains embedded NUL", EINVAL);
    }
    auto result = JsonWrapperPointerType(json_value_init_string_with_len(input.data(), input.size()), &json_value_free);
    if (nullptr == result)
    {
        return Error("Failed to parse JSON-encoded string", EINVAL);
    }

    if (JSONString != json_value_get_type(result.get()))
    {
        return Error("Failed to parse a JSON-encoded string: the parsed value is not a string", EINVAL);
    }

    return JsonWrapper(std::move(result));
}

Result<JsonWrapper> JsonWrapper::FromRawValue(json_value_t** value)
{
    if ((nullptr == value) || (nullptr == *value))
    {
        return Error("Failed to create JSON wrapper: null value", EINVAL);
    }

    auto result = Result<JsonWrapper>(JsonWrapper(JsonWrapperPointerType(*value, &json_value_free)));
    *value = nullptr;
    return result;
}

Result<JsonWrapper> JsonWrapper::MakeObject()
{
    auto* value = json_value_init_object();
    return FromRawValue(&value);
}

JsonWrapper::JsonWrapper()
    : JsonWrapperPointerType(nullptr, &json_value_free)
{
}

JsonWrapper::JsonWrapper(JsonWrapperPointerType&& value)
    : JsonWrapperPointerType(std::move(value))
{
}
} // namespace ComplianceEngine
