// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "Protocol.hpp"

#include <cerrno>
#include <parson.h>

namespace Komplid
{
using ComplianceEngine::Error;
using ComplianceEngine::JsonWrapper;
using ComplianceEngine::Result;
using std::string;

namespace
{
Result<RequestMode> ParseMode(const string& mode)
{
    if ("audit" == mode)
    {
        return RequestMode::Audit;
    }
    if ("remediate" == mode)
    {
        return RequestMode::Remediate;
    }
    if ("enforce" == mode)
    {
        return RequestMode::Enforce;
    }
    return Error("Request has an unrecognized 'mode' value: '" + mode + "'", EINVAL);
}

Result<string> RequiredString(const JSON_Object* object, const char* key)
{
    const char* value = json_object_get_string(object, key);
    if (nullptr == value || '\0' == value[0])
    {
        return Error(string("request is missing required string field '") + key + "'", EINVAL);
    }
    return string(value);
}

// Serializes `value` and returns one line (no trailing newline) - the shared
// tail of BuildResultResponse/BuildErrorResponse.
Result<string> Serialize(const JsonWrapper& value)
{
    char* serialized = json_serialize_to_string(value.get());
    if (nullptr == serialized)
    {
        return Error("Failed to serialize response", ENOMEM);
    }
    string line(serialized);
    json_free_serialized_string(serialized);
    return line;
}
} // namespace

string ExtractRequestId(const string& line)
{
    auto jsonResult = JsonWrapper::FromString(line);
    if (!jsonResult.HasValue())
    {
        return string();
    }
    const auto* object = json_value_get_object(jsonResult.Value().get());
    if (nullptr == object)
    {
        return string();
    }
    const char* requestId = json_object_get_string(object, "requestId");
    return (nullptr != requestId) ? string(requestId) : string();
}

Result<Request> ParseRequest(const string& line)
{
    auto jsonResult = JsonWrapper::FromString(line);
    if (!jsonResult.HasValue())
    {
        return Error("Request line is not valid JSON", EINVAL);
    }
    const auto* object = json_value_get_object(jsonResult.Value().get());
    if (nullptr == object)
    {
        return Error("Request must be a JSON object", EINVAL);
    }

    auto requestId = RequiredString(object, "requestId");
    if (!requestId.HasValue())
    {
        return requestId.Error();
    }

    auto benchmark = RequiredString(object, "benchmark");
    if (!benchmark.HasValue())
    {
        return benchmark.Error();
    }
    // `benchmark` names a file under a fixed directory (RequestHandler
    // resolves it to <definitionsDir>/<benchmark>.benchmark.json) - it must
    // be a bare name, never a path, so a request can't escape that directory.
    if (string::npos != benchmark.Value().find('/'))
    {
        return Error("Request 'benchmark' must be a bare name, not a path: '" + benchmark.Value() + "'", EINVAL);
    }

    auto id = RequiredString(object, "id");
    if (!id.HasValue())
    {
        return id.Error();
    }

    auto modeStr = RequiredString(object, "mode");
    if (!modeStr.HasValue())
    {
        return modeStr.Error();
    }
    auto mode = ParseMode(modeStr.Value());
    if (!mode.HasValue())
    {
        return mode.Error();
    }

    Request request;
    request.requestId = requestId.Value();
    request.benchmark = benchmark.Value();
    request.id = id.Value();
    request.mode = mode.Value();

    const JSON_Value* parametersValue = json_object_get_value(object, "parameters");
    if (nullptr != parametersValue)
    {
        if (JSONObject != json_value_get_type(parametersValue))
        {
            return Error("Request 'parameters' must be an object", EINVAL);
        }
        const JSON_Object* parametersObject = json_value_get_object(parametersValue);
        const size_t count = json_object_get_count(parametersObject);
        for (size_t i = 0; i < count; ++i)
        {
            const char* name = json_object_get_name(parametersObject, i);
            const JSON_Value* value = json_object_get_value_at(parametersObject, i);
            if (nullptr == name || nullptr == value || JSONString != json_value_get_type(value))
            {
                return Error("Request 'parameters' values must be strings", EINVAL);
            }
            request.parameters[name] = json_value_get_string(value);
        }
    }

    return request;
}

const char* ToString(ErrorCode code)
{
    switch (code)
    {
        case ErrorCode::InvalidRequest:
            return "invalid_request";
        case ErrorCode::UnknownBenchmark:
            return "unknown_benchmark";
        case ErrorCode::UnknownRule:
            return "unknown_rule";
        case ErrorCode::UnsupportedMode:
            return "unsupported_mode";
        case ErrorCode::BenchmarkNotApplicable:
            return "benchmark_not_applicable";
        case ErrorCode::Unauthorized:
            return "unauthorized";
        case ErrorCode::InternalError:
        default:
            return "internal_error";
    }
}

Result<string> BuildResultResponse(const string& requestId, JsonWrapper result)
{
    auto envelopeResult = JsonWrapper::MakeObject();
    if (!envelopeResult.HasValue())
    {
        return Error("Failed to build response envelope", ENOMEM);
    }
    auto envelope = std::move(envelopeResult.Value());
    auto* object = json_value_get_object(envelope.get());
    if (nullptr == object)
    {
        return Error("Failed to build response envelope", ENOMEM);
    }

    if (JSONSuccess != json_object_set_string(object, "type", "result") ||
        JSONSuccess != json_object_set_string(object, "requestId", requestId.c_str()) ||
        JSONSuccess != json_object_set_value(object, "result", result.release()))
    {
        return Error("Failed to build response envelope", ENOMEM);
    }

    return Serialize(envelope);
}

Result<string> BuildErrorResponse(const string& requestId, ErrorCode code, const string& message)
{
    auto envelopeResult = JsonWrapper::MakeObject();
    if (!envelopeResult.HasValue())
    {
        return Error("Failed to build error response", ENOMEM);
    }
    auto envelope = std::move(envelopeResult.Value());
    auto* object = json_value_get_object(envelope.get());
    if (nullptr == object)
    {
        return Error("Failed to build error response", ENOMEM);
    }

    if (JSONSuccess != json_object_set_string(object, "type", "error") ||
        JSONSuccess != json_object_set_string(object, "requestId", requestId.c_str()) ||
        JSONSuccess != json_object_set_string(object, "code", ToString(code)) ||
        JSONSuccess != json_object_set_string(object, "message", message.c_str()))
    {
        return Error("Failed to build error response", ENOMEM);
    }

    return Serialize(envelope);
}

} // namespace Komplid
