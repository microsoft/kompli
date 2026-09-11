// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <BenchmarkFormatter.hpp>
#include <RuleResult.hpp>
#include <cerrno>
#include <cstdlib>
#include <iomanip>
#include <parson.h>
#include <sstream>

namespace ComplianceEngine
{
namespace BenchmarkFormatters
{
using std::string;
using std::chrono::duration_cast;
using std::chrono::milliseconds;
using std::chrono::steady_clock;
using std::chrono::system_clock;

string BenchmarkFormatter::ToISODatetime(const system_clock::time_point& tp)
{
    const auto time = system_clock::to_time_t(tp);
    const auto tm = *std::gmtime(&time); // Convert to UTC time

    char buffer[32];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buffer;
}

BenchmarkFormatter::BenchmarkFormatter(DistributionInfo distributionInfo)
    : mDistributionInfo(std::move(distributionInfo))
{
}

Result<BenchmarkFormatter> BenchmarkFormatter::Begin(DistributionInfo distributionInfo, const Action action)
{
    BenchmarkFormatter formatter(std::move(distributionInfo));

    auto json = JsonWrapper::MakeObject();
    if (!json.HasValue())
    {
        return Error("Failed to initialize JSON object", ENOMEM);
    }

    formatter.mJson = std::move(json.Value());
    auto* object = json_value_get_object(formatter.mJson.get());
    if (nullptr == object)
    {
        return Error("Failed to get JSON object", ENOMEM);
    }

    formatter.mBegin = steady_clock::now();

    if (JSONSuccess != json_object_set_string(object, "timestamp", ToISODatetime(system_clock::now()).c_str()))
    {
        return Error("Failed to set timestamp", ENOMEM);
    }

    if (JSONSuccess != json_object_set_string(object, "action", action == Action::Audit ? "Audit" : "Remediation"))
    {
        return Error("Failed to set action", ENOMEM);
    }

    const auto arch = std::to_string(formatter.mDistributionInfo.architecture);
    const auto distribution = std::to_string(formatter.mDistributionInfo.distribution);
    auto* hostValue = json_value_init_object();
    if (nullptr == hostValue)
    {
        return Error("Failed to initialize host JSON object", ENOMEM);
    }
    auto* hostObject = json_value_get_object(hostValue);
    if (nullptr == hostObject || JSONSuccess != json_object_set_string(hostObject, "arch", arch.c_str()) ||
        JSONSuccess != json_object_set_string(hostObject, "distribution", distribution.c_str()) ||
        JSONSuccess != json_object_set_string(hostObject, "distributionVersion", formatter.mDistributionInfo.version.c_str()))
    {
        json_value_free(hostValue);
        return Error("Failed to set host info", ENOMEM);
    }
    if (JSONSuccess != json_object_set_value(object, "host", hostValue))
    {
        json_value_free(hostValue);
        return Error("Failed to set host info", ENOMEM);
    }

    auto* arrayValue = json_value_init_array();
    if (nullptr == arrayValue)
    {
        return Error("Failed to initialize JSON array", ENOMEM);
    }
    if (JSONSuccess != json_object_set_value(object, "rules", arrayValue))
    {
        json_value_free(arrayValue);
        return Error("Failed to set rules", ENOMEM);
    }

    return formatter;
}

Optional<Error> BenchmarkFormatter::AddEntry(const BenchmarkIO::Resource& entry, const Status status, const string& payload,
    const std::map<std::string, std::string>& parameters) &
{
    auto resultWrapper = BenchmarkIO::BuildRuleResultJson(entry, status, payload, parameters);
    if (!resultWrapper.HasValue())
    {
        return resultWrapper.Error();
    }
    auto result = std::move(resultWrapper.Value());

    auto* object = json_value_get_object(mJson.get());
    if (nullptr == object)
    {
        return Error("Failed to get JSON object", ENOMEM);
    }
    auto* array = json_object_get_array(object, "rules");
    if (nullptr == array)
    {
        return Error("Failed to get JSON array", ENOMEM);
    }

    if (JSONSuccess != json_array_append_value(array, result.release()))
    {
        return Error("Failed to append JSON value", ENOMEM);
    }

    return Optional<Error>();
}

Result<string> BenchmarkFormatter::Finish(Status status) &&
{
    auto* object = json_value_get_object(mJson.get());
    if (nullptr == object)
    {
        return Error("Failed to get JSON object", ENOMEM);
    }

    if (JSONSuccess != json_object_set_number(object, "durationMs",
                           std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - mBegin).count()))
    {
        return Error("Failed to set JSON duration", ENOMEM);
    }

    if (JSONSuccess != json_object_set_string(object, "status", std::to_string(status).c_str()))
    {
        return Error("Failed to set JSON status", ENOMEM);
    }

    auto* serializedString = json_serialize_to_string_pretty(mJson.get());
    if (nullptr == serializedString)
    {
        return Error("Failed to serialize JSON string", ENOMEM);
    }

    string result(serializedString);
    json_free_serialized_string(serializedString);

    return result;
}

} // namespace BenchmarkFormatters
} // namespace ComplianceEngine
