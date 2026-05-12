// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "Telemetry.h"

#include "JsonWrapper.h"

#include <memory>

#ifdef BUILD_TELEMETRY
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <utility>
#endif // BUILD_TELEMETRY

namespace std
{

std::string to_string(const ComplianceEngine::TelemetryEventType type)
{
    switch (type)
    {
        case ComplianceEngine::TelemetryEventType::Audit:
            return std::string("audit");
        case ComplianceEngine::TelemetryEventType::Remediation:
            return std::string("remediation");
        case ComplianceEngine::TelemetryEventType::BenchmarkRun:
            return std::string("benchmarkRun");
    }
    return "unknown";
}
} // namespace std
namespace ComplianceEngine
{

TelemetryInterface::~TelemetryInterface() = default;

void LogCreatedTelemetryEvent(const TelemetryEvent& event, TelemetryInterface& telemetry, OsConfigLogHandle log, int64_t durationUs,
    const std::chrono::system_clock::time_point& createdAt) noexcept
{
    (void)log;
    telemetry.LogEvent(event, durationUs, createdAt);
}

#ifdef BUILD_TELEMETRY

namespace
{
static int64_t ToEpochMicroseconds(const std::chrono::system_clock::time_point& timestamp) noexcept
{
    return std::chrono::duration_cast<std::chrono::microseconds>(timestamp.time_since_epoch()).count();
}

} // namespace
  //
static std::string SerializeTelemetryEvent(const TelemetryEvent& event, int64_t durationUs, const std::chrono::system_clock::time_point& createdAt)
{
    auto json = JsonWrapper::MakeObject();
    if (!json.HasValue())
    {
        return {};
    }

    auto* object = json_value_get_object(json.Value().get());
    const auto eventName = std::to_string(event.Type());
    if ((nullptr == object) || (JSONSuccess != json_object_set_string(object, "EventName", eventName.c_str())) ||
        (JSONSuccess != json_object_set_number(object, "createdAtUs", static_cast<double>(ToEpochMicroseconds(createdAt)))) ||
        (JSONSuccess != json_object_set_number(object, "completedAtUs", static_cast<double>(ToEpochMicroseconds(std::chrono::system_clock::now())))) ||
        (JSONSuccess != json_object_set_number(object, "durationUs", static_cast<double>(durationUs))))
    {
        return {};
    }

    if (!event.Name().empty() && (JSONSuccess != json_object_set_string_with_len(object, "name", event.Name().data(), event.Name().size())))
    {
        return {};
    }

    for (const auto& field : event.Context())
    {
        JSON_Status status = JSONFailure;
        switch (field.kind)
        {
            case TelemetryField::Str:
                status = json_object_set_string_with_len(object, field.key.c_str(), field.strVal.data(), field.strVal.size());
                break;
            case TelemetryField::Int:
            case TelemetryField::Int64:
                status = json_object_set_number(object, field.key.c_str(), static_cast<double>(field.numVal));
                break;
        }
        if (JSONSuccess != status)
        {
            return {};
        }
    }

    std::unique_ptr<char, decltype(&json_free_serialized_string)> serialized(json_serialize_to_string(json.Value().get()), &json_free_serialized_string);
    return serialized ? std::string(serialized.get()) : std::string();
}

Telemetry::Telemetry(const int fd) noexcept
    : fd(fd)
{
}

Telemetry::~Telemetry() noexcept
{
    if (0 <= fd)
    {
        close(fd);
    }
}

void Telemetry::LogEvent(const TelemetryEvent& event, int64_t durationUs, const std::chrono::system_clock::time_point& createdAt) noexcept
{
    if (0 > fd)
    {
        return;
    }

    const auto serializedEvent = SerializeTelemetryEvent(event, durationUs, createdAt);
    if (!serializedEvent.empty())
    {
        dprintf(fd, "%s\n", serializedEvent.c_str());
    }
}

#endif // BUILD_TELEMETRY
} // namespace ComplianceEngine
