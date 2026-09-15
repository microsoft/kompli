// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "Telemetry.h"

#include <sstream>

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
namespace
{
static int64_t ToEpochMicroseconds(const std::chrono::system_clock::time_point& timestamp) noexcept
{
    return std::chrono::duration_cast<std::chrono::microseconds>(timestamp.time_since_epoch()).count();
}

// Escape a string for embedding as a JSON string value.
static std::string JsonEscape(const std::string& s)
{
    std::string out;
    out.reserve(s.size() + 4);
    for (char c : s)
    {
        switch (c)
        {
            case '"':
                out += "\\\"";
                break;
            case '\\':
                out += "\\\\";
                break;
            case '\n':
                out += "\\n";
                break;
            case '\r':
                out += "\\r";
                break;
            case '\t':
                out += "\\t";
                break;
            default:
                out += c;
                break;
        }
    }
    return out;
}

static std::string SerializeTelemetryEvent(const TelemetryEvent& event, int64_t durationUs, const std::chrono::system_clock::time_point& createdAt)
{
    std::ostringstream output;
    output << "{\"EventName\":\"" << std::to_string(event.Type()) << "\"";
    if (!event.Name().empty())
    {
        output << ",\"name\":\"" << JsonEscape(event.Name()) << "\"";
    }
    output << ",\"createdAtUs\":" << ToEpochMicroseconds(createdAt) << ",\"completedAtUs\":" << ToEpochMicroseconds(std::chrono::system_clock::now())
           << ",\"durationUs\":" << durationUs;

    for (const auto& field : event.Context())
    {
        output << ",\"" << JsonEscape(field.key) << "\":";
        switch (field.kind)
        {
            case TelemetryField::Str:
                output << "\"" << JsonEscape(field.strVal) << "\"";
                break;
            case TelemetryField::Int:
            case TelemetryField::Int64:
                output << field.numVal;
                break;
        }
    }
    output << "}";
    return output.str();
}

} // namespace

TelemetryInterface::~TelemetryInterface() = default;

void LogCreatedTelemetryEvent(const TelemetryEvent& event, TelemetryInterface& telemetry, OsConfigLogHandle log, int64_t durationUs,
    const std::chrono::system_clock::time_point& createdAt) noexcept
{
    telemetry.LogEvent(event, durationUs, createdAt);
    const auto serializedEvent = SerializeTelemetryEvent(event, durationUs, createdAt);
    OsConfigLogCritical(log, "%s", serializedEvent.c_str());
}

#ifdef BUILD_TELEMETRY

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
    dprintf(fd, "%s\n", serializedEvent.c_str());
}

#endif // BUILD_TELEMETRY
} // namespace ComplianceEngine
