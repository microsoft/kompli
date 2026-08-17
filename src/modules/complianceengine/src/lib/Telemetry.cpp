// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "Telemetry.h"

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
#ifdef BUILD_TELEMETRY

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

} // namespace

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

    const int64_t createdAtUs = ToEpochMicroseconds(createdAt);
    const int64_t completedAtUs = ToEpochMicroseconds(std::chrono::system_clock::now());

    dprintf(fd, "{\"EventName\":\"%s\"", std::to_string(event.Type()).c_str());

    if (!event.Name().empty())
    {
        dprintf(fd, ",\"name\":\"%s\"", JsonEscape(event.Name()).c_str());
    }

    dprintf(fd, ",\"createdAtUs\":%lld,\"completedAtUs\":%lld,\"durationUs\":%lld", static_cast<long long>(createdAtUs),
        static_cast<long long>(completedAtUs), static_cast<long long>(durationUs));

    for (const auto& field : event.Context())
    {
        switch (field.kind)
        {
            case TelemetryField::Str:
                dprintf(fd, ",\"%s\":\"%s\"", JsonEscape(field.key).c_str(), JsonEscape(field.strVal).c_str());
                break;
            case TelemetryField::Int:
            case TelemetryField::Int64:
                dprintf(fd, ",\"%s\":%lld", JsonEscape(field.key).c_str(), static_cast<long long>(field.numVal));
                break;
        }
    }

    dprintf(fd, "}\n");
}

#endif // BUILD_TELEMETRY
} // namespace ComplianceEngine
