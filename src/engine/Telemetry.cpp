// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "Telemetry.h"

#include "JsonWrapper.h"

#include <memory>

#ifdef BUILD_TELEMETRY
#include <algorithm>
#include <cerrno>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#endif // BUILD_TELEMETRY

namespace std
{

std::string to_string(const Kompli::TelemetryEventType type)
{
    switch (type)
    {
        case Kompli::TelemetryEventType::Audit:
            return std::string("audit");
        case Kompli::TelemetryEventType::Remediation:
            return std::string("remediation");
        case Kompli::TelemetryEventType::BenchmarkRun:
            return std::string("benchmarkRun");
    }
    return "unknown";
}
} // namespace std
namespace Kompli
{

TelemetryInterface::~TelemetryInterface() = default;

void LogCreatedTelemetryEvent(const TelemetryEvent& event, TelemetryInterface& telemetry, OsConfigLogHandle log, int64_t durationUs,
    const std::chrono::system_clock::time_point& createdAt)
{
    (void)log;
    telemetry.LogEvent(event, durationUs, createdAt);
}

#ifdef BUILD_TELEMETRY

int OpenTelemetryFile(const std::string& path, OsConfigLogHandle log)
{
    const int descriptor = open(path.c_str(), O_CREAT | O_NOFOLLOW | O_RDWR | O_CLOEXEC | O_NONBLOCK, 0600);
    if (descriptor < 0)
    {
        OsConfigLogError(log, "Failed to open telemetry file %s: %d", path.c_str(), errno);
        return -1;
    }

    auto fail = [&](const char* operation, int error) {
        OsConfigLogError(log, "Failed to %s telemetry file %s: %d", operation, path.c_str(), error);
        close(descriptor);
        return -1;
    };

    struct stat metadata = {};
    if (fstat(descriptor, &metadata) != 0)
    {
        return fail("stat", errno);
    }
    if (!S_ISREG(metadata.st_mode))
    {
        return fail("validate", EINVAL);
    }
    if (fchmod(descriptor, 0600) != 0)
    {
        return fail("set permissions on", errno);
    }

    if (metadata.st_size >= static_cast<off_t>(kTelemetryLogSizeLimit))
    {
        // Only the last limit bytes can survive. Starting after the first
        // newline in this window preserves events and leaves strictly less
        // than the limit, even when the window starts in the middle of one.
        char buffer[64 * 1024];
        off_t source = metadata.st_size - static_cast<off_t>(kTelemetryLogSizeLimit);
        while (source < metadata.st_size)
        {
            const auto size = static_cast<std::size_t>(std::min<off_t>(sizeof(buffer), metadata.st_size - source));
            const auto count = pread(descriptor, buffer, size, source);
            if (count < 0 && errno == EINTR)
            {
                continue;
            }
            if (count <= 0)
            {
                return fail("read", count < 0 ? errno : EIO);
            }
            const auto newline = std::find(buffer, buffer + count, '\n');
            source += newline - buffer;
            if (newline != buffer + count)
            {
                ++source;
                break;
            }
        }

        off_t destination = 0;
        while (source < metadata.st_size)
        {
            const auto size = static_cast<std::size_t>(std::min<off_t>(sizeof(buffer), metadata.st_size - source));
            const auto count = pread(descriptor, buffer, size, source);
            if (count < 0 && errno == EINTR)
            {
                continue;
            }
            if (count <= 0)
            {
                return fail("read", count < 0 ? errno : EIO);
            }
            ssize_t written = 0;
            while (written < count)
            {
                // O_APPEND is enabled only after compaction: on Linux it
                // also makes pwrite ignore the explicit offset.
                const auto bytes = pwrite(descriptor, buffer + written, static_cast<std::size_t>(count - written), destination + written);
                if (bytes < 0 && errno == EINTR)
                {
                    continue;
                }
                if (bytes <= 0)
                {
                    return fail("write", bytes < 0 ? errno : EIO);
                }
                written += bytes;
            }
            source += count;
            destination += count;
        }
        if (ftruncate(descriptor, destination) != 0)
        {
            return fail("truncate", errno);
        }
    }

    const int flags = fcntl(descriptor, F_GETFL);
    if (flags < 0 || fcntl(descriptor, F_SETFL, (flags & ~O_NONBLOCK) | O_APPEND) != 0)
    {
        return fail("enable append on", errno);
    }
    return descriptor;
}

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
    CloseFileDescriptor();
}

void Telemetry::SetFileDescriptor(const int newFd) noexcept
{
    CloseFileDescriptor();
    fd = newFd;
}

void Telemetry::CloseFileDescriptor() noexcept
{
    if (0 <= fd)
    {
        close(fd);
        fd = -1;
    }
}

void Telemetry::LogEvent(const TelemetryEvent& event, int64_t durationUs, const std::chrono::system_clock::time_point& createdAt)
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
} // namespace Kompli
