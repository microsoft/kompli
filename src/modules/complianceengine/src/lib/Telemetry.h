// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_CETELEMETRY_H
#define COMPLIANCEENGINE_CETELEMETRY_H

#include "Optional.h"
#include "Result.h"

#include <chrono>
#include <cstdint>
#include <exception>
#include <string>
#include <utility>
#include <vector>

namespace ComplianceEngine
{

enum class TelemetryEventType
{
    Audit,
    Remediation,
    BenchmarkRun,
};

// A single key/value context field attached to a TelemetryEvent.
// String values are serialized as JSON strings; integer values as JSON numbers.
struct TelemetryField
{
    enum Kind
    {
        Str,
        Int,
        Int64
    } kind;
    std::string key;
    std::string strVal; // used when kind == Str
    int64_t numVal;     // used when kind == Int or Int64
};

class TelemetryEvent
{
public:
    TelemetryEvent(TelemetryEventType type, std::string name)
        : mType(type),
          mName(std::move(name))
    {
    }

    explicit TelemetryEvent(TelemetryEventType type)
        : mType(type)
    {
    }

    TelemetryEventType Type() const noexcept
    {
        return mType;
    }

    const std::string& Name() const noexcept
    {
        return mName;
    }

    // Add a string context field (serialized as a JSON string).
    TelemetryEvent& Add(std::string key, std::string val)
    {
        mContext.push_back({TelemetryField::Str, std::move(key), std::move(val), 0});
        return *this;
    }

    // Add an int context field (serialized as a JSON number).
    TelemetryEvent& Add(std::string key, int val)
    {
        mContext.push_back({TelemetryField::Int, std::move(key), {}, static_cast<int64_t>(val)});
        return *this;
    }

    // Add a 64-bit int context field (serialized as a JSON number).
    TelemetryEvent& Add(std::string key, int64_t val)
    {
        mContext.push_back({TelemetryField::Int64, std::move(key), {}, val});
        return *this;
    }

    const std::vector<TelemetryField>& Context() const noexcept
    {
        return mContext;
    }

private:
    TelemetryEventType mType;
    std::string mName;
    std::vector<TelemetryField> mContext;
};

class TelemetryInterface
{
public:
    virtual ~TelemetryInterface() = 0;

private:
    virtual void LogEvent(const TelemetryEvent& event, int64_t durationUs, const std::chrono::system_clock::time_point& createdAt) noexcept = 0;
    template <typename F>
    friend auto RunWithTelemetry(const TelemetryEvent& event, TelemetryInterface& telemetry, F&& function) -> decltype(std::forward<F>(function)());
    friend void LogTelemetryEvent(const TelemetryEvent& event, TelemetryInterface& telemetry, int64_t durationUs,
        const std::chrono::system_clock::time_point& createdAt) noexcept;
};

#ifdef BUILD_TELEMETRY

class Telemetry : public TelemetryInterface
{
public:
    explicit Telemetry(const int fd) noexcept;
    virtual ~Telemetry() noexcept;

    Telemetry(const Telemetry&) = delete;
    Telemetry& operator=(const Telemetry&) = delete;
    Telemetry(Telemetry&&) = delete;
    Telemetry& operator=(Telemetry&&) = delete;

private:
    void LogEvent(const TelemetryEvent& event, int64_t durationUs, const std::chrono::system_clock::time_point& createdAt) noexcept override;
    int fd = -1;
};

template <typename F>
auto RunWithTelemetry(const TelemetryEvent& event, TelemetryInterface& telemetry, F&& function) -> decltype(std::forward<F>(function)())
{
    const auto createdAt = std::chrono::system_clock::now();
    const auto begin = std::chrono::steady_clock::now();
    using chrono_time = std::chrono::time_point<std::chrono::steady_clock>;
    chrono_time end;

    // Use Optional to hold data that has no default constructor
    Optional<decltype(std::forward<F>(function)())> tmp_result;
    try
    {
        tmp_result = std::forward<F>(function)();
    }
    catch (const std::exception& e)
    {
        end = std::chrono::steady_clock::now();
        const auto durationUs = std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();
        TelemetryEvent logged = event;
        logged.Add("exception", std::string(e.what()));
        telemetry.LogEvent(logged, durationUs, createdAt);
        throw;
    }
    catch (...)
    {
        end = std::chrono::steady_clock::now();
        const auto durationUs = std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();
        TelemetryEvent logged = event;
        logged.Add("exception", std::string("unknown non-std exception"));
        telemetry.LogEvent(logged, durationUs, createdAt);
        throw;
    }

    auto result = tmp_result.Value();
    if (result.HasValue())
    {
        return std::forward<decltype(result)>(result);
    }

    end = std::chrono::steady_clock::now();
    const auto durationUs = std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();
    TelemetryEvent logged = event;
    logged.Add("resultCode", result.Error().code);
    if (!result.Error().message.empty())
    {
        logged.Add("errorMessage", result.Error().message);
    }
    telemetry.LogEvent(logged, durationUs, createdAt);
    return std::forward<decltype(result)>(result);
}

inline void LogTelemetryEvent(const TelemetryEvent& event, TelemetryInterface& telemetry, int64_t durationUs, const std::chrono::system_clock::time_point& createdAt) noexcept
{
    telemetry.LogEvent(event, durationUs, createdAt);
}
#else  // BUILD_TELEMETRY

class Telemetry : public TelemetryInterface
{
public:
    explicit Telemetry(const int fd) noexcept
    {
        (void)fd;
    }

    ~Telemetry() noexcept override = default;

    Telemetry(const Telemetry&) = delete;
    Telemetry& operator=(const Telemetry&) = delete;
    Telemetry(Telemetry&&) = delete;
    Telemetry& operator=(Telemetry&&) = delete;

private:
    void LogEvent(const TelemetryEvent& event, int64_t durationUs, const std::chrono::system_clock::time_point& createdAt) noexcept override
    {
        (void)event;
        (void)durationUs;
        (void)createdAt;
    }
};

template <typename F>
auto RunWithTelemetry(const TelemetryEvent& event, TelemetryInterface& telemetry, F&& function) -> decltype(std::forward<F>(function)())
{
    (void)event;
    (void)telemetry;
    return std::forward<F>(function)();
}

inline void LogTelemetryEvent(const TelemetryEvent& event, TelemetryInterface& telemetry, int64_t durationUs, const std::chrono::system_clock::time_point& createdAt) noexcept
{
    (void)event;
    (void)telemetry;
    (void)durationUs;
    (void)createdAt;
}
#endif // BUILD_TELEMETRY
} // namespace ComplianceEngine

namespace std
{
std::string to_string(const ComplianceEngine::TelemetryEventType type); // NOLINT(*-identifier-naming)
} // namespace std
#endif // COMPLIANCEENGINE_CETELEMETRY_H
