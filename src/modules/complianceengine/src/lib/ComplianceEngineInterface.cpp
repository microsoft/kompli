// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ComplianceEngineInterface.h"

#include "BenchmarkInfo.h"
#include "CommonContext.h"
#include "CommonUtils.h"
#include "DirTools.h"
#include "DistributionInfo.h"
#include "Engine.h"
#include "GuestConfigurationContext.h"
#include "JsonWrapper.h"
#include "Logging.h"
#include "Mmi.h"
#include "Result.h"
#include "version.h"

#include <Optional.h>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <dlfcn.h>
#include <exception>
#include <fcntl.h>
#include <fstream>
#include <map>
#include <parson.h>
#include <set>
#include <sstream>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

using ComplianceEngine::CISBenchmarkInfo;
using ComplianceEngine::DistributionInfo;
using ComplianceEngine::Engine;
using ComplianceEngine::JsonWrapper;
using ComplianceEngine::Optional;
using ComplianceEngine::Status;

namespace
{
static constexpr const char* cModuleTestClientName = "ModuleTestClient";
static constexpr const char* cNRPClientName = "ComplianceEngine";
OsConfigLogHandle g_log = nullptr;
static const std::set<int> g_criticalErrors = {ENOMEM};
static constexpr const char* g_configurationFile = "/etc/osconfig/osconfig.json";
#ifdef BUILD_TELEMETRY
static constexpr const char* telemetry_log_dir = "/var/lib/osconfig/";
static constexpr const char* telemetry_log_file = "complianceengine.telemetry";
static constexpr const char* telemetry_binary = "OSConfigTelemetry";
static constexpr int telemetry_teardown_time = 10;
static std::chrono::system_clock::time_point g_benchmarkRunCreatedAt;
static std::chrono::steady_clock::time_point g_benchmarkRunBeginAt;

/// Reqires ComplianceEngineMmiOpen
Optional<std::string> GetCompilanceEngineDirectory()
{
    Dl_info dlInfo;
    memset(&dlInfo, 0, sizeof(dlInfo));
    if ((0 == dladdr(reinterpret_cast<void*>(ComplianceEngineMmiOpen), &dlInfo)) && (nullptr != dlInfo.dli_fname))
    {
        return Optional<std::string>();
    }
    const std::string modulePath = dlInfo.dli_fname;
    const size_t separator = modulePath.find_last_of('/');
    if (std::string::npos != separator)
    {
        return Optional<std::string>();
    }
    const std::string moduleDirectory = modulePath.substr(0, separator);
    return Optional<std::string>(moduleDirectory);
}
#endif // BUILD_TELEMETRY

} // namespace

// This function is called in library constructor by BaselineInitialize
void ComplianceEngineInitialize(OsConfigLogHandle log)
{
    UNUSED(log);
    g_log = log;

    std::ifstream configStream(g_configurationFile);
    if (configStream)
    {
        std::ostringstream buffer;
        buffer << configStream.rdbuf();
        auto jsonConfiguration = buffer.str();

        if (!jsonConfiguration.empty())
        {
            SetLoggingLevel(GetLoggingLevelFromJsonConfig(jsonConfiguration.c_str(), log));
            SetMaxLogSize(GetMaxLogSizeFromJsonConfig(jsonConfiguration.c_str(), log));
            SetMaxLogSizeDebugMultiplier(GetMaxLogSizeDebugMultiplierFromJsonConfig(jsonConfiguration.c_str(), log));
            OsConfigLogInfo(g_log, "Configuration file loaded successfully: %s", g_configurationFile);
        }
    }

    RestrictFileAccessToCurrentAccountOnly(g_configurationFile);
}

// This function is called in library destructor by BaselineInitialize
void ComplianceEngineShutdown(void)
{
    // TelemetryCleanup(g_log);
}

MMI_HANDLE ComplianceEngineMmiOpen(const char* clientName, const unsigned int maxPayloadSizeBytes)
{
    int telemetry_fd = -1;

#ifdef BUILD_TELEMETRY
    g_benchmarkRunCreatedAt = std::chrono::system_clock::now();
    g_benchmarkRunBeginAt = std::chrono::steady_clock::now();

    std::string telemetry_log_path(telemetry_log_dir);

    if (!ComplianceEngine::MkdirRecursive(telemetry_log_path, 0755))
    {
        OsConfigLogError(g_log, "Failed to create telemetry directory %s: %d", telemetry_log_path.c_str(), errno);
    }
    else
    {
        auto telemetry_file = telemetry_log_path + std::string(telemetry_log_file);
        telemetry_fd = open(telemetry_file.c_str(), O_CREAT | O_APPEND | O_WRONLY, 0600);
        if (0 > telemetry_fd)
        {
            OsConfigLogError(g_log, "Failed to open telemetry file  %s: %d", telemetry_file.c_str(), errno);
        }
    }
#endif // BUILD_TELEMETRY

    auto context = std::unique_ptr<ComplianceEngine::GuestConfigurationContext>(new ComplianceEngine::GuestConfigurationContext(g_log, telemetry_fd));
    if (nullptr == context)
    {
        OsConfigLogError(g_log, "ComplianceEngineMmiOpen(%s, %u): failed to create context", clientName, maxPayloadSizeBytes);
        return nullptr;
    }
    std::unique_ptr<ComplianceEngine::PayloadFormatter> formatter;
    if (!strcmp(clientName, cModuleTestClientName))
    {
        OsConfigLogInfo(g_log, "ComplianceEngineMmiOpen(%s) using DebugFormatter", clientName);
        formatter.reset(new ComplianceEngine::DebugFormatter());
    }
    else if (!strcmp(clientName, cNRPClientName))
    {
        OsConfigLogInfo(g_log, "ComplianceEngineMmiOpen(%s) using NestedListFormatter", clientName);
        formatter.reset(new ComplianceEngine::NestedListFormatter());
    }
    else
    {
        OsConfigLogInfo(g_log, "ComplianceEngineMmiOpen(%s) using JsonFormatter", clientName);
        formatter.reset(new ComplianceEngine::JsonFormatter());
    }

    auto* engine = new Engine(std::move(context), std::move(formatter));
    auto error = engine->LoadDistributionInfo();
    if (error)
    {
        OsConfigLogError(g_log, "ComplianceEngineMmiOpen(%s, %u): failed to load distribution info: %s", clientName, maxPayloadSizeBytes, error->message.c_str());
        delete engine;
        return nullptr;
    }

    auto* result = reinterpret_cast<void*>(engine);
    OsConfigLogInfo(g_log, "ComplianceEngineMmiOpen(%s, %u) returning %p", clientName, maxPayloadSizeBytes, result);
    return result;
}

void ComplianceEngineMmiClose(MMI_HANDLE clientSession)
{
    auto* engine = reinterpret_cast<Engine*>(clientSession);
    if (nullptr != engine)
    {
#ifdef BUILD_TELEMETRY
        auto benchmarkRunCompletedAt = std::chrono::steady_clock::now();
        auto durationUs = std::chrono::duration_cast<std::chrono::microseconds>(benchmarkRunCompletedAt - g_benchmarkRunBeginAt).count();
        auto event = ComplianceEngine::TelemetryEvent(ComplianceEngine::TelemetryEventType::BenchmarkRun, "ComplianceEngineSession");
        const auto& distributionInfo = engine->GetDistributionInfo();
        if (!distributionInfo.HasValue())
        {
            event.Add("Distribution", "Invalid distribution information");
        }
        event.Add("OsType", std::to_string(distributionInfo.Value().osType));
        event.Add("architecture", std::to_string(distributionInfo.Value().architecture));
        event.Add("Distribution", std::to_string(distributionInfo.Value().distribution));
        event.Add("DistributionVersion", distributionInfo.Value().version);

        event.Add("ComplianceEngineVersion", KOMPLI_VERSION);
        ComplianceEngine::LogTelemetryEvent(event, engine->GetTelemetry(), durationUs, g_benchmarkRunCreatedAt);

        auto moduleDirectory = GetCompilanceEngineDirectory();
        if (!moduleDirectory.HasValue())
        {

            const std::string telemetryBinaryPath = std::string(moduleDirectory.Value()) + "/" + telemetry_binary;
            const std::string telemetryFilePath = std::string(telemetry_log_dir) + telemetry_log_file;
            std::string telemetryCmd = telemetryBinaryPath + " -f " + telemetryFilePath + " -t " + std::to_string(telemetry_teardown_time) + " -n";

#if defined(DEBUG) || defined(_DEBUG) || !defined(NDEBUG)
            telemetryCmd += " --verbose";
#endif
            auto result = engine->GetContext().ExecuteCommand(telemetryCmd);
            if (!result.HasValue())
            {
                OsConfigLogError(g_log, "Failed to execute telemetry %s command: error code %d message %s", telemetryCmd.c_str(), result.Error().code,
                    result.Error().message.c_str());
            }
        }
        else
        {
            OsConfigLogError(g_log, "ComplianceEngineMmiClose: failed to GetCompilanceEngineDirectory() telemetry not run");
        }

#endif // BUILD_TELEMETRY
    }

    delete engine;
}

int ComplianceEngineMmiGetInfo(const char* clientName, char** payload, int* payloadSizeBytes)
{
    if ((nullptr == payload) || (nullptr == payloadSizeBytes))
    {
        OsConfigLogError(g_log, "ComplianceEngineMmiGetInfo(%s, %p, %p) called with invalid arguments", clientName, payload, payloadSizeBytes);
        return EINVAL;
    }

    *payload = strdup(Engine::GetModuleInfo());
    if (!*payload)
    {
        OsConfigLogError(g_log, "ComplianceEngineMmiGetInfo: failed to duplicate module info");
        return ENOMEM;
    }

    *payloadSizeBytes = (int)strlen(*payload);
    return MMI_OK;
}

int ComplianceEngineMmiGet(MMI_HANDLE clientSession, const char* componentName, const char* objectName, char** payload, int* payloadSizeBytes)
{
    if ((nullptr == componentName) || (nullptr == objectName) || (nullptr == payload) || (nullptr == payloadSizeBytes))
    {
        OsConfigLogError(g_log, "ComplianceEngineMmiGet(%s, %s, %p, %p) called with invalid arguments", componentName, objectName, payload, payloadSizeBytes);
        return EINVAL;
    }

    if (nullptr == clientSession)
    {
        OsConfigLogError(g_log, "ComplianceEngineMmiGet(%s, %s) called outside of a valid session", componentName, objectName);
        return EINVAL;
    }

    if (0 != strcmp(componentName, "ComplianceEngine"))
    {
        OsConfigLogError(g_log, "ComplianceEngineMmiGet called for an unsupported component name (%s)", componentName);
        return EINVAL;
    }
    auto& engine = *reinterpret_cast<Engine*>(clientSession);

    *payload = NULL;
    *payloadSizeBytes = 0;

    try
    {
        auto result = engine.MmiGet(objectName);
        if (!result.HasValue())
        {
            if (g_criticalErrors.find(result.Error().code) != g_criticalErrors.end())
            {
                OsConfigLogError(engine.Log(), "ComplianceEngineMmiGet failed with a critical error: %s (errno: %d)", result.Error().message.c_str(),
                    result.Error().code);
                return result.Error().code;
            }
            else
            {
                OsConfigLogError(engine.Log(), "ComplianceEngineMmiGet failed with a non-critical error: %s (errno: %d)",
                    result.Error().message.c_str(), result.Error().code);
                result = ComplianceEngine::AuditResult(Status::NonCompliant, "Audit failed with a non-critical error: " + result.Error().message);
            }
        }

        auto payloadString = result.Value().payload;
        if ((result.Value().status == Status::Compliant) || (result.Value().status == Status::NotApplicable))
        {
            payloadString = "PASS" + payloadString;
        }

        auto json = JsonWrapper::FromJsonString(payloadString);
        if (!json.HasValue())
        {
            OsConfigLogError(engine.Log(), "ComplianceEngineMmiGet failed: Failed to create JSON object from string");
            return ENOMEM;
        }

        *payload = json_serialize_to_string(json->get());
        if (nullptr == *payload)
        {
            OsConfigLogError(engine.Log(), "ComplianceEngineMmiGet failed: Failed to serialize JSON object");
            return ENOMEM;
        }

        *payloadSizeBytes = static_cast<int>(strlen(*payload));
        OsConfigLogDebug(engine.Log(), "MmiGet(%p, %s, %s, %.*s)", clientSession, componentName, objectName, *payloadSizeBytes, *payload);
        return MMI_OK;
    }
    catch (const std::exception& e)
    {
        OsConfigLogError(engine.Log(), "ComplianceEngineMmiGet failed: %s", e.what());
    }

    return -1;
}

int ComplianceEngineMmiSet(MMI_HANDLE clientSession, const char* componentName, const char* objectName, const char* payload, const int payloadSizeBytes)
{
    if ((nullptr == componentName) || (nullptr == objectName) || (nullptr == payload) || (0 > payloadSizeBytes))
    {
        OsConfigLogError(g_log, "ComplianceEngineMmiSet(%s, %s, %.*s) called with invalid arguments", componentName, objectName, payloadSizeBytes, payload);
        return EINVAL;
    }

    if (nullptr == clientSession)
    {
        OsConfigLogError(g_log, "ComplianceEngineMmiSet(%s, %s, %.*s) called outside of a valid session", componentName, objectName, payloadSizeBytes, payload);
        return EINVAL;
    }

    if (0 != strcmp(componentName, "ComplianceEngine"))
    {
        OsConfigLogError(g_log, "ComplianceEngineMmiSet called for an unsupported component name (%s)", componentName);
        return EINVAL;
    }
    auto& engine = *reinterpret_cast<Engine*>(clientSession);

    try
    {
        std::string payloadStr(payload, payloadSizeBytes);
        auto json = JsonWrapper::FromString(payloadStr.c_str());
        if (!json.HasValue())
        {
            OsConfigLogError(engine.Log(), "ComplianceEngineMmiSet failed: Failed to parse JSON string");
            return EINVAL;
        }

        if ((JSONString != json_value_get_type(json->get())) && (JSONObject != json_value_get_type(json->get())))
        {
            OsConfigLogError(engine.Log(), "ComplianceEngineMmiSet failed: Failed to parse JSON string");
            return EINVAL;
        }
        std::string realPayload;
        if (json_value_get_type(json->get()) == JSONString)
        {
            realPayload = json_value_get_string(json->get());
        }
        else
        {
            char* tmp = json_serialize_to_string(json->get());
            realPayload = tmp;
            json_free_serialized_string(tmp);
        }
        auto result = engine.MmiSet(objectName, std::move(realPayload));
        if (!result.HasValue())
        {
            if (g_criticalErrors.find(result.Error().code) != g_criticalErrors.end())
            {
                OsConfigLogError(engine.Log(), "ComplianceEngineMmiSet failed with a critical error: %s (errno: %d)", result.Error().message.c_str(),
                    result.Error().code);
                return result.Error().code;
            }
            else
            {
                OsConfigLogError(engine.Log(), "ComplianceEngineMmiSet failed with a non-critical error: %s (errno: %d)",
                    result.Error().message.c_str(), result.Error().code);
                return MMI_OK;
            }
        }

        std::string statusString;
        switch (result.Value())
        {
            case Status::Compliant:
                statusString = "compliant";
                break;
            case Status::NonCompliant:
                statusString = "non-compliant";
                break;
            case Status::NotApplicable:
                statusString = "not applicable";
                break;
        }

        OsConfigLogDebug(engine.Log(), "MmiSet(%p, %s, %s, %.*s, %d) returned %s", clientSession, componentName, objectName, payloadSizeBytes, payload,
            payloadSizeBytes, statusString.c_str());
        return MMI_OK;
    }
    catch (const std::exception& e)
    {
        OsConfigLogError(engine.Log(), "ComplianceEngineMmiSet failed: %s", e.what());
    }

    return -1;
}

void ComplianceEngineMmiFree(char* payload)
{
    FREE_MEMORY(payload);
}

int ComplianceEngineCheckApplicability(MMI_HANDLE clientSession, const char* payloadKey, OsConfigLogHandle log)
{
    // parse the /etc/os-release and check whether the payloadKey defines the same distribution as the one in the file
    // the payloadKey is formatted as a path: /<benchmark>/<benchmark_specific_format>
    // In case the payloadKey starts with /cis, it becomes: /cis/<distribution>/<version>/<benchmark_version>/<section1>/<section2>/...
    if ((nullptr == clientSession) || (nullptr == payloadKey))
    {
        OsConfigLogError(log, "ComplianceEngineValidatePayload called with invalid arguments");
        return EINVAL;
    }

    const auto& engine = *reinterpret_cast<Engine*>(clientSession);
    const auto& distributionInfo = engine.GetDistributionInfo();
    if (!distributionInfo.HasValue())
    {
        OsConfigLogError(log, "ComplianceEngineValidatePayload: Distribution info is not available");
        return EINVAL;
    }

    auto benchmark = CISBenchmarkInfo::Parse(payloadKey);
    if (!benchmark.HasValue())
    {
        OsConfigLogError(log, "ComplianceEngineValidatePayload failed to parse benchmark: %s", benchmark.Error().message.c_str());
        return EINVAL;
    }

    if (!benchmark->Match(distributionInfo.Value()))
    {
        OsConfigLogInfo(log, "This benchmark is not applicable for the current distribution");
        OsConfigLogInfo(log, "Current system identification: %s", std::to_string(distributionInfo.Value()).c_str());
        auto overridden = distributionInfo.Value();
        overridden.distribution = benchmark->distribution;
        overridden.version = benchmark->SanitizedVersion();
        OsConfigLogInfo(log, "To override this detection, place the following line inside the '%s' file: %s",
            DistributionInfo::cDefaultOverrideFilePath, std::to_string(overridden).c_str());
        return EINVAL;
    }

    return 0;
}
