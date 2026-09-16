// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "Config.hpp"

#include <InputSecurity.hpp>
#include <JsonWrapper.h>
#include <cerrno>
#include <parson.h>
#include <unistd.h>
#include <vector>

namespace Komplid
{
using ComplianceEngine::Error;
using ComplianceEngine::JsonWrapper;
using ComplianceEngine::Result;
using std::string;

namespace
{
Result<string> ReadFd(int fd)
{
    string content;
    char buffer[4096];
    for (;;)
    {
        const ssize_t n = ::read(fd, buffer, sizeof(buffer));
        if (n < 0)
        {
            return Error("failed to read kompli.conf");
        }
        if (0 == n)
        {
            break;
        }
        content.append(buffer, static_cast<size_t>(n));
    }
    return content;
}
} // namespace

Result<KompliConfig> LoadConfigFromString(const string& json)
{
    KompliConfig config;

    auto jsonResult = JsonWrapper::FromString(json);
    if (!jsonResult.HasValue())
    {
        return Error("kompli.conf is not valid JSON: " + jsonResult.Error().message);
    }
    const auto* object = json_value_get_object(jsonResult.Value().get());
    if (nullptr == object)
    {
        return Error("kompli.conf must be a JSON object");
    }

    const char* apiVersion = json_object_get_string(object, "apiVersion");
    const char* kind = json_object_get_string(object, "kind");
    if (nullptr == apiVersion || string("v1") != apiVersion || nullptr == kind || string("KompliConfig") != kind)
    {
        return Error("kompli.conf must declare {\"apiVersion\": \"v1\", \"kind\": \"KompliConfig\"}");
    }

    const JSON_Object* auditCache = json_object_get_object(object, "auditCache");
    if (nullptr != auditCache)
    {
        if (json_object_has_value_of_type(auditCache, "ttlSeconds", JSONNumber))
        {
            const double ttl = json_object_get_number(auditCache, "ttlSeconds");
            if (ttl < 0)
            {
                return Error("kompli.conf: auditCache.ttlSeconds must be >= 0");
            }
            config.auditCacheTtlSeconds = static_cast<long>(ttl);
        }
        else if (json_object_has_value(auditCache, "ttlSeconds"))
        {
            return Error("kompli.conf: auditCache.ttlSeconds must be a number");
        }
    }

    const JSON_Object* backgroundTasks = json_object_get_object(object, "backgroundTasks");
    if (nullptr != backgroundTasks)
    {
        const JSON_Array* rules = json_object_get_array(backgroundTasks, "rules");
        if (nullptr != rules)
        {
            const size_t count = json_array_get_count(rules);
            for (size_t i = 0; i < count; ++i)
            {
                const char* rule = json_array_get_string(rules, i);
                if (nullptr == rule)
                {
                    return Error("kompli.conf: backgroundTasks.rules entries must be strings");
                }
                config.backgroundTaskRules.insert(rule);
            }
        }
        else if (json_object_has_value(backgroundTasks, "rules"))
        {
            return Error("kompli.conf: backgroundTasks.rules must be an array of strings");
        }
    }

    return config;
}

Result<KompliConfig> LoadConfig(const string& path)
{
    // ENOENT means "use defaults" (see kompli/docs/configuration.md "Load
    // semantics"); any other failure - including a symlink, wrong ownership,
    // or group/world-writable parent - is fail-closed below.
    if (0 != ::access(path.c_str(), F_OK))
    {
        if (ENOENT == errno)
        {
            return KompliConfig();
        }
    }

    auto fdResult = ComplianceEngine::BenchmarkIO::OpenVerifiedInput(path, nullptr);
    if (!fdResult.HasValue())
    {
        return Error("refusing to read kompli.conf '" + path + "': " + fdResult.Error().message);
    }
    const int fd = fdResult.Value();
    auto contentResult = ReadFd(fd);
    ::close(fd);
    if (!contentResult.HasValue())
    {
        return contentResult.Error();
    }

    return LoadConfigFromString(contentResult.Value());
}

} // namespace Komplid
