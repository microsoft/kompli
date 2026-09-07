// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "Plan.hpp"

#include "BenchmarkDefinition.hpp"
#include "InputSecurity.hpp"

#include <JsonWrapper.h>
#include <cerrno>
#include <ext/stdio_filebuf.h>
#include <istream>
#include <memory>
#include <openssl/evp.h>
#include <parson.h>

namespace ComplianceEngine
{
namespace Cli
{
using std::string;

namespace
{
// Upper bound on the number of bytes read while hashing a benchmark-definition
// file. Matches BenchmarkDefinition's own input cap (the same files are hashed
// here that are parsed there).
constexpr std::size_t kMaxHashInputBytes = static_cast<std::size_t>(8) * 1024 * 1024;

// Upper bound on a plan file's size. Plans are tiny (one small object per
// rule); generous but bounds memory for a hostile input while running as root.
constexpr std::size_t kMaxPlanInputBytes = static_cast<std::size_t>(8) * 1024 * 1024;

const char* ToModeString(ToggleMode mode)
{
    switch (mode)
    {
        case ToggleMode::Audit:
            return "audit";
        case ToggleMode::Remediate:
            return "remediate";
        case ToggleMode::Enforce:
            return "enforce";
    }
    return "audit";
}

Result<ToggleMode> FromModeString(const string& mode)
{
    if (mode == "audit")
    {
        return ToggleMode::Audit;
    }
    if (mode == "remediate")
    {
        return ToggleMode::Remediate;
    }
    if (mode == "enforce")
    {
        return ToggleMode::Enforce;
    }
    return Error("Invalid plan rule mode: '" + mode + "'. Must be 'audit', 'remediate' or 'enforce'.", EINVAL);
}

// Applies the same input-hardening posture as benchmark-definition reads
// (path-traversal rejection, root-owned non-writable parent directory,
// O_NOFOLLOW open, regular-file/ownership/mode checks) and returns the
// verified fd's stdio_filebuf-wrapped stream via the supplied buffer.
Result<int> OpenVerified(const string& path, OsConfigLogHandle logHandle)
{
    if (BenchmarkIO::RefusePathTraversal(path, logHandle))
    {
        return Error("Refusing to open '" + path + "' with an unsafe path", EACCES);
    }
    if (BenchmarkIO::RefuseWritableParentDir(path, logHandle))
    {
        return Error("Refusing to open '" + path + "' in a writable parent directory", EACCES);
    }
    return BenchmarkIO::OpenVerifiedInput(path, logHandle);
}
} // anonymous namespace

Result<string> HashFile(const string& path, OsConfigLogHandle logHandle)
{
    auto fdResult = OpenVerified(path, logHandle);
    if (!fdResult.HasValue())
    {
        return fdResult.Error();
    }

    // stdio_filebuf takes ownership of the verified fd and closes it on destruction.
    __gnu_cxx::stdio_filebuf<char> buffer(fdResult.Value(), std::ios_base::in);
    std::istream stream(&buffer);

    std::unique_ptr<EVP_MD_CTX, void (*)(EVP_MD_CTX*)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (nullptr == ctx)
    {
        return Error("Failed to allocate SHA-256 context", ENOMEM);
    }
    if (1 != EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr))
    {
        return Error("Failed to initialize SHA-256 digest", EIO);
    }

    char readBuffer[64 * 1024];
    std::size_t total = 0;
    while (stream.read(readBuffer, sizeof(readBuffer)) || stream.gcount() > 0)
    {
        const auto n = static_cast<std::size_t>(stream.gcount());
        total += n;
        if (total > kMaxHashInputBytes)
        {
            return Error("File exceeds the maximum size of " + std::to_string(kMaxHashInputBytes) + " bytes for hashing", EFBIG);
        }
        if (1 != EVP_DigestUpdate(ctx.get(), readBuffer, n))
        {
            return Error("Failed to update SHA-256 digest", EIO);
        }
    }
    if (stream.bad())
    {
        return Error("I/O error while hashing '" + path + "'", EIO);
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digestLen = 0;
    if (1 != EVP_DigestFinal_ex(ctx.get(), digest, &digestLen))
    {
        return Error("Failed to finalize SHA-256 digest", EIO);
    }

    static const char* const hex = "0123456789abcdef";
    string result;
    result.reserve(static_cast<std::size_t>(digestLen) * 2);
    for (unsigned int i = 0; i < digestLen; ++i)
    {
        result.push_back(hex[(digest[i] >> 4) & 0xF]);
        result.push_back(hex[digest[i] & 0xF]);
    }
    return result;
}

Result<string> GeneratePlan(const string& benchmarkFile, const std::vector<Toggle>& toggles, OsConfigLogHandle logHandle)
{
    auto resourcesResult = BenchmarkDefinition::ParseFile(benchmarkFile, logHandle);
    if (!resourcesResult.HasValue())
    {
        return resourcesResult.Error();
    }
    const auto& resources = resourcesResult.Value();

    auto nameResult = BenchmarkDefinition::ParseName(benchmarkFile, logHandle);
    if (!nameResult.HasValue())
    {
        return nameResult.Error();
    }

    auto hashResult = HashFile(benchmarkFile, logHandle);
    if (!hashResult.HasValue())
    {
        return hashResult.Error();
    }

    // Seed every rule at `audit` (never a mutating default).
    std::map<string, ToggleMode> modes;
    for (const auto& resource : resources)
    {
        modes[resource.benchmarkInfo.section] = ToggleMode::Audit;
    }

    // Apply toggles in argument order; a section a toggle doesn't recognise is
    // a fail-fast error rather than a silently-ignored no-op.
    for (const auto& toggle : toggles)
    {
        if (modes.find(toggle.section) == modes.end())
        {
            return Error("Unknown section '" + toggle.section + "' in benchmark definition '" + benchmarkFile + "'", EINVAL);
        }
        modes[toggle.section] = toggle.mode;
    }

    auto jsonResult = JsonWrapper::MakeObject();
    if (!jsonResult.HasValue())
    {
        return Error("Failed to initialize plan JSON object", ENOMEM);
    }
    auto json = std::move(jsonResult.Value());
    auto* root = json_value_get_object(json.get());
    if (nullptr == root)
    {
        return Error("Failed to get plan JSON object", ENOMEM);
    }

    auto* benchmarkValue = json_value_init_object();
    if (nullptr == benchmarkValue)
    {
        return Error("Failed to initialize plan benchmark JSON object", ENOMEM);
    }
    auto* benchmarkObject = json_value_get_object(benchmarkValue);
    if (nullptr == benchmarkObject || JSONSuccess != json_object_set_string(benchmarkObject, "file", benchmarkFile.c_str()) ||
        JSONSuccess != json_object_set_string(benchmarkObject, "name", nameResult.Value().c_str()) ||
        JSONSuccess != json_object_set_string(benchmarkObject, "sha256", hashResult.Value().c_str()))
    {
        json_value_free(benchmarkValue);
        return Error("Failed to set plan benchmark fields", ENOMEM);
    }
    if (JSONSuccess != json_object_set_value(root, "benchmark", benchmarkValue))
    {
        json_value_free(benchmarkValue);
        return Error("Failed to set plan benchmark object", ENOMEM);
    }

    auto* rulesValue = json_value_init_object();
    if (nullptr == rulesValue)
    {
        return Error("Failed to initialize plan rules JSON object", ENOMEM);
    }
    auto* rulesObject = json_value_get_object(rulesValue);
    if (nullptr == rulesObject)
    {
        json_value_free(rulesValue);
        return Error("Failed to get plan rules JSON object", ENOMEM);
    }
    for (const auto& entry : modes)
    {
        auto* ruleValue = json_value_init_object();
        if (nullptr == ruleValue)
        {
            json_value_free(rulesValue);
            return Error("Failed to initialize plan rule JSON object", ENOMEM);
        }
        auto* ruleObject = json_value_get_object(ruleValue);
        auto* parametersValue = json_value_init_object();
        if (nullptr == ruleObject || nullptr == parametersValue || JSONSuccess != json_object_set_string(ruleObject, "mode", ToModeString(entry.second)) ||
            JSONSuccess != json_object_set_value(ruleObject, "parameters", parametersValue))
        {
            json_value_free(parametersValue);
            json_value_free(ruleValue);
            json_value_free(rulesValue);
            return Error("Failed to build plan rule '" + entry.first + "'", ENOMEM);
        }
        if (JSONSuccess != json_object_set_value(rulesObject, entry.first.c_str(), ruleValue))
        {
            json_value_free(ruleValue);
            json_value_free(rulesValue);
            return Error("Failed to set plan rule '" + entry.first + "'", ENOMEM);
        }
    }
    if (JSONSuccess != json_object_set_value(root, "rules", rulesValue))
    {
        json_value_free(rulesValue);
        return Error("Failed to set plan rules object", ENOMEM);
    }

    auto* serialized = json_serialize_to_string_pretty(json.get());
    if (nullptr == serialized)
    {
        return Error("Failed to serialize plan JSON", ENOMEM);
    }
    string result(serialized);
    json_free_serialized_string(serialized);
    result += "\n";
    return result;
}

Result<Plan> ParsePlanFile(const string& path, OsConfigLogHandle logHandle)
{
    auto fdResult = OpenVerified(path, logHandle);
    if (!fdResult.HasValue())
    {
        return fdResult.Error();
    }

    string content;
    {
        // stdio_filebuf takes ownership of the verified fd and closes it on destruction.
        __gnu_cxx::stdio_filebuf<char> buffer(fdResult.Value(), std::ios_base::in);
        std::istream stream(&buffer);
        char readBuffer[64 * 1024];
        while (stream.read(readBuffer, sizeof(readBuffer)) || stream.gcount() > 0)
        {
            content.append(readBuffer, static_cast<std::size_t>(stream.gcount()));
            if (content.size() > kMaxPlanInputBytes)
            {
                return Error("Plan file exceeds the maximum size of " + std::to_string(kMaxPlanInputBytes) + " bytes", EFBIG);
            }
        }
        if (stream.bad())
        {
            return Error("I/O error reading plan file '" + path + "'", EIO);
        }
    }

    auto document = JsonWrapper::FromString(content);
    if (!document.HasValue())
    {
        return Error("Failed to parse plan JSON: " + document.Error().message, EINVAL);
    }
    auto* root = json_value_get_object(document.Value().get());
    if (nullptr == root)
    {
        return Error("Plan file is not a JSON object", EINVAL);
    }

    auto* benchmarkObject = json_object_get_object(root, "benchmark");
    if (nullptr == benchmarkObject)
    {
        return Error("Plan file is missing the 'benchmark' object", EINVAL);
    }

    Plan plan;
    const char* file = json_object_get_string(benchmarkObject, "file");
    if (nullptr == file || file[0] == '\0')
    {
        return Error("Plan file's 'benchmark.file' is missing or empty", EINVAL);
    }
    plan.benchmarkFile = file;

    const char* name = json_object_get_string(benchmarkObject, "name");
    plan.benchmarkName = (nullptr != name) ? string(name) : string();

    const char* sha256 = json_object_get_string(benchmarkObject, "sha256");
    if (nullptr == sha256 || sha256[0] == '\0')
    {
        return Error("Plan file's 'benchmark.sha256' is missing or empty", EINVAL);
    }
    plan.benchmarkSha256 = sha256;

    auto* rulesObject = json_object_get_object(root, "rules");
    if (nullptr == rulesObject)
    {
        return Error("Plan file is missing the 'rules' object", EINVAL);
    }

    const std::size_t count = json_object_get_count(rulesObject);
    for (std::size_t i = 0; i < count; ++i)
    {
        const char* section = json_object_get_name(rulesObject, i);
        if (nullptr == section || section[0] == '\0')
        {
            return Error("Plan file has a rule with an empty section name", EINVAL);
        }
        auto* ruleValue = json_object_get_value_at(rulesObject, i);
        auto* ruleObject = (nullptr != ruleValue) ? json_value_get_object(ruleValue) : nullptr;
        if (nullptr == ruleObject)
        {
            return Error("Plan file's rule '" + string(section) + "' is not a JSON object", EINVAL);
        }
        const char* mode = json_object_get_string(ruleObject, "mode");
        if (nullptr == mode || mode[0] == '\0')
        {
            return Error("Plan file's rule '" + string(section) + "' is missing a 'mode' field", EINVAL);
        }
        auto modeResult = FromModeString(mode);
        if (!modeResult.HasValue())
        {
            return modeResult.Error();
        }
        plan.rules[section] = PlanRuleMode{modeResult.Value()};
    }

    return plan;
}

} // namespace Cli
} // namespace ComplianceEngine
