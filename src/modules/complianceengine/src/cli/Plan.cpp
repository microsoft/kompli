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
    auto docResult = BenchmarkDefinition::ParseFile(benchmarkFile, logHandle);
    if (!docResult.HasValue())
    {
        return docResult.Error();
    }
    const auto& doc = docResult.Value();

    auto hashResult = HashFile(benchmarkFile, logHandle);
    if (!hashResult.HasValue())
    {
        return hashResult.Error();
    }

    // Seed every rule at `audit` (never a mutating default), keyed by
    // payloadKey (the identifier guaranteed unique within this file - see
    // docs/payload-key-format.md \u00a76). Toggles are given by `section`
    // (human-typeable), resolved to the matching rule's payloadKey here.
    std::map<string, ToggleMode> modes;
    std::map<string, string> sectionToPayloadKey;
    for (const auto& resource : doc.resources)
    {
        modes[resource.payloadKey] = ToggleMode::Audit;
        // Last rule with a given section wins the lookup; section uniqueness
        // isn't enforced by the parser (only payloadKey is - see
        // BenchmarkDefinition::ParseString), so a duplicate section would
        // silently resolve a toggle to whichever rule parsed last. Not
        // guarded against here - out of scope for this pass.
        sectionToPayloadKey[resource.section] = resource.payloadKey;
    }

    // Apply toggles in argument order; a section a toggle doesn't recognise is
    // a fail-fast error rather than a silently-ignored no-op.
    for (const auto& toggle : toggles)
    {
        auto it = sectionToPayloadKey.find(toggle.section);
        if (it == sectionToPayloadKey.end())
        {
            return Error("Unknown section '" + toggle.section + "' in benchmark definition '" + benchmarkFile + "'", EINVAL);
        }
        modes[it->second] = toggle.mode;
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

    auto* benchmarksValue = json_value_init_array();
    if (nullptr == benchmarksValue)
    {
        return Error("Failed to initialize plan benchmarks JSON array", ENOMEM);
    }
    auto* benchmarksArray = json_value_get_array(benchmarksValue);

    auto* benchmarkValue = json_value_init_object();
    if (nullptr == benchmarkValue)
    {
        json_value_free(benchmarksValue);
        return Error("Failed to initialize plan benchmark JSON object", ENOMEM);
    }
    auto* benchmarkObject = json_value_get_object(benchmarkValue);
    if (nullptr == benchmarkObject || JSONSuccess != json_object_set_string(benchmarkObject, "file", benchmarkFile.c_str()) ||
        JSONSuccess != json_object_set_string(benchmarkObject, "name", doc.name.c_str()) ||
        JSONSuccess != json_object_set_string(benchmarkObject, "sha256", hashResult.Value().c_str()))
    {
        json_value_free(benchmarkValue);
        json_value_free(benchmarksValue);
        return Error("Failed to set plan benchmark fields", ENOMEM);
    }

    auto* rulesValue = json_value_init_object();
    if (nullptr == rulesValue)
    {
        json_value_free(benchmarkValue);
        json_value_free(benchmarksValue);
        return Error("Failed to initialize plan rules JSON object", ENOMEM);
    }
    auto* rulesObject = json_value_get_object(rulesValue);
    if (nullptr == rulesObject)
    {
        json_value_free(rulesValue);
        json_value_free(benchmarkValue);
        json_value_free(benchmarksValue);
        return Error("Failed to get plan rules JSON object", ENOMEM);
    }
    for (const auto& entry : modes)
    {
        auto* ruleValue = json_value_init_object();
        if (nullptr == ruleValue)
        {
            json_value_free(rulesValue);
            json_value_free(benchmarkValue);
            json_value_free(benchmarksValue);
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
            json_value_free(benchmarkValue);
            json_value_free(benchmarksValue);
            return Error("Failed to build plan rule '" + entry.first + "'", ENOMEM);
        }
        if (JSONSuccess != json_object_set_value(rulesObject, entry.first.c_str(), ruleValue))
        {
            json_value_free(ruleValue);
            json_value_free(rulesValue);
            json_value_free(benchmarkValue);
            json_value_free(benchmarksValue);
            return Error("Failed to set plan rule '" + entry.first + "'", ENOMEM);
        }
    }
    if (JSONSuccess != json_object_set_value(benchmarkObject, "rules", rulesValue))
    {
        json_value_free(rulesValue);
        json_value_free(benchmarkValue);
        json_value_free(benchmarksValue);
        return Error("Failed to set plan benchmark rules object", ENOMEM);
    }
    if (JSONSuccess != json_array_append_value(benchmarksArray, benchmarkValue))
    {
        json_value_free(benchmarkValue);
        json_value_free(benchmarksValue);
        return Error("Failed to append plan benchmark entry", ENOMEM);
    }
    if (JSONSuccess != json_object_set_value(root, "benchmarks", benchmarksValue))
    {
        json_value_free(benchmarksValue);
        return Error("Failed to set plan benchmarks array", ENOMEM);
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

    auto* benchmarksArray = json_object_get_array(root, "benchmarks");
    if (nullptr == benchmarksArray)
    {
        return Error("Plan file is missing the 'benchmarks' array", EINVAL);
    }
    const std::size_t benchmarkCount = json_array_get_count(benchmarksArray);
    if (0 == benchmarkCount)
    {
        return Error("Plan file's 'benchmarks' array must not be empty", EINVAL);
    }

    Plan plan;
    plan.benchmarks.reserve(benchmarkCount);
    for (std::size_t b = 0; b < benchmarkCount; ++b)
    {
        const string context = "benchmarks[" + std::to_string(b) + "]";
        auto* benchmarkObject = json_array_get_object(benchmarksArray, b);
        if (nullptr == benchmarkObject)
        {
            return Error("Plan file's '" + context + "' is not a JSON object", EINVAL);
        }

        PlanBenchmark benchmark;
        const char* file = json_object_get_string(benchmarkObject, "file");
        if (nullptr == file || file[0] == '\0')
        {
            return Error("Plan file's '" + context + ".file' is missing or empty", EINVAL);
        }
        benchmark.file = file;

        const char* name = json_object_get_string(benchmarkObject, "name");
        benchmark.name = (nullptr != name) ? string(name) : string();

        const char* sha256 = json_object_get_string(benchmarkObject, "sha256");
        if (nullptr == sha256 || sha256[0] == '\0')
        {
            return Error("Plan file's '" + context + ".sha256' is missing or empty", EINVAL);
        }
        benchmark.sha256 = sha256;

        auto* rulesObject = json_object_get_object(benchmarkObject, "rules");
        if (nullptr == rulesObject)
        {
            return Error("Plan file's '" + context + "' is missing the 'rules' object", EINVAL);
        }

        const std::size_t ruleCount = json_object_get_count(rulesObject);
        for (std::size_t i = 0; i < ruleCount; ++i)
        {
            const char* payloadKey = json_object_get_name(rulesObject, i);
            if (nullptr == payloadKey || payloadKey[0] == '\0')
            {
                return Error("Plan file's '" + context + "' has a rule with an empty payload key", EINVAL);
            }
            auto* ruleValue = json_object_get_value_at(rulesObject, i);
            auto* ruleObject = (nullptr != ruleValue) ? json_value_get_object(ruleValue) : nullptr;
            if (nullptr == ruleObject)
            {
                return Error("Plan file's '" + context + "' rule '" + string(payloadKey) + "' is not a JSON object", EINVAL);
            }
            const char* mode = json_object_get_string(ruleObject, "mode");
            if (nullptr == mode || mode[0] == '\0')
            {
                return Error("Plan file's '" + context + "' rule '" + string(payloadKey) + "' is missing a 'mode' field", EINVAL);
            }
            auto modeResult = FromModeString(mode);
            if (!modeResult.HasValue())
            {
                return modeResult.Error();
            }
            benchmark.rules[payloadKey] = PlanRuleMode{modeResult.Value()};
        }

        plan.benchmarks.push_back(std::move(benchmark));
    }

    return plan;
}

} // namespace Cli
} // namespace ComplianceEngine
