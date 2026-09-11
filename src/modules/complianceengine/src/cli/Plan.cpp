// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "Plan.hpp"

#include "BenchmarkDefinition.hpp"
#include "InputSecurity.hpp"
#include "Regex.h"

#include <JsonWrapper.h>
#include <cerrno>
#include <climits>
#include <cstdlib>
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

namespace
{
// Splits off the final path component (the part after the last '/', or the
// whole string if there's none) - used to resolve a qualified toggle's
// <file-basename> against the files given to a multi-file `plan` invocation
// (docs/CLI.md section 8.1).
string BaseName(const string& path)
{
    const auto slash = path.find_last_of('/');
    return (string::npos == slash) ? path : path.substr(slash + 1);
}

// Builds one `benchmarks[]` entry's JSON value: `file`/`name`/`sha256` plus a
// `rules` object with one entry per (id -> mode/parameters) in `rules`. On
// failure the caller owns nothing (any partial allocation is freed here); on
// success the caller owns the returned value and must free it if it isn't
// subsequently handed to a parent JSON container (matching parson's
// ownership-transfer convention, e.g. json_array_append_value).
Result<JSON_Value*> BuildBenchmarkEntry(const string& benchmarkFile, const string& name, const string& sha256, const std::map<string, PlanRuleMode>& rules)
{
    auto* benchmarkValue = json_value_init_object();
    if (nullptr == benchmarkValue)
    {
        return Error("Failed to initialize plan benchmark JSON object", ENOMEM);
    }
    auto* benchmarkObject = json_value_get_object(benchmarkValue);
    if (nullptr == benchmarkObject || JSONSuccess != json_object_set_string(benchmarkObject, "file", benchmarkFile.c_str()) ||
        JSONSuccess != json_object_set_string(benchmarkObject, "name", name.c_str()) ||
        JSONSuccess != json_object_set_string(benchmarkObject, "sha256", sha256.c_str()))
    {
        json_value_free(benchmarkValue);
        return Error("Failed to set plan benchmark fields", ENOMEM);
    }

    auto* rulesValue = json_value_init_object();
    if (nullptr == rulesValue)
    {
        json_value_free(benchmarkValue);
        return Error("Failed to initialize plan rules JSON object", ENOMEM);
    }
    auto* rulesObject = json_value_get_object(rulesValue);
    if (nullptr == rulesObject)
    {
        json_value_free(rulesValue);
        json_value_free(benchmarkValue);
        return Error("Failed to get plan rules JSON object", ENOMEM);
    }
    for (const auto& entry : rules)
    {
        auto* ruleValue = json_value_init_object();
        if (nullptr == ruleValue)
        {
            json_value_free(rulesValue);
            json_value_free(benchmarkValue);
            return Error("Failed to initialize plan rule JSON object", ENOMEM);
        }
        auto* ruleObject = json_value_get_object(ruleValue);
        auto* parametersValue = json_value_init_object();
        auto* parametersObject = (nullptr != parametersValue) ? json_value_get_object(parametersValue) : nullptr;
        if (nullptr == ruleObject || nullptr == parametersObject || JSONSuccess != json_object_set_string(ruleObject, "mode", ToModeString(entry.second.mode)))
        {
            json_value_free(parametersValue);
            json_value_free(ruleValue);
            json_value_free(rulesValue);
            json_value_free(benchmarkValue);
            return Error("Failed to build plan rule '" + entry.first + "'", ENOMEM);
        }
        for (const auto& param : entry.second.parameters)
        {
            if (JSONSuccess != json_object_set_string(parametersObject, param.first.c_str(), param.second.c_str()))
            {
                json_value_free(parametersValue);
                json_value_free(ruleValue);
                json_value_free(rulesValue);
                json_value_free(benchmarkValue);
                return Error("Failed to build plan rule '" + entry.first + "' parameter '" + param.first + "'", ENOMEM);
            }
        }
        if (JSONSuccess != json_object_set_value(ruleObject, "parameters", parametersValue))
        {
            json_value_free(parametersValue);
            json_value_free(ruleValue);
            json_value_free(rulesValue);
            json_value_free(benchmarkValue);
            return Error("Failed to build plan rule '" + entry.first + "'", ENOMEM);
        }
        if (JSONSuccess != json_object_set_value(rulesObject, entry.first.c_str(), ruleValue))
        {
            json_value_free(ruleValue);
            json_value_free(rulesValue);
            json_value_free(benchmarkValue);
            return Error("Failed to set plan rule '" + entry.first + "'", ENOMEM);
        }
    }
    if (JSONSuccess != json_object_set_value(benchmarkObject, "rules", rulesValue))
    {
        json_value_free(rulesValue);
        json_value_free(benchmarkValue);
        return Error("Failed to set plan benchmark rules object", ENOMEM);
    }
    return benchmarkValue;
}

// One input file's already-parsed state, kept around long enough to apply
// toggles/param overrides and then serialize (docs/CLI.md section 8.1).
struct ParsedBenchmarkFile
{
    string file;
    string name;
    string sha256;
    std::map<string, PlanRuleMode> rules;
    // Every rules[] key's parameterMetadata, kept alongside for `--param=`
    // validation (name exists, value matches validationRegex) - see
    // docs/CLI.md "Parametrization".
    std::map<string, std::map<string, BenchmarkIO::ParameterMetadata>> parameterMetadata;
};

// A toggle/`--param=` reference resolved against `parsedFiles`: with exactly
// one file, `ref` is that file's unqualified id; with more than one, it must
// be qualified as `<file-basename>:<id>` since `id` is only unique within one
// file (docs/CLI.md section 8.1).
struct ResolvedRuleRef
{
    ParsedBenchmarkFile* file;
    string id;
};

Result<ResolvedRuleRef> ResolveRuleRef(std::vector<ParsedBenchmarkFile>& parsedFiles, const string& ref, bool multiFile)
{
    if (!multiFile)
    {
        return ResolvedRuleRef{&parsedFiles.front(), ref};
    }
    const auto colon = ref.find(':');
    if (string::npos == colon)
    {
        return Error("'" + ref + "' must be qualified as <file-basename>:<id> when more than one file is given", EINVAL);
    }
    const string basename = ref.substr(0, colon);
    const string id = ref.substr(colon + 1);
    for (auto& parsed : parsedFiles)
    {
        if (BaseName(parsed.file) == basename)
        {
            return ResolvedRuleRef{&parsed, id};
        }
    }
    return Error("Unknown file '" + basename + "' in qualified rule reference '" + ref + "'", EINVAL);
}
} // anonymous namespace

Result<string> GeneratePlan(
    const std::vector<string>& benchmarkFiles, const std::vector<Toggle>& toggles, const std::vector<ParamOverride>& paramOverrides, OsConfigLogHandle logHandle)
{
    if (benchmarkFiles.empty())
    {
        return Error("At least one benchmark-definition file is required", EINVAL);
    }

    // Reject the same file path given twice, or two paths that canonicalize
    // to the same file (docs/CLI.md section 8.1) - fail fast, before parsing
    // anything. Falls back to the literal path when realpath() can't resolve
    // it (e.g. the file doesn't exist yet); ParseFile below still catches
    // that case with its own, more specific error.
    std::map<string, string> canonicalToOriginal;
    for (const auto& file : benchmarkFiles)
    {
        char resolved[PATH_MAX];
        const string canonical = (nullptr != ::realpath(file.c_str(), resolved)) ? string(resolved) : file;
        auto it = canonicalToOriginal.find(canonical);
        if (it != canonicalToOriginal.end())
        {
            return Error("Duplicate benchmark file: '" + it->second + "' and '" + file + "' refer to the same file", EINVAL);
        }
        canonicalToOriginal.emplace(canonical, file);
    }

    std::vector<ParsedBenchmarkFile> parsedFiles;
    parsedFiles.reserve(benchmarkFiles.size());
    std::vector<std::pair<string, CISBenchmarkInfo>> identities;
    identities.reserve(benchmarkFiles.size());

    for (const auto& file : benchmarkFiles)
    {
        auto docResult = BenchmarkDefinition::ParseFile(file, logHandle);
        if (!docResult.HasValue())
        {
            return docResult.Error();
        }
        auto hashResult = HashFile(file, logHandle);
        if (!hashResult.HasValue())
        {
            return hashResult.Error();
        }
        const auto& doc = docResult.Value();

        ParsedBenchmarkFile parsed;
        parsed.file = file;
        parsed.name = doc.name;
        parsed.sha256 = hashResult.Value();
        // Seed every rule at `audit` (never a mutating default) with its
        // parameters pre-filled from parameterMetadata's defaults (docs/CLI.md
        // "Parametrization"), keyed by id (the identifier guaranteed unique
        // within this file - see docs/payload-key-format.md section 6/12).
        for (const auto& resource : doc.resources)
        {
            PlanRuleMode ruleMode{ToggleMode::Audit};
            for (const auto& param : resource.parameterMetadata)
            {
                ruleMode.parameters[param.first] = param.second.defaultValue;
            }
            parsed.rules[resource.id] = std::move(ruleMode);
            parsed.parameterMetadata[resource.id] = resource.parameterMetadata;
        }
        identities.emplace_back(file, doc.benchmarkInfo);
        parsedFiles.push_back(std::move(parsed));
    }

    // Two files that resolve to the same (framework, distribution,
    // distributionVersion, benchmarkVersion) tuple are ambiguous - the same
    // benchmark staged twice, or two revisions disagreeing about which is
    // current (docs/CLI.md section 8.1). `run` enforces the same invariant
    // over a plan's blocks (Main.cpp), reusing this exact function.
    auto duplicateIdentityError = CheckUniqueBenchmarkIdentities(identities);
    if (duplicateIdentityError.HasValue())
    {
        return duplicateIdentityError.Value();
    }

    // Apply toggles in argument order. With exactly one file, a toggle's
    // `section` is that file's unqualified id (today's contract, unchanged).
    // With more than one, `id` is only unique within one file, so it must be
    // qualified as <file-basename>:<id> (docs/CLI.md section 8.1); an
    // unqualified value, an unrecognised basename, or an id a toggle doesn't
    // recognise are all fail-fast errors rather than silently-ignored no-ops.
    const bool multiFile = parsedFiles.size() > 1;
    for (const auto& toggle : toggles)
    {
        auto refResult = ResolveRuleRef(parsedFiles, toggle.section, multiFile);
        if (!refResult.HasValue())
        {
            return refResult.Error();
        }
        const auto& ref = refResult.Value();
        auto it = ref.file->rules.find(ref.id);
        if (it == ref.file->rules.end())
        {
            return Error("Unknown rule '" + ref.id + "' in benchmark definition '" + ref.file->file + "'", EINVAL);
        }
        it->second.mode = toggle.mode;
    }

    // Apply `--param=` overrides the same way (docs/CLI.md "Parametrization"):
    // `ref` uses the same qualification rule as a toggle's `section`. A
    // parameter name not in the rule's parameterMetadata, or a value that
    // doesn't match its validationRegex, is a fail-fast error - same
    // eager-validation principle as an unrecognised toggle rule reference.
    for (const auto& paramOverride : paramOverrides)
    {
        auto refResult = ResolveRuleRef(parsedFiles, paramOverride.ref, multiFile);
        if (!refResult.HasValue())
        {
            return refResult.Error();
        }
        const auto& ref = refResult.Value();
        auto ruleIt = ref.file->rules.find(ref.id);
        if (ruleIt == ref.file->rules.end())
        {
            return Error("Unknown rule '" + ref.id + "' in benchmark definition '" + ref.file->file + "'", EINVAL);
        }
        // Always present alongside `rules` (seeded together above), so this
        // lookup cannot miss for a ruleIt that was just found.
        const auto& metadata = ref.file->parameterMetadata[ref.id];
        const auto paramIt = metadata.find(paramOverride.name);
        if (paramIt == metadata.end())
        {
            return Error("Unknown parameter '" + paramOverride.name + "' for rule '" + ref.id + "' in benchmark definition '" + ref.file->file + "'", EINVAL);
        }
        if (paramIt->second.validationRegex.HasValue())
        {
            try
            {
                const regex pattern(paramIt->second.validationRegex.Value(), std::regex_constants::ECMAScript);
                if (!regex_match(paramOverride.value, pattern))
                {
                    return Error(paramIt->second.validationFailedMessage.HasValue()
                            ? paramIt->second.validationFailedMessage.Value()
                            : ("Value '" + paramOverride.value + "' for parameter '" + paramOverride.name + "' does not match its required pattern"),
                        EINVAL);
                }
            }
            catch (const regex_error&)
            {
                return Error("Parameter '" + paramOverride.name + "' has an invalid validationRegex", EINVAL);
            }
        }
        ruleIt->second.parameters[paramOverride.name] = paramOverride.value;
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

    for (const auto& parsed : parsedFiles)
    {
        auto entryResult = BuildBenchmarkEntry(parsed.file, parsed.name, parsed.sha256, parsed.rules);
        if (!entryResult.HasValue())
        {
            json_value_free(benchmarksValue);
            return entryResult.Error();
        }
        if (JSONSuccess != json_array_append_value(benchmarksArray, entryResult.Value()))
        {
            json_value_free(entryResult.Value());
            json_value_free(benchmarksValue);
            return Error("Failed to append plan benchmark entry", ENOMEM);
        }
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
            const char* id = json_object_get_name(rulesObject, i);
            if (nullptr == id || id[0] == '\0')
            {
                return Error("Plan file's '" + context + "' has a rule with an empty id", EINVAL);
            }
            auto* ruleValue = json_object_get_value_at(rulesObject, i);
            auto* ruleObject = (nullptr != ruleValue) ? json_value_get_object(ruleValue) : nullptr;
            if (nullptr == ruleObject)
            {
                return Error("Plan file's '" + context + "' rule '" + string(id) + "' is not a JSON object", EINVAL);
            }
            const char* mode = json_object_get_string(ruleObject, "mode");
            if (nullptr == mode || mode[0] == '\0')
            {
                return Error("Plan file's '" + context + "' rule '" + string(id) + "' is missing a 'mode' field", EINVAL);
            }
            auto modeResult = FromModeString(mode);
            if (!modeResult.HasValue())
            {
                return modeResult.Error();
            }
            PlanRuleMode ruleMode{modeResult.Value()};
            auto* parametersObject = json_object_get_object(ruleObject, "parameters");
            if (nullptr != parametersObject)
            {
                const std::size_t parameterCount = json_object_get_count(parametersObject);
                for (std::size_t p = 0; p < parameterCount; ++p)
                {
                    const char* paramName = json_object_get_name(parametersObject, p);
                    if (nullptr == paramName || paramName[0] == '\0')
                    {
                        return Error("Plan file's '" + context + "' rule '" + string(id) + "' has a parameter with an empty name", EINVAL);
                    }
                    const char* paramValue = json_object_get_string(parametersObject, paramName);
                    if (nullptr == paramValue)
                    {
                        return Error(
                            "Plan file's '" + context + "' rule '" + string(id) + "' parameter '" + string(paramName) + "' is not a string", EINVAL);
                    }
                    ruleMode.parameters[paramName] = paramValue;
                }
            }
            benchmark.rules[id] = std::move(ruleMode);
        }

        plan.benchmarks.push_back(std::move(benchmark));
    }

    return plan;
}

Optional<Error> CheckUniqueBenchmarkIdentities(const std::vector<std::pair<string, CISBenchmarkInfo>>& benchmarks)
{
    // identity string (std::to_string(CISBenchmarkInfo), see BenchmarkInfo.h -
    // section is always empty on this path, so it doesn't affect the tuple)
    // -> the first file seen with it.
    std::map<string, string> seen;
    for (const auto& entry : benchmarks)
    {
        const string identity = std::to_string(entry.second);
        auto it = seen.find(identity);
        if (it != seen.end())
        {
            return Error("Benchmark files '" + it->second + "' and '" + entry.first +
                    "' share the same (framework, distribution, distributionVersion, benchmarkVersion) identity '" + identity + "'",
                EINVAL);
        }
        seen.emplace(identity, entry.first);
    }
    return Optional<Error>();
}

Result<string> ApplyParameterOverrides(const string& procedureJson, const std::map<string, string>& parameters)
{
    auto document = JsonWrapper::FromString(procedureJson);
    if (!document.HasValue())
    {
        return Error("Failed to parse procedure JSON: " + document.Error().message, EINVAL);
    }
    auto* root = json_value_get_object(document.Value().get());
    if (nullptr == root)
    {
        return Error("Procedure JSON is not a JSON object", EINVAL);
    }

    auto* parametersObject = json_object_get_object(root, "parameters");
    if (nullptr == parametersObject)
    {
        auto* parametersValue = json_value_init_object();
        if (nullptr == parametersValue || JSONSuccess != json_object_set_value(root, "parameters", parametersValue))
        {
            json_value_free(parametersValue);
            return Error("Failed to add parameters object to procedure JSON", ENOMEM);
        }
        parametersObject = json_value_get_object(parametersValue);
    }

    for (const auto& parameter : parameters)
    {
        if (JSONSuccess != json_object_set_string(parametersObject, parameter.first.c_str(), parameter.second.c_str()))
        {
            return Error("Failed to set procedure parameter '" + parameter.first + "'", ENOMEM);
        }
    }

    auto* serialized = json_serialize_to_string(document.Value().get());
    if (nullptr == serialized)
    {
        return Error("Failed to serialize procedure JSON", ENOMEM);
    }
    string result(serialized);
    json_free_serialized_string(serialized);
    return result;
}

} // namespace Cli
} // namespace ComplianceEngine
