// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "Plan.hpp"

#include "BenchmarkDefinition.hpp"
#include "InputSecurity.hpp"
#include "Regex.h"

#include <JsonWrapper.h>
#include <cctype>
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <ext/stdio_filebuf.h>
#include <fcntl.h>
#include <istream>
#include <parson.h>
#include <sys/stat.h>
#include <tuple>
#include <unistd.h>

namespace ComplianceEngine
{
namespace Kompli
{
using std::string;

namespace
{
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

Result<string> ReadPlanString(const JSON_Value* value, const string& context, bool allowEmpty = false)
{
    if (nullptr == value || JSONString != json_value_get_type(value))
    {
        return Error("Plan file's '" + context + "' is missing or is not a string", EINVAL);
    }

    string result(json_value_get_string(value), json_value_get_string_len(value));
    if (string::npos != result.find('\0'))
    {
        return Error("Plan file's '" + context + "' contains an embedded NUL", EINVAL);
    }
    if (!allowEmpty && result.empty())
    {
        return Error("Plan file's '" + context + "' is empty", EINVAL);
    }
    return result;
}

Optional<Error> ValidateParameters(const string& benchmarkFile, const string& ruleId, const std::map<string, BenchmarkIO::ParameterMetadata>& metadata,
    const std::map<string, string>& parameters)
{
    for (const auto& entry : metadata)
    {
        if (entry.second.mandatory && parameters.find(entry.first) == parameters.end())
        {
            return Error("Missing mandatory parameter '" + entry.first + "' for rule '" + ruleId + "' in benchmark definition '" + benchmarkFile + "'", EINVAL);
        }
    }
    for (const auto& parameter : parameters)
    {
        const auto metadataIt = metadata.find(parameter.first);
        if (metadataIt == metadata.end())
        {
            return Error("Unknown parameter '" + parameter.first + "' for rule '" + ruleId + "' in benchmark definition '" + benchmarkFile + "'", EINVAL);
        }
        if (!metadataIt->second.validationRegex.HasValue())
        {
            continue;
        }
        try
        {
            const regex pattern(metadataIt->second.validationRegex.Value(), std::regex_constants::ECMAScript);
            if (!regex_match(parameter.second, pattern))
            {
                return Error(metadataIt->second.validationFailedMessage.HasValue() ?
                                 metadataIt->second.validationFailedMessage.Value() :
                                 ("Value '" + parameter.second + "' for parameter '" + parameter.first + "' does not match its required pattern"),
                    EINVAL);
            }
        }
        catch (const regex_error&)
        {
            return Error("Parameter '" + parameter.first + "' has an invalid validationRegex", EINVAL);
        }
    }
    return {};
}

Optional<Error> RejectTrailingPlanData(const string& content)
{
    std::size_t position = 0;
    while (position < content.size() && std::isspace(static_cast<unsigned char>(content[position])))
    {
        ++position;
    }
    if (position == content.size() || content[position] != '{')
    {
        return {};
    }

    std::vector<char> delimiters;
    bool inString = false;
    bool escaped = false;
    for (; position < content.size(); ++position)
    {
        const char ch = content[position];
        if (inString)
        {
            if (escaped)
            {
                escaped = false;
            }
            else if (ch == '\\')
            {
                escaped = true;
            }
            else if (ch == '"')
            {
                inString = false;
            }
            continue;
        }
        if (ch == '"')
        {
            inString = true;
        }
        else if (ch == '{' || ch == '[')
        {
            delimiters.push_back(ch);
        }
        else if (ch == '}' || ch == ']')
        {
            if (delimiters.empty())
            {
                return {};
            }
            const char expected = (ch == '}') ? '{' : '[';
            if (delimiters.back() != expected)
            {
                return {};
            }
            delimiters.pop_back();
            if (delimiters.empty())
            {
                ++position;
                while (position < content.size() && std::isspace(static_cast<unsigned char>(content[position])))
                {
                    ++position;
                }
                if (position != content.size())
                {
                    return Error("Plan file contains trailing data after the JSON document", EINVAL);
                }
                return {};
            }
        }
    }
    return {};
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

// Builds one `benchmarks[]` entry's JSON value: `file`/`name` plus a
// `rules` object with one entry per (id -> mode/parameters) in `rules`. On
// failure the caller owns nothing (any partial allocation is freed here); on
// success the caller owns the returned value and must free it if it isn't
// subsequently handed to a parent JSON container (matching parson's
// ownership-transfer convention, e.g. json_array_append_value).
Result<JSON_Value*> BuildBenchmarkEntry(const string& benchmarkFile, const string& name, const std::map<string, PlanRuleMode>& rules)
{
    auto* benchmarkValue = json_value_init_object();
    if (nullptr == benchmarkValue)
    {
        return Error("Failed to initialize plan benchmark JSON object", ENOMEM);
    }
    auto* benchmarkObject = json_value_get_object(benchmarkValue);
    if (nullptr == benchmarkObject || JSONSuccess != json_object_set_string(benchmarkObject, "file", benchmarkFile.c_str()) ||
        JSONSuccess != json_object_set_string(benchmarkObject, "name", name.c_str()))
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

struct ResolvedParameterOverride
{
    ParsedBenchmarkFile* file;
    string id;
    string name;
};

Result<ResolvedParameterOverride> ResolveParameterOverride(std::vector<ParsedBenchmarkFile>& parsedFiles, const string& selector, bool multiFile)
{
    Optional<ResolvedParameterOverride> match;
    for (auto& parsed : parsedFiles)
    {
        const string qualifier = multiFile ? BaseName(parsed.file) + ":" : "";
        for (const auto& rule : parsed.parameterMetadata)
        {
            for (const auto& parameter : rule.second)
            {
                if (qualifier + rule.first + "." + parameter.first != selector)
                {
                    continue;
                }
                if (match.HasValue())
                {
                    return Error("Ambiguous parameter selector '" + selector + "'; it matches more than one rule and parameter", EINVAL);
                }
                match = ResolvedParameterOverride{&parsed, rule.first, parameter.first};
            }
        }
    }
    if (!match.HasValue())
    {
        return Error("Unknown parameter selector '" + selector + "'", EINVAL);
    }
    return match.Value();
}

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
    ParsedBenchmarkFile* match = nullptr;
    for (auto& parsed : parsedFiles)
    {
        if (BaseName(parsed.file) == basename)
        {
            if (nullptr != match)
            {
                return Error("Ambiguous file '" + basename + "' in qualified rule reference '" + ref + "'", EINVAL);
            }
            match = &parsed;
        }
    }
    if (nullptr != match)
    {
        return ResolvedRuleRef{match, id};
    }
    return Error("Unknown file '" + basename + "' in qualified rule reference '" + ref + "'", EINVAL);
}
} // anonymous namespace

Result<string> GeneratePlan(const std::vector<string>& benchmarkFiles, const std::vector<Toggle>& toggles,
    const std::vector<ParamOverride>& paramOverrides, OsConfigLogHandle logHandle)
{
    if (benchmarkFiles.empty())
    {
        return Error("At least one benchmark-definition file is required", EINVAL);
    }

    auto duplicateFileError = CheckUniqueBenchmarkFiles(benchmarkFiles);
    if (duplicateFileError.HasValue())
    {
        return duplicateFileError.Value();
    }

    std::vector<ParsedBenchmarkFile> parsedFiles;
    parsedFiles.reserve(benchmarkFiles.size());
    std::vector<std::pair<string, BenchmarkInfo>> identities;
    identities.reserve(benchmarkFiles.size());

    for (const auto& file : benchmarkFiles)
    {
        auto docResult = BenchmarkDefinition::ParseFile(file, logHandle);
        if (!docResult.HasValue())
        {
            return docResult.Error();
        }
        const auto& doc = docResult.Value();

        ParsedBenchmarkFile parsed;
        parsed.file = file;
        parsed.name = doc.name;
        // Seed every rule at `audit` (never a mutating default) with its
        // parameters pre-filled from parameterMetadata's defaults (docs/CLI.md
        // "Parametrization"), keyed by id (the identifier guaranteed unique
        // within this file).
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

    // Resolve the complete selector against metadata because dots are valid
    // in both rule ids and parameter names.
    for (const auto& paramOverride : paramOverrides)
    {
        auto refResult = ResolveParameterOverride(parsedFiles, paramOverride.selector, multiFile);
        if (!refResult.HasValue())
        {
            return refResult.Error();
        }
        const auto& ref = refResult.Value();
        auto ruleIt = ref.file->rules.find(ref.id);
        ruleIt->second.parameters[ref.name] = paramOverride.value;
    }
    for (const auto& parsed : parsedFiles)
    {
        for (const auto& rule : parsed.rules)
        {
            const auto& metadata = parsed.parameterMetadata.at(rule.first);
            auto validationError = ValidateParameters(parsed.file, rule.first, metadata, rule.second.parameters);
            if (validationError.HasValue())
            {
                return validationError.Value();
            }
        }
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
        auto entryResult = BuildBenchmarkEntry(parsed.file, parsed.name, parsed.rules);
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
    if (result.size() > kMaxPlanInputBytes)
    {
        return Error("Generated plan exceeds the maximum size of " + std::to_string(kMaxPlanInputBytes) + " bytes", EFBIG);
    }
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

    if (string::npos != content.find('\0'))
    {
        return Error("Plan file contains a raw NUL byte", EINVAL);
    }
    auto trailingDataError = RejectTrailingPlanData(content);
    if (trailingDataError.HasValue())
    {
        return trailingDataError.Value();
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
        auto file = ReadPlanString(json_object_get_value(benchmarkObject, "file"), context + ".file");
        if (!file.HasValue())
        {
            return file.Error();
        }
        benchmark.file = std::move(file.Value());

        const JSON_Value* nameValue = json_object_get_value(benchmarkObject, "name");
        if (nullptr != nameValue)
        {
            auto name = ReadPlanString(nameValue, context + ".name", true);
            if (!name.HasValue())
            {
                return name.Error();
            }
            benchmark.name = std::move(name.Value());
        }

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
            auto mode = ReadPlanString(json_object_get_value(ruleObject, "mode"), context + ".rules." + string(id) + ".mode");
            if (!mode.HasValue())
            {
                return mode.Error();
            }
            auto modeResult = FromModeString(mode.Value());
            if (!modeResult.HasValue())
            {
                return modeResult.Error();
            }
            PlanRuleMode ruleMode{modeResult.Value()};
            const JSON_Value* parametersValue = json_object_get_value(ruleObject, "parameters");
            if (nullptr != parametersValue && JSONObject != json_value_get_type(parametersValue))
            {
                return Error("Plan file's '" + context + "' rule '" + string(id) + "' has a 'parameters' field that is not a JSON object", EINVAL);
            }
            auto* parametersObject = json_value_get_object(parametersValue);
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
                    auto paramValue = ReadPlanString(json_object_get_value(parametersObject, paramName),
                        context + ".rules." + string(id) + ".parameters." + string(paramName), true);
                    if (!paramValue.HasValue())
                    {
                        return paramValue.Error();
                    }
                    ruleMode.parameters[paramName] = std::move(paramValue.Value());
                }
            }
            benchmark.rules[id] = std::move(ruleMode);
        }

        plan.benchmarks.push_back(std::move(benchmark));
    }

    return plan;
}

Optional<Error> WritePlanFile(const string& path, const string& content)
{
    const std::size_t slash = path.rfind('/');
    const string parentPath = (slash == string::npos) ? "." : (slash == 0 ? "/" : path.substr(0, slash));
    const string filename = (slash == string::npos) ? path : path.substr(slash + 1);
    if (filename.empty() || filename == "." || filename == "..")
    {
        return Error("Invalid output file path '" + path + "'", EINVAL);
    }

    int parentFd = ::open(parentPath[0] == '/' ? "/" : ".", O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (parentFd < 0)
    {
        return Error("Failed to open output parent for '" + path + "': " + std::strerror(errno), errno);
    }
    std::size_t position = parentPath[0] == '/' ? 1 : 0;
    while (position < parentPath.size())
    {
        const std::size_t nextSlash = parentPath.find('/', position);
        const string component = parentPath.substr(position, nextSlash == string::npos ? string::npos : nextSlash - position);
        position = (nextSlash == string::npos) ? parentPath.size() : nextSlash + 1;
        if (component.empty() || component == ".")
        {
            continue;
        }
        if (component == "..")
        {
            ::close(parentFd);
            return Error("Refusing output path '" + path + "': contains path traversal component '..'", EINVAL);
        }
        const int nextFd = ::openat(parentFd, component.c_str(), O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (nextFd < 0)
        {
            const int error = errno;
            ::close(parentFd);
            return Error("Failed to resolve output parent for '" + path + "': " + std::strerror(error), error);
        }
        ::close(parentFd);
        parentFd = nextFd;
    }

    struct stat parentInfo
    {
    };
    if (::fstat(parentFd, &parentInfo) != 0)
    {
        const int error = errno;
        ::close(parentFd);
        return Error("Failed to inspect output parent for '" + path + "': " + std::strerror(error), error);
    }
    if (!S_ISDIR(parentInfo.st_mode) || parentInfo.st_uid != ::geteuid() || (parentInfo.st_mode & (S_IWGRP | S_IWOTH)) != 0)
    {
        ::close(parentFd);
        return Error("Refusing output path '" + path + "': parent directory is not trusted", EPERM);
    }

    const int fd = ::openat(parentFd, filename.c_str(), O_WRONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0600);
    const int openError = errno;
    ::close(parentFd);
    if (fd < 0)
    {
        return Error("Failed to open output file '" + path + "': " + std::strerror(openError), openError);
    }

    struct stat info
    {
    };
    if (::fstat(fd, &info) != 0)
    {
        const int error = errno;
        ::close(fd);
        return Error("Failed to inspect output file '" + path + "': " + std::strerror(error), error);
    }
    if (!S_ISREG(info.st_mode) || info.st_nlink != 1)
    {
        ::close(fd);
        return Error("Refusing to write output file '" + path + "': destination is not a singly-linked regular file", EINVAL);
    }
    if (::ftruncate(fd, 0) != 0)
    {
        const int error = errno;
        ::close(fd);
        return Error("Failed to truncate output file '" + path + "': " + std::strerror(error), error);
    }

    std::size_t written = 0;
    while (written < content.size())
    {
        const ssize_t result = ::write(fd, content.data() + written, content.size() - written);
        if (result < 0)
        {
            if (EINTR == errno)
            {
                continue;
            }
            const int error = errno;
            ::close(fd);
            return Error("Failed to write output file '" + path + "': " + std::strerror(error), error);
        }
        written += static_cast<std::size_t>(result);
    }
    if (::close(fd) != 0)
    {
        return Error("Failed to close output file '" + path + "': " + std::strerror(errno), errno);
    }
    return {};
}

Optional<Error> CheckUniqueBenchmarkFiles(const std::vector<string>& benchmarkFiles)
{
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
    return {};
}

Optional<Error> ValidatePlanForRun(const Plan& plan, const std::vector<BenchmarkDefinition::BenchmarkDocument>& documents, const DistributionInfo& distributionInfo)
{
    if (plan.benchmarks.size() != documents.size())
    {
        return Error("Plan validation received a mismatched definition set", EINVAL);
    }

    for (std::size_t b = 0; b < plan.benchmarks.size(); ++b)
    {
        const auto& benchmark = plan.benchmarks[b];
        const auto& document = documents[b];
        if (!document.benchmarkInfo.Match(distributionInfo))
        {
            return Error("Benchmark '" + benchmark.file + "' is not applicable for the current distribution", EINVAL);
        }

        std::map<string, const BenchmarkIO::Resource*> resources;
        for (const auto& resource : document.resources)
        {
            resources.emplace(resource.id, &resource);
        }
        for (const auto& rule : benchmark.rules)
        {
            const auto resourceIt = resources.find(rule.first);
            if (resourceIt == resources.end())
            {
                return Error("Unknown rule '" + rule.first + "' in benchmark definition '" + benchmark.file + "'", EINVAL);
            }
            auto parameterError = ValidateParameters(benchmark.file, rule.first, resourceIt->second->parameterMetadata, rule.second.parameters);
            if (parameterError.HasValue())
            {
                return parameterError.Value();
            }
        }
    }
    return {};
}

Optional<Error> CheckUniqueBenchmarkIdentities(const std::vector<std::pair<string, BenchmarkInfo>>& benchmarks)
{
    using Identity = std::tuple<string, LinuxDistribution, string, string>;
    std::map<Identity, string> seen;
    for (const auto& entry : benchmarks)
    {
        const auto& benchmarkInfo = entry.second;
        const string benchmarkVersion = (!benchmarkInfo.benchmarkVersion.empty() && benchmarkInfo.benchmarkVersion[0] == 'v') ?
                                            benchmarkInfo.benchmarkVersion.substr(1) :
                                            benchmarkInfo.benchmarkVersion;
        const Identity identity{benchmarkInfo.framework, benchmarkInfo.distribution, benchmarkInfo.version, benchmarkVersion};
        auto it = seen.find(identity);
        if (it != seen.end())
        {
            return Error("Benchmark files '" + it->second + "' and '" + entry.first +
                             "' share the same (framework, distribution, distributionVersion, benchmarkVersion) identity '" +
                             std::to_string(benchmarkInfo) + "'",
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

} // namespace Kompli
} // namespace ComplianceEngine
