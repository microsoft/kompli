// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "BenchmarkDefinition.hpp"

#include "InputSecurity.hpp"

#include <BenchmarkInfo.h>
#include <JsonWrapper.h>
#include <algorithm>
#include <cerrno>
#include <ext/stdio_filebuf.h>
#include <memory>
#include <parson.h>
#include <string>
#include <vector>

namespace ComplianceEngine
{
namespace BenchmarkDefinition
{
using std::string;

namespace
{
// Upper bound on the total number of input bytes read from a definition file or
// stream. The largest committed definition is a little over 1 MiB; an 8 MiB cap
// leaves ample headroom for the verbose per-rule descriptions and future growth
// while bounding the worst-case memory use (buffer plus the parson DOM built on
// top) for a malformed or hostile input while running as root.
constexpr size_t kMaxInputBytes = static_cast<size_t>(8) * 1024 * 1024;

// Upper bound on the number of rules parsed from a single definition.
constexpr size_t kMaxRules = 100000;

// Reads an entire stream into a string, refusing inputs larger than the cap.
Result<string> ReadAllBounded(std::istream& stream)
{
    string content;
    char buffer[64 * 1024];
    while (stream.read(buffer, sizeof(buffer)) || stream.gcount() > 0)
    {
        content.append(buffer, static_cast<size_t>(stream.gcount()));
        if (content.size() > kMaxInputBytes)
        {
            return Error("Benchmark definition exceeds the maximum size of " + std::to_string(kMaxInputBytes) + " bytes", EFBIG);
        }
    }
    if (stream.bad())
    {
        return Error("I/O error reading benchmark definition", EIO);
    }
    return content;
}

// Reads a required, non-empty string field from a JSON object. `context`
// identifies the enclosing element for error messages.
Result<string> RequiredString(const JSON_Object* object, const char* key, const string& context)
{
    const char* value = json_object_get_string(object, key);
    if (nullptr == value)
    {
        return Error("Benchmark definition " + context + " is missing required string field '" + string(key) + "'", EINVAL);
    }
    if (value[0] == '\0')
    {
        return Error("Benchmark definition " + context + " has an empty '" + string(key) + "' field", EINVAL);
    }
    return string(value);
}

// Serializes a rule's `payload` object into the compact JSON the ComplianceEngine
// consumes as the procedure. The engine parses plain JSON directly
// (Engine::SetProcedure falls back from base64 to a plain-JSON parse), so no
// base64 encoding is needed here.
Result<string> SerializeProcedure(const JSON_Object* ruleObject, const string& context)
{
    const JSON_Value* payload = json_object_get_value(ruleObject, "payload");
    if (nullptr == payload || json_value_get_type(payload) != JSONObject)
    {
        return Error("Benchmark definition " + context + " is missing an object 'payload' field", EINVAL);
    }

    char* serialized = json_serialize_to_string(payload);
    if (nullptr == serialized)
    {
        return Error("Failed to serialize the payload of benchmark definition " + context, EINVAL);
    }
    string procedure(serialized);
    json_free_serialized_string(serialized);
    return procedure;
}

Result<Resource> ParseRule(const JSON_Object* ruleObject, size_t index)
{
    const string context = "rule #" + std::to_string(index);

    auto title = RequiredString(ruleObject, "title", context);
    if (!title.HasValue())
    {
        return title.Error();
    }
    auto ruleId = RequiredString(ruleObject, "ruleId", context);
    if (!ruleId.HasValue())
    {
        return ruleId.Error();
    }
    auto ruleName = RequiredString(ruleObject, "ruleName", context);
    if (!ruleName.HasValue())
    {
        return ruleName.Error();
    }
    auto payloadKey = RequiredString(ruleObject, "payloadKey", context);
    if (!payloadKey.HasValue())
    {
        return payloadKey.Error();
    }
    auto procedure = SerializeProcedure(ruleObject, context);
    if (!procedure.HasValue())
    {
        return procedure.Error();
    }

    auto benchmarkInfo = CISBenchmarkInfo::Parse(payloadKey.Value());
    if (!benchmarkInfo.HasValue())
    {
        return Error("Failed to parse payloadKey of benchmark definition " + context + ": " + benchmarkInfo.Error().message, benchmarkInfo.Error().code);
    }

    Resource resource;
    resource.resourceID = std::move(title.Value());
    resource.ruleId = std::move(ruleId.Value());
    resource.benchmarkInfo = std::move(benchmarkInfo.Value());
    // The section in the payload key is '/'-separated (e.g. "1/1/1/1"); the rest
    // of the assessor expects dotted notation (e.g. "1.1.1.1").
    std::replace(resource.benchmarkInfo.section.begin(), resource.benchmarkInfo.section.end(), '/', '.');
    resource.procedure = std::move(procedure.Value());
    resource.ruleName = std::move(ruleName.Value());
    // Every rule carries an init object.
    resource.hasInitAudit = true;
    // Definitions carry no desired object value; the payload is modelled as
    // absent.

    return resource;
}
} // anonymous namespace

Result<std::vector<Resource>> ParseString(const string& json, OsConfigLogHandle logHandle)
{
    // Fail closed on an embedded NUL. The underlying JSON parser is NUL-terminated
    // (parses via c_str()), so a NUL would silently truncate the document and hide
    // everything after it; reject such input outright rather than parse a prefix.
    if (json.find('\0') != string::npos)
    {
        return Error("Benchmark definition contains a NUL byte", EINVAL);
    }

    auto document = JsonWrapper::FromString(json);
    if (!document.HasValue())
    {
        return Error("Failed to parse benchmark definition JSON: " + document.Error().message, EINVAL);
    }

    auto* root = json_value_get_object(document.Value().get());
    if (nullptr == root)
    {
        return Error("Benchmark definition is not a JSON object", EINVAL);
    }

    const auto* kind = json_object_get_string(root, "kind");
    if (nullptr == kind || string(kind) != "BenchmarkDefinition")
    {
        return Error("Benchmark definition has an unexpected or missing 'kind' (expected 'BenchmarkDefinition')", EINVAL);
    }

    auto apiVersion = RequiredString(root, "apiVersion", "document");
    if (!apiVersion.HasValue())
    {
        return apiVersion.Error();
    }

    if (nullptr == json_object_get_object(root, "metadata"))
    {
        return Error("Benchmark definition is missing the 'metadata' object", EINVAL);
    }

    auto* spec = json_object_get_object(root, "spec");
    if (nullptr == spec)
    {
        return Error("Benchmark definition is missing the 'spec' object", EINVAL);
    }

    auto* rules = json_object_get_array(spec, "rules");
    if (nullptr == rules)
    {
        return Error("Benchmark definition is missing the 'spec.rules' array", EINVAL);
    }

    const size_t ruleCount = json_array_get_count(rules);
    if (ruleCount > kMaxRules)
    {
        return Error("Benchmark definition has more than the maximum of " + std::to_string(kMaxRules) + " rules", E2BIG);
    }

    std::vector<Resource> resources;
    resources.reserve(ruleCount);
    for (size_t i = 0; i < ruleCount; ++i)
    {
        const JSON_Object* ruleObject = json_array_get_object(rules, i);
        if (nullptr == ruleObject)
        {
            return Error("Benchmark definition rule #" + std::to_string(i) + " is not a JSON object", EINVAL);
        }

        auto resource = ParseRule(ruleObject, i);
        if (!resource.HasValue())
        {
            OsConfigLogError(logHandle, "Failed to parse benchmark definition rule #%zu: %s", i, resource.Error().message.c_str());
            return resource.Error();
        }
        resources.push_back(std::move(resource.Value()));
    }

    return resources;
}

Result<std::vector<Resource>> ParseStream(std::istream& stream, OsConfigLogHandle logHandle)
{
    auto content = ReadAllBounded(stream);
    if (!content.HasValue())
    {
        return content.Error();
    }
    return ParseString(content.Value(), logHandle);
}

Result<std::vector<Resource>> ParseFile(const string& path, OsConfigLogHandle logHandle)
{
    // Apply the full input-hardening posture before reading: reject path
    // traversal, require a root-owned non-writable parent directory, and open
    // with O_NOFOLLOW plus regular-file/ownership/mode checks on the resulting fd.
    if (Assessor::RefusePathTraversal(path, logHandle))
    {
        return Error("Refusing to open benchmark definition with an unsafe path: '" + path + "'", EACCES);
    }
    if (Assessor::RefuseWritableParentDir(path, logHandle))
    {
        return Error("Refusing to open benchmark definition in a writable parent directory: '" + path + "'", EACCES);
    }
    auto fdResult = Assessor::OpenVerifiedInput(path, logHandle);
    if (!fdResult.HasValue())
    {
        return fdResult.Error();
    }

    // stdio_filebuf takes ownership of the verified fd and closes it on destruction.
    __gnu_cxx::stdio_filebuf<char> buffer(fdResult.Value(), std::ios_base::in);
    std::istream stream(&buffer);
    return ParseStream(stream, logHandle);
}

} // namespace BenchmarkDefinition
} // namespace ComplianceEngine
