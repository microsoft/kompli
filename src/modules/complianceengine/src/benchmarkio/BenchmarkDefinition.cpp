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

Result<string> ReadStringValue(const JSON_Value* jsonValue, const char* key, const string& context)
{
    string value(json_value_get_string(jsonValue), json_value_get_string_len(jsonValue));
    if (string::npos != value.find('\0'))
    {
        return Error("Benchmark definition " + context + " has an embedded NUL in '" + string(key) + "'", EINVAL);
    }
    return value;
}

// Reads a required, non-empty string field from a JSON object. `context`
// identifies the enclosing element for error messages.
Result<string> RequiredString(const JSON_Object* object, const char* key, const string& context)
{
    const JSON_Value* jsonValue = json_object_get_value(object, key);
    if (nullptr == jsonValue || JSONString != json_value_get_type(jsonValue))
    {
        return Error("Benchmark definition " + context + " is missing required string field '" + string(key) + "'", EINVAL);
    }
    auto value = ReadStringValue(jsonValue, key, context);
    if (!value.HasValue())
    {
        return value.Error();
    }
    if (value.Value().empty())
    {
        return Error("Benchmark definition " + context + " has an empty '" + string(key) + "' field", EINVAL);
    }
    return value;
}

Result<Optional<string>> OptionalString(const JSON_Object* object, const char* key, const string& context)
{
    const JSON_Value* jsonValue = json_object_get_value(object, key);
    if (nullptr == jsonValue)
    {
        return Optional<string>();
    }
    if (JSONString != json_value_get_type(jsonValue))
    {
        return Error("Benchmark definition " + context + " has a non-string '" + string(key) + "' field", EINVAL);
    }
    auto value = ReadStringValue(jsonValue, key, context);
    if (!value.HasValue())
    {
        return value.Error();
    }
    return Optional<string>(std::move(value.Value()));
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

Result<std::vector<string>> ParseTags(const JSON_Object* ruleObject, const string& context)
{
    const JSON_Value* value = json_object_get_value(ruleObject, "tags");
    if (nullptr == value || json_value_get_type(value) != JSONArray)
    {
        return Error("Benchmark definition " + context + " is missing an array 'tags' field", EINVAL);
    }
    const JSON_Array* array = json_value_get_array(value);
    const size_t count = json_array_get_count(array);
    std::vector<string> tags;
    tags.reserve(count);
    for (size_t i = 0; i < count; ++i)
    {
        const JSON_Value* tagValue = json_array_get_value(array, i);
        if (nullptr == tagValue || JSONString != json_value_get_type(tagValue))
        {
            return Error("Benchmark definition " + context + " has a non-string 'tags' entry", EINVAL);
        }
        string tag(json_value_get_string(tagValue), json_value_get_string_len(tagValue));
        if (string::npos != tag.find('\0'))
        {
            return Error("Benchmark definition " + context + " has an embedded NUL in a 'tags' entry", EINVAL);
        }
        const auto colon = tag.find(':');
        if (string::npos == colon || 0 == colon || colon + 1 == tag.size() ||
            !std::all_of(tag.begin(), tag.begin() + colon, [](char c) { return ('a' <= c && c <= 'z') || ('0' <= c && c <= '9') || c == '-'; }))
        {
            return Error("Benchmark definition " + context + " has an invalid 'tags' entry", EINVAL);
        }
        tags.push_back(std::move(tag));
    }
    return tags;
}

Result<BenchmarkIO::Metadata> ParseMetadata(const JSON_Object* ruleObject, const string& context)
{
    const JSON_Object* metadataObject = json_object_get_object(ruleObject, "metadata");
    if (nullptr == metadataObject)
    {
        return Error("Benchmark definition " + context + " is missing an object 'metadata' field", EINVAL);
    }
    const string metadataContext = context + ".metadata";
    auto description = OptionalString(metadataObject, "description", metadataContext);
    if (!description.HasValue())
    {
        return description.Error();
    }
    auto rationale = OptionalString(metadataObject, "rationale", metadataContext);
    if (!rationale.HasValue())
    {
        return rationale.Error();
    }
    auto fixtext = OptionalString(metadataObject, "fixtext", metadataContext);
    if (!fixtext.HasValue())
    {
        return fixtext.Error();
    }
    auto severity = OptionalString(metadataObject, "severity", metadataContext);
    if (!severity.HasValue())
    {
        return severity.Error();
    }
    auto references = OptionalString(metadataObject, "references", metadataContext);
    if (!references.HasValue())
    {
        return references.Error();
    }
    BenchmarkIO::Metadata metadata;
    metadata.description = std::move(description.Value());
    metadata.rationale = std::move(rationale.Value());
    metadata.fixtext = std::move(fixtext.Value());
    metadata.severity = std::move(severity.Value());
    metadata.references = std::move(references.Value());
    for (size_t i = 0; i < json_object_get_count(metadataObject); ++i)
    {
        const char* name = json_object_get_name(metadataObject, i);
        if (nullptr == name)
        {
            return Error("Benchmark definition " + metadataContext + " has an invalid property name", EINVAL);
        }
        const string key(name);
        if (key == "description" || key == "rationale" || key == "fixtext" || key == "severity" || key == "references")
        {
            continue;
        }
        auto extra = OptionalString(metadataObject, name, metadataContext);
        if (!extra.HasValue())
        {
            return extra.Error();
        }
        metadata.additional.emplace(key, std::move(extra.Value().Value()));
    }
    return metadata;
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
    auto section = RequiredString(ruleObject, "section", context);
    if (!section.HasValue())
    {
        return section.Error();
    }
    auto procedure = SerializeProcedure(ruleObject, context);
    if (!procedure.HasValue())
    {
        return procedure.Error();
    }
    auto tags = ParseTags(ruleObject, context);
    if (!tags.HasValue())
    {
        return tags.Error();
    }
    auto metadata = ParseMetadata(ruleObject, context);
    if (!metadata.HasValue())
    {
        return metadata.Error();
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
    // of the caller expects dotted notation (e.g. "1.1.1.1").
    std::replace(resource.benchmarkInfo.section.begin(), resource.benchmarkInfo.section.end(), '/', '.');
    // The rule's explicit `section` must agree with the section encoded in the
    // payload key (the generator derives one from the other); a mismatch is a
    // corrupt or hand-edited definition and is rejected rather than silently
    // resolved to the payload-key value.
    if (section.Value() != resource.benchmarkInfo.section)
    {
        return Error("Benchmark definition " + context + " has a 'section' ('" + section.Value() + "') that disagrees with its payloadKey section ('" +
                         resource.benchmarkInfo.section + "')",
            EINVAL);
    }
    resource.procedure = std::move(procedure.Value());
    resource.ruleName = std::move(ruleName.Value());
    resource.tags = std::move(tags.Value());
    resource.metadata = std::move(metadata.Value());
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

    auto kind = RequiredString(root, "kind", "document");
    if (!kind.HasValue() || kind.Value() != "BenchmarkDefinition")
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
    if (BenchmarkIO::RefusePathTraversal(path, logHandle))
    {
        return Error("Refusing to open benchmark definition with an unsafe path: '" + path + "'", EACCES);
    }
    if (BenchmarkIO::RefuseWritableParentDir(path, logHandle))
    {
        return Error("Refusing to open benchmark definition in a writable parent directory: '" + path + "'", EACCES);
    }
    auto fdResult = BenchmarkIO::OpenVerifiedInput(path, logHandle);
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
