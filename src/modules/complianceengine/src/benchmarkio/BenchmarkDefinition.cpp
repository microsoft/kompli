// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "BenchmarkDefinition.hpp"

#include "InputSecurity.hpp"

#include <BenchmarkInfo.h>
#include <JsonWrapper.h>
#include <cerrno>
#include <ext/stdio_filebuf.h>
#include <memory>
#include <parson.h>
#include <set>
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

// Supported envelope format versions (ADR-0008 §4: the format axis, gated at
// generation time by the committed schema and now, per M-27, at parse time
// too - closes TM-5). Extend this set (never silently reinterpret an
// unrecognised value) when a schema reshape adds a new apiVersion; kompli may
// carry a bounded window of several supported entries during a migration,
// dropping the oldest once its definitions are no longer expected in the
// field, per a stated support-window policy decided when that first happens.
const std::set<string> kSupportedApiVersions = {"v1"};

// Joins a set of strings with ", " for a human-readable error message.
string JoinSet(const std::set<string>& values)
{
    string joined;
    for (const auto& value : values)
    {
        if (!joined.empty())
        {
            joined += ", ";
        }
        joined += value;
    }
    return joined;
}

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

// Applies the full input-hardening posture (path-traversal rejection,
// root-owned non-writable parent directory, O_NOFOLLOW open, regular-file/
// ownership/mode checks) and reads the whole file into a string. Used by
// ParseFile.
Result<string> ReadVerifiedFile(const string& path, OsConfigLogHandle logHandle)
{
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
    return ReadAllBounded(stream);
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

// Parses a rule's optional `parameterMetadata` object (name -> {type,
// default, displayName, validationRegex, validationFailedMessage, mandatory}
// - see benchmark.schema.json). Absent entirely is not an error: a rule with
// no tunable parameters simply has none.
Result<std::map<string, BenchmarkIO::ParameterMetadata>> ParseParameterMetadata(const JSON_Object* ruleObject, const string& context)
{
    std::map<string, BenchmarkIO::ParameterMetadata> result;
    const JSON_Value* value = json_object_get_value(ruleObject, "parameterMetadata");
    if (nullptr == value)
    {
        return result;
    }
    if (json_value_get_type(value) != JSONObject)
    {
        return Error("Benchmark definition " + context + " has a 'parameterMetadata' field that is not a JSON object", EINVAL);
    }
    const JSON_Object* metadataObject = json_value_get_object(value);
    const size_t count = json_object_get_count(metadataObject);
    for (size_t i = 0; i < count; ++i)
    {
        const char* name = json_object_get_name(metadataObject, i);
        if (nullptr == name || name[0] == '\0')
        {
            return Error("Benchmark definition " + context + " has a 'parameterMetadata' entry with an empty name", EINVAL);
        }
        const string entryContext = context + ".parameterMetadata." + string(name);
        const JSON_Value* entryValue = json_object_get_value_at(metadataObject, i);
        const JSON_Object* entryObject = (nullptr != entryValue) ? json_value_get_object(entryValue) : nullptr;
        if (nullptr == entryObject)
        {
            return Error("Benchmark definition " + entryContext + " is not a JSON object", EINVAL);
        }
        auto defaultValue = RequiredString(entryObject, "default", entryContext);
        if (!defaultValue.HasValue())
        {
            return defaultValue.Error();
        }
        auto type = RequiredString(entryObject, "type", entryContext);
        if (!type.HasValue())
        {
            return type.Error();
        }

        BenchmarkIO::ParameterMetadata metadata;
        metadata.defaultValue = std::move(defaultValue.Value());
        metadata.type = std::move(type.Value());
        const char* displayName = json_object_get_string(entryObject, "displayName");
        if (nullptr != displayName)
        {
            metadata.displayName = string(displayName);
        }
        const char* validationRegex = json_object_get_string(entryObject, "validationRegex");
        if (nullptr != validationRegex)
        {
            metadata.validationRegex = string(validationRegex);
        }
        const char* validationFailedMessage = json_object_get_string(entryObject, "validationFailedMessage");
        if (nullptr != validationFailedMessage)
        {
            metadata.validationFailedMessage = string(validationFailedMessage);
        }
        metadata.mandatory = (1 == json_object_get_boolean(entryObject, "mandatory"));
        result[name] = std::move(metadata);
    }
    return result;
}

// Parses a rule's required `tags` array (flat "axis:value" strings - see
// benchmark.schema.json). A missing/non-array field, or a non-string entry,
// is a hard error, matching the schema's `required: [..., "tags"]`.
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
        const char* tag = json_array_get_string(array, i);
        if (nullptr == tag)
        {
            return Error("Benchmark definition " + context + " has a non-string 'tags' entry", EINVAL);
        }
        tags.emplace_back(tag);
    }
    return tags;
}

// Parses a rule's required `metadata` object (description/rationale/fixtext/
// severity/references, all required strings - see benchmark.schema.json).
Result<BenchmarkIO::Metadata> ParseMetadata(const JSON_Object* ruleObject, const string& context)
{
    const JSON_Object* metadataObject = json_object_get_object(ruleObject, "metadata");
    if (nullptr == metadataObject)
    {
        return Error("Benchmark definition " + context + " is missing an object 'metadata' field", EINVAL);
    }
    const string metadataContext = context + ".metadata";

    auto description = RequiredString(metadataObject, "description", metadataContext);
    if (!description.HasValue())
    {
        return description.Error();
    }
    auto rationale = RequiredString(metadataObject, "rationale", metadataContext);
    if (!rationale.HasValue())
    {
        return rationale.Error();
    }
    auto fixtext = RequiredString(metadataObject, "fixtext", metadataContext);
    if (!fixtext.HasValue())
    {
        return fixtext.Error();
    }
    auto severity = RequiredString(metadataObject, "severity", metadataContext);
    if (!severity.HasValue())
    {
        return severity.Error();
    }
    auto references = RequiredString(metadataObject, "references", metadataContext);
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
    auto ruleName = RequiredString(ruleObject, "ruleName", context);
    if (!ruleName.HasValue())
    {
        return ruleName.Error();
    }
    auto id = RequiredString(ruleObject, "id", context);
    if (!id.HasValue())
    {
        return id.Error();
    }
    auto ruleId = RequiredString(ruleObject, "ruleId", context);
    if (!ruleId.HasValue())
    {
        return ruleId.Error();
    }
    auto procedure = SerializeProcedure(ruleObject, context);
    if (!procedure.HasValue())
    {
        return procedure.Error();
    }
    auto parameterMetadata = ParseParameterMetadata(ruleObject, context);
    if (!parameterMetadata.HasValue())
    {
        return parameterMetadata.Error();
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

    Resource resource;
    resource.resourceID = std::move(title.Value());
    // id is opaque here: the file-level prefix lives once on
    // BenchmarkDocument::benchmarkInfo, so this is just the framework-defined
    // rule identifier, stored verbatim without parsing.
    resource.id = std::move(id.Value());
    resource.ruleId = std::move(ruleId.Value());
    resource.procedure = std::move(procedure.Value());
    resource.ruleName = std::move(ruleName.Value());
    resource.tags = std::move(tags.Value());
    resource.metadata = std::move(metadata.Value());
    // Every rule carries an init object.
    resource.hasInitAudit = true;
    // Definitions carry no desired object value; the payload is modelled as
    // absent.
    resource.parameterMetadata = std::move(parameterMetadata.Value());

    return resource;
}

} // anonymous namespace

Result<BenchmarkDocument> ParseString(const string& json, OsConfigLogHandle logHandle)
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
    if (0 == kSupportedApiVersions.count(apiVersion.Value()))
    {
        return Error("Benchmark definition has an unsupported 'apiVersion' (\"" + apiVersion.Value() + "\"); supported: " + JoinSet(kSupportedApiVersions), EINVAL);
    }

    auto* metadata = json_object_get_object(root, "metadata");
    if (nullptr == metadata)
    {
        return Error("Benchmark definition is missing the 'metadata' object", EINVAL);
    }
    auto name = RequiredString(metadata, "name", "metadata");
    if (!name.HasValue())
    {
        return name.Error();
    }

    // The file-level prefix (framework/distribution/distributionVersion/
    // benchmarkVersion) is hoisted once here rather than repeated per rule.
    auto* labels = json_object_get_object(metadata, "labels");
    if (nullptr == labels)
    {
        return Error("Benchmark definition is missing the 'metadata.labels' object", EINVAL);
    }
    auto framework = RequiredString(labels, "framework", "metadata.labels");
    if (!framework.HasValue())
    {
        return framework.Error();
    }
    auto distribution = RequiredString(labels, "distribution", "metadata.labels");
    if (!distribution.HasValue())
    {
        return distribution.Error();
    }
    auto distributionVersion = RequiredString(labels, "distributionVersion", "metadata.labels");
    if (!distributionVersion.HasValue())
    {
        return distributionVersion.Error();
    }
    auto* annotations = json_object_get_object(metadata, "annotations");
    if (nullptr == annotations)
    {
        return Error("Benchmark definition is missing the 'metadata.annotations' object", EINVAL);
    }
    auto benchmarkVersion = RequiredString(annotations, "benchmarkVersion", "metadata.annotations");
    if (!benchmarkVersion.HasValue())
    {
        return benchmarkVersion.Error();
    }
    auto benchmarkInfo = BenchmarkInfo::FromMetadata(framework.Value(), distribution.Value(), distributionVersion.Value(), benchmarkVersion.Value());
    if (!benchmarkInfo.HasValue())
    {
        return Error("Benchmark definition has an invalid file-level prefix: " + benchmarkInfo.Error().message, benchmarkInfo.Error().code);
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

    BenchmarkDocument doc;
    doc.name = std::move(name.Value());
    doc.benchmarkInfo = std::move(benchmarkInfo.Value());
    doc.resources.reserve(ruleCount);
    // Rules already seen, keyed by id - the identifier guaranteed unique
    // within one file; plan/run key
    // on it directly, so a duplicate here would make a rule reference
    // ambiguous.
    std::set<string> seenIds;
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
        if (!seenIds.insert(resource.Value().id).second)
        {
            return Error("Benchmark definition rule #" + std::to_string(i) + " has a duplicate id: '" + resource.Value().id + "'", EINVAL);
        }
        doc.resources.push_back(std::move(resource.Value()));
    }

    return doc;
}

Result<BenchmarkDocument> ParseStream(std::istream& stream, OsConfigLogHandle logHandle)
{
    auto content = ReadAllBounded(stream);
    if (!content.HasValue())
    {
        return content.Error();
    }
    return ParseString(content.Value(), logHandle);
}

Result<BenchmarkDocument> ParseFile(const string& path, OsConfigLogHandle logHandle)
{
    auto content = ReadVerifiedFile(path, logHandle);
    if (!content.HasValue())
    {
        return content.Error();
    }
    return ParseString(content.Value(), logHandle);
}

} // namespace BenchmarkDefinition
} // namespace ComplianceEngine
