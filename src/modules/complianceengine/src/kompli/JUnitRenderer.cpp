// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <JUnitRenderer.hpp>
#include <StringTools.h>
#include <cerrno>
#include <cstdint>
#include <parson.h>
#include <sstream>
#include <string>

namespace ComplianceEngine
{
namespace Kompli
{
using std::string;

namespace
{
// Escapes XML entities and neutralises low control characters. The completed
// document is checked for other invalid XML 1.0 characters and UTF-8 sequences.
string EscapeXml(const string& in)
{
    string out;
    out.reserve(in.size());
    for (const char ch : in)
    {
        switch (ch)
        {
            case '&':
                out += "&amp;";
                break;
            case '<':
                out += "&lt;";
                break;
            case '>':
                out += "&gt;";
                break;
            case '"':
                out += "&quot;";
                break;
            case '\'':
                out += "&apos;";
                break;
            default:
                if (static_cast<unsigned char>(ch) < 0x20 && ch != '\t' && ch != '\n' && ch != '\r')
                {
                    out += ' ';
                }
                else
                {
                    out += ch;
                }
                break;
        }
    }
    return out;
}

bool HasValidXmlCharacters(const string& xml)
{
    for (size_t i = 0; i < xml.size();)
    {
        const auto first = static_cast<unsigned char>(xml[i]);
        std::uint32_t codePoint = 0;
        size_t length = 1;
        if (0x80 > first)
        {
            codePoint = first;
        }
        else if ((0xC2 <= first) && (0xDF >= first))
        {
            codePoint = first & 0x1F;
            length = 2;
        }
        else if ((0xE0 <= first) && (0xEF >= first))
        {
            codePoint = first & 0x0F;
            length = 3;
        }
        else if ((0xF0 <= first) && (0xF4 >= first))
        {
            codePoint = first & 0x07;
            length = 4;
        }
        else
        {
            return false;
        }
        if (length > xml.size() - i)
        {
            return false;
        }
        for (size_t j = 1; j < length; ++j)
        {
            const auto next = static_cast<unsigned char>(xml[i + j]);
            if (0x80 != (next & 0xC0))
            {
                return false;
            }
            codePoint = (codePoint << 6) | (next & 0x3F);
        }
        if (((2 == length) && (0x80 > codePoint)) || ((3 == length) && (0x800 > codePoint)) || ((4 == length) && (0x10000 > codePoint)) ||
            ((0xD800 <= codePoint) && (0xDFFF >= codePoint)) || (0x10FFFF < codePoint) ||
            ((0x09 != codePoint) && (0x0A != codePoint) && (0x0D != codePoint) && (0x20 > codePoint)) || ((0xFFFE <= codePoint) && (0xFFFF >= codePoint)))
        {
            return false;
        }
        i += length;
    }
    return true;
}

// Recursively renders an indicators array into the readable indented style used
// by tests/reporting/junit.py: "{indent*depth}  - {label} [{status}]". A node's
// label is its message (leaf) or its procedure (branch); children are rendered
// one level deeper.
//
// Recursion is bounded to guard against pathologically deep (or maliciously
// crafted) indicator trees causing stack exhaustion; nodes below the limit are
// silently dropped from the rendered output.
constexpr size_t cMaxIndicatorDepth = 16;

void AppendIndicators(const JSON_Array* indicators, size_t depth, std::ostringstream& body)
{
    if (nullptr == indicators || depth >= cMaxIndicatorDepth)
    {
        return;
    }
    const size_t count = json_array_get_count(indicators);
    for (size_t i = 0; i < count; ++i)
    {
        const JSON_Object* node = json_array_get_object(indicators, i);
        if (nullptr == node)
        {
            continue;
        }
        string label = StringOrEmpty(json_object_get_string(node, "message"));
        if (label.empty())
        {
            label = StringOrEmpty(json_object_get_string(node, "procedure"));
        }
        const string status = StringOrEmpty(json_object_get_string(node, "status"));
        body << string(depth * 2, ' ') << "  - " << label;
        if (!status.empty())
        {
            body << " [" << status << "]";
        }
        body << "\n";
        AppendIndicators(json_object_get_array(node, "indicators"), depth + 1, body);
    }
}

// Builds the human-readable failure body for a rule: the engine's `ruleName`,
// a Parameters section (present when the canonical JSON carries per-rule
// parameters) followed by an indented Indicators tree.
string BuildBody(const JSON_Object* rule)
{
    std::ostringstream body;
    body << "Rule: " << StringOrEmpty(json_object_get_string(rule, "ruleName")) << "\n\n";

    const JSON_Object* parameters = json_object_get_object(rule, "parameters");
    body << "Parameters:\n";
    if (nullptr != parameters)
    {
        const size_t count = json_object_get_count(parameters);
        for (size_t i = 0; i < count; ++i)
        {
            const string key = StringOrEmpty(json_object_get_name(parameters, i));
            const JSON_Value* value = json_object_get_value_at(parameters, i);
            string valueStr = StringOrEmpty(json_value_get_string(value));
            if (valueStr.empty() && nullptr != value && json_value_get_type(value) != JSONString)
            {
                char* serialized = json_serialize_to_string(value);
                if (nullptr != serialized)
                {
                    // Deliberately deep-copy into our own std::string before
                    // freeing parson's buffer, so the value survives the free.
                    valueStr = std::string(serialized);
                    json_free_serialized_string(serialized);
                }
            }
            body << "  - " << key << ": " << valueStr << "\n";
        }
    }

    body << "\nIndicators:\n";
    AppendIndicators(json_object_get_array(rule, "indicators"), 0, body);
    return body.str();
}

// Renders a rule's `tags` array (flat "axis:value" strings) as a <tags> block
// mirroring the definition's own field name, one <tag value="..."/> per
// entry. Returns empty when there are no tags, so a bare passing testcase
// with no tags can still self-close.
Result<string> BuildTags(const JSON_Object* rule)
{
    const JSON_Value* tagsValue = json_object_get_value(rule, "tags");
    if (nullptr == tagsValue)
    {
        return string();
    }
    const JSON_Array* tags = json_value_get_array(tagsValue);
    if (nullptr == tags)
    {
        return Error("Canonical result JSON rule has a non-array 'tags' field", EINVAL);
    }
    if (0 == json_array_get_count(tags))
    {
        return string();
    }
    std::ostringstream out;
    out << "    <tags>\n";
    const size_t count = json_array_get_count(tags);
    for (size_t i = 0; i < count; ++i)
    {
        const char* tag = json_array_get_string(tags, i);
        if (nullptr == tag)
        {
            return Error("Canonical result JSON rule has a non-string tag", EINVAL);
        }
        const string value(tag, json_array_get_string_len(tags, i));
        if (string::npos != value.find('\0'))
        {
            return Error("Canonical result JSON rule has a tag with an embedded NUL", EINVAL);
        }
        out << "      <tag value=\"" << EscapeXml(value) << "\"/>\n";
    }
    out << "    </tags>\n";
    return out.str();
}
} // anonymous namespace

Result<string> RenderJUnit(const string& canonicalJson, const string& suiteName)
{
    JSON_Value* root = json_parse_string(canonicalJson.c_str());
    if (nullptr == root)
    {
        return Error("Failed to parse canonical result JSON", EINVAL);
    }
    // Own the parsed document for the duration of this function.
    struct RootGuard
    {
        JSON_Value* v;
        ~RootGuard()
        {
            json_value_free(v);
        }
    } guard{root};

    const JSON_Object* rootObject = json_value_get_object(root);
    if (nullptr == rootObject)
    {
        return Error("Canonical result JSON is not an object", EINVAL);
    }
    const JSON_Array* rules = json_object_get_array(rootObject, "rules");
    if (nullptr == rules)
    {
        return Error("Canonical result JSON has no 'rules' array", EINVAL);
    }

    const size_t ruleCount = json_array_get_count(rules);
    size_t failureCount = 0;
    size_t skippedCount = 0;
    std::ostringstream cases;
    for (size_t i = 0; i < ruleCount; ++i)
    {
        const JSON_Object* rule = json_array_get_object(rules, i);
        if (nullptr == rule)
        {
            return Error("Canonical result JSON 'rules' entry is not an object", EINVAL);
        }
        const string id = StringOrEmpty(json_object_get_string(rule, "id"));
        const JSON_Value* titleValue = json_object_get_value(rule, "title");
        if (nullptr != titleValue && JSONString != json_value_get_type(titleValue))
        {
            return Error("Canonical result JSON rule has a non-string 'title'", EINVAL);
        }
        const JSON_Value* nameValue = (nullptr != titleValue) ? titleValue : json_object_get_value(rule, "ruleName");
        if (nullptr == nameValue || JSONString != json_value_get_type(nameValue))
        {
            return Error("Canonical result JSON rule has neither a string 'title' nor a string 'ruleName'", EINVAL);
        }
        const string title(json_value_get_string(nameValue), json_value_get_string_len(nameValue));
        if (string::npos != title.find('\0'))
        {
            return Error("Canonical result JSON rule has an embedded NUL in its testcase name", EINVAL);
        }
        const string status = StringOrEmpty(json_object_get_string(rule, "status"));

        // Guard against schema drift / upstream bugs: an unrecognised or missing
        // status must not be silently rendered as a passing test case. `Skipped`
        // is accepted ahead of its own landing (kompli-cli-completion M-4 item 5)
        // so this renderer doesn't hard-fail the day it appears.
        if (status != "Compliant" && status != "NonCompliant" && status != "NotApplicable" && status != "Skipped")
        {
            return Error("Canonical result JSON rule has invalid 'status' value: '" + status + "'", EINVAL);
        }

        auto tagsXml = BuildTags(rule);
        if (!tagsXml.HasValue())
        {
            return tagsXml.Error();
        }

        cases << "  <testcase classname=\"" << EscapeXml(id) << "\" name=\"" << EscapeXml(title) << "\"";
        if (status == "NonCompliant")
        {
            ++failureCount;
            cases << ">\n" << tagsXml.Value();
            cases << "    <failure message=\"Rule is non-compliant\" type=\"NonCompliant\">" << EscapeXml(BuildBody(rule)) << "</failure>\n";
            cases << "  </testcase>\n";
        }
        else if (status == "NotApplicable" || status == "Skipped")
        {
            // Neither a pass nor a failure; JUnit models both as a skipped test case.
            ++skippedCount;
            const string message = (status == "NotApplicable") ? "Rule is not applicable" : "Rule was skipped";
            cases << ">\n" << tagsXml.Value();
            cases << "    <skipped message=\"" << message << "\">" << EscapeXml(BuildBody(rule)) << "</skipped>\n";
            cases << "  </testcase>\n";
        }
        else if (!tagsXml.Value().empty())
        {
            // status == "Compliant" but tags are present: can't self-close.
            cases << ">\n" << tagsXml.Value();
            cases << "  </testcase>\n";
        }
        else
        {
            // status == "Compliant", no tags: a bare passing test case.
            cases << "/>\n";
        }
    }

    std::ostringstream out;
    out << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    out << "<testsuites>\n";
    out << "  <testsuite name=\"" << EscapeXml(suiteName) << "\" tests=\"" << ruleCount << "\" failures=\"" << failureCount << "\" skipped=\""
        << skippedCount << "\">\n";
    out << cases.str();
    out << "  </testsuite>\n";
    out << "</testsuites>\n";
    const string xml = out.str();
    if (!HasValidXmlCharacters(xml))
    {
        return Error("Canonical result contains invalid XML 1.0 characters or UTF-8", EINVAL);
    }
    return xml;
}

} // namespace Kompli
} // namespace ComplianceEngine
