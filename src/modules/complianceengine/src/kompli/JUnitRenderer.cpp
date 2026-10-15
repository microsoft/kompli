// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <JUnitRenderer.hpp>
#include <StringTools.h>
#include <TagLimits.hpp>
#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <parson.h>
#include <sstream>
#include <streambuf>
#include <string>

namespace ComplianceEngine
{
namespace Kompli
{
using std::string;

namespace
{
constexpr size_t kMaxJUnitBytes = static_cast<size_t>(16) * 1024 * 1024;

// Parson validates the object but accepts trailing input. Locate its end without
// treating braces in strings as structure; only JSON whitespace may follow.
bool HasTrailingObjectData(const string& json)
{
    size_t depth = 0;
    bool inString = false;
    for (size_t i = json.find('{'); i < json.size(); ++i)
    {
        const char ch = json[i];
        if (inString)
        {
            if (ch == '\\')
            {
                ++i;
            }
            else if (ch == '"')
            {
                inString = false;
            }
        }
        else if (ch == '"')
        {
            inString = true;
        }
        else if (ch == '{')
        {
            ++depth;
        }
        else if (ch == '}' && --depth == 0)
        {
            return json.find_first_not_of(" \t\r\n", i + 1) != string::npos;
        }
    }
    return true;
}

class BoundedXmlBuffer : public std::streambuf
{
public:
    explicit BoundedXmlBuffer(size_t limit)
        : mLimit(limit)
    {
    }

    const string& Value() const
    {
        return mValue;
    }

    void RemoveLast(size_t count)
    {
        mValue.resize(mValue.size() - count);
    }

protected:
    std::streamsize xsputn(const char* data, std::streamsize count) override
    {
        if (count < 0 || static_cast<size_t>(count) > mLimit - mValue.size())
        {
            return 0;
        }
        mValue.append(data, static_cast<size_t>(count));
        return count;
    }

    int_type overflow(int_type ch) override
    {
        if (traits_type::eq_int_type(ch, traits_type::eof()))
        {
            return traits_type::not_eof(ch);
        }
        if (mValue.size() == mLimit)
        {
            return traits_type::eof();
        }
        mValue.push_back(traits_type::to_char_type(ch));
        return ch;
    }

private:
    size_t mLimit;
    string mValue;
};

// Attribute whitespace needs character references to survive XML parsing.
// Illegal ASCII controls are normalized only in legacy element text; attributes
// retain them so the completed document validation can reject them.
void EscapeXml(const string& in, std::ostream& out, bool attribute = false)
{
    for (const char ch : in)
    {
        switch (ch)
        {
            case '&':
                out << "&amp;";
                break;
            case '<':
                out << "&lt;";
                break;
            case '>':
                out << "&gt;";
                break;
            case '"':
                out << "&quot;";
                break;
            case '\'':
                out << "&apos;";
                break;
            case '\t':
                out << (attribute ? "&#9;" : "\t");
                break;
            case '\n':
                out << (attribute ? "&#10;" : "\n");
                break;
            case '\r':
                out << (attribute ? "&#13;" : "\r");
                break;
            default:
                if (!attribute && static_cast<unsigned char>(ch) < 0x20 && ch != '\t' && ch != '\n' && ch != '\r')
                {
                    out << ' ';
                }
                else
                {
                    out << ch;
                }
                break;
        }
        if (!out)
        {
            return;
        }
    }
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

void AppendIndicators(const JSON_Array* indicators, size_t depth, std::ostream& body)
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
Result<string> BuildBody(const JSON_Object* rule)
{
    BoundedXmlBuffer buffer(kMaxJUnitBytes);
    std::ostream body(&buffer);
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
    if (!body)
    {
        return Error("JUnit result exceeds the maximum output size", EFBIG);
    }
    return buffer.Value();
}

// Renders a rule's `tags` array as a <tags> block. Returns false when
// there are no tags, so a bare passing testcase can still self-close.
Result<bool> BuildTags(const JSON_Object* rule, std::ostream& out)
{
    const JSON_Value* tagsValue = json_object_get_value(rule, "tags");
    if (nullptr == tagsValue)
    {
        return false;
    }
    const JSON_Array* tags = json_value_get_array(tagsValue);
    if (nullptr == tags)
    {
        return Error("Canonical result JSON rule has a non-array 'tags' field", EINVAL);
    }
    if (0 == json_array_get_count(tags))
    {
        return false;
    }
    out << "    <tags>\n";
    const size_t count = json_array_get_count(tags);
    for (size_t i = 0; i < count; ++i)
    {
        const char* tag = json_array_get_string(tags, i);
        if (nullptr == tag)
        {
            return Error("Canonical result JSON rule has a non-string tag", EINVAL);
        }
        const size_t length = json_array_get_string_len(tags, i);
        if (ComplianceEngine::BenchmarkDefinition::kMaxTagBytes < length)
        {
            return Error("Canonical result JSON rule has a tag exceeding " + std::to_string(ComplianceEngine::BenchmarkDefinition::kMaxTagBytes) +
                             " bytes",
                E2BIG);
        }
        const string value(tag, length);
        if (string::npos != value.find('\0'))
        {
            return Error("Canonical result JSON rule has a tag with an embedded NUL", EINVAL);
        }
        const auto colon = value.find(':');
        if (string::npos == colon || colon == 0 || colon + 1 == value.size() ||
            !std::all_of(value.begin(), value.begin() + colon, [](char ch) { return ('a' <= ch && ch <= 'z') || ('0' <= ch && ch <= '9') || ch == '-'; }))
        {
            return Error("Canonical result JSON rule has an invalid 'axis:value' tag", EINVAL);
        }
        out << "      <tag value=\"";
        EscapeXml(value, out, true);
        out << "\"/>\n";
        if (!out)
        {
            return Error("JUnit result exceeds the maximum output size", EFBIG);
        }
    }
    out << "    </tags>\n";
    if (!out)
    {
        return Error("JUnit result exceeds the maximum output size", EFBIG);
    }
    return true;
}
} // anonymous namespace

Result<string> RenderJUnit(const string& canonicalJson, const string& suiteName)
{
    if (canonicalJson.find('\0') != string::npos)
    {
        return Error("Canonical result JSON contains a NUL byte", EINVAL);
    }
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
    if (HasTrailingObjectData(canonicalJson))
    {
        return Error("Canonical result JSON contains trailing data", EINVAL);
    }
    const JSON_Array* rules = json_object_get_array(rootObject, "rules");
    if (nullptr == rules)
    {
        return Error("Canonical result JSON has no 'rules' array", EINVAL);
    }

    const size_t ruleCount = json_array_get_count(rules);
    size_t failureCount = 0;
    size_t skippedCount = 0;
    BoundedXmlBuffer casesBuffer(kMaxJUnitBytes);
    std::ostream cases(&casesBuffer);
    for (size_t i = 0; i < ruleCount; ++i)
    {
        const JSON_Object* rule = json_array_get_object(rules, i);
        if (nullptr == rule)
        {
            return Error("Canonical result JSON 'rules' entry is not an object", EINVAL);
        }
        const JSON_Value* idValue = json_object_get_value(rule, "id");
        if (nullptr == idValue || JSONString != json_value_get_type(idValue))
        {
            return Error("Canonical result JSON rule has no string 'id'", EINVAL);
        }
        const string id(json_value_get_string(idValue), json_value_get_string_len(idValue));
        if (id.empty())
        {
            return Error("Canonical result JSON rule has an empty 'id'", EINVAL);
        }
        if (string::npos != id.find('\0'))
        {
            return Error("Canonical result JSON rule has an embedded NUL in its testcase classname", EINVAL);
        }
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
        const JSON_Value* statusValue = json_object_get_value(rule, "status");
        if (nullptr == statusValue || JSONString != json_value_get_type(statusValue))
        {
            return Error("Canonical result JSON rule has no string 'status'", EINVAL);
        }
        const string status(json_value_get_string(statusValue), json_value_get_string_len(statusValue));
        if (string::npos != status.find('\0'))
        {
            return Error("Canonical result JSON rule has an embedded NUL in its status", EINVAL);
        }

        // Guard against schema drift / upstream bugs: an unrecognised or missing
        // status must not be silently rendered as a passing test case. `Skipped`
        // is accepted ahead of its own landing (kompli-cli-completion M-4 item 5)
        // so this renderer doesn't hard-fail the day it appears.
        if (status != "Compliant" && status != "NonCompliant" && status != "NotApplicable" && status != "Skipped")
        {
            return Error("Canonical result JSON rule has invalid 'status' value: '" + status + "'", EINVAL);
        }

        cases << "  <testcase classname=\"";
        EscapeXml(id, cases, true);
        cases << "\" name=\"";
        EscapeXml(title, cases, true);
        cases << "\"";
        if (!cases)
        {
            return Error("JUnit result exceeds the maximum output size", EFBIG);
        }
        cases << ">\n";
        if (!cases)
        {
            return Error("JUnit result exceeds the maximum output size", EFBIG);
        }
        auto hasTags = BuildTags(rule, cases);
        if (!hasTags.HasValue())
        {
            return hasTags.Error();
        }
        if (status == "NonCompliant")
        {
            ++failureCount;
            auto body = BuildBody(rule);
            if (!body.HasValue())
            {
                return body.Error();
            }
            cases << "    <failure message=\"Rule is non-compliant\" type=\"NonCompliant\">";
            EscapeXml(body.Value(), cases);
            cases << "</failure>\n";
            cases << "  </testcase>\n";
        }
        else if (status == "NotApplicable" || status == "Skipped")
        {
            // Neither a pass nor a failure; JUnit models both as a skipped test case.
            ++skippedCount;
            const string message = (status == "NotApplicable") ? "Rule is not applicable" : "Rule was skipped";
            auto body = BuildBody(rule);
            if (!body.HasValue())
            {
                return body.Error();
            }
            cases << "    <skipped message=\"" << message << "\">";
            EscapeXml(body.Value(), cases);
            cases << "</skipped>\n";
            cases << "  </testcase>\n";
        }
        else if (hasTags.Value())
        {
            // status == "Compliant" but tags are present: can't self-close.
            cases << "  </testcase>\n";
        }
        else
        {
            // status == "Compliant", no tags: a bare passing test case.
            casesBuffer.RemoveLast(2);
            cases << "/>\n";
        }
        if (!cases)
        {
            return Error("JUnit result exceeds the maximum output size", EFBIG);
        }
    }

    BoundedXmlBuffer outputBuffer(kMaxJUnitBytes);
    std::ostream out(&outputBuffer);
    out << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    out << "<testsuites>\n";
    out << "  <testsuite name=\"";
    EscapeXml(suiteName, out, true);
    out << "\" tests=\"" << ruleCount << "\" failures=\"" << failureCount << "\" skipped=\"" << skippedCount << "\">\n";
    out << casesBuffer.Value();
    out << "  </testsuite>\n";
    out << "</testsuites>\n";
    if (!out)
    {
        return Error("JUnit result exceeds the maximum output size", EFBIG);
    }
    const string xml = outputBuffer.Value();
    if (!HasValidXmlCharacters(xml))
    {
        return Error("Canonical result contains invalid XML 1.0 characters or UTF-8", EINVAL);
    }
    return xml;
}

} // namespace Kompli
} // namespace ComplianceEngine
