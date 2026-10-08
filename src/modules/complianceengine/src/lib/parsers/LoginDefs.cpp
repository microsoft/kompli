// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "LoginDefs.h"

#include <cerrno>

namespace ComplianceEngine
{
namespace LoginDefs
{
namespace
{
bool IsSeparator(char value)
{
    return (' ' == value) || ('\t' == value) || ('\r' == value) || ('\v' == value) || ('\f' == value);
}

Result<Document> LimitError(const char* limit)
{
    return Error(std::string("login.defs ") + limit + " limit exceeded", E2BIG);
}
} // anonymous namespace

std::string Document::Text(Span span) const
{
    return bytes.substr(span.offset, span.length);
}

std::vector<const Record*> Document::FindAll(const std::string& key) const
{
    std::vector<const Record*> found;
    for (const auto& record : records)
    {
        if (record.key == key)
        {
            found.push_back(&record);
        }
    }
    return found;
}

const Record* Document::FindFirst(const std::string& key) const
{
    for (const auto& record : records)
    {
        if (record.key == key)
        {
            return &record;
        }
    }
    return nullptr;
}

const Record* Document::FindLast(const std::string& key) const
{
    for (auto it = records.rbegin(); it != records.rend(); ++it)
    {
        if (it->key == key)
        {
            return &*it;
        }
    }
    return nullptr;
}

Result<Document> Parse(const std::string& bytes, const std::string& source)
{
    if (MaxBytes < bytes.size())
    {
        return LimitError("byte");
    }

    Document document{source, bytes, {}, {}};
    std::size_t start = 0;
    std::size_t lineNumber = 1;
    std::size_t nextNul = bytes.find('\0');
    while (start < bytes.size())
    {
        const auto newline = bytes.find('\n', start);
        const auto end = std::string::npos == newline ? bytes.size() : newline;
        if (MaxLineBytes < end - start)
        {
            return LimitError("line");
        }

        if (nextNul < end)
        {
            if (MaxDiagnostics <= document.diagnostics.size())
            {
                return LimitError("diagnostic");
            }
            document.diagnostics.push_back({Diagnostic::Kind::EmbeddedNul, {nextNul, 1}, lineNumber, nextNul - start + 1});
            nextNul = bytes.find('\0', end);
        }

        std::size_t keyStart = start;
        while ((keyStart < end) && IsSeparator(bytes[keyStart]))
        {
            ++keyStart;
        }
        if ((keyStart < end) && ('#' != bytes[keyStart]))
        {
            if (MaxRecords <= document.records.size())
            {
                return LimitError("record");
            }
            std::size_t keyEnd = keyStart;
            while ((keyEnd < end) && !IsSeparator(bytes[keyEnd]))
            {
                ++keyEnd;
            }
            std::size_t valueStart = keyEnd;
            while ((valueStart < end) && IsSeparator(bytes[valueStart]))
            {
                ++valueStart;
            }
            const bool hasValue = valueStart < end;
            document.records.push_back({{start, end - start}, {keyStart, keyEnd - keyStart}, {valueStart, end - valueStart}, lineNumber, hasValue,
                bytes.substr(keyStart, keyEnd - keyStart)});
            if (!hasValue)
            {
                if (MaxDiagnostics <= document.diagnostics.size())
                {
                    return LimitError("diagnostic");
                }
                document.diagnostics.push_back({Diagnostic::Kind::MissingValue, {valueStart, 0}, lineNumber, valueStart - start + 1});
            }
        }

        if (std::string::npos == newline)
        {
            break;
        }
        start = end + 1;
        ++lineNumber;
    }
    return document;
}
} // namespace LoginDefs
} // namespace ComplianceEngine
