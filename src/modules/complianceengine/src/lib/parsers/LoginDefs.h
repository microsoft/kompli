// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_PARSERS_LOGIN_DEFS_H
#define COMPLIANCEENGINE_PARSERS_LOGIN_DEFS_H

#include <Result.h>
#include <cstddef>
#include <string>
#include <vector>

namespace ComplianceEngine
{
namespace LoginDefs
{
enum : std::size_t
{
    MaxBytes = 1024 * 1024,
    MaxLineBytes = 16 * 1024,
    MaxRecords = 8192,
    MaxDiagnostics = 8192
};

struct Span
{
    std::size_t offset;
    std::size_t length;
};

struct Record
{
    Span lineSpan;
    Span keySpan;
    // The raw remainder is not quote-decoded or stripped of inline hashes.
    Span valueSpan;
    std::size_t line;
    bool hasValue;
    std::string key;
};

struct Diagnostic
{
    enum class Kind
    {
        MissingValue,
        EmbeddedNul
    };

    Kind kind;
    Span span;
    std::size_t line;
    std::size_t column;
};

struct Document
{
    std::string source;
    std::string bytes;
    std::vector<Record> records;
    std::vector<Diagnostic> diagnostics;

    std::string Text(Span span) const;
    std::vector<const Record*> FindAll(const std::string& key) const;
    const Record* FindFirst(const std::string& key) const;
    const Record* FindLast(const std::string& key) const;
    bool HasEmbeddedNul(const Record& record) const;
};

// Offsets and columns count bytes, not characters. Lines and columns are 1-based.
// LF ends a physical line; a preceding CR remains in the raw line/value.
Result<Document> Parse(const std::string& bytes, const std::string& source);
} // namespace LoginDefs
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_PARSERS_LOGIN_DEFS_H
