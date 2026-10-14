// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "LoginDefs.h"

#include <StringTools.h>
#include <cerrno>
#include <limits>
#include <set>
#include <utility>

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

Result<Document> SyntaxError(const std::string& source, std::size_t line, std::size_t column, const char* problem)
{
    return Error(source + ":" + std::to_string(line) + ":" + std::to_string(column) + ": login.defs " + problem, EBADMSG);
}

Error NumericError(const Document& document, std::size_t line, std::size_t column, const std::string& key, const Error& error)
{
    return Error(document.source + ":" + std::to_string(line) + ":" + std::to_string(column) + ": invalid " + key + " value: " + error.message, EBADMSG);
}
} // anonymous namespace

Result<Document> Parse(std::string bytes, std::string source, OsConfigLogHandle logHandle)
{
    if (MaxBytes < bytes.size())
    {
        return LimitError("byte");
    }

    Document document;
    document.source = std::move(source);
    std::set<std::string> seen;
    std::size_t recordCount = 0;
    const auto& input = bytes;
    std::size_t start = 0;
    std::size_t lineNumber = 1;
    const auto firstNul = input.find('\0');
    while (start < input.size())
    {
        const auto newline = input.find('\n', start);
        const auto end = std::string::npos == newline ? input.size() : newline;
        if (MaxLineBytes < end - start)
        {
            return LimitError("line");
        }

        if (firstNul < end)
        {
            return SyntaxError(document.source, lineNumber, firstNul - start + 1, "embedded NUL");
        }

        std::size_t keyStart = start;
        while ((keyStart < end) && IsSeparator(input[keyStart]))
        {
            ++keyStart;
        }
        if ((keyStart < end) && ('#' != input[keyStart]))
        {
            if (MaxRecords <= recordCount)
            {
                return LimitError("record");
            }
            ++recordCount;
            std::size_t keyEnd = keyStart;
            while ((keyEnd < end) && !IsSeparator(input[keyEnd]))
            {
                ++keyEnd;
            }
            const auto key = input.substr(keyStart, keyEnd - keyStart);
            const bool firstOccurrence = seen.insert(key).second;
            if (!firstOccurrence)
            {
                OsConfigLogWarning(logHandle, "Duplicate %s in %s at line %zu", key.c_str(), document.source.c_str(), lineNumber);
            }
            std::size_t valueStart = keyEnd;
            while ((valueStart < end) && IsSeparator(input[valueStart]))
            {
                ++valueStart;
            }
            if (valueStart == end)
            {
                return SyntaxError(document.source, lineNumber, valueStart - start + 1, "missing value");
            }
            Optional<uid_t> uid;
            Optional<int> number;
            if (key == "UID_MIN")
            {
                const auto value = TrimWhiteSpaces(input.substr(valueStart, end - valueStart));
                const auto parsed = TryStringToUint(value);
                if (!parsed.HasValue())
                {
                    return NumericError(document, lineNumber, valueStart - start + 1, key, parsed.Error());
                }
                if (parsed.Value() > std::numeric_limits<uid_t>::max())
                {
                    return NumericError(document, lineNumber, valueStart - start + 1, key, Error("Integer value out of uid_t range: " + value, ERANGE));
                }
                uid = static_cast<uid_t>(parsed.Value());
            }
            else if (key == "PASS_MAX_DAYS" || key == "PASS_MIN_DAYS" || key == "PASS_WARN_AGE")
            {
                const auto parsed = TryStringToInt(TrimWhiteSpaces(input.substr(valueStart, end - valueStart)));
                if (!parsed.HasValue())
                {
                    return NumericError(document, lineNumber, valueStart - start + 1, key, parsed.Error());
                }
                number = parsed.Value();
            }
            if (firstOccurrence && uid.HasValue())
            {
                document.uidMin = uid.Value();
            }
            else if (firstOccurrence && key == "PASS_MAX_DAYS")
            {
                document.passMaxDays = number.Value();
            }
            else if (firstOccurrence && key == "PASS_MIN_DAYS")
            {
                document.passMinDays = number.Value();
            }
            else if (firstOccurrence && key == "PASS_WARN_AGE")
            {
                document.passWarnAge = number.Value();
            }
            else if (firstOccurrence && key == "ENCRYPT_METHOD")
            {
                document.encryptMethod = input.substr(valueStart, end - valueStart);
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
