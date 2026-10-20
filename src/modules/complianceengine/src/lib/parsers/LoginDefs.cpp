// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "LoginDefs.h"

#include <StringTools.h>
#include <cerrno>
#include <limits>
#include <set>
#include <stdexcept>
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

Error ValueError(const Document& document, std::size_t line, std::size_t column, const std::string& key, const Error& error)
{
    return Error(document.source + ":" + std::to_string(line) + ":" + std::to_string(column) + ": invalid " + key + " value: " + error.message, EBADMSG);
}

Error ConflictError(const Document& document, std::size_t line, std::size_t column, const std::string& key)
{
    return Error(document.source + ":" + std::to_string(line) + ":" + std::to_string(column) + ": conflicting duplicate " + key + " value", EBADMSG);
}
} // anonymous namespace

Result<EncryptionMethod> ParseEncryptionMethod(const std::string& value)
{
    const auto name = ToLower(value);
    if (name == "des")
        return EncryptionMethod::DES;
    if (name == "md5")
        return EncryptionMethod::MD5;
    if (name == "sha256")
        return EncryptionMethod::SHA256;
    if (name == "sha512")
        return EncryptionMethod::SHA512;
    if (name == "yescrypt")
        return EncryptionMethod::YESCRYPT;
    if (name == "bcrypt")
        return EncryptionMethod::BCRYPT;
    return Error("Unsupported encryption method: " + value, EINVAL);
}

const char* EncryptionMethodName(EncryptionMethod method)
{
    switch (method)
    {
        case EncryptionMethod::DES:
            return "DES";
        case EncryptionMethod::MD5:
            return "MD5";
        case EncryptionMethod::SHA256:
            return "SHA256";
        case EncryptionMethod::SHA512:
            return "SHA512";
        case EncryptionMethod::YESCRYPT:
            return "YESCRYPT";
        case EncryptionMethod::BCRYPT:
            return "BCRYPT";
    }
    throw std::invalid_argument("Unknown login.defs encryption method");
}

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
            // A hash after parser whitespace starts a trailing comment; an attached hash is part of the value.
            std::size_t valueEnd = end;
            for (std::size_t offset = valueStart; offset < end; ++offset)
            {
                if (('#' == input[offset]) && ((offset == valueStart) || IsSeparator(input[offset - 1])))
                {
                    valueEnd = offset;
                    break;
                }
            }
            if (valueStart == valueEnd)
            {
                return SyntaxError(document.source, lineNumber, valueStart - start + 1, "missing value");
            }
            const auto value = TrimWhiteSpaces(input.substr(valueStart, valueEnd - valueStart));
            // Shadow-utils duplicate precedence varies by backend; never assess a conflicting known value.
            if (key == "UID_MIN")
            {
                const auto parsed = TryStringToUint(value);
                if (!parsed.HasValue())
                {
                    return ValueError(document, lineNumber, valueStart - start + 1, key, parsed.Error());
                }
                if (parsed.Value() > std::numeric_limits<uid_t>::max())
                {
                    return ValueError(document, lineNumber, valueStart - start + 1, key, Error("Integer value out of uid_t range: " + value, ERANGE));
                }
                const auto uid = static_cast<uid_t>(parsed.Value());
                if (!firstOccurrence && document.uidMin.Value() != uid)
                {
                    return ConflictError(document, lineNumber, valueStart - start + 1, key);
                }
                if (firstOccurrence)
                {
                    document.uidMin = uid;
                }
            }
            else if (key == "PASS_MAX_DAYS" || key == "PASS_MIN_DAYS" || key == "PASS_WARN_AGE")
            {
                const auto parsed = TryStringToInt(value);
                if (!parsed.HasValue())
                {
                    return ValueError(document, lineNumber, valueStart - start + 1, key, parsed.Error());
                }
                auto& number = key == "PASS_MAX_DAYS" ? document.passMaxDays : key == "PASS_MIN_DAYS" ? document.passMinDays : document.passWarnAge;
                if (!firstOccurrence && number.Value() != parsed.Value())
                {
                    return ConflictError(document, lineNumber, valueStart - start + 1, key);
                }
                if (firstOccurrence)
                {
                    number = parsed.Value();
                }
            }
            else if (key == "ENCRYPT_METHOD")
            {
                const auto method = ParseEncryptionMethod(value);
                if (!method.HasValue())
                {
                    return ValueError(document, lineNumber, valueStart - start + 1, key, method.Error());
                }
                if (!firstOccurrence && document.encryptMethod.Value() != method.Value())
                {
                    return ConflictError(document, lineNumber, valueStart - start + 1, key);
                }
                if (firstOccurrence)
                {
                    document.encryptMethod = method.Value();
                }
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
