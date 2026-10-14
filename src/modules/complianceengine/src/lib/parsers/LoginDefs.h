// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_PARSERS_LOGIN_DEFS_H
#define COMPLIANCEENGINE_PARSERS_LOGIN_DEFS_H

#include <Logging.h>
#include <Optional.h>
#include <Result.h>
#include <cstddef>
#include <string>
#include <sys/types.h>

namespace ComplianceEngine
{
namespace LoginDefs
{
enum : std::size_t
{
    MaxBytes = 1024 * 1024,
    MaxLineBytes = 16 * 1024,
    MaxRecords = 8192
};

enum class EncryptionMethod
{
    DES,
    MD5,
    SHA256,
    SHA512,
    YESCRYPT,
    BCRYPT
};

struct Document
{
    std::string source;
    Optional<uid_t> uidMin;
    Optional<int> passMaxDays;
    Optional<int> passMinDays;
    Optional<int> passWarnAge;
    Optional<EncryptionMethod> encryptMethod;
};

Result<EncryptionMethod> ParseEncryptionMethod(const std::string& value);
const char* EncryptionMethodName(EncryptionMethod method);
// Error columns count bytes; lines and columns are 1-based.
// LF ends a physical line; a preceding CR remains in the raw value.
Result<Document> Parse(std::string bytes, std::string source, OsConfigLogHandle logHandle);
} // namespace LoginDefs
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_PARSERS_LOGIN_DEFS_H
