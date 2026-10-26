// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <parsers/LoginDefs.h>

#include <Optional.h>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>

namespace
{
std::size_t maxObservedInputBytes = 0;

void ReportMaxObservedInput()
{
    if (std::fprintf(stderr, "MAX_OBSERVED_INPUT_BYTES=%zu\n", maxObservedInputBytes) < 0)
    {
        std::abort();
    }
}
} // namespace

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
    SetConsoleLoggingEnabled(false);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    static const int reportRegistration = std::atexit(ReportMaxObservedInput);
    if (reportRegistration != 0)
    {
        std::abort();
    }
    if (size > maxObservedInputBytes)
    {
        maxObservedInputBytes = size;
    }
    const std::string bytes = 0 == size ? std::string() : std::string(reinterpret_cast<const char*>(data), size);
    const auto first = ComplianceEngine::LoginDefs::Parse(bytes, "fuzz", nullptr);
    const auto second = ComplianceEngine::LoginDefs::Parse(bytes, "fuzz", nullptr);
    if (first.HasValue() != second.HasValue())
    {
        std::abort();
    }
    if (!first.HasValue())
    {
        if ((first.Error().code != second.Error().code) || (first.Error().message != second.Error().message))
        {
            std::abort();
        }
        return 0;
    }
    const auto& document = first.Value();
    const auto& repeated = second.Value();
    if ((document.source != repeated.source) || (bytes.find('\0') != std::string::npos))
    {
        std::abort();
    }
    const auto equalUid = [](const ComplianceEngine::Optional<uid_t>& left, const ComplianceEngine::Optional<uid_t>& right) {
        return left.HasValue() == right.HasValue() && (!left.HasValue() || left.Value() == right.Value());
    };
    const auto equalInt = [](const ComplianceEngine::Optional<int>& left, const ComplianceEngine::Optional<int>& right) {
        return left.HasValue() == right.HasValue() && (!left.HasValue() || left.Value() == right.Value());
    };
    const auto equalMethod = [](const ComplianceEngine::Optional<ComplianceEngine::LoginDefs::EncryptionMethod>& left,
                                 const ComplianceEngine::Optional<ComplianceEngine::LoginDefs::EncryptionMethod>& right) {
        return left.HasValue() == right.HasValue() && (!left.HasValue() || left.Value() == right.Value());
    };
    if (!equalUid(document.uidMin, repeated.uidMin) || !equalInt(document.passMaxDays, repeated.passMaxDays) ||
        !equalInt(document.passMinDays, repeated.passMinDays) || !equalInt(document.passWarnAge, repeated.passWarnAge) ||
        !equalMethod(document.encryptMethod, repeated.encryptMethod))
    {
        std::abort();
    }
    return 0;
}
