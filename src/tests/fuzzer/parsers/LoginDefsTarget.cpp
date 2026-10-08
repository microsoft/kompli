// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <parsers/LoginDefs.h>

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    const std::string bytes = 0 == size ? std::string() : std::string(reinterpret_cast<const char*>(data), size);
    const auto first = ComplianceEngine::LoginDefs::Parse(bytes, "fuzz");
    const auto second = ComplianceEngine::LoginDefs::Parse(bytes, "fuzz");
    if (first.HasValue() != second.HasValue())
    {
        std::abort();
    }
    if (!first.HasValue())
    {
        if (first.Error().code != second.Error().code)
        {
            std::abort();
        }
        return 0;
    }
    const auto& document = first.Value();
    const auto& repeated = second.Value();
    if ((document.records.size() != repeated.records.size()) || (document.diagnostics.size() != repeated.diagnostics.size()) ||
        (document.bytes != bytes))
    {
        std::abort();
    }
    std::size_t previous = 0;
    for (std::size_t i = 0; i < document.records.size(); ++i)
    {
        const auto& record = document.records[i];
        if ((record.lineSpan.offset < previous) || (record.lineSpan.offset > bytes.size()) ||
            (record.lineSpan.length > bytes.size() - record.lineSpan.offset) ||
            (record.keySpan.offset < record.lineSpan.offset) || (record.keySpan.offset > bytes.size()) ||
            (record.keySpan.offset > record.lineSpan.offset + record.lineSpan.length) ||
            (record.keySpan.length > bytes.size() - record.keySpan.offset) ||
            (record.keySpan.length > record.lineSpan.length - (record.keySpan.offset - record.lineSpan.offset)) ||
            (record.valueSpan.offset < record.keySpan.offset) || (record.valueSpan.offset > bytes.size()) ||
            (record.valueSpan.length > bytes.size() - record.valueSpan.offset) ||
            (record.valueSpan.offset > record.lineSpan.offset + record.lineSpan.length) ||
            (record.valueSpan.length > record.lineSpan.offset + record.lineSpan.length - record.valueSpan.offset) ||
            (record.key != repeated.records[i].key) ||
            (record.valueSpan.offset != repeated.records[i].valueSpan.offset))
        {
            std::abort();
        }
        previous = record.lineSpan.offset + record.lineSpan.length;
    }
    for (std::size_t i = 0; i < document.diagnostics.size(); ++i)
    {
        const auto& diagnostic = document.diagnostics[i];
        if ((diagnostic.span.offset > bytes.size()) ||
            (diagnostic.span.length > bytes.size() - diagnostic.span.offset) ||
            (diagnostic.kind != repeated.diagnostics[i].kind) ||
            (diagnostic.span.offset != repeated.diagnostics[i].span.offset))
        {
            std::abort();
        }
    }
    return 0;
}
