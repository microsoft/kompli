// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
//
// libFuzzer target for the benchmark-definition parser used by the kompli
// CLI and (in the future) komplid.
//
// Scope: parser only (BenchmarkDefinition::ParseString). The engine and
// procedure evaluation are intentionally out of scope — the goal is to ensure
// the parser is crash-free and bounded against adversarial input.
//
// Run:
//   ./benchmark-definition-fuzzer -max_total_time=60 seed_corpus/

#include "BenchmarkDefinition.hpp"

#include <cstddef>
#include <cstdint>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    if (size == 0)
    {
        return 0; // not interesting
    }

    try
    {
        std::string input(reinterpret_cast<const char*>(data), size);

        // Discard the result. We only care that the parser is crash-free and
        // that every error is surfaced as a Result<> rather than an exception or
        // undefined behaviour.
        auto result = ComplianceEngine::BenchmarkDefinition::ParseString(input, nullptr);
        (void)result;
    }
    catch (...)
    {
        // The parser must never throw. Surface any exception as a crash so
        // libFuzzer records the reproducer.
        __builtin_trap();
    }
    return 0;
}
