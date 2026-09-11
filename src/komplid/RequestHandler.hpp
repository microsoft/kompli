// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef KOMPLID_REQUEST_HANDLER_HPP
#define KOMPLID_REQUEST_HANDLER_HPP

#include "Protocol.hpp"

#include <BenchmarkDefinition.hpp>
#include <DistributionInfo.h>
#include <Engine.h>
#include <map>
#include <string>

namespace Komplid
{
// Resolves and dispatches JSONL requests (see Protocol.hpp) against benchmark
// definitions under a fixed directory, through a shared Engine, for the
// lifetime of one connection (one process per connection, Accept=yes - see
// README.md). Not thread-safe; intended for use from a single-threaded read
// loop (Main.cpp).
class RequestHandler
{
public:
    // `engine` must outlive the handler. `definitionsDir` is the directory
    // benchmark files are resolved relative to (see README.md "Privilege
    // model" - normally /etc/kompli/definitions).
    RequestHandler(ComplianceEngine::Engine& engine, ComplianceEngine::DistributionInfo distributionInfo, std::string definitionsDir);

    // Parses and executes one JSONL request line, returning the JSONL
    // response line to write back (no trailing newline). Never throws: any
    // failure is reported as a "type":"error" response line rather than
    // propagated.
    std::string HandleLine(const std::string& line);

private:
    struct CachedBenchmark
    {
        ComplianceEngine::BenchmarkDefinition::BenchmarkDocument document;
        // Whether `document.benchmarkInfo` matches this host's distro/version -
        // computed once, at load time, since every rule in a file shares the
        // same file-level prefix.
        bool applicable;

        CachedBenchmark(ComplianceEngine::BenchmarkDefinition::BenchmarkDocument document, bool applicable)
            : document(std::move(document)),
              applicable(applicable)
        {
        }
    };

    // Outcome of resolving a `benchmark` name to a cached, parsed definition.
    // `benchmark` is null iff resolution failed, in which case errorCode/
    // errorMessage describe why; both are unused otherwise.
    struct ResolveOutcome
    {
        const CachedBenchmark* benchmark;
        ErrorCode errorCode;
        std::string errorMessage;

        ResolveOutcome(const CachedBenchmark* benchmark, ErrorCode errorCode, std::string errorMessage)
            : benchmark(benchmark),
              errorCode(errorCode),
              errorMessage(std::move(errorMessage))
        {
        }
    };

    ResolveOutcome ResolveBenchmark(const std::string& benchmark);
    std::string Dispatch(const Request& request);
    // Wraps BuildErrorResponse, falling back to a fixed literal line if
    // building the response itself fails (out-of-memory territory).
    std::string BuildError(const std::string& requestId, ErrorCode code, const std::string& message);

    ComplianceEngine::Engine& mEngine;
    ComplianceEngine::DistributionInfo mDistributionInfo;
    std::string mDefinitionsDir;
    std::map<std::string, CachedBenchmark> mCache;
};

} // namespace Komplid

#endif // KOMPLID_REQUEST_HANDLER_HPP
