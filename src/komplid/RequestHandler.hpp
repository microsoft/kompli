// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef KOMPLID_REQUEST_HANDLER_HPP
#define KOMPLID_REQUEST_HANDLER_HPP

#include "Config.hpp"
#include "Protocol.hpp"
#include "TaskRegistry.hpp"

#include <BenchmarkDefinition.hpp>
#include <DistributionInfo.h>
#include <Engine.h>
#include <map>
#include <string>
#include <sys/types.h>

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
    // model" - normally /etc/kompli/definitions). `registry` is optional
    // (nullptr disables the audit-result cache and background-task
    // dispatch entirely, falling back to the original always-synchronous
    // behavior - used by callers, e.g. tests, that don't need either);
    // when non-null it must outlive the handler, same as `engine`.
    // `remediationLockPath` and `registryPath` are only used when `registry`
    // is non-null; `registryPath` is the filesystem path `registry` was
    // opened from - a background task forks and must open its own,
    // independent connection to the same file rather than sharing the
    // parent's (see BackgroundWorker.cpp).
    RequestHandler(ComplianceEngine::Engine& engine, ComplianceEngine::DistributionInfo distributionInfo, std::string definitionsDir,
        KompliConfig config = KompliConfig(), TaskRegistry* registry = nullptr, std::string registryPath = std::string(),
        std::string remediationLockPath = std::string());

    // Parses and executes one JSONL request line, returning the JSONL
    // response line to write back (no trailing newline). Never throws: any
    // failure is reported as a "type":"error" response line rather than
    // propagated. Also handles "check task" query lines (see
    // Protocol.hpp's IsTaskQuery).
    std::string HandleLine(const std::string& line);

    // A background task spawned by the most recent HandleLine() call, if
    // any - Main.cpp calls this right after HandleLine() to learn the child
    // pid to track (for SIGCHLD-driven completion delivery) alongside the
    // task id it belongs to. Returns no value if that call didn't spawn a
    // new background process (no eligible request, a dedup-attach to an
    // already in-flight task, or the registry is disabled). Clears the
    // pending value once read.
    struct SpawnedTask
    {
        pid_t pid;
        std::string taskId;
        // The requestId of the request that triggered this background task -
        // reused to correlate the later, unsolicited taskResult push back to
        // it (see the wire protocol envelope draft in README.md).
        std::string requestId;
    };
    ComplianceEngine::Optional<SpawnedTask> TakeLastSpawnedTask();

    // Outcome of the low-level per-rule dispatch, before it's wrapped into a
    // response envelope. Public (and DispatchCore below, public) so
    // BackgroundWorker.cpp - a separate translation unit representing the
    // forked child - can run the same per-rule logic and persist its raw
    // outcome into the task registry, instead of duplicating this logic or
    // going through the synchronous response-envelope path.
    struct DispatchOutcome
    {
        ComplianceEngine::Optional<ComplianceEngine::JsonWrapper> result;
        ErrorCode errorCode = ErrorCode::InternalError;
        std::string errorMessage;
    };

    // The actual per-rule work (resolve benchmark, run the Engine, build the
    // canonical result), without building a response envelope and without
    // taking the remediation lock itself - callers (DispatchSynchronously,
    // BackgroundWorker.cpp) are responsible for that, since the right
    // blocking behavior differs between them (see README.md "Remediation
    // locking still applies").
    DispatchOutcome DispatchCore(const Request& request);

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
    // Runs the synchronous path end to end: acquires the remediation lock
    // (non-blocking) if needed, calls DispatchCore, updates the audit cache,
    // and builds the response envelope.
    std::string DispatchSynchronously(const Request& request);
    std::string BuildResponseFromOutcome(const std::string& requestId, DispatchOutcome outcome);
    // Wraps BuildErrorResponse, falling back to a fixed literal line if
    // building the response itself fails (out-of-memory territory).
    std::string BuildError(const std::string& requestId, ErrorCode code, const std::string& message);

    // Returns a full response line if `request` (an Audit) was served from
    // the cache, or no value on a cache miss/disabled cache.
    ComplianceEngine::Optional<std::string> TryServeCachedAudit(const Request& request);
    // Returns a full response line ("task" ack, either a fresh task or an
    // attach to an existing in-flight one) if `request` was routed to the
    // background, or no value if it should run synchronously instead.
    ComplianceEngine::Optional<std::string> TryDispatchInBackground(const Request& request);
    // Upserts/invalidates the audit cache after a synchronous dispatch.
    void UpdateCacheAfterDispatch(const Request& request, const DispatchOutcome& outcome);
    std::string HandleTaskQuery(const std::string& line);

    ComplianceEngine::Engine& mEngine;
    ComplianceEngine::DistributionInfo mDistributionInfo;
    std::string mDefinitionsDir;
    std::map<std::string, CachedBenchmark> mCache;

    KompliConfig mConfig;
    TaskRegistry* mRegistry;
    std::string mRegistryPath;
    std::string mRemediationLockPath;
    ComplianceEngine::Optional<SpawnedTask> mLastSpawned;
};

} // namespace Komplid

#endif // KOMPLID_REQUEST_HANDLER_HPP
