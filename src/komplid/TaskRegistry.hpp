// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef KOMPLID_TASK_REGISTRY_HPP
#define KOMPLID_TASK_REGISTRY_HPP

#include <Optional.h>
#include <Result.h>
#include <map>
#include <string>

struct sqlite3;

namespace Komplid
{
// Status of one row in the `tasks` table - see src/komplid/README.md
// "Long-running rules: background tasks".
enum class TaskStatus
{
    Running,
    Done,
    Failed
};

struct TaskRecord
{
    TaskStatus status = TaskStatus::Running;
    // Valid iff status == Done (the canonical per-rule result JSON, same
    // shape BuildResultResponse embeds).
    std::string resultJson;
    // Valid iff status == Failed.
    std::string errorMessage;
};

// Serializes a request's `parameters` map into a canonical, order-stable
// string key used both for background-task dedup and audit-cache lookups
// (see README.md "Duplicate concurrent requests" and "Result caching" -
// caching/dedup key on parameters, not just (benchmark, id, mode), since two
// different parameterizations of the same rule can legitimately produce
// different results). std::map already iterates in key order, so joining in
// iteration order is deterministic regardless of insertion order. `\x1f`/
// `\x1e` (ASCII unit/record separator) are used as delimiters since they
// cannot appear in a JSON string key or value read from the wire protocol.
std::string SerializeParametersKey(const std::map<std::string, std::string>& parameters);

// The SQLite-backed task registry + audit-result cache described in
// src/komplid/README.md ("Long-running rules: background tasks" and "Result
// caching"). Fixed path and ownership per ADR-0004
// (/var/lib/komplid/komplid.db, root:root 0600 - achieved via the daemon's
// process umask; see Main.cpp). Every `komplid` process (Accept=yes: one per
// connection) opens its own connection to the same file; SQLite's own
// file-locking serializes writes across them - no additional coordination is
// needed here. Not thread-safe (komplid is single-threaded per process).
class TaskRegistry
{
public:
    // Opens (creating if necessary) the database at `path` and ensures its
    // schema exists.
    static ComplianceEngine::Result<TaskRegistry> Open(const std::string& path);

    ~TaskRegistry();
    TaskRegistry(const TaskRegistry&) = delete;
    TaskRegistry& operator=(const TaskRegistry&) = delete;
    TaskRegistry(TaskRegistry&& other) noexcept;
    TaskRegistry& operator=(TaskRegistry&& other) noexcept;

    // Returns the task id of an already-`Running` task matching this exact
    // (benchmark, ruleId, mode, parametersKey), if any.
    ComplianceEngine::Result<ComplianceEngine::Optional<std::string>> FindInFlightTask(
        const std::string& benchmark, const std::string& ruleId, const std::string& mode, const std::string& parametersKey);

    // Creates a new `Running` task row and returns its generated id. Callers
    // must have already checked FindInFlightTask to avoid starting a
    // redundant duplicate.
    ComplianceEngine::Result<std::string> CreateTask(
        const std::string& benchmark, const std::string& ruleId, const std::string& mode, const std::string& parametersKey);

    ComplianceEngine::Result<bool> CompleteTask(const std::string& taskId, const std::string& resultJson);
    ComplianceEngine::Result<bool> FailTask(const std::string& taskId, const std::string& message);

    // No value means "no such task id" - RequestHandler turns that into an
    // UnknownTask error.
    ComplianceEngine::Result<ComplianceEngine::Optional<TaskRecord>> GetTask(const std::string& taskId);

    // Cached audit lookup. No value means either no entry, or an entry older
    // than `ttlSeconds` (which this also opportunistically deletes).
    ComplianceEngine::Result<ComplianceEngine::Optional<std::string>> GetCachedAudit(
        const std::string& benchmark, const std::string& ruleId, const std::string& parametersKey, long ttlSeconds);
    ComplianceEngine::Result<bool> UpsertCachedAudit(
        const std::string& benchmark, const std::string& ruleId, const std::string& parametersKey, const std::string& resultJson);
    // Drops every cached audit entry for (benchmark, ruleId), regardless of
    // parametersKey - see "Invalidation on remediation" in README.md: a
    // remediation can plausibly affect the result of any parameterization of
    // the same rule, not only the one just remediated with.
    ComplianceEngine::Result<bool> InvalidateCachedAudits(const std::string& benchmark, const std::string& ruleId);

    // Deletes Done/Failed task rows older than maxAgeSeconds. Not run
    // automatically; the daemon calls this opportunistically (see Main.cpp).
    ComplianceEngine::Result<bool> CleanupOldTasks(long maxAgeSeconds);

private:
    explicit TaskRegistry(sqlite3* db);
    sqlite3* mDb = nullptr;
};

} // namespace Komplid

#endif // KOMPLID_TASK_REGISTRY_HPP
