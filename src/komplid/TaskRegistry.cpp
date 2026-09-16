// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "TaskRegistry.hpp"

#include <sqlite3.h>

#include <cstdio>
#include <ctime>
#include <fcntl.h>
#include <unistd.h>

namespace Komplid
{
using ComplianceEngine::Error;
using ComplianceEngine::Optional;
using ComplianceEngine::Result;
using std::string;

namespace
{
constexpr const char* kSchema = R"sql(
CREATE TABLE IF NOT EXISTS tasks (
    task_id         TEXT PRIMARY KEY,
    benchmark       TEXT NOT NULL,
    rule_id         TEXT NOT NULL,
    mode            TEXT NOT NULL,
    parameters_key  TEXT NOT NULL,
    status          TEXT NOT NULL,
    result_json     TEXT,
    error_message   TEXT,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tasks_dedup
    ON tasks(benchmark, rule_id, mode, parameters_key, status);

CREATE TABLE IF NOT EXISTS audit_cache (
    benchmark       TEXT NOT NULL,
    rule_id         TEXT NOT NULL,
    parameters_key  TEXT NOT NULL,
    result_json     TEXT NOT NULL,
    audited_at      INTEGER NOT NULL,
    PRIMARY KEY (benchmark, rule_id, parameters_key)
);
)sql";

Optional<TaskStatus> ParseStatus(const string& status)
{
    if ("running" == status)
    {
        return TaskStatus::Running;
    }
    if ("done" == status)
    {
        return TaskStatus::Done;
    }
    if ("failed" == status)
    {
        return TaskStatus::Failed;
    }
    return Optional<TaskStatus>();
}

// 128 bits of randomness from /dev/urandom, hex-encoded. Uniqueness, not
// unguessability, is the actual requirement (task ids aren't a capability -
// SO_PEERCRED auth already gates the connection itself), but urandom is the
// simplest available source of collision-resistant bytes with no extra
// dependency.
Result<string> GenerateTaskId()
{
    unsigned char bytes[16];
    const int fd = ::open("/dev/urandom", O_RDONLY);
    if (fd < 0)
    {
        return Error("failed to open /dev/urandom for task id generation");
    }
    ssize_t total = 0;
    while (total < static_cast<ssize_t>(sizeof(bytes)))
    {
        const ssize_t n = ::read(fd, bytes + total, sizeof(bytes) - static_cast<size_t>(total));
        if (n <= 0)
        {
            ::close(fd);
            return Error("failed to read randomness for task id generation");
        }
        total += n;
    }
    ::close(fd);

    char hex[sizeof(bytes) * 2 + 1];
    for (size_t i = 0; i < sizeof(bytes); ++i)
    {
        std::snprintf(hex + (i * 2), 3, "%02x", bytes[i]);
    }
    return string(hex, sizeof(bytes) * 2);
}

// Thin RAII wrapper around sqlite3_stmt* so every early-return path still
// finalizes it.
class Statement
{
public:
    Statement(sqlite3* db, const char* sql)
    {
        sqlite3_prepare_v2(db, sql, -1, &mStmt, nullptr);
    }
    ~Statement()
    {
        sqlite3_finalize(mStmt);
    }
    Statement(const Statement&) = delete;
    Statement& operator=(const Statement&) = delete;

    sqlite3_stmt* get() const
    {
        return mStmt;
    }
    bool Valid() const
    {
        return nullptr != mStmt;
    }

private:
    sqlite3_stmt* mStmt = nullptr;
};

void BindText(sqlite3_stmt* stmt, int index, const string& value)
{
    sqlite3_bind_text(stmt, index, value.c_str(), -1, SQLITE_TRANSIENT);
}

} // namespace

string SerializeParametersKey(const std::map<string, string>& parameters)
{
    string key;
    for (const auto& entry : parameters)
    {
        key += entry.first;
        key += '\x1f';
        key += entry.second;
        key += '\x1e';
    }
    return key;
}

TaskRegistry::TaskRegistry(sqlite3* db)
    : mDb(db)
{
}

TaskRegistry::~TaskRegistry()
{
    if (nullptr != mDb)
    {
        sqlite3_close(mDb);
        mDb = nullptr;
    }
}

TaskRegistry::TaskRegistry(TaskRegistry&& other) noexcept
    : mDb(other.mDb)
{
    other.mDb = nullptr;
}

TaskRegistry& TaskRegistry::operator=(TaskRegistry&& other) noexcept
{
    if (this != &other)
    {
        if (nullptr != mDb)
        {
            sqlite3_close(mDb);
        }
        mDb = other.mDb;
        other.mDb = nullptr;
    }
    return *this;
}

Result<TaskRegistry> TaskRegistry::Open(const string& path)
{
    sqlite3* db = nullptr;
    // The file itself is created here if missing; ADR-0004's root:root 0600
    // ownership/mode comes from the daemon's process umask (see Main.cpp),
    // not from anything sqlite does.
    const int rc = sqlite3_open_v2(path.c_str(), &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr);
    if (SQLITE_OK != rc)
    {
        const string message = (nullptr != db) ? sqlite3_errmsg(db) : "unknown error";
        if (nullptr != db)
        {
            sqlite3_close(db);
        }
        return Error("failed to open task registry '" + path + "': " + message);
    }
    // Multiple `komplid` processes (Accept=yes) may open this file
    // concurrently; wait rather than fail immediately on a transient lock.
    sqlite3_busy_timeout(db, 5000);

    char* errMsg = nullptr;
    if (SQLITE_OK != sqlite3_exec(db, kSchema, nullptr, nullptr, &errMsg))
    {
        const string message = (nullptr != errMsg) ? errMsg : "unknown error";
        sqlite3_free(errMsg);
        sqlite3_close(db);
        return Error("failed to initialize task registry schema: " + message);
    }

    return Result<TaskRegistry>(TaskRegistry(db));
}

Result<Optional<string>> TaskRegistry::FindInFlightTask(const string& benchmark, const string& ruleId, const string& mode, const string& parametersKey)
{
    Statement stmt(mDb, "SELECT task_id FROM tasks WHERE benchmark = ?1 AND rule_id = ?2 AND mode = ?3 AND parameters_key = ?4 AND status = 'running' "
                        "LIMIT 1");
    if (!stmt.Valid())
    {
        return Error(string("failed to prepare task lookup: ") + sqlite3_errmsg(mDb));
    }
    BindText(stmt.get(), 1, benchmark);
    BindText(stmt.get(), 2, ruleId);
    BindText(stmt.get(), 3, mode);
    BindText(stmt.get(), 4, parametersKey);

    const int rc = sqlite3_step(stmt.get());
    if (SQLITE_ROW == rc)
    {
        const auto* text = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
        return Optional<string>(string(nullptr != text ? text : ""));
    }
    if (SQLITE_DONE == rc)
    {
        return Optional<string>();
    }
    return Error(string("failed to query in-flight task: ") + sqlite3_errmsg(mDb));
}

Result<string> TaskRegistry::CreateTask(const string& benchmark, const string& ruleId, const string& mode, const string& parametersKey)
{
    auto taskIdResult = GenerateTaskId();
    if (!taskIdResult.HasValue())
    {
        return taskIdResult.Error();
    }
    const string taskId = taskIdResult.Value();
    const long now = static_cast<long>(::time(nullptr));

    Statement stmt(mDb, "INSERT INTO tasks (task_id, benchmark, rule_id, mode, parameters_key, status, created_at, updated_at) "
                        "VALUES (?1, ?2, ?3, ?4, ?5, 'running', ?6, ?6)");
    if (!stmt.Valid())
    {
        return Error(string("failed to prepare task insert: ") + sqlite3_errmsg(mDb));
    }
    BindText(stmt.get(), 1, taskId);
    BindText(stmt.get(), 2, benchmark);
    BindText(stmt.get(), 3, ruleId);
    BindText(stmt.get(), 4, mode);
    BindText(stmt.get(), 5, parametersKey);
    sqlite3_bind_int64(stmt.get(), 6, now);

    if (SQLITE_DONE != sqlite3_step(stmt.get()))
    {
        return Error(string("failed to insert task: ") + sqlite3_errmsg(mDb));
    }
    return taskId;
}

Result<bool> TaskRegistry::CompleteTask(const string& taskId, const string& resultJson)
{
    Statement stmt(mDb, "UPDATE tasks SET status = 'done', result_json = ?1, updated_at = ?2 WHERE task_id = ?3");
    if (!stmt.Valid())
    {
        return Error(string("failed to prepare task completion: ") + sqlite3_errmsg(mDb));
    }
    BindText(stmt.get(), 1, resultJson);
    sqlite3_bind_int64(stmt.get(), 2, static_cast<long>(::time(nullptr)));
    BindText(stmt.get(), 3, taskId);

    if (SQLITE_DONE != sqlite3_step(stmt.get()))
    {
        return Error(string("failed to complete task: ") + sqlite3_errmsg(mDb));
    }
    return true;
}

Result<bool> TaskRegistry::FailTask(const string& taskId, const string& message)
{
    Statement stmt(mDb, "UPDATE tasks SET status = 'failed', error_message = ?1, updated_at = ?2 WHERE task_id = ?3");
    if (!stmt.Valid())
    {
        return Error(string("failed to prepare task failure update: ") + sqlite3_errmsg(mDb));
    }
    BindText(stmt.get(), 1, message);
    sqlite3_bind_int64(stmt.get(), 2, static_cast<long>(::time(nullptr)));
    BindText(stmt.get(), 3, taskId);

    if (SQLITE_DONE != sqlite3_step(stmt.get()))
    {
        return Error(string("failed to mark task failed: ") + sqlite3_errmsg(mDb));
    }
    return true;
}

Result<Optional<TaskRecord>> TaskRegistry::GetTask(const string& taskId)
{
    Statement stmt(mDb, "SELECT status, result_json, error_message FROM tasks WHERE task_id = ?1");
    if (!stmt.Valid())
    {
        return Error(string("failed to prepare task query: ") + sqlite3_errmsg(mDb));
    }
    BindText(stmt.get(), 1, taskId);

    const int rc = sqlite3_step(stmt.get());
    if (SQLITE_DONE == rc)
    {
        return Optional<TaskRecord>();
    }
    if (SQLITE_ROW != rc)
    {
        return Error(string("failed to query task: ") + sqlite3_errmsg(mDb));
    }

    const auto* statusText = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
    auto status = ParseStatus(string(nullptr != statusText ? statusText : ""));
    if (!status.HasValue())
    {
        return Error("task registry has an unrecognized status value for task '" + taskId + "'");
    }

    TaskRecord record;
    record.status = status.Value();
    const auto* resultText = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 1));
    if (nullptr != resultText)
    {
        record.resultJson = resultText;
    }
    const auto* errorText = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 2));
    if (nullptr != errorText)
    {
        record.errorMessage = errorText;
    }
    return Optional<TaskRecord>(std::move(record));
}

Result<Optional<string>> TaskRegistry::GetCachedAudit(const string& benchmark, const string& ruleId, const string& parametersKey, long ttlSeconds)
{
    Statement stmt(mDb, "SELECT result_json, audited_at FROM audit_cache WHERE benchmark = ?1 AND rule_id = ?2 AND parameters_key = ?3");
    if (!stmt.Valid())
    {
        return Error(string("failed to prepare audit-cache lookup: ") + sqlite3_errmsg(mDb));
    }
    BindText(stmt.get(), 1, benchmark);
    BindText(stmt.get(), 2, ruleId);
    BindText(stmt.get(), 3, parametersKey);

    const int rc = sqlite3_step(stmt.get());
    if (SQLITE_DONE == rc)
    {
        return Optional<string>();
    }
    if (SQLITE_ROW != rc)
    {
        return Error(string("failed to query audit cache: ") + sqlite3_errmsg(mDb));
    }

    const auto* resultText = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
    const long audited_at = sqlite3_column_int64(stmt.get(), 1);
    const long now = static_cast<long>(::time(nullptr));
    if (now - audited_at >= ttlSeconds)
    {
        // Expired: drop it opportunistically and report a miss.
        Statement del(mDb, "DELETE FROM audit_cache WHERE benchmark = ?1 AND rule_id = ?2 AND parameters_key = ?3");
        if (del.Valid())
        {
            BindText(del.get(), 1, benchmark);
            BindText(del.get(), 2, ruleId);
            BindText(del.get(), 3, parametersKey);
            sqlite3_step(del.get());
        }
        return Optional<string>();
    }

    return Optional<string>(string(nullptr != resultText ? resultText : ""));
}

Result<bool> TaskRegistry::UpsertCachedAudit(const string& benchmark, const string& ruleId, const string& parametersKey, const string& resultJson)
{
    Statement stmt(mDb, "INSERT INTO audit_cache (benchmark, rule_id, parameters_key, result_json, audited_at) VALUES (?1, ?2, ?3, ?4, ?5) "
                        "ON CONFLICT(benchmark, rule_id, parameters_key) DO UPDATE SET result_json = excluded.result_json, "
                        "audited_at = excluded.audited_at");
    if (!stmt.Valid())
    {
        return Error(string("failed to prepare audit-cache upsert: ") + sqlite3_errmsg(mDb));
    }
    BindText(stmt.get(), 1, benchmark);
    BindText(stmt.get(), 2, ruleId);
    BindText(stmt.get(), 3, parametersKey);
    BindText(stmt.get(), 4, resultJson);
    sqlite3_bind_int64(stmt.get(), 5, static_cast<long>(::time(nullptr)));

    if (SQLITE_DONE != sqlite3_step(stmt.get()))
    {
        return Error(string("failed to upsert audit cache: ") + sqlite3_errmsg(mDb));
    }
    return true;
}

Result<bool> TaskRegistry::InvalidateCachedAudits(const string& benchmark, const string& ruleId)
{
    Statement stmt(mDb, "DELETE FROM audit_cache WHERE benchmark = ?1 AND rule_id = ?2");
    if (!stmt.Valid())
    {
        return Error(string("failed to prepare audit-cache invalidation: ") + sqlite3_errmsg(mDb));
    }
    BindText(stmt.get(), 1, benchmark);
    BindText(stmt.get(), 2, ruleId);

    if (SQLITE_DONE != sqlite3_step(stmt.get()))
    {
        return Error(string("failed to invalidate audit cache: ") + sqlite3_errmsg(mDb));
    }
    return true;
}

Result<bool> TaskRegistry::CleanupOldTasks(long maxAgeSeconds)
{
    const long cutoff = static_cast<long>(::time(nullptr)) - maxAgeSeconds;
    Statement stmt(mDb, "DELETE FROM tasks WHERE status != 'running' AND updated_at < ?1");
    if (!stmt.Valid())
    {
        return Error(string("failed to prepare task cleanup: ") + sqlite3_errmsg(mDb));
    }
    sqlite3_bind_int64(stmt.get(), 1, cutoff);

    if (SQLITE_DONE != sqlite3_step(stmt.get()))
    {
        return Error(string("failed to clean up old tasks: ") + sqlite3_errmsg(mDb));
    }
    return true;
}

} // namespace Komplid
