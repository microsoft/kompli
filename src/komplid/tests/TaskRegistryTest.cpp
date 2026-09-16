// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <TaskRegistry.hpp>

#include <cstdlib>
#include <cstring>
#include <ftw.h>
#include <gtest/gtest.h>
#include <map>
#include <string>
#include <unistd.h>
#include <vector>

using ComplianceEngine::Optional;
using std::string;

namespace Komplid
{
namespace
{
// Respects $TMPDIR (falling back to /tmp) rather than hardcoding /tmp - see
// MockContext.h's known sandbox-write-blocked gotcha this deliberately
// avoids repeating.
string MakeTempDir()
{
    const char* base = std::getenv("TMPDIR");
    string tmpl = (nullptr != base && '\0' != base[0]) ? string(base) : string("/tmp");
    tmpl += "/komplid-task-registry-test.XXXXXX";
    std::vector<char> buffer(tmpl.begin(), tmpl.end());
    buffer.push_back('\0');
    const char* dir = ::mkdtemp(buffer.data());
    return (nullptr != dir) ? string(dir) : string();
}

int RemoveEntry(const char* path, const struct stat*, int, struct FTW*)
{
    return ::remove(path);
}

void RemoveTree(const string& path)
{
    ::nftw(path.c_str(), RemoveEntry, 16, FTW_DEPTH | FTW_PHYS);
}

class TaskRegistryTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        mTempDir = MakeTempDir();
        ASSERT_FALSE(mTempDir.empty());
        mDbPath = mTempDir + "/komplid.db";
    }

    void TearDown() override
    {
        RemoveTree(mTempDir);
    }

    string mTempDir;
    string mDbPath;
};

} // namespace

TEST(SerializeParametersKeyTest, EmptyMapProducesEmptyKey)
{
    EXPECT_EQ("", SerializeParametersKey({}));
}

TEST(SerializeParametersKeyTest, OrderIndependentOfInsertionOrder)
{
    std::map<string, string> a;
    a["b"] = "2";
    a["a"] = "1";
    std::map<string, string> b;
    b["a"] = "1";
    b["b"] = "2";
    EXPECT_EQ(SerializeParametersKey(a), SerializeParametersKey(b));
}

TEST(SerializeParametersKeyTest, DifferentValuesProduceDifferentKeys)
{
    std::map<string, string> a;
    a["package"] = "nginx";
    std::map<string, string> b;
    b["package"] = "apache2";
    EXPECT_NE(SerializeParametersKey(a), SerializeParametersKey(b));
}

TEST_F(TaskRegistryTest, OpenCreatesSchemaAndIsReopenable)
{
    auto openResult = TaskRegistry::Open(mDbPath);
    ASSERT_TRUE(openResult.HasValue());
    // Destructor closes the connection; reopening the same file must not fail.
    {
        auto registry = std::move(openResult.Value());
        (void)registry;
    }
    auto reopenResult = TaskRegistry::Open(mDbPath);
    EXPECT_TRUE(reopenResult.HasValue());
}

TEST_F(TaskRegistryTest, FindInFlightTaskMissesWhenNoneCreated)
{
    auto registry = TaskRegistry::Open(mDbPath).Value();
    auto result = registry.FindInFlightTask("b", "1.1", "audit", "");
    ASSERT_TRUE(result.HasValue());
    EXPECT_FALSE(result.Value().HasValue());
}

TEST_F(TaskRegistryTest, CreateTaskThenFindInFlightTaskMatches)
{
    auto registry = TaskRegistry::Open(mDbPath).Value();
    auto createResult = registry.CreateTask("b", "1.1", "audit", "");
    ASSERT_TRUE(createResult.HasValue());
    const string taskId = createResult.Value();
    EXPECT_FALSE(taskId.empty());

    auto findResult = registry.FindInFlightTask("b", "1.1", "audit", "");
    ASSERT_TRUE(findResult.HasValue());
    ASSERT_TRUE(findResult.Value().HasValue());
    EXPECT_EQ(taskId, findResult.Value().Value());
}

TEST_F(TaskRegistryTest, DifferentParametersKeyDoesNotDedup)
{
    auto registry = TaskRegistry::Open(mDbPath).Value();
    ASSERT_TRUE(registry.CreateTask("b", "1.1", "audit", "package=nginx").HasValue());

    auto findResult = registry.FindInFlightTask("b", "1.1", "audit", "package=apache2");
    ASSERT_TRUE(findResult.HasValue());
    EXPECT_FALSE(findResult.Value().HasValue());
}

TEST_F(TaskRegistryTest, CompleteTaskThenGetTaskReturnsDoneWithResult)
{
    auto registry = TaskRegistry::Open(mDbPath).Value();
    const string taskId = registry.CreateTask("b", "1.1", "audit", "").Value();

    ASSERT_TRUE(registry.CompleteTask(taskId, R"({"status":"compliant"})").HasValue());

    auto getResult = registry.GetTask(taskId);
    ASSERT_TRUE(getResult.HasValue());
    ASSERT_TRUE(getResult.Value().HasValue());
    EXPECT_EQ(TaskStatus::Done, getResult.Value().Value().status);
    EXPECT_EQ(R"({"status":"compliant"})", getResult.Value().Value().resultJson);
}

TEST_F(TaskRegistryTest, CompletedTaskNoLongerCountsAsInFlight)
{
    auto registry = TaskRegistry::Open(mDbPath).Value();
    const string taskId = registry.CreateTask("b", "1.1", "audit", "").Value();
    ASSERT_TRUE(registry.CompleteTask(taskId, "{}").HasValue());

    auto findResult = registry.FindInFlightTask("b", "1.1", "audit", "");
    ASSERT_TRUE(findResult.HasValue());
    EXPECT_FALSE(findResult.Value().HasValue());
}

TEST_F(TaskRegistryTest, FailTaskThenGetTaskReturnsFailedWithMessage)
{
    auto registry = TaskRegistry::Open(mDbPath).Value();
    const string taskId = registry.CreateTask("b", "1.1", "remediate", "").Value();

    ASSERT_TRUE(registry.FailTask(taskId, "engine exploded").HasValue());

    auto getResult = registry.GetTask(taskId);
    ASSERT_TRUE(getResult.HasValue());
    ASSERT_TRUE(getResult.Value().HasValue());
    EXPECT_EQ(TaskStatus::Failed, getResult.Value().Value().status);
    EXPECT_EQ("engine exploded", getResult.Value().Value().errorMessage);
}

TEST_F(TaskRegistryTest, GetTaskReturnsNoValueForUnknownId)
{
    auto registry = TaskRegistry::Open(mDbPath).Value();
    auto getResult = registry.GetTask("does-not-exist");
    ASSERT_TRUE(getResult.HasValue());
    EXPECT_FALSE(getResult.Value().HasValue());
}

TEST_F(TaskRegistryTest, AuditCacheMissWhenEmpty)
{
    auto registry = TaskRegistry::Open(mDbPath).Value();
    auto result = registry.GetCachedAudit("b", "1.1", "", 300);
    ASSERT_TRUE(result.HasValue());
    EXPECT_FALSE(result.Value().HasValue());
}

TEST_F(TaskRegistryTest, AuditCacheHitWithinTtl)
{
    auto registry = TaskRegistry::Open(mDbPath).Value();
    ASSERT_TRUE(registry.UpsertCachedAudit("b", "1.1", "", R"({"status":"compliant"})").HasValue());

    auto result = registry.GetCachedAudit("b", "1.1", "", 300);
    ASSERT_TRUE(result.HasValue());
    ASSERT_TRUE(result.Value().HasValue());
    EXPECT_EQ(R"({"status":"compliant"})", result.Value().Value());
}

TEST_F(TaskRegistryTest, AuditCacheMissWhenTtlAlreadyExpired)
{
    auto registry = TaskRegistry::Open(mDbPath).Value();
    ASSERT_TRUE(registry.UpsertCachedAudit("b", "1.1", "", "{}").HasValue());

    // A TTL of 0 means "already expired" (age >= ttl is always true for a
    // just-written entry with ttl=0).
    auto result = registry.GetCachedAudit("b", "1.1", "", 0);
    ASSERT_TRUE(result.HasValue());
    EXPECT_FALSE(result.Value().HasValue());
}

TEST_F(TaskRegistryTest, AuditCacheKeyedByParametersToo)
{
    auto registry = TaskRegistry::Open(mDbPath).Value();
    ASSERT_TRUE(registry.UpsertCachedAudit("b", "1.1", "package=nginx", R"({"v":1})").HasValue());

    auto sameParams = registry.GetCachedAudit("b", "1.1", "package=nginx", 300);
    ASSERT_TRUE(sameParams.HasValue() && sameParams.Value().HasValue());
    EXPECT_EQ(R"({"v":1})", sameParams.Value().Value());

    auto differentParams = registry.GetCachedAudit("b", "1.1", "package=apache2", 300);
    ASSERT_TRUE(differentParams.HasValue());
    EXPECT_FALSE(differentParams.Value().HasValue());
}

TEST_F(TaskRegistryTest, UpsertOverwritesExistingEntry)
{
    auto registry = TaskRegistry::Open(mDbPath).Value();
    ASSERT_TRUE(registry.UpsertCachedAudit("b", "1.1", "", R"({"v":1})").HasValue());
    ASSERT_TRUE(registry.UpsertCachedAudit("b", "1.1", "", R"({"v":2})").HasValue());

    auto result = registry.GetCachedAudit("b", "1.1", "", 300);
    ASSERT_TRUE(result.HasValue() && result.Value().HasValue());
    EXPECT_EQ(R"({"v":2})", result.Value().Value());
}

TEST_F(TaskRegistryTest, InvalidateCachedAuditsDropsAllParameterVariants)
{
    auto registry = TaskRegistry::Open(mDbPath).Value();
    ASSERT_TRUE(registry.UpsertCachedAudit("b", "1.1", "package=nginx", "{}").HasValue());
    ASSERT_TRUE(registry.UpsertCachedAudit("b", "1.1", "package=apache2", "{}").HasValue());
    ASSERT_TRUE(registry.UpsertCachedAudit("b", "1.2", "", "{}").HasValue());

    ASSERT_TRUE(registry.InvalidateCachedAudits("b", "1.1").HasValue());

    EXPECT_FALSE(registry.GetCachedAudit("b", "1.1", "package=nginx", 300).Value().HasValue());
    EXPECT_FALSE(registry.GetCachedAudit("b", "1.1", "package=apache2", 300).Value().HasValue());
    // A different rule id is untouched.
    EXPECT_TRUE(registry.GetCachedAudit("b", "1.2", "", 300).Value().HasValue());
}

TEST_F(TaskRegistryTest, CleanupOldTasksDropsOnlyOldCompletedRows)
{
    auto registry = TaskRegistry::Open(mDbPath).Value();
    const string doneTaskId = registry.CreateTask("b", "1.1", "audit", "").Value();
    ASSERT_TRUE(registry.CompleteTask(doneTaskId, "{}").HasValue());
    const string runningTaskId = registry.CreateTask("b", "1.2", "audit", "").Value();

    // A negative maxAgeSeconds pushes the cutoff into the future, so it
    // reliably catches the just-completed row regardless of same-second
    // clock granularity (avoids a flaky "updated_at < now" check racing
    // against a CompleteTask() that ran within the same second).
    ASSERT_TRUE(registry.CleanupOldTasks(-60).HasValue());

    EXPECT_FALSE(registry.GetTask(doneTaskId).Value().HasValue());
    ASSERT_TRUE(registry.GetTask(runningTaskId).Value().HasValue());
    EXPECT_EQ(TaskStatus::Running, registry.GetTask(runningTaskId).Value().Value().status);
}

} // namespace Komplid
