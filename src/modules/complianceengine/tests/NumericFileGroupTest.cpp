// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "MockContext.h"

#include <Evaluator.h>
#include <FilePermissions.h>
#include <JsonWrapper.h>
#include <Pattern.h>
#include <cerrno>
#include <fstream>
#include <gtest/gtest.h>
#include <map>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace
{
using namespace ComplianceEngine;

class NumericFileGroupTest : public ::testing::Test
{
protected:
    MockContext context;
    IndicatorsTree indicators;

    void SetUp() override
    {
        indicators.Push("FilePermissions");
    }

    static int DifferentGroup(int groupId)
    {
        return groupId == 0 ? 1 : 0;
    }
};

TEST_F(NumericFileGroupTest, DirectAuditComparesNumericIdWithoutNameLookup)
{
    const auto path = context.MakeTempfile("audit\n");
    struct stat file;
    ASSERT_EQ(0, stat(path.c_str(), &file));
    FilePermissionsParams params;
    params.path = path;
    params.groupId = static_cast<int>(file.st_gid);
    auto result = AuditFilePermissions(params, indicators, context);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());

    params.groupId = DifferentGroup(static_cast<int>(file.st_gid));
    result = AuditFilePermissions(params, indicators, context);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::NonCompliant, result.Value());

    params.groupId = 0;
    result = AuditFilePermissions(params, indicators, context);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(file.st_gid == 0 ? Status::Compliant : Status::NonCompliant, result.Value());

    params.path = context.GetTempdirPath() + "/absent";
    result = AuditFilePermissions(params, indicators, context);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::NonCompliant, result.Value());
}

TEST_F(NumericFileGroupTest, LiveLinkChecksTargetAndDanglingLinkFails)
{
    const auto target = context.MakeTempfile("audit\n");
    struct stat file;
    ASSERT_EQ(0, stat(target.c_str(), &file));
    const auto link = context.GetTempdirPath() + "/selected-link";
    ASSERT_EQ(0, symlink(target.c_str(), link.c_str()));
    FilePermissionsParams params;
    params.path = link;
    params.groupId = static_cast<int>(file.st_gid);
    auto result = AuditFilePermissions(params, indicators, context);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());

    ASSERT_EQ(0, unlink(target.c_str()));
    result = AuditFilePermissions(params, indicators, context);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::NonCompliant, result.Value());
}

TEST_F(NumericFileGroupTest, RejectsConflictingAndInvalidSelectorsBeforeStat)
{
    FilePermissionsParams params;
    params.path = context.GetTempdirPath() + "/absent";
    params.groupId = -1;
    auto result = AuditFilePermissions(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EINVAL, result.Error().code);

    params.groupId = 0;
    auto named = Pattern::Make("root");
    ASSERT_TRUE(named.HasValue());
    params.group = {{std::move(named.Value())}};
    result = AuditFilePermissions(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EINVAL, result.Error().code);
}

TEST_F(NumericFileGroupTest, NumericRemediationRejectsWithoutChangingFile)
{
    FilePermissionsParams params;
    params.path = context.MakeTempfile("audit\n");
    struct stat before;
    ASSERT_EQ(0, stat(params.path.c_str(), &before));
    params.groupId = DifferentGroup(static_cast<int>(before.st_gid));
    const auto result = RemediateFilePermissions(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(ENOTSUP, result.Error().code);
    struct stat after;
    ASSERT_EQ(0, stat(params.path.c_str(), &after));
    EXPECT_EQ(before.st_gid, after.st_gid);
    EXPECT_EQ(before.st_mode, after.st_mode);
}

TEST_F(NumericFileGroupTest, CollectionForwardsExactGroupEquality)
{
    const auto path = context.MakeTempfile("audit\n");
    struct stat file;
    ASSERT_EQ(0, stat(path.c_str(), &file));
    FilePermissionsCollectionParams params;
    params.directory = context.GetTempdirPath();
    params.filePattern = path.substr(path.find_last_of('/') + 1);
    params.recurse = false;
    params.groupId = static_cast<int>(file.st_gid);
    auto result = AuditFilePermissionsCollection(params, indicators, context);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());

    params.groupId = DifferentGroup(static_cast<int>(file.st_gid));
    result = AuditFilePermissionsCollection(params, indicators, context);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::NonCompliant, result.Value());

    params.maximumGid = static_cast<int>(file.st_gid);
    result = AuditFilePermissionsCollection(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EINVAL, result.Error().code);

    const auto remediation = RemediateFilePermissionsCollection(params, indicators, context);
    ASSERT_FALSE(remediation.HasValue());
    EXPECT_EQ(EINVAL, remediation.Error().code);
    params.maximumGid.Reset();
    const auto numericRemediation = RemediateFilePermissionsCollection(params, indicators, context);
    ASSERT_FALSE(numericRemediation.HasValue());
    EXPECT_EQ(ENOTSUP, numericRemediation.Error().code);
}

TEST_F(NumericFileGroupTest, SerializedNumericSelectorChecksGidZero)
{
    const auto selected = context.MakeTempfile("audit\n");
    struct stat file;
    ASSERT_EQ(0, stat(selected.c_str(), &file));
    const auto audit = JsonWrapper::FromString(R"({"FilePermissions":{"path":")" + selected + R"(","groupId":"0"}})");
    ASSERT_TRUE(audit.HasValue());
    DebugFormatter formatter;
    const ParameterMap parameters;
    Evaluator evaluator("numeric GID", json_value_get_object(audit->get()), parameters, context);
    const auto result = evaluator.ExecuteAudit(formatter);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(file.st_gid == 0 ? Status::Compliant : Status::NonCompliant, result.Value().status);
}

TEST_F(NumericFileGroupTest, SerializedNumericSelectorRejectsMalformedId)
{
    const auto selected = context.MakeTempfile("audit\n");
    const auto audit = JsonWrapper::FromString(R"({"FilePermissions":{"path":")" + selected + R"(","groupId":"0junk"}})");
    ASSERT_TRUE(audit.HasValue());
    DebugFormatter formatter;
    const ParameterMap parameters;
    Evaluator evaluator("malformed numeric GID", json_value_get_object(audit->get()), parameters, context);
    const auto result = evaluator.ExecuteAudit(formatter);
    ASSERT_FALSE(result.HasValue());
}

std::string AuditLogScript(const std::string& config, int groupId)
{
    return "local paths = {}\nfor line in io.lines('" + config + R"(') do
    local path = string.match(line, '^%s*log_file%s*=%s*(%S+)%s*$')
    if path == nil then
        path = string.match(line, '^%s*log_file%s*=%s*(%S+)%s+#.*$')
    end
    if path ~= nil then
        table.insert(paths, path)
    end
end
if #paths == 0 then
    return false, 'No log_file configured in )" +
           config + R"('
end
local compliant = true
local reason = nil
for _, path in ipairs(paths) do
    local status, message = ce.AuditFilePermissions({path = path, groupId = )" +
           std::to_string(groupId) + R"(})
    if not status then
        compliant = false
        reason = message
    end
end
return compliant, reason)";
}

class ComposedNumericFileGroupTest : public NumericFileGroupTest
{
protected:
    std::string config = context.GetTempdirPath() + "/auditd.conf";
    std::string selected;
    int selectedGid = 0;

    void SetUp() override
    {
        NumericFileGroupTest::SetUp();
        selected = context.MakeTempfile("audit\n");
        struct stat file;
        ASSERT_EQ(0, stat(selected.c_str(), &file));
        selectedGid = static_cast<int>(file.st_gid);
    }

    Result<AuditResult> Evaluate(int groupId)
    {
        // Mirror the M-14 YAML's two-child audit with a private config path.
        const auto serialized =
            R"({"allOf":[{"FileRegexMatch":{"path":")" + context.GetTempdirPath() +
            R"(","filenamePattern":"auditd\\.conf","matchPattern":"^\\s*log_group\\s*=\\s*(\\S+)\\s*(?:#.*)?$","statePattern":"^root$","allMatches":"True"}},{"Lua":{"script":""}}]})";
        auto audit = JsonWrapper::FromString(serialized);
        if (!audit.HasValue())
        {
            return audit.Error();
        }
        auto* children = json_object_get_array(json_value_get_object(audit->get()), "allOf");
        if (nullptr == children)
        {
            return Error("Missing audit children", EINVAL);
        }
        auto* child = json_array_get_object(children, 1);
        if (nullptr == child)
        {
            return Error("Missing Lua audit child", EINVAL);
        }
        auto* lua = json_object_get_object(child, "Lua");
        if (nullptr == lua)
        {
            return Error("Missing Lua audit child", EINVAL);
        }
        const auto script = AuditLogScript(config, groupId);
        if (JSONSuccess != json_object_set_string(lua, "script", script.c_str()))
        {
            return Error("Cannot set audit log script", EINVAL);
        }
        DebugFormatter formatter;
        const ParameterMap parameters;
        Evaluator evaluator("SV-270829", json_value_get_object(audit->get()), parameters, context);
        return evaluator.ExecuteAudit(formatter);
    }

    void ExpectStatus(const std::string& contents, int groupId, Status expected)
    {
        std::ofstream(config) << contents;
        const auto result = Evaluate(groupId);
        ASSERT_TRUE(result.HasValue()) << result.Error().message;
        EXPECT_EQ(expected, result.Value().status);
    }
};

TEST_F(ComposedNumericFileGroupTest, ConfigurationAndLiteralZeroGroup)
{
    // The first child prevents a missing or invalid setting from reaching Lua.
    const auto missing = Evaluate(selectedGid);
    ASSERT_TRUE(missing.HasValue()) << missing.Error().message;
    EXPECT_EQ(Status::NonCompliant, missing.Value().status);

    ExpectStatus("log_group = adm\nlog_file = " + selected + "\n", selectedGid, Status::NonCompliant);
    ExpectStatus("log_group = root\n", selectedGid, Status::NonCompliant);
    ExpectStatus("log_group = root\nlog_file = " + selected + "\n", selectedGid, Status::Compliant);
    ExpectStatus("log_group = root\nlog_file = " + selected + "\n", 0, 0 == selectedGid ? Status::Compliant : Status::NonCompliant);
    ExpectStatus("log_group = root\nlog_group = adm\nlog_file = " + selected + "\n", selectedGid, Status::NonCompliant);
    ExpectStatus("log_group = adm\nlog_group = root\nlog_file = " + selected + "\n", selectedGid, Status::NonCompliant);
}

TEST_F(ComposedNumericFileGroupTest, AuditsEverySelectedPathWithoutScanningSiblings)
{
    const auto other = context.MakeTempfile("unselected\n");
    struct stat otherStat;
    ASSERT_EQ(0, stat(other.c_str(), &otherStat));
    ExpectStatus("log_group = root\nlog_file = " + selected + "\nlog_file = " + selected + "\n", selectedGid, Status::Compliant);
    ExpectStatus("log_group = root\nlog_file = " + selected + "\nlog_file = " + other + "\n", selectedGid, Status::Compliant);
    const auto absent = context.GetTempdirPath() + "/absent";
    ExpectStatus("log_group = root\nlog_file = " + selected + "\nlog_file = " + absent + "\n", selectedGid, Status::NonCompliant);
    ExpectStatus("log_group = root\nlog_file = " + absent + "\nlog_file = " + selected + "\n", selectedGid, Status::NonCompliant);
}

TEST_F(ComposedNumericFileGroupTest, FollowsSelectedLinkAndPropagatesStatError)
{
    const auto link = context.GetTempdirPath() + "/selected-link";
    ASSERT_EQ(0, symlink(selected.c_str(), link.c_str()));
    ExpectStatus("log_group = root\nlog_file = " + link + "\n", selectedGid, Status::Compliant);

    const auto loop = context.GetTempdirPath() + "/selected-loop";
    ASSERT_EQ(0, symlink(loop.c_str(), loop.c_str()));
    std::ofstream(config) << "log_group = root\nlog_file = " << loop << "\n";
    const auto result = Evaluate(selectedGid);
    ASSERT_FALSE(result.HasValue());
    EXPECT_NE(std::string::npos, result.Error().message.find("Stat error"));
}
} // namespace
