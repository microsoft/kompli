// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "Evaluator.h"

#include "JsonWrapper.h"
#include "MockContext.h"
#include "parson.h"

#include <UserDotFilePermissions.h>
#include <UserHomeDirectoryPermissions.h>
#include <UserPermissionsTestSeams.h>
#include <cerrno>
#include <dirent.h>
#include <fstream>
#include <grp.h>
#include <gtest/gtest.h>
#include <limits>
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

using ComplianceEngine::action_func_t;
using ComplianceEngine::Error;
using ComplianceEngine::Evaluator;
using ComplianceEngine::JsonWrapper;
using ComplianceEngine::Result;
using ComplianceEngine::Status;

class EvaluatorTest : public ::testing::Test
{
protected:
    std::map<std::string, std::string> mParameters;
    MockContext mContext;
    ComplianceEngine::DebugFormatter mFormatter;
};

TEST_F(EvaluatorTest, Contructor)
{
    Evaluator evaluator("test", nullptr, mParameters, mContext);
    auto auditResult = evaluator.ExecuteAudit(mFormatter);
    ASSERT_FALSE(auditResult);
    ASSERT_EQ(auditResult.Error().message, std::string("invalid json argument"));
    auto remediationResult = evaluator.ExecuteRemediation();
    ASSERT_FALSE(remediationResult);
    ASSERT_EQ(remediationResult.Error().message, std::string("invalid json argument"));
}

TEST_F(EvaluatorTest, ExecuteAudit_InvalidJSON_1)
{
    auto json = JsonWrapper::FromString("{}");
    ASSERT_TRUE(json.HasValue());
    ASSERT_TRUE(json->get());
    Evaluator evaluator("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator.ExecuteAudit(mFormatter);
    ASSERT_FALSE(result);
    ASSERT_EQ(result.Error().message, std::string("Rule name or value is null"));
}

TEST_F(EvaluatorTest, ExecuteAudit_InvalidJSON_2)
{
    auto json = JsonWrapper::FromString("{\"anyOf\":null}");
    ASSERT_TRUE(json.HasValue());
    ASSERT_TRUE(json->get());
    Evaluator evaluator1("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator1.ExecuteAudit(mFormatter);
    ASSERT_FALSE(result);
    ASSERT_EQ(result.Error().message, std::string("anyOf value is not an array"));

    json = JsonWrapper::FromString("{\"anyOf\":{}}");
    ASSERT_TRUE(json.HasValue());
    ASSERT_TRUE(json->get());
    Evaluator evaluator2("test", json_value_get_object(json->get()), mParameters, mContext);
    result = evaluator2.ExecuteAudit(mFormatter);
    ASSERT_FALSE(result);
    ASSERT_EQ(result.Error().message, std::string("anyOf value is not an array"));
}

TEST_F(EvaluatorTest, ExecuteAudit_InvalidJSON_3)
{
    auto json = JsonWrapper::FromString("{\"allOf\":1234}");
    ASSERT_TRUE(json.HasValue());
    ASSERT_TRUE(json->get());
    Evaluator evaluator1("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator1.ExecuteAudit(mFormatter);
    ASSERT_FALSE(result);
    ASSERT_EQ(result.Error().message, std::string("allOf value is not an array"));

    json = JsonWrapper::FromString("{\"allOf\":{}}");
    ASSERT_TRUE(json.HasValue());
    ASSERT_TRUE(json->get());
    Evaluator evaluator2("test", json_value_get_object(json->get()), mParameters, mContext);
    result = evaluator2.ExecuteAudit(mFormatter);
    ASSERT_FALSE(result);
    ASSERT_EQ(result.Error().message, std::string("allOf value is not an array"));
}

TEST_F(EvaluatorTest, ExecuteAudit_InvalidJSON_4)
{
    auto json = JsonWrapper::FromString("{\"not\":\"foo\"}");
    ASSERT_TRUE(json.HasValue());
    ASSERT_TRUE(json->get());
    Evaluator evaluator1("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator1.ExecuteAudit(mFormatter);
    ASSERT_FALSE(result);
    ASSERT_EQ(result.Error().message, std::string("not value is not an object"));

    json = JsonWrapper::FromString("{\"not\":[]}");
    ASSERT_TRUE(json.HasValue());
    ASSERT_TRUE(json->get());
    Evaluator evaluator2("test", json_value_get_object(json->get()), mParameters, mContext);
    result = evaluator2.ExecuteAudit(mFormatter);
    ASSERT_FALSE(result);
    ASSERT_EQ(result.Error().message, std::string("not value is not an object"));
}

TEST_F(EvaluatorTest, ExecuteAudit_1)
{
    auto json = JsonWrapper::FromString("{\"allOf\":[]}");
    ASSERT_TRUE(json.HasValue());
    ASSERT_TRUE(json->get());
    Evaluator evaluator1("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator1.ExecuteAudit(mFormatter);
    ASSERT_TRUE(result);
    EXPECT_EQ(result.Value().status, Status::Compliant);
}

TEST_F(EvaluatorTest, ExecuteAudit_2)
{
    auto json = JsonWrapper::FromString("{\"allOf\":[{\"foo\":{}}]}");
    ASSERT_TRUE(json.HasValue());
    ASSERT_TRUE(json->get());
    Evaluator evaluator1("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator1.ExecuteAudit(mFormatter);
    ASSERT_FALSE(result);
    ASSERT_EQ(result.Error().message, std::string("Unknown function 'foo'"));
}

TEST_F(EvaluatorTest, ExecuteAudit_3)
{
    auto json = JsonWrapper::FromString("{\"allOf\":[{\"AuditSuccess\":{}}]}");
    ASSERT_TRUE(json.HasValue());
    ASSERT_TRUE(json->get());
    Evaluator evaluator1("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator1.ExecuteAudit(mFormatter);
    ASSERT_TRUE(result);
    EXPECT_EQ(result.Value().status, Status::Compliant);
}

TEST_F(EvaluatorTest, ExecuteAudit_4)
{
    auto json = JsonWrapper::FromString("{\"allOf\":[{\"AuditFailure\":{}}]}");
    ASSERT_TRUE(json.HasValue());
    ASSERT_TRUE(json->get());
    Evaluator evaluator1("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator1.ExecuteAudit(mFormatter);
    ASSERT_TRUE(result);
    EXPECT_EQ(result.Value().status, Status::NonCompliant);
}

TEST_F(EvaluatorTest, ExecuteAudit_5)
{
    auto json = JsonWrapper::FromString("{\"anyOf\":[{\"AuditFailure\":{}}, {\"AuditSuccess\":{}}]}");
    ASSERT_TRUE(json.HasValue());
    ASSERT_TRUE(json->get());
    Evaluator evaluator1("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator1.ExecuteAudit(mFormatter);
    ASSERT_TRUE(result);
    EXPECT_EQ(result.Value().status, Status::Compliant);
}

TEST_F(EvaluatorTest, ExecuteAudit_6)
{
    auto json = JsonWrapper::FromString("{\"anyOf\":[{\"AuditSuccess\":{}}, {\"AuditFailure\":{}}]}");
    ASSERT_TRUE(json.HasValue());
    ASSERT_TRUE(json->get());
    Evaluator evaluator1("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator1.ExecuteAudit(mFormatter);
    ASSERT_TRUE(result);
    EXPECT_EQ(result.Value().status, Status::Compliant);
}

TEST_F(EvaluatorTest, ExecuteAudit_7)
{
    auto json = JsonWrapper::FromString("{\"allOf\":[{\"AuditFailure\":{}}, {\"AuditSuccess\":{}}]}");
    ASSERT_TRUE(json.HasValue());
    ASSERT_TRUE(json->get());
    Evaluator evaluator1("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator1.ExecuteAudit(mFormatter);
    ASSERT_TRUE(result);
    EXPECT_EQ(result.Value().status, Status::NonCompliant);
}

TEST_F(EvaluatorTest, ExecuteAudit_8)
{
    auto json = JsonWrapper::FromString("{\"allOf\":[{\"AuditSuccess\":{}}, {\"AuditFailure\":{}}]}");
    ASSERT_TRUE(json.HasValue());
    ASSERT_TRUE(json->get());
    Evaluator evaluator1("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator1.ExecuteAudit(mFormatter);
    ASSERT_TRUE(result);
    EXPECT_EQ(result.Value().status, Status::NonCompliant);
}

TEST_F(EvaluatorTest, ExecuteAudit_9)
{
    auto json = JsonWrapper::FromString("{\"not\":{\"AuditSuccess\":{}}}");
    ASSERT_TRUE(json.HasValue());
    ASSERT_TRUE(json->get());
    Evaluator evaluator1("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator1.ExecuteAudit(mFormatter);
    ASSERT_TRUE(result);
    EXPECT_EQ(result.Value().status, Status::NonCompliant);
}

TEST_F(EvaluatorTest, ExecuteAudit_10)
{
    auto json = JsonWrapper::FromString("{\"not\":{\"AuditFailure\":{}}}");
    ASSERT_TRUE(json.HasValue());
    ASSERT_TRUE(json->get());
    Evaluator evaluator1("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator1.ExecuteAudit(mFormatter);
    ASSERT_TRUE(result);
    EXPECT_EQ(result.Value().status, Status::Compliant);
}

TEST_F(EvaluatorTest, ExecuteAudit_11)
{
    auto json = JsonWrapper::FromString("{\"not\":{\"not\":{\"AuditFailure\":{}}}}");
    ASSERT_TRUE(json.HasValue());
    ASSERT_TRUE(json->get());
    Evaluator evaluator1("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator1.ExecuteAudit(mFormatter);
    ASSERT_TRUE(result);
    EXPECT_EQ(result.Value().status, Status::NonCompliant);
}

TEST_F(EvaluatorTest, ExecuteAudit_12)
{
    auto json = JsonWrapper::FromString("{\"allOf\":[{\"foo\":[]}]}");
    ASSERT_TRUE(json.HasValue());
    ASSERT_TRUE(json->get());
    Evaluator evaluator1("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator1.ExecuteAudit(mFormatter);
    ASSERT_FALSE(result);
    ASSERT_EQ(result.Error().message, std::string("invalid argument"));
}

TEST_F(EvaluatorTest, ReachedFileRegexErrorSurvivesRuleOperators)
{
    const auto filename = mContext.GetTempdirPath() + "/result-evaluation.txt";
    std::ofstream(filename) << "key=ok\n";
    const std::string leaf =
        "{\"FileRegexMatch\":{\"path\":\"" + mContext.GetTempdirPath() + "\",\"filenamePattern\":\"result-evaluation.txt\",\"matchPattern\":\"(?i)\"}}";
    const std::vector<std::string> expressions = {
        "{\"not\":" + leaf + "}",
        "{\"allOf\":[{\"AuditSuccess\":{}}," + leaf + "]}",
        "{\"anyOf\":[" + leaf + ",{\"AuditSuccess\":{}}]}",
        "{\"allOf\":[{\"AuditSuccess\":{}},{\"not\":" + leaf + "}]}",
    };
    for (const auto& expression : expressions)
    {
        auto json = JsonWrapper::FromString(expression);
        ASSERT_TRUE(json.HasValue()) << expression;
        Evaluator evaluator("test", json_value_get_object(json->get()), mParameters, mContext);
        const auto result = evaluator.ExecuteAudit(mFormatter);
        ASSERT_FALSE(result.HasValue()) << expression;
        EXPECT_EQ(EINVAL, result.Error().code) << expression;
    }
    auto json = JsonWrapper::FromString("{\"anyOf\":[{\"AuditSuccess\":{}}," + leaf + "]}");
    ASSERT_TRUE(json.HasValue());
    Evaluator evaluator("test", json_value_get_object(json->get()), mParameters, mContext);
    const auto result = evaluator.ExecuteAudit(mFormatter);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value().status);
}

TEST_F(EvaluatorTest, SerializedRegexSelectionAndBehaviorReachNativeHandler)
{
    const auto filename = mContext.GetTempdirPath() + "/result-evaluation.conf";
    std::ofstream(filename) << "key=ok\n";
    const std::string arguments = "\"path\":\"" + mContext.GetTempdirPath() +
                                  "\",\"filenamePattern\":\"\\\\.conf$\",\"filenameSearch\":\"true\","
                                  "\"matchPattern\":\"^key=(.*)$\",\"statePattern\":\"^forbidden$\",\"noneMatches\":\"true\"";
    auto json = JsonWrapper::FromString("{\"FileRegexMatch\":{" + arguments + ",\"behavior\":\"at_least_one_exists\"}}");
    ASSERT_TRUE(json.HasValue());
    Evaluator evaluator("test", json_value_get_object(json->get()), mParameters, mContext);
    auto result = evaluator.ExecuteAudit(mFormatter);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value().status);

    std::ofstream(filename) << "key=forbidden\n";
    Evaluator forbiddenEvaluator("test", json_value_get_object(json->get()), mParameters, mContext);
    result = forbiddenEvaluator.ExecuteAudit(mFormatter);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::NonCompliant, result.Value().status);

    auto invalid = JsonWrapper::FromString("{\"FileRegexMatch\":{" + arguments + ",\"behavior\":\"invalid\"}}");
    ASSERT_TRUE(invalid.HasValue());
    Evaluator invalidEvaluator("test", json_value_get_object(invalid->get()), mParameters, mContext);
    EXPECT_FALSE(invalidEvaluator.ExecuteAudit(mFormatter).HasValue());

    std::ofstream(filename) << "key=forbidden\nkey=ok\n";
    const std::string allArguments = "\"path\":\"" + mContext.GetTempdirPath() +
                                     "\",\"filenamePattern\":\"\\\\.conf$\",\"filenameSearch\":\"true\","
                                     "\"matchPattern\":\"^key=(.*)$\",\"statePattern\":\"^forbidden$\","
                                     "\"allMatches\":\"true\",\"behavior\":\"at_least_one_exists\"";
    auto all = JsonWrapper::FromString("{\"FileRegexMatch\":{" + allArguments + "}}");
    ASSERT_TRUE(all.HasValue());
    Evaluator allEvaluator("test", json_value_get_object(all->get()), mParameters, mContext);
    const auto allResult = allEvaluator.ExecuteAudit(mFormatter);
    ASSERT_TRUE(allResult.HasValue());
    EXPECT_EQ(Status::NonCompliant, allResult.Value().status);
}

TEST_F(EvaluatorTest, SerializedCollectionRegexSelectsOnlyMatchingFilenames)
{
    const auto directory = mContext.GetTempdirPath() + "/result-evaluation";
    ASSERT_EQ(0, mkdir(directory.c_str(), 0700));
    std::ofstream(directory + "/selected.conf") << "value\n";
    const std::string arguments = "\"directory\":\"" + directory +
                                  "\",\"filePattern\":\".*\\\\.conf\",\"filePatternIsRegex\":\"true\","
                                  "\"behavior\":\"at_least_one_exists\"";
    auto json = JsonWrapper::FromString("{\"FilePermissionsCollection\":{" + arguments + "}}");
    ASSERT_TRUE(json.HasValue());
    Evaluator evaluator("test", json_value_get_object(json->get()), mParameters, mContext);
    const auto result = evaluator.ExecuteAudit(mFormatter);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value().status);

    auto unselected = JsonWrapper::FromString("{\"FilePermissionsCollection\":{\"directory\":\"" + directory +
                                              "\",\"filePattern\":\".*\\\\.txt\",\"filePatternIsRegex\":\"true\","
                                              "\"behavior\":\"at_least_one_exists\"}}");
    ASSERT_TRUE(unselected.HasValue());
    Evaluator unselectedEvaluator("test", json_value_get_object(unselected->get()), mParameters, mContext);
    const auto absent = unselectedEvaluator.ExecuteAudit(mFormatter);
    ASSERT_TRUE(absent.HasValue());
    EXPECT_EQ(Status::NonCompliant, absent.Value().status);
}

TEST_F(EvaluatorTest, SubstitutedLogfileRootRejectsRelativeInputWithoutComplianceVerdict)
{
    mContext.SetSpecialFilePath("/etc/shells", mContext.MakeTempfile("/bin/sh\n"));
    mContext.SetSpecialFilePath("/etc/passwd", mContext.MakeTempfile("root:x:0:0:root:/root:/bin/sh\n"));
    auto json = JsonWrapper::FromString("{\"LogFilePermissions\":{\"path\":\"$logRoot\"}}");
    ASSERT_TRUE(json.HasValue());
    mParameters["logRoot"] = ".";
    for (bool remediate : {false, true})
    {
        Evaluator evaluator("test", json_value_get_object(json->get()), mParameters, mContext);
        if (remediate)
        {
            const auto result = evaluator.ExecuteRemediation();
            ASSERT_FALSE(result.HasValue());
            EXPECT_EQ(EINVAL, result.Error().code);
            EXPECT_EQ("Filesystem collection root path must be absolute", result.Error().message);
        }
        else
        {
            const auto result = evaluator.ExecuteAudit(mFormatter);
            ASSERT_FALSE(result.HasValue());
            EXPECT_EQ(EINVAL, result.Error().code);
            EXPECT_EQ("Filesystem collection root path must be absolute", result.Error().message);
        }
    }
}

TEST_F(EvaluatorTest, ExecuteRemediation_1)
{
    auto json = JsonWrapper::FromString("{\"allOf\":[]}");
    ASSERT_TRUE(json.HasValue());
    ASSERT_TRUE(json->get());
    Evaluator evaluator1("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator1.ExecuteRemediation();
    ASSERT_TRUE(result);
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EvaluatorTest, ExecuteRemediation_2)
{
    auto json = JsonWrapper::FromString("{\"anyOf\":[]}");
    ASSERT_TRUE(json.HasValue());
    ASSERT_TRUE(json->get());
    Evaluator evaluator1("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator1.ExecuteRemediation();
    ASSERT_TRUE(result);
    EXPECT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EvaluatorTest, ExecuteRemediation_3)
{
    auto json = JsonWrapper::FromString("{\"allOf\":[{\"RemediationSuccess\":{}}]}");
    ASSERT_TRUE(json.HasValue());
    ASSERT_TRUE(json->get());
    Evaluator evaluator1("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator1.ExecuteRemediation();
    ASSERT_TRUE(result);
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EvaluatorTest, ExecuteRemediation_4)
{
    auto json = JsonWrapper::FromString("{\"anyOf\":[{\"RemediationSuccess\":{}}]}");
    ASSERT_TRUE(json.HasValue());
    ASSERT_TRUE(json->get());
    Evaluator evaluator1("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator1.ExecuteRemediation();
    ASSERT_TRUE(result);
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EvaluatorTest, ExecuteRemediation_5)
{
    auto json = JsonWrapper::FromString("{\"anyOf\":[{\"RemediationFailure\":{}}, {\"RemediationSuccess\":{}}]}");
    ASSERT_TRUE(json.HasValue());
    ASSERT_TRUE(json->get());
    Evaluator evaluator1("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator1.ExecuteRemediation();
    ASSERT_TRUE(result);
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EvaluatorTest, ExecuteRemediation_6)
{
    auto json = JsonWrapper::FromString("{\"anyOf\":[{\"RemediationSuccess\":{}}, {\"RemediationFailure\":{}}]}");
    ASSERT_TRUE(json.HasValue());
    ASSERT_TRUE(json->get());
    Evaluator evaluator1("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator1.ExecuteRemediation();
    ASSERT_TRUE(result);
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EvaluatorTest, ExecuteRemediation_7)
{
    auto json = JsonWrapper::FromString("{\"allOf\":[{\"RemediationFailure\":{}}, {\"RemediationSuccess\":{}}]}");
    ASSERT_TRUE(json.HasValue());
    ASSERT_TRUE(json->get());
    Evaluator evaluator1("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator1.ExecuteRemediation();
    ASSERT_TRUE(result);
    EXPECT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EvaluatorTest, ExecuteRemediation_8)
{
    auto json = JsonWrapper::FromString("{\"allOf\":[{\"RemediationSuccess\":{}}, {\"RemediationFailure\":{}}]}");
    ASSERT_TRUE(json.HasValue());
    ASSERT_TRUE(json->get());
    Evaluator evaluator1("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator1.ExecuteRemediation();
    ASSERT_TRUE(result);
    EXPECT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EvaluatorTest, ExecuteRemediation_9)
{
    auto json = JsonWrapper::FromString("{\"not\":{\"RemediationSuccess\":{}}}");
    ASSERT_TRUE(json.HasValue());
    ASSERT_TRUE(json->get());
    Evaluator evaluator1("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator1.ExecuteRemediation();
    ASSERT_FALSE(result);
}

TEST_F(EvaluatorTest, ExecuteAudit_ProcedureMising_1)
{
    auto json = JsonWrapper::FromString("{\"anyOf\":[{\"RemediationSuccess\":{}}, {\"AuditFailure\":{}}]}");
    ASSERT_TRUE(json.HasValue());
    ASSERT_TRUE(json->get());
    Evaluator evaluator1("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator1.ExecuteAudit(mFormatter);
    ASSERT_FALSE(result);
}

TEST_F(EvaluatorTest, ExecuteAudit_ProcedureMising_2)
{
    auto json = JsonWrapper::FromString("{\"anyOf\":[{\"AuditFailure\":{}}, {\"RemediationSuccess\":{}}]}");
    ASSERT_TRUE(json.HasValue());
    ASSERT_TRUE(json->get());
    Evaluator evaluator1("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator1.ExecuteAudit(mFormatter);
    ASSERT_FALSE(result);
}

TEST_F(EvaluatorTest, ExecuteAudit_ProcedureMising_3)
{
    auto json = JsonWrapper::FromString("{\"anyOf\":[{\"AuditSuccess\":{}}, {\"RemediationSuccess\":{}}]}");
    ASSERT_TRUE(json.HasValue());
    ASSERT_TRUE(json->get());
    Evaluator evaluator1("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator1.ExecuteAudit(mFormatter);
    ASSERT_TRUE(result);
    EXPECT_EQ(result.Value().status, Status::Compliant);
}

TEST_F(EvaluatorTest, ExecuteRemediation_ProcedureMising_1)
{
    auto json = JsonWrapper::FromString("{\"anyOf\":[{\"foo\":{}}, {\"RemediationFailure\":{}}]}");
    ASSERT_TRUE(json.HasValue());
    ASSERT_TRUE(json->get());
    Evaluator evaluator1("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator1.ExecuteRemediation();
    ASSERT_FALSE(result);
}

TEST_F(EvaluatorTest, ExecuteRemediation_ProcedureMising_2)
{
    auto json = JsonWrapper::FromString("{\"anyOf\":[{\"RemediationSuccess\":{}}, {\"foo\":{}}]}");
    ASSERT_TRUE(json.HasValue());
    ASSERT_TRUE(json->get());
    Evaluator evaluator1("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator1.ExecuteRemediation();
    ASSERT_TRUE(result);
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EvaluatorTest, ExecuteRemediation_AuditFallback_1)
{
    auto json = JsonWrapper::FromString("{\"anyOf\":[{\"RemediationFailure\":{}}, {\"AuditSuccess\":{}}]}");
    ASSERT_TRUE(json.HasValue());
    ASSERT_TRUE(json->get());
    Evaluator evaluator1("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator1.ExecuteRemediation();
    ASSERT_TRUE(result);
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EvaluatorTest, ExecuteRemediation_AuditFallback_2)
{
    auto json = JsonWrapper::FromString("{\"anyOf\":[{\"RemediationFailure\":{}}, {\"AuditFailure\":{}}]}");
    ASSERT_TRUE(json.HasValue());
    ASSERT_TRUE(json->get());
    Evaluator evaluator1("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator1.ExecuteRemediation();
    ASSERT_TRUE(result);
    EXPECT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EvaluatorTest, ExecuteRemediation_Parameters_1)
{
    auto json = JsonWrapper::FromString("{\"anyOf\":[{\"RemediationParametrized\":{\"foo\":\"bar\"}}]}");
    ASSERT_TRUE(json.HasValue());
    ASSERT_TRUE(json->get());
    Evaluator evaluator1("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator1.ExecuteRemediation();
    ASSERT_FALSE(result);
    EXPECT_EQ(result.Error().message, std::string("Unknown parameter 'foo'"));
}

TEST_F(EvaluatorTest, ExecuteRemediation_Parameters_2)
{
    auto json = JsonWrapper::FromString("{\"anyOf\":[{\"RemediationParametrized\":{\"result\":\"bar\"}}]}");
    ASSERT_TRUE(json.HasValue());
    ASSERT_TRUE(json->get());
    Evaluator evaluator1("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator1.ExecuteRemediation();
    ASSERT_FALSE(result);
}

TEST_F(EvaluatorTest, ExecuteRemediation_Parameters_3)
{
    auto json = JsonWrapper::FromString("{\"anyOf\":[{\"RemediationParametrized\":{\"result\":\"success\"}}]}");
    ASSERT_TRUE(json.HasValue());
    ASSERT_TRUE(json->get());
    Evaluator evaluator1("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator1.ExecuteRemediation();
    ASSERT_TRUE(result);
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EvaluatorTest, ExecuteRemediation_Parameters_4)
{
    auto json = JsonWrapper::FromString("{\"anyOf\":[{\"RemediationParametrized\":{\"result\":\"failure\"}}]}");
    ASSERT_TRUE(json.HasValue());
    ASSERT_TRUE(json->get());
    Evaluator evaluator1("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator1.ExecuteRemediation();
    ASSERT_TRUE(result);
    EXPECT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EvaluatorTest, ExecuteRemediation_Parameters_5)
{
    auto json = JsonWrapper::FromString("{\"anyOf\":[{\"RemediationParametrized\":{\"result\":123}}]}");
    ASSERT_TRUE(json.HasValue());
    ASSERT_TRUE(json->get());
    Evaluator evaluator1("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator1.ExecuteRemediation();
    ASSERT_FALSE(result);
    EXPECT_EQ(result.Error().message, std::string("Argument type is not a string"));
}

TEST_F(EvaluatorTest, ExecuteRemediation_Parameters_6)
{
    mParameters = {{"placeholder", "failure"}};
    auto json = JsonWrapper::FromString("{\"anyOf\":[{\"RemediationParametrized\":{\"result\":\"$placeholder\"}}]}");
    ASSERT_TRUE(json.HasValue());
    ASSERT_TRUE(json->get());
    Evaluator evaluator1("test", json_value_get_object(json->get()), mParameters, mContext);
}

TEST_F(EvaluatorTest, ExecuteRemediation_Parameters_7)
{
    mParameters = {{"placeholder", "success"}};
    auto json = JsonWrapper::FromString("{\"anyOf\":[{\"RemediationParametrized\":{\"result\":\"$placeholder\"}}]}");
    ASSERT_TRUE(json.HasValue());
    ASSERT_TRUE(json->get());
    Evaluator evaluator1("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator1.ExecuteRemediation();
    ASSERT_TRUE(result);
    EXPECT_EQ(result.Value(), Status::Compliant);
}

// ── Three-valued logic (3VL) tests ────────────────────────────────────────────

// not(N/A) → N/A
TEST_F(EvaluatorTest, ThreeValuedLogic_Not_NotApplicable)
{
    auto json = JsonWrapper::FromString("{\"not\":{\"AuditNotApplicable\":{}}}");
    ASSERT_TRUE(json.HasValue());
    Evaluator evaluator("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator.ExecuteAudit(mFormatter);
    ASSERT_TRUE(result);
    EXPECT_EQ(result.Value().status, Status::NotApplicable);
}

// not(not(N/A)) → N/A  (double negation preserves N/A)
TEST_F(EvaluatorTest, ThreeValuedLogic_Not_Not_NotApplicable)
{
    auto json = JsonWrapper::FromString("{\"not\":{\"not\":{\"AuditNotApplicable\":{}}}}");
    ASSERT_TRUE(json.HasValue());
    Evaluator evaluator("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator.ExecuteAudit(mFormatter);
    ASSERT_TRUE(result);
    EXPECT_EQ(result.Value().status, Status::NotApplicable);
}

// allOf([N/A]) → N/A  (only N/A, no absorbing element)
TEST_F(EvaluatorTest, ThreeValuedLogic_AllOf_OnlyNotApplicable)
{
    auto json = JsonWrapper::FromString("{\"allOf\":[{\"AuditNotApplicable\":{}}]}");
    ASSERT_TRUE(json.HasValue());
    Evaluator evaluator("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator.ExecuteAudit(mFormatter);
    ASSERT_TRUE(result);
    EXPECT_EQ(result.Value().status, Status::NotApplicable);
}

// allOf([Compliant, N/A]) → N/A  (N/A contaminates a passing allOf)
TEST_F(EvaluatorTest, ThreeValuedLogic_AllOf_Compliant_NotApplicable)
{
    auto json = JsonWrapper::FromString("{\"allOf\":[{\"AuditSuccess\":{}},{\"AuditNotApplicable\":{}}]}");
    ASSERT_TRUE(json.HasValue());
    Evaluator evaluator("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator.ExecuteAudit(mFormatter);
    ASSERT_TRUE(result);
    EXPECT_EQ(result.Value().status, Status::NotApplicable);
}

// allOf([N/A, Compliant]) → N/A  (order must not matter)
TEST_F(EvaluatorTest, ThreeValuedLogic_AllOf_NotApplicable_Compliant)
{
    auto json = JsonWrapper::FromString("{\"allOf\":[{\"AuditNotApplicable\":{}},{\"AuditSuccess\":{}}]}");
    ASSERT_TRUE(json.HasValue());
    Evaluator evaluator("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator.ExecuteAudit(mFormatter);
    ASSERT_TRUE(result);
    EXPECT_EQ(result.Value().status, Status::NotApplicable);
}

// allOf([NonCompliant, N/A]) → NonCompliant  (NC absorbs N/A in allOf)
TEST_F(EvaluatorTest, ThreeValuedLogic_AllOf_NonCompliant_NotApplicable)
{
    auto json = JsonWrapper::FromString("{\"allOf\":[{\"AuditFailure\":{}},{\"AuditNotApplicable\":{}}]}");
    ASSERT_TRUE(json.HasValue());
    Evaluator evaluator("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator.ExecuteAudit(mFormatter);
    ASSERT_TRUE(result);
    EXPECT_EQ(result.Value().status, Status::NonCompliant);
}

// allOf([N/A, NonCompliant]) → NonCompliant  (absorbing element reached after N/A)
TEST_F(EvaluatorTest, ThreeValuedLogic_AllOf_NotApplicable_NonCompliant)
{
    auto json = JsonWrapper::FromString("{\"allOf\":[{\"AuditNotApplicable\":{}},{\"AuditFailure\":{}}]}");
    ASSERT_TRUE(json.HasValue());
    Evaluator evaluator("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator.ExecuteAudit(mFormatter);
    ASSERT_TRUE(result);
    EXPECT_EQ(result.Value().status, Status::NonCompliant);
}

// anyOf([N/A]) → N/A  (only N/A, no absorbing element)
TEST_F(EvaluatorTest, ThreeValuedLogic_AnyOf_OnlyNotApplicable)
{
    auto json = JsonWrapper::FromString("{\"anyOf\":[{\"AuditNotApplicable\":{}}]}");
    ASSERT_TRUE(json.HasValue());
    Evaluator evaluator("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator.ExecuteAudit(mFormatter);
    ASSERT_TRUE(result);
    EXPECT_EQ(result.Value().status, Status::NotApplicable);
}

// anyOf([NonCompliant, N/A]) → N/A  (N/A contaminates a failing anyOf)
TEST_F(EvaluatorTest, ThreeValuedLogic_AnyOf_NonCompliant_NotApplicable)
{
    auto json = JsonWrapper::FromString("{\"anyOf\":[{\"AuditFailure\":{}},{\"AuditNotApplicable\":{}}]}");
    ASSERT_TRUE(json.HasValue());
    Evaluator evaluator("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator.ExecuteAudit(mFormatter);
    ASSERT_TRUE(result);
    EXPECT_EQ(result.Value().status, Status::NotApplicable);
}

// anyOf([N/A, NonCompliant]) → N/A  (order must not matter)
TEST_F(EvaluatorTest, ThreeValuedLogic_AnyOf_NotApplicable_NonCompliant)
{
    auto json = JsonWrapper::FromString("{\"anyOf\":[{\"AuditNotApplicable\":{}},{\"AuditFailure\":{}}]}");
    ASSERT_TRUE(json.HasValue());
    Evaluator evaluator("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator.ExecuteAudit(mFormatter);
    ASSERT_TRUE(result);
    EXPECT_EQ(result.Value().status, Status::NotApplicable);
}

// anyOf([Compliant, N/A]) → Compliant  (C absorbs N/A in anyOf)
TEST_F(EvaluatorTest, ThreeValuedLogic_AnyOf_Compliant_NotApplicable)
{
    auto json = JsonWrapper::FromString("{\"anyOf\":[{\"AuditSuccess\":{}},{\"AuditNotApplicable\":{}}]}");
    ASSERT_TRUE(json.HasValue());
    Evaluator evaluator("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator.ExecuteAudit(mFormatter);
    ASSERT_TRUE(result);
    EXPECT_EQ(result.Value().status, Status::Compliant);
}

// anyOf([N/A, Compliant]) → Compliant  (absorbing element reached after N/A)
TEST_F(EvaluatorTest, ThreeValuedLogic_AnyOf_NotApplicable_Compliant)
{
    auto json = JsonWrapper::FromString("{\"anyOf\":[{\"AuditNotApplicable\":{}},{\"AuditSuccess\":{}}]}");
    ASSERT_TRUE(json.HasValue());
    Evaluator evaluator("test", json_value_get_object(json->get()), mParameters, mContext);

    auto result = evaluator.ExecuteAudit(mFormatter);
    ASSERT_TRUE(result);
    EXPECT_EQ(result.Value().status, Status::Compliant);
}

TEST(UserDotFilePermissionsErrorsTest, InvalidAccountPatternRemainsError)
{
    MockContext context;
    ComplianceEngine::IndicatorsTree indicators;
    indicators.Push("UserDotFilePermissions");
    const std::string home = context.GetTempdirPath() + "/home";
    ASSERT_EQ(0, mkdir(home.c_str(), 0700));
    std::ofstream(home + "/.config") << "settings\n";
    context.SetSpecialFilePath("/etc/shells", context.MakeTempfile("/bin/sh\n"));
    const auto* group = getgrnam("root");
    ASSERT_NE(nullptr, group);
    const std::string passwd =
        context.MakeTempfile("(:x:" + std::to_string(getuid()) + ":" + std::to_string(group->gr_gid) + "::" + home + ":/bin/sh\n");

    const auto result = ComplianceEngine::AuditUserDotFilePermissionsWithPasswdFile(indicators, context, passwd);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EINVAL, result.Error().code);
    EXPECT_NE(std::string::npos, result.Error().message.find("Regular expression"));
}

TEST(UserDotFilePermissionsErrorsTest, MissingGroupIgnoresStaleErrnoInAuditAndRemediation)
{
    MockContext context;
    context.SetSpecialFilePath("/etc/shells", context.MakeTempfile("/bin/sh\n"));
    const gid_t absent = std::numeric_limits<gid_t>::max();
    errno = 0;
    if (nullptr != getgrgid(absent))
    {
        GTEST_SKIP() << "The maximum gid is configured on this host";
    }
    const std::string passwd = context.MakeTempfile("fixture:x:" + std::to_string(getuid()) + ":" + std::to_string(absent) + "::/nonexistent:/bin/sh\n");
    for (bool remediate : {false, true})
    {
        ComplianceEngine::IndicatorsTree indicators;
        indicators.Push("UserDotFilePermissions");
        errno = EIO;
        const auto result = remediate ? ComplianceEngine::RemediateUserDotFilePermissionsWithPasswdFile(indicators, context, passwd) :
                                        ComplianceEngine::AuditUserDotFilePermissionsWithPasswdFile(indicators, context, passwd);
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ(ENOENT, result.Error().code);
        EXPECT_NE(std::string::npos, result.Error().message.find("No such file or directory"));
    }
}

TEST(UserDotFilePermissionsErrorsTest, ForbiddenDotFileRemainsOrdinaryVerdict)
{
    MockContext context;
    ComplianceEngine::IndicatorsTree indicators;
    indicators.Push("UserDotFilePermissions");
    const std::string home = context.GetTempdirPath() + "/home";
    ASSERT_EQ(0, mkdir(home.c_str(), 0700));
    std::ofstream(home + "/.rhosts") << "host\n";
    context.SetSpecialFilePath("/etc/shells", context.MakeTempfile("/bin/sh\n"));
    const auto* group = getgrnam("root");
    ASSERT_NE(nullptr, group);
    const std::string passwd =
        context.MakeTempfile("fixture:x:" + std::to_string(getuid()) + ":" + std::to_string(group->gr_gid) + "::" + home + ":/bin/sh\n");

    const auto result = ComplianceEngine::AuditUserDotFilePermissionsWithPasswdFile(indicators, context, passwd);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::NonCompliant, result.Value());
}

TEST(UserDotFilePermissionsErrorsTest, NonDirectoryHomeRemainsWalkError)
{
    MockContext context;
    ComplianceEngine::IndicatorsTree indicators;
    indicators.Push("UserDotFilePermissions");
    const std::string home = context.MakeTempfile("not a directory");
    context.SetSpecialFilePath("/etc/shells", context.MakeTempfile("/bin/sh\n"));
    const auto* group = getgrnam("root");
    ASSERT_NE(nullptr, group);
    const std::string passwd =
        context.MakeTempfile("fixture:x:" + std::to_string(getuid()) + ":" + std::to_string(group->gr_gid) + "::" + home + ":/bin/sh\n");

    const auto result = ComplianceEngine::AuditUserDotFilePermissionsWithPasswdFile(indicators, context, passwd);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(ENOTDIR, result.Error().code);
}

TEST(UserDotFilePermissionsErrorsTest, RegularDotFileRetainsPermissionVerdict)
{
    MockContext context;
    ComplianceEngine::IndicatorsTree indicators;
    indicators.Push("UserDotFilePermissions");
    const std::string home = context.GetTempdirPath() + "/home";
    ASSERT_EQ(0, mkdir(home.c_str(), 0700));
    const std::string filename = home + "/.config";
    std::ofstream(filename) << "settings\n";
    ASSERT_EQ(0, chmod(filename.c_str(), 0666));
    context.SetSpecialFilePath("/etc/shells", context.MakeTempfile("/bin/sh\n"));
    const auto* user = getpwuid(getuid());
    ASSERT_NE(nullptr, user);
    const auto* group = getgrgid(user->pw_gid);
    ASSERT_NE(nullptr, group);
    const std::string passwd = context.MakeTempfile(std::string(user->pw_name) + ":x:" + std::to_string(user->pw_uid) + ":" +
                                                    std::to_string(group->gr_gid) + "::" + home + ":/bin/sh\n");

    const auto result = ComplianceEngine::AuditUserDotFilePermissionsWithPasswdFile(indicators, context, passwd);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::NonCompliant, result.Value());
}

TEST(UserDotFilePermissionsErrorsTest, RemediationNonDirectoryHomePropagatesWalkError)
{
    MockContext context;
    ComplianceEngine::IndicatorsTree indicators;
    indicators.Push("UserDotFilePermissions");
    const std::string home = context.MakeTempfile("not a directory");
    context.SetSpecialFilePath("/etc/shells", context.MakeTempfile("/bin/sh\n"));
    const auto* group = getgrnam("root");
    ASSERT_NE(nullptr, group);
    const std::string passwd =
        context.MakeTempfile("fixture:x:" + std::to_string(getuid()) + ":" + std::to_string(group->gr_gid) + "::" + home + ":/bin/sh\n");

    const auto result = ComplianceEngine::RemediateUserDotFilePermissionsWithPasswdFile(indicators, context, passwd);

    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(ENOTDIR, result.Error().code);
    EXPECT_TRUE(indicators.Back().indicators.empty());
}

TEST(UserDotFilePermissionsErrorsTest, RemediationForbiddenFileRetainsOrdinaryVerdict)
{
    MockContext context;
    ComplianceEngine::IndicatorsTree indicators;
    indicators.Push("UserDotFilePermissions");
    const std::string home = context.GetTempdirPath() + "/home";
    ASSERT_EQ(0, mkdir(home.c_str(), 0700));
    std::ofstream(home + "/.rhosts") << "host\n";
    context.SetSpecialFilePath("/etc/shells", context.MakeTempfile("/bin/sh\n"));
    const auto* group = getgrnam("root");
    ASSERT_NE(nullptr, group);
    const std::string passwd =
        context.MakeTempfile("fixture:x:" + std::to_string(getuid()) + ":" + std::to_string(group->gr_gid) + "::" + home + ":/bin/sh\n");

    const auto result = ComplianceEngine::RemediateUserDotFilePermissionsWithPasswdFile(indicators, context, passwd);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::NonCompliant, result.Value());
    ASSERT_EQ(1u, indicators.Back().indicators.size());
    EXPECT_EQ(Status::NonCompliant, indicators.Back().indicators[0].status);
}

TEST(UserDotFilePermissionsErrorsTest, RemediationLaterWalkErrorOverridesNoncompliance)
{
    MockContext context;
    ComplianceEngine::IndicatorsTree indicators;
    indicators.Push("UserDotFilePermissions");
    const std::string firstHome = context.GetTempdirPath() + "/home";
    ASSERT_EQ(0, mkdir(firstHome.c_str(), 0700));
    std::ofstream(firstHome + "/.rhosts") << "host\n";
    const std::string secondHome = context.MakeTempfile("not a directory");
    context.SetSpecialFilePath("/etc/shells", context.MakeTempfile("/bin/sh\n"));
    const auto* group = getgrnam("root");
    ASSERT_NE(nullptr, group);
    const std::string gid = std::to_string(group->gr_gid);
    const std::string uid = std::to_string(getuid());
    const std::string passwd = context.MakeTempfile("first:x:" + uid + ":" + gid + "::" + firstHome + ":/bin/sh\n" + "second:x:" + uid + ":" + gid +
                                                    "::" + secondHome + ":/bin/sh\n");

    const auto result = ComplianceEngine::RemediateUserDotFilePermissionsWithPasswdFile(indicators, context, passwd);

    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(ENOTDIR, result.Error().code);
    ASSERT_EQ(1u, indicators.Back().indicators.size());
    EXPECT_EQ(Status::NonCompliant, indicators.Back().indicators[0].status);
}

class UserDotFileRangeTest : public ::testing::Test
{
protected:
    MockContext context;
    ComplianceEngine::IndicatorsTree indicators;

    void SetUp() override
    {
        context.SetSpecialFilePath("/etc/shells", context.MakeTempfile("/bin/sh\n"));
        indicators.Push("UserDotFilePermissions");
        ASSERT_NE(nullptr, getgrgid(getgid()));
    }

    std::string User(const std::string& name, const std::string& home) const
    {
        return name + ":x:" + std::to_string(getuid()) + ":" + std::to_string(getgid()) + "::" + home + ":/bin/sh\n";
    }

    Result<Status> Run(bool remediate, const std::string& passwd)
    {
        const auto path = context.MakeTempfile(passwd);
        return remediate ? ComplianceEngine::RemediateUserDotFilePermissionsWithPasswdFile(indicators, context, path) :
                           ComplianceEngine::AuditUserDotFilePermissionsWithPasswdFile(indicators, context, path);
    }
};

TEST_F(UserDotFileRangeTest, MalformedPasswdHomesAreErrorsForAuditAndRemediation)
{
    // The username deliberately differs from the process owner: malformed
    // homes must not be hidden by an owner-only account filter.
    for (const std::string& home : {"", ".", "..", "relative/home"})
    {
        SCOPED_TRACE(home);
        for (bool remediate : {false, true})
        {
            SCOPED_TRACE(remediate);
            const auto result = Run(remediate, User("fixture", home));
            ASSERT_FALSE(result.HasValue());
            EXPECT_EQ(EINVAL, result.Error().code);
            EXPECT_NE(std::string::npos, result.Error().message.find("Filesystem collection root path"));
            EXPECT_TRUE(indicators.Back().indicators.empty());
        }
    }
}

TEST_F(UserDotFileRangeTest, AuditStopsAtFirstViolationPerUserAndContinuesToNextUser)
{
    const auto first = context.GetTempdirPath() + "/first-home";
    const auto second = context.GetTempdirPath() + "/second-home";
    ASSERT_EQ(0, mkdir(first.c_str(), 0700));
    ASSERT_EQ(0, mkdir(second.c_str(), 0700));
    std::ofstream(first + "/.rhosts") << "host\n";
    std::ofstream(first + "/.forward") << "mail\n";
    std::ofstream(second + "/.forward") << "mail\n";
    const auto result = Run(false, User("first", first) + User("second", second));
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::NonCompliant, result.Value());
    EXPECT_EQ(2u, indicators.Back().indicators.size());
}

TEST_F(UserDotFileRangeTest, RemediationScansAllViolationsAcrossUsers)
{
    const auto first = context.GetTempdirPath() + "/first-home";
    const auto second = context.GetTempdirPath() + "/second-home";
    ASSERT_EQ(0, mkdir(first.c_str(), 0700));
    ASSERT_EQ(0, mkdir(second.c_str(), 0700));
    std::ofstream(first + "/.rhosts") << "host\n";
    std::ofstream(first + "/.forward") << "mail\n";
    std::ofstream(second + "/.forward") << "mail\n";
    const auto result = Run(true, User("first", first) + User("second", second));
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::NonCompliant, result.Value());
    EXPECT_EQ(3u, indicators.Back().indicators.size());
}

TEST_F(UserDotFileRangeTest, RemediationRefusesHardLinksWithoutChangingTheSharedInode)
{
    const auto home = context.GetTempdirPath() + "/home";
    ASSERT_EQ(0, mkdir(home.c_str(), 0700));
    const auto original = context.GetTempdirPath() + "/original";
    std::ofstream(original) << "unchanged\n";
    ASSERT_EQ(0, chmod(original.c_str(), 0666));
    ASSERT_EQ(0, link(original.c_str(), (home + "/.config").c_str()));
    std::ofstream(home + "/.forward") << "mail\n";
    const auto result = Run(true, User("fixture", home));
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::NonCompliant, result.Value());
    ASSERT_EQ(2u, indicators.Back().indicators.size());
    struct stat metadata = {};
    ASSERT_EQ(0, stat(original.c_str(), &metadata));
    EXPECT_EQ(0666, metadata.st_mode & 0777);
    EXPECT_EQ(2, metadata.st_nlink);
}

TEST_F(UserDotFileRangeTest, LeafReplacementAfterAcquisitionKeepsAuditAndRemediationOnThePinnedFile)
{
    const auto* user = getpwuid(getuid());
    ASSERT_NE(nullptr, user);
    for (bool remediate : {false, true})
    {
        const auto home = context.GetTempdirPath() + (remediate ? "/remediate-home" : "/audit-home");
        ASSERT_EQ(0, mkdir(home.c_str(), 0700));
        const auto target = home + "/.config";
        const auto held = context.GetTempdirPath() + (remediate ? "/remediate-held" : "/audit-held");
        std::ofstream(target) << "original\n";
        ASSERT_EQ(0, chmod(target.c_str(), remediate ? 0666 : 0600));
        struct stat original = {};
        ASSERT_EQ(0, stat(target.c_str(), &original));
        bool yielded = false;
        ON_CALL(context, ReadDirectory(::testing::_)).WillByDefault([&](DIR * stream) -> struct dirent* {
            if (yielded)
            {
                errno = 0;
                return nullptr; // The replacement is not another collected entry.
            }
            auto* entry = readdir(stream);
            if (entry && std::string(entry->d_name) == ".config")
            {
                yielded = true;
            }
            return entry;
        });
        int observations = 0;
        bool replaced = false;
        ON_CALL(context, StatFileDescriptor(::testing::_, ::testing::_)).WillByDefault([&](int descriptor, struct stat* metadata) {
            const int result = context.ContextInterface::StatFileDescriptor(descriptor, metadata);
            if ((0 == result) && (original.st_dev == metadata->st_dev) && (original.st_ino == metadata->st_ino) && (2 == ++observations))
            {
                replaced = (0 == rename(target.c_str(), held.c_str()));
                std::ofstream(target) << "replacement\n";
                replaced = replaced && (0 == chmod(target.c_str(), remediate ? 0666 : 0777));
            }
            return result;
        });
        const auto result = Run(remediate, User(user->pw_name, home));
        ASSERT_TRUE(result.HasValue()) << result.Error().message;
        EXPECT_EQ(Status::Compliant, result.Value());
        EXPECT_TRUE(yielded);
        EXPECT_TRUE(replaced);
        struct stat pinned = {}, replacement = {};
        ASSERT_EQ(0, stat(held.c_str(), &pinned));
        ASSERT_EQ(0, stat(target.c_str(), &replacement));
        EXPECT_EQ(remediate ? 0644 : 0600, pinned.st_mode & 0777);
        EXPECT_EQ(remediate ? 0666 : 0777, replacement.st_mode & 0777);
        EXPECT_NE(pinned.st_ino, replacement.st_ino);
    }
}

TEST_F(UserDotFileRangeTest, ReplacedAncestorAfterAcquisitionDoesNotRedirectRemediation)
{
    const auto* user = getpwuid(getuid());
    ASSERT_NE(nullptr, user);
    const auto home = context.GetTempdirPath() + "/home";
    const auto nested = home + "/nested";
    const auto moved = home + "/moved";
    ASSERT_EQ(0, mkdir(home.c_str(), 0700));
    ASSERT_EQ(0, mkdir(nested.c_str(), 0700));
    const auto target = nested + "/.config";
    std::ofstream(target) << "original\n";
    ASSERT_EQ(0, chmod(target.c_str(), 0666));
    struct stat original = {}, root = {}, directory = {};
    ASSERT_EQ(0, stat(target.c_str(), &original));
    ASSERT_EQ(0, stat(home.c_str(), &root));
    ASSERT_EQ(0, stat(nested.c_str(), &directory));
    bool sawRootChild = false, sawFile = false;
    ON_CALL(context, ReadDirectory(::testing::_)).WillByDefault([&](DIR * stream) -> struct dirent* {
        struct stat opened = {};
        if (0 != fstat(dirfd(stream), &opened))
        {
            return nullptr;
        }
        bool& selected = (opened.st_ino == root.st_ino) ? sawRootChild : sawFile;
        if (selected)
        {
            errno = 0;
            return nullptr;
        }
        auto* entry = readdir(stream);
        if (entry && ((opened.st_ino == root.st_ino && std::string(entry->d_name) == "nested") ||
                         (opened.st_ino == directory.st_ino && std::string(entry->d_name) == ".config")))
        {
            selected = true;
        }
        return entry;
    });
    int observations = 0;
    bool replaced = false;
    ON_CALL(context, StatFileDescriptor(::testing::_, ::testing::_)).WillByDefault([&](int descriptor, struct stat* metadata) {
        const int result = context.ContextInterface::StatFileDescriptor(descriptor, metadata);
        if ((0 == result) && (original.st_dev == metadata->st_dev) && (original.st_ino == metadata->st_ino) && (2 == ++observations))
        {
            replaced = (0 == rename(nested.c_str(), moved.c_str())) && (0 == mkdir(nested.c_str(), 0700));
            std::ofstream(target) << "replacement\n";
            replaced = replaced && (0 == chmod(target.c_str(), 0666));
        }
        return result;
    });
    const auto result = Run(true, User(user->pw_name, home));
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(Status::Compliant, result.Value());
    EXPECT_TRUE(replaced);
    EXPECT_TRUE(sawRootChild);
    EXPECT_TRUE(sawFile);
    struct stat pinned = {}, replacement = {};
    ASSERT_EQ(0, stat((moved + "/.config").c_str(), &pinned));
    ASSERT_EQ(0, stat(target.c_str(), &replacement));
    EXPECT_EQ(0644, pinned.st_mode & 0777);
    EXPECT_EQ(0666, replacement.st_mode & 0777);
}

TEST_F(UserDotFileRangeTest, HardLinkAddedAfterAcquisitionIsRefusedBeforeMutation)
{
    const auto* user = getpwuid(getuid());
    ASSERT_NE(nullptr, user);
    const auto home = context.GetTempdirPath() + "/home";
    ASSERT_EQ(0, mkdir(home.c_str(), 0700));
    const auto target = home + "/.config";
    const auto other = context.GetTempdirPath() + "/another-link";
    std::ofstream(target) << "original\n";
    ASSERT_EQ(0, chmod(target.c_str(), 0666));
    struct stat original = {};
    ASSERT_EQ(0, stat(target.c_str(), &original));
    int observations = 0;
    bool linked = false;
    ON_CALL(context, StatFileDescriptor(::testing::_, ::testing::_)).WillByDefault([&](int descriptor, struct stat* metadata) {
        const int result = context.ContextInterface::StatFileDescriptor(descriptor, metadata);
        if ((0 == result) && (original.st_dev == metadata->st_dev) && (original.st_ino == metadata->st_ino) && (2 == ++observations))
        {
            linked = (0 == link(target.c_str(), other.c_str()));
        }
        return result;
    });
    const auto result = Run(true, User(user->pw_name, home));
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(Status::NonCompliant, result.Value());
    EXPECT_TRUE(linked);
    struct stat unchanged = {};
    ASSERT_EQ(0, stat(target.c_str(), &unchanged));
    EXPECT_EQ(0666, unchanged.st_mode & 0777);
    EXPECT_EQ(2, unchanged.st_nlink);
}

TEST_F(UserDotFileRangeTest, UnreadableDotfileIsInspectedAndRemediatedThroughItsPin)
{
    const auto* user = getpwuid(getuid());
    ASSERT_NE(nullptr, user);
    const auto home = context.GetTempdirPath() + "/home";
    ASSERT_EQ(0, mkdir(home.c_str(), 0700));
    const auto target = home + "/.config";
    std::ofstream(target) << "original\n";
    ASSERT_EQ(0, chmod(target.c_str(), 0222));
    const auto audit = Run(false, User(user->pw_name, home));
    ASSERT_TRUE(audit.HasValue()) << audit.Error().message;
    EXPECT_EQ(Status::NonCompliant, audit.Value());
    const auto remediation = Run(true, User(user->pw_name, home));
    ASSERT_TRUE(remediation.HasValue()) << remediation.Error().message;
    EXPECT_EQ(Status::Compliant, remediation.Value());
    struct stat corrected = {};
    ASSERT_EQ(0, stat(target.c_str(), &corrected));
    EXPECT_EQ(0200, corrected.st_mode & 0777);
}

TEST_F(UserDotFileRangeTest, MetadataDescentIncludesHiddenFilesButNotLinksOrSpecialFiles)
{
    const auto home = context.GetTempdirPath() + "/home";
    const auto hidden = home + "/.nested";
    ASSERT_EQ(0, mkdir(home.c_str(), 0700));
    ASSERT_EQ(0, mkdir(hidden.c_str(), 0700));
    std::ofstream(hidden + "/.forward") << "mail\n";
    std::ofstream(home + "/plain") << "ignored\n";
    ASSERT_EQ(0, symlink((hidden + "/.forward").c_str(), (home + "/.forward").c_str()));
    ASSERT_EQ(0, mkfifo((home + "/.rhosts").c_str(), 0600));
    bool unknownDirectoryType = false;
    ON_CALL(context, ReadDirectory(::testing::_)).WillByDefault([&unknownDirectoryType](DIR * stream) -> struct dirent* {
        struct dirent* entry = readdir(stream);
        if (entry && std::string(entry->d_name) == ".nested")
        {
            entry->d_type = DT_UNKNOWN;
            unknownDirectoryType = true;
        }
        return entry;
    });
    const auto result = Run(false, User("fixture", home));
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::NonCompliant, result.Value());
    EXPECT_TRUE(unknownDirectoryType);
    EXPECT_EQ(1u, indicators.Back().indicators.size());
}

TEST_F(UserDotFileRangeTest, MissingRootsAreCompliantAndFactoryFailuresPropagate)
{
    const auto home = context.GetTempdirPath() + "/absent";
    for (bool remediate : {false, true})
    {
        const auto absent = Run(remediate, User("fixture", home));
        ASSERT_TRUE(absent.HasValue());
        EXPECT_EQ(Status::Compliant, absent.Value());
    }
    ASSERT_EQ(0, mkdir(home.c_str(), 0700));
    struct stat expectedHome = {};
    ASSERT_EQ(0, stat(home.c_str(), &expectedHome));
    // Fail at the actual accepted-root acquisition seam, not while reading
    // /etc/shells (which also inspects a descriptor before traversal starts).
    ON_CALL(context, StatFileDescriptor(::testing::_, ::testing::_)).WillByDefault([this, expectedHome](int descriptor, struct stat* metadata) {
        struct stat acquired = {};
        if ((0 == ::fstat(descriptor, &acquired)) && (acquired.st_dev == expectedHome.st_dev) && (acquired.st_ino == expectedHome.st_ino) &&
            S_ISDIR(acquired.st_mode))
        {
            errno = EACCES;
            return -1;
        }
        return context.ContextInterface::StatFileDescriptor(descriptor, metadata);
    });
    for (bool remediate : {false, true})
    {
        const auto result = Run(remediate, User("fixture", home));
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ(EACCES, result.Error().code);
    }
    ON_CALL(context, StatFileDescriptor(::testing::_, ::testing::_)).WillByDefault([this](int descriptor, struct stat* metadata) {
        return context.ContextInterface::StatFileDescriptor(descriptor, metadata);
    });
    ON_CALL(context, ReadDirectory(::testing::_)).WillByDefault([](DIR*) -> struct dirent* {
        errno = EACCES;
        return nullptr;
    });
    for (bool remediate : {false, true})
    {
        const auto result = Run(remediate, User("fixture", home));
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ(EACCES, result.Error().code);
    }
}

TEST_F(UserDotFileRangeTest, CheckedCloseFailureOverridesEarlyAuditVerdictAndRemediationVerdict)
{
    const auto home = context.GetTempdirPath() + "/home";
    ASSERT_EQ(0, mkdir(home.c_str(), 0700));
    std::ofstream(home + "/.rhosts") << "host\n";
    ON_CALL(context, CloseDirectory(::testing::_)).WillByDefault([](DIR* stream) {
        const int result = closedir(stream);
        errno = EIO;
        return result == 0 ? -1 : result;
    });
    for (bool remediate : {false, true})
    {
        const auto result = Run(remediate, User("fixture", home));
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ(EIO, result.Error().code);
    }
    EXPECT_EQ(2u, indicators.Back().indicators.size());
}

TEST_F(UserDotFileRangeTest, RemediationReachedItemErrorAfterViolationOutranksCleanupError)
{
    const auto home = context.GetTempdirPath() + "/home";
    ASSERT_EQ(0, mkdir(home.c_str(), 0700));
    std::ofstream(home + "/.rhosts") << "host\n";
    std::size_t entries = 0;
    ON_CALL(context, ReadDirectory(::testing::_)).WillByDefault([&entries](DIR * stream) -> struct dirent* {
        if (entries == 1)
        {
            errno = EACCES;
            return nullptr;
        }
        struct dirent* entry = readdir(stream);
        if (entry && std::string(entry->d_name) != "." && std::string(entry->d_name) != "..")
        {
            ++entries;
        }
        return entry;
    });
    ON_CALL(context, CloseDirectory(::testing::_)).WillByDefault([](DIR* stream) {
        const int result = closedir(stream);
        errno = EIO;
        return result == 0 ? -1 : result;
    });
    const auto result = Run(true, User("fixture", home));
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EACCES, result.Error().code);
    EXPECT_EQ(1u, indicators.Back().indicators.size());
}

TEST_F(UserDotFileRangeTest, AuditReachedErrorInNextUserOverridesEarlierNoncompliance)
{
    const auto first = context.GetTempdirPath() + "/first-home";
    const auto second = context.GetTempdirPath() + "/second-home";
    ASSERT_EQ(0, mkdir(first.c_str(), 0700));
    ASSERT_EQ(0, mkdir(second.c_str(), 0700));
    std::ofstream(first + "/.rhosts") << "host\n";
    ASSERT_EQ(0, mkdir((second + "/nested").c_str(), 0700));
    struct stat nested = {};
    ASSERT_EQ(0, stat((second + "/nested").c_str(), &nested));
    ON_CALL(context, ReadDirectory(::testing::_)).WillByDefault([nested](DIR * stream) -> struct dirent* {
        struct stat opened = {};
        if ((0 == fstat(dirfd(stream), &opened)) && (nested.st_dev == opened.st_dev) && (nested.st_ino == opened.st_ino))
        {
            errno = EACCES;
            return nullptr;
        }
        return readdir(stream);
    });
    const auto result = Run(false, User("first", first) + User("second", second));
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EACCES, result.Error().code);
    EXPECT_EQ(1u, indicators.Back().indicators.size());
}

TEST_F(UserDotFileRangeTest, FollowsRootDirectoryLinkAndReportsDepthOverflow)
{
    const auto home = context.GetTempdirPath() + "/home";
    const auto linkedRoot = context.GetTempdirPath() + "/linked-home";
    ASSERT_EQ(0, mkdir(home.c_str(), 0700));
    ASSERT_EQ(0, symlink(home.c_str(), linkedRoot.c_str()));
    std::ofstream(home + "/.rhosts") << "host\n";
    const auto linked = Run(false, User("fixture", linkedRoot));
    ASSERT_TRUE(linked.HasValue());
    EXPECT_EQ(Status::NonCompliant, linked.Value());

    std::string directory = home;
    for (int depth = 0; depth < 33; ++depth)
    {
        directory += "/d";
        ASSERT_EQ(0, mkdir(directory.c_str(), 0700));
    }
    // Remediation must descend after seeing the forbidden file rather than
    // returning its verdict before encountering the depth error.
    const auto tooDeep = Run(true, User("fixture", home));
    ASSERT_FALSE(tooDeep.HasValue());
    // Pinned continuation may exhaust the approved descriptor budget before
    // the 32-level descent limit; neither outcome silently truncates the walk.
    EXPECT_TRUE((std::string::npos != tooDeep.Error().message.find("Maximum recursion depth")) ||
                (std::string::npos != tooDeep.Error().message.find("descriptor budget")) || (EMFILE == tooDeep.Error().code));
}

TEST(UserHomeDirectoryPermissionsErrorsTest, FailedChildRemediationPropagatesWithoutMutatingHome)
{
    MockContext context;
    ComplianceEngine::IndicatorsTree indicators;
    indicators.Push("UserHomeDirectoryPermissions");
    const std::string home = context.GetTempdirPath() + "/home";
    ASSERT_EQ(0, mkdir(home.c_str(), 0700));
    context.SetSpecialFilePath("/etc/shells", context.MakeTempfile("/bin/sh\n"));
    const auto* group = getgrnam("root");
    ASSERT_NE(nullptr, group);
    const std::string passwd =
        context.MakeTempfile("fixture:x:" + std::to_string(getuid()) + ":" + std::to_string(group->gr_gid) + "::" + home + ":/bin/sh\n");
    struct stat before;
    ASSERT_EQ(0, stat(home.c_str(), &before));
    const auto failRemediation = [](const ComplianceEngine::FilePermissionsParams&, ComplianceEngine::IndicatorsTree&,
                                     ComplianceEngine::ContextInterface&) -> ComplianceEngine::Result<Status> {
        return Error("Simulated child remediation failure", EIO);
    };

    const auto result = ComplianceEngine::RemediateUserHomeDirectoryPermissionsWithPasswdFile(indicators, context, passwd, failRemediation);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EIO, result.Error().code);
    EXPECT_EQ("Simulated child remediation failure", result.Error().message);
    EXPECT_EQ("UserHomeDirectoryPermissions", indicators.Back().procedureName);
    ASSERT_EQ(1U, indicators.Back().children.size());
    struct stat after;
    ASSERT_EQ(0, stat(home.c_str(), &after));
    EXPECT_EQ(before.st_ino, after.st_ino);
    EXPECT_EQ(before.st_uid, after.st_uid);
    EXPECT_EQ(before.st_gid, after.st_gid);
    EXPECT_EQ(before.st_mode, after.st_mode);
}

TEST(UserHomeDirectoryPermissionsErrorsTest, SuccessfulChildRetainsOrdinaryVerdict)
{
    MockContext context;
    ComplianceEngine::IndicatorsTree indicators;
    indicators.Push("UserHomeDirectoryPermissions");
    const std::string home = context.GetTempdirPath() + "/home";
    ASSERT_EQ(0, mkdir(home.c_str(), 0700));
    context.SetSpecialFilePath("/etc/shells", context.MakeTempfile("/bin/sh\n"));
    const auto* group = getgrnam("root");
    ASSERT_NE(nullptr, group);
    const std::string passwd =
        context.MakeTempfile("fixture:x:" + std::to_string(getuid()) + ":" + std::to_string(group->gr_gid) + "::" + home + ":/bin/sh\n");
    const auto compliant = [](const ComplianceEngine::FilePermissionsParams&, ComplianceEngine::IndicatorsTree&,
                               ComplianceEngine::ContextInterface&) -> ComplianceEngine::Result<Status> { return Status::Compliant; };

    const auto result = ComplianceEngine::RemediateUserHomeDirectoryPermissionsWithPasswdFile(indicators, context, passwd, compliant);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());
}

namespace
{
void CheckHomeRemediationResults(const std::vector<std::string>& outcomes, Status expectedStatus, bool expectError = false)
{
    MockContext context;
    ComplianceEngine::IndicatorsTree indicators;
    indicators.Push("UserHomeDirectoryPermissions");
    context.SetSpecialFilePath("/etc/shells", context.MakeTempfile("/bin/sh\n"));
    const auto* group = getgrnam("root");
    ASSERT_NE(nullptr, group);
    std::string accounts;
    for (size_t i = 0; i < outcomes.size(); ++i)
    {
        const std::string home = context.GetTempdirPath() + "/" + outcomes[i] + std::to_string(i);
        ASSERT_EQ(0, mkdir(home.c_str(), 0700));
        accounts += "fixture" + std::to_string(i) + ":x:" + std::to_string(getuid()) + ":" + std::to_string(group->gr_gid) + "::" + home + ":/bin/sh\n";
    }
    const auto passwd = context.MakeTempfile(accounts);
    const auto remediate = [](const ComplianceEngine::FilePermissionsParams& params, ComplianceEngine::IndicatorsTree& tree,
                               ComplianceEngine::ContextInterface&) -> ComplianceEngine::Result<Status> {
        const auto homeName = params.path.substr(params.path.find_last_of('/') + 1);
        if (homeName.rfind("error", 0) == 0)
        {
            return Error("Simulated child remediation failure", EIO);
        }
        const auto status = homeName.rfind("bad", 0) == 0 ? Status::NonCompliant : Status::Compliant;
        tree.AddIndicator("Fixture child result", status);
        return status;
    };

    const auto result = ComplianceEngine::RemediateUserHomeDirectoryPermissionsWithPasswdFile(indicators, context, passwd, remediate);
    if (expectError)
    {
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ(EIO, result.Error().code);
    }
    else
    {
        ASSERT_TRUE(result.HasValue());
        EXPECT_EQ(expectedStatus, result.Value());
    }
    EXPECT_EQ("UserHomeDirectoryPermissions", indicators.Back().procedureName);
    const auto& children = indicators.Back().children;
    ASSERT_EQ(outcomes.size(), children.size());
    for (size_t i = 0; i < outcomes.size(); ++i)
    {
        EXPECT_EQ("EnsureFilePermissions", children[i]->procedureName);
        if (outcomes[i] == "error")
        {
            EXPECT_TRUE(children[i]->indicators.empty());
            continue;
        }
        const auto status = outcomes[i] == "bad" ? Status::NonCompliant : Status::Compliant;
        EXPECT_EQ(status, children[i]->status);
        ASSERT_EQ(1U, children[i]->indicators.size());
        EXPECT_EQ(status, children[i]->indicators[0].status);
    }
}
} // namespace

TEST(UserHomeDirectoryPermissionsErrorsTest, NonCompliantChildRemainsNonCompliant)
{
    CheckHomeRemediationResults({"bad"}, Status::NonCompliant);
}

TEST(UserHomeDirectoryPermissionsErrorsTest, MixedChildrenRemainNonCompliantInEitherOrder)
{
    CheckHomeRemediationResults({"bad", "good"}, Status::NonCompliant);
    CheckHomeRemediationResults({"good", "bad"}, Status::NonCompliant);
}

TEST(UserHomeDirectoryPermissionsErrorsTest, AllCompliantChildrenRemainCompliant)
{
    CheckHomeRemediationResults({"good", "good"}, Status::Compliant);
}

TEST(UserHomeDirectoryPermissionsErrorsTest, ErrorAfterNonCompliantChildPropagates)
{
    CheckHomeRemediationResults({"bad", "error"}, Status::NonCompliant, true);
}
