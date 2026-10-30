// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "Evaluator.h"

#include "JsonWrapper.h"
#include "MockContext.h"
#include "parson.h"

#include <UserDotFilePermissions.h>
#include <cerrno>
#include <fstream>
#include <gtest/gtest.h>
#include <sys/stat.h>

using ComplianceEngine::action_func_t;
using ComplianceEngine::Error;
using ComplianceEngine::Evaluator;
using ComplianceEngine::JsonWrapper;
using ComplianceEngine::NestedListFormatter;
using ComplianceEngine::Result;
using ComplianceEngine::Status;

class EvaluatorTest : public ::testing::Test
{
protected:
    std::map<std::string, std::string> mParameters;
    MockContext mContext;
    ComplianceEngine::DebugFormatter mFormatter;
};

TEST_F(EvaluatorTest, UserDotFileRemediationIsDisabledWithoutChangingFiles)
{
    const auto& actions = Evaluator::mProcedureMap.at("UserDotFilePermissions");
    ASSERT_TRUE(actions.audit);
    ASSERT_TRUE(actions.remediate); // A null handler would fall back to audit in remediation mode.

    const std::string file = mContext.MakeTempfile("unchanged\n");
    ASSERT_EQ(0, chmod(file.c_str(), 0666));
    struct stat before = {}, after = {};
    ASSERT_EQ(0, stat(file.c_str(), &before));

    ComplianceEngine::IndicatorsTree indicators;
    indicators.Push("UserDotFilePermissions");
    const auto direct = ComplianceEngine::RemediateUserDotFilePermissions(indicators, mContext);
    ASSERT_FALSE(direct.HasValue());
    EXPECT_EQ(ENOTSUP, direct.Error().code);
    EXPECT_EQ("UserDotFilePermissions remediation is disabled", direct.Error().message);
    EXPECT_TRUE(indicators.Back().indicators.empty());

    auto json = JsonWrapper::FromString("{\"UserDotFilePermissions\":{}}");
    ASSERT_TRUE(json.HasValue());
    Evaluator evaluator("test", json_value_get_object(json->get()), mParameters, mContext);
    const auto result = evaluator.ExecuteRemediation();
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(ENOTSUP, result.Error().code);
    EXPECT_EQ("UserDotFilePermissions remediation is disabled", result.Error().message);
    ASSERT_EQ(0, stat(file.c_str(), &after));
    EXPECT_EQ(before.st_mode, after.st_mode);
    EXPECT_EQ(before.st_uid, after.st_uid);
    EXPECT_EQ(before.st_gid, after.st_gid);
}

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

TEST_F(EvaluatorTest, NestedListFormatter_AllOfPreservesFailuresAfterCompliantLimit)
{
    auto json = JsonWrapper::FromString(R"({"allOf":[
        {"AuditSuccess":{"message":"pass 1"}},
        {"AuditSuccess":{"message":"pass 2"}},
        {"AuditSuccess":{"message":"pass 3"}},
        {"AuditNotApplicable":{"message":"not applicable before limit"}},
        {"AuditSuccess":{"message":"pass 4"}},
        {"AuditSuccess":{"message":"pass 5"}},
        {"AuditSuccess":{"message":"pass 6"}},
        {"AuditSuccess":{"message":"pass 7"}},
        {"AuditNotApplicable":{"message":"not applicable after limit"}},
        {"not":{"AuditSuccess":{"message":"inner passed"}}}
    ]})");
    ASSERT_TRUE(json.HasValue());
    Evaluator evaluator("rule", json_value_get_object(json->get()), mParameters, mContext);
    const NestedListFormatter formatter;

    const auto result = evaluator.ExecuteAudit(formatter);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::NonCompliant, result.Value().status);
    const auto& output = result.Value().payload;
    EXPECT_NE(std::string::npos, output.find("✅ pass 1"));
    EXPECT_NE(std::string::npos, output.find("✅ pass 2"));
    EXPECT_NE(std::string::npos, output.find("✅ pass 3"));
    EXPECT_NE(std::string::npos, output.find("✅ pass 4"));
    EXPECT_NE(std::string::npos, output.find("✅ pass 5"));
    EXPECT_EQ(std::string::npos, output.find("pass 6"));
    EXPECT_EQ(std::string::npos, output.find("pass 7"));
    EXPECT_NE(std::string::npos, output.find("➖ AuditNotApplicable\n\t\t\t➖ not applicable before limit"));
    EXPECT_NE(std::string::npos, output.find("➖ AuditNotApplicable\n\t\t\t➖ not applicable after limit"));
    EXPECT_NE(std::string::npos, output.find("❌ not\n\t\t\t✓ AuditSuccess\n\t\t\t\t✓ inner passed"));
    EXPECT_LT(output.find("not applicable after limit"), output.find("❌ not"));
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
