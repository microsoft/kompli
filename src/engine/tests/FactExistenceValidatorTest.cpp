// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "FactExistenceValidator.h"

#include <gtest/gtest.h>

using Kompli::Error;
using Kompli::FactExistenceValidator;
using Kompli::Result;

class FactExistenceValidatorTest : public ::testing::Test
{
};

TEST_F(FactExistenceValidatorTest, MapBehavior)
{
    auto result = Kompli::FactExistenceValidator::MapBehavior("all_exist");
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Kompli::FactExistenceValidator::Behavior::AllExist);

    result = Kompli::FactExistenceValidator::MapBehavior("any_exist");
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Kompli::FactExistenceValidator::Behavior::AnyExist);

    result = Kompli::FactExistenceValidator::MapBehavior("at_least_one_exists");
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Kompli::FactExistenceValidator::Behavior::AtLeastOneExists);

    result = Kompli::FactExistenceValidator::MapBehavior("none_exist");
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Kompli::FactExistenceValidator::Behavior::NoneExist);

    result = Kompli::FactExistenceValidator::MapBehavior("only_one_exists");
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Kompli::FactExistenceValidator::Behavior::OnlyOneExists);

    result = Kompli::FactExistenceValidator::MapBehavior("invalid_value");
    ASSERT_FALSE(result.HasValue());
}

TEST_F(FactExistenceValidatorTest, AllExist_1)
{
    FactExistenceValidator validator(Kompli::FactExistenceValidator::Behavior::AllExist);
    ASSERT_FALSE(validator.Done());
    validator.Finish();
    ASSERT_TRUE(validator.Done());
    ASSERT_EQ(validator.Result(), Kompli::Status::Compliant);

    // Already done, Finish should not affact the state
    validator.Finish();
    ASSERT_TRUE(validator.Done());
    ASSERT_EQ(validator.Result(), Kompli::Status::Compliant);
}

TEST_F(FactExistenceValidatorTest, AllExist_2)
{
    FactExistenceValidator validator(Kompli::FactExistenceValidator::Behavior::AllExist);
    ASSERT_FALSE(validator.Done());
    validator.CriteriaMet();
    ASSERT_FALSE(validator.Done());
    validator.CriteriaMet();
    ASSERT_FALSE(validator.Done());
    validator.Finish();
    ASSERT_TRUE(validator.Done());
    ASSERT_EQ(validator.Result(), Kompli::Status::Compliant);
    // Already done, should not change state anymore
    validator.CriteriaUnmet();
    ASSERT_EQ(validator.Result(), Kompli::Status::Compliant);
}

TEST_F(FactExistenceValidatorTest, AllExist_3)
{
    FactExistenceValidator validator(Kompli::FactExistenceValidator::Behavior::AllExist);
    ASSERT_FALSE(validator.Done());
    validator.CriteriaUnmet();
    ASSERT_TRUE(validator.Done());
    ASSERT_EQ(validator.Result(), Kompli::Status::NonCompliant);
}

TEST_F(FactExistenceValidatorTest, AnyExist_1)
{
    FactExistenceValidator validator(Kompli::FactExistenceValidator::Behavior::AnyExist);
    ASSERT_FALSE(validator.Done());
    validator.Finish();
    ASSERT_TRUE(validator.Done());
    ASSERT_EQ(validator.Result(), Kompli::Status::Compliant);
}

TEST_F(FactExistenceValidatorTest, AnyExist_2)
{
    FactExistenceValidator validator(Kompli::FactExistenceValidator::Behavior::AnyExist);
    ASSERT_FALSE(validator.Done());
    validator.CriteriaUnmet();
    ASSERT_FALSE(validator.Done());
    validator.CriteriaUnmet();
    ASSERT_FALSE(validator.Done());
    validator.Finish();
    ASSERT_TRUE(validator.Done());
    ASSERT_EQ(validator.Result(), Kompli::Status::Compliant);
}

TEST_F(FactExistenceValidatorTest, AnyExist_3)
{
    FactExistenceValidator validator(Kompli::FactExistenceValidator::Behavior::AnyExist);
    ASSERT_FALSE(validator.Done());
    validator.CriteriaMet();
    ASSERT_TRUE(validator.Done());
    ASSERT_EQ(validator.Result(), Kompli::Status::Compliant);
}

TEST_F(FactExistenceValidatorTest, AtLeastOneExists_1)
{
    FactExistenceValidator validator(Kompli::FactExistenceValidator::Behavior::AtLeastOneExists);
    ASSERT_FALSE(validator.Done());
    validator.Finish();
    ASSERT_TRUE(validator.Done());
    ASSERT_EQ(validator.Result(), Kompli::Status::NonCompliant);
}

TEST_F(FactExistenceValidatorTest, AtLeastOneExists_2)
{
    FactExistenceValidator validator(Kompli::FactExistenceValidator::Behavior::AtLeastOneExists);
    ASSERT_FALSE(validator.Done());
    validator.CriteriaUnmet();
    ASSERT_FALSE(validator.Done());
    validator.CriteriaUnmet();
    ASSERT_FALSE(validator.Done());
    validator.Finish();
    ASSERT_TRUE(validator.Done());
    ASSERT_EQ(validator.Result(), Kompli::Status::NonCompliant);
    // Already done, should not change state anymore
    validator.CriteriaMet();
    ASSERT_EQ(validator.Result(), Kompli::Status::NonCompliant);
}

TEST_F(FactExistenceValidatorTest, AtLeastOneExists_3)
{
    FactExistenceValidator validator(Kompli::FactExistenceValidator::Behavior::AtLeastOneExists);
    ASSERT_FALSE(validator.Done());
    validator.CriteriaMet();
    ASSERT_TRUE(validator.Done());
    ASSERT_EQ(validator.Result(), Kompli::Status::Compliant);
    // Already done, should not change state anymore
    validator.CriteriaMet();
    ASSERT_EQ(validator.Result(), Kompli::Status::Compliant);
}

TEST_F(FactExistenceValidatorTest, NoneExist_1)
{
    FactExistenceValidator validator(Kompli::FactExistenceValidator::Behavior::NoneExist);
    ASSERT_FALSE(validator.Done());
    validator.Finish();
    ASSERT_TRUE(validator.Done());
    ASSERT_EQ(validator.Result(), Kompli::Status::Compliant);
}

TEST_F(FactExistenceValidatorTest, NoneExist_2)
{
    FactExistenceValidator validator(Kompli::FactExistenceValidator::Behavior::NoneExist);
    ASSERT_FALSE(validator.Done());
    validator.CriteriaMet();
    ASSERT_TRUE(validator.Done());
    ASSERT_EQ(validator.Result(), Kompli::Status::NonCompliant);
}

TEST_F(FactExistenceValidatorTest, NoneExist_3)
{
    FactExistenceValidator validator(Kompli::FactExistenceValidator::Behavior::NoneExist);
    ASSERT_FALSE(validator.Done());
    validator.CriteriaUnmet();
    ASSERT_TRUE(validator.Done());
    validator.CriteriaUnmet();
    ASSERT_TRUE(validator.Done());
    validator.Finish();
    ASSERT_TRUE(validator.Done());
    ASSERT_EQ(validator.Result(), Kompli::Status::Compliant);
    // Already done, should not change state anymore
    validator.CriteriaMet();
    ASSERT_EQ(validator.Result(), Kompli::Status::Compliant);
}

TEST_F(FactExistenceValidatorTest, OnlyOneExists_1)
{
    FactExistenceValidator validator(Kompli::FactExistenceValidator::Behavior::OnlyOneExists);
    ASSERT_FALSE(validator.Done());
    validator.Finish();
    ASSERT_TRUE(validator.Done());
    ASSERT_EQ(validator.Result(), Kompli::Status::NonCompliant);
}

TEST_F(FactExistenceValidatorTest, OnlyOneExists_2)
{
    FactExistenceValidator validator(Kompli::FactExistenceValidator::Behavior::OnlyOneExists);
    ASSERT_FALSE(validator.Done());
    validator.CriteriaUnmet();
    ASSERT_FALSE(validator.Done());
    validator.CriteriaMet();
    ASSERT_FALSE(validator.Done());
    validator.CriteriaUnmet();
    ASSERT_FALSE(validator.Done());
    validator.Finish();
    ASSERT_TRUE(validator.Done());
    ASSERT_EQ(validator.Result(), Kompli::Status::Compliant);
    // Already done, should not change state anymore
    validator.CriteriaMet();
    ASSERT_EQ(validator.Result(), Kompli::Status::Compliant);
}

TEST_F(FactExistenceValidatorTest, OnlyOneExists_3)
{
    FactExistenceValidator validator(Kompli::FactExistenceValidator::Behavior::OnlyOneExists);
    ASSERT_FALSE(validator.Done());
    validator.CriteriaUnmet();
    ASSERT_FALSE(validator.Done());
    validator.CriteriaMet();
    ASSERT_FALSE(validator.Done());
    validator.CriteriaMet();
    ASSERT_TRUE(validator.Done());
    ASSERT_EQ(validator.Result(), Kompli::Status::NonCompliant);
}
