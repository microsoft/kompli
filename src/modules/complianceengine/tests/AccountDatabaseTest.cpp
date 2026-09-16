// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "MockContext.h"

TEST(AccountDatabaseTest, LoadsBothDatabasesOncePerContext)
{
    MockContext context;
    context.SetAccountDatabaseRecords({{"first", 1000, 2000, "/home/first", "/bin/bash"}}, {{"first-group", 2000}});

    auto& database = context.GetAccountDatabase();
    auto firstUser = database.FindUserByName("first");
    ASSERT_TRUE(firstUser.HasValue());
    ASSERT_NE(firstUser.Value(), nullptr);
    EXPECT_EQ(firstUser.Value()->uid, 1000);

    context.SetAccountDatabaseRecords({{"second", 1001, 2001, "/home/second", "/bin/sh"}}, {{"second-group", 2001}});

    auto firstGroup = database.FindGroupById(2000);
    ASSERT_TRUE(firstGroup.HasValue());
    ASSERT_NE(firstGroup.Value(), nullptr);
    EXPECT_EQ(firstGroup.Value()->name, "first-group");

    auto secondUser = database.FindUserByName("second");
    ASSERT_TRUE(secondUser.HasValue());
    EXPECT_EQ(secondUser.Value(), nullptr);
}

TEST(AccountDatabaseTest, ReturnsLoadErrorForMissingDatabase)
{
    MockContext context;
    context.SetAccountDatabaseError(ComplianceEngine::Error("NSS enumeration failed", EIO));

    auto users = context.GetAccountDatabase().GetUsers();

    ASSERT_FALSE(users.HasValue());
    EXPECT_EQ(users.Error().code, EIO);
}
