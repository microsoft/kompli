// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <PasswdGroupsExist.h>
#include <cerrno>
#include <cstring>
#include <functional>
#include <gtest/gtest.h>
#include <memory>
#include <vector>

using ComplianceEngine::EvaluatePasswdGroupsExist;
using ComplianceEngine::IndicatorsTree;
using ComplianceEngine::Status;

namespace
{
// Builds a getgrent()-style enumerator: returns each fixture entry in turn, then nullptr with
// `endErrno` set. 0 and ENOENT both simulate a conforming backend's normal end of enumeration
// (see EvaluatePasswdGroupsExist); any other value simulates a genuine enumeration failure.
std::function<struct group*()> MakeGroupEnumerator(std::shared_ptr<std::vector<struct group>> entries, int endErrno)
{
    auto index = std::make_shared<std::size_t>(0);
    return [entries, index, endErrno]() -> struct group*
    {
        if (*index < entries->size())
        {
            return &(*entries)[(*index)++];
        }
        errno = endErrno;
        return nullptr;
    };
}

// Same contract as MakeGroupEnumerator, for getpwent().
std::function<struct passwd*()> MakePasswdEnumerator(std::shared_ptr<std::vector<struct passwd>> entries, int endErrno)
{
    auto index = std::make_shared<std::size_t>(0);
    return [entries, index, endErrno]() -> struct passwd*
    {
        if (*index < entries->size())
        {
            return &(*entries)[(*index)++];
        }
        errno = endErrno;
        return nullptr;
    };
}

struct group MakeGroup(gid_t gid)
{
    struct group g
    {
    };
    g.gr_gid = gid;
    return g;
}

struct passwd MakeUser(const char* name, gid_t gid)
{
    struct passwd p
    {
    };
    p.pw_name = const_cast<char*>(name);
    p.pw_gid = gid;
    return p;
}

std::function<void()> NoOp()
{
    return []() {};
}
} // namespace

class PasswdGroupsExistTest : public ::testing::Test
{
protected:
    IndicatorsTree mIndicators;

    void SetUp() override
    {
        mIndicators.Push("PasswdGroupsExist");
    }

    // Runs EvaluatePasswdGroupsExist with the given fixture entries and end-of-enumeration errno
    // for each loop; begin/end hooks (setgrent/endgrent, setpwent/endpwent equivalents) are no-ops.
    ComplianceEngine::Result<Status> Evaluate(std::vector<struct group> groups, int groupEndErrno, std::vector<struct passwd> users, int userEndErrno)
    {
        auto groupEntries = std::make_shared<std::vector<struct group>>(std::move(groups));
        auto userEntries = std::make_shared<std::vector<struct passwd>>(std::move(users));
        return EvaluatePasswdGroupsExist(mIndicators, NoOp(), MakeGroupEnumerator(groupEntries, groupEndErrno), NoOp(), NoOp(),
            MakePasswdEnumerator(userEntries, userEndErrno), NoOp());
    }
};

TEST_F(PasswdGroupsExistTest, EnumerationEndingWithEnoentIsCompliant)
{
    // Matches the evidenced `aad` NSS backend, which ends both group and passwd enumeration with
    // errno ENOENT; this must be treated as a normal end, not an error.
    auto result = Evaluate({MakeGroup(1000)}, ENOENT, {MakeUser("alice", 1000)}, ENOENT);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());
}

TEST_F(PasswdGroupsExistTest, EnumerationEndingWithZeroErrnoIsCompliant)
{
    // Matches the `files`/`systemd` NSS backends, which leave errno untouched (0) at EOF.
    auto result = Evaluate({MakeGroup(1000)}, 0, {MakeUser("alice", 1000)}, 0);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());
}

TEST_F(PasswdGroupsExistTest, UserGroupMissingFromGroupsIsNonCompliant)
{
    // The passwd loop still ends normally with ENOENT; the user's GID simply isn't present among
    // the enumerated groups, which must still be detected and reported as NonCompliant.
    auto result = Evaluate({MakeGroup(1000)}, ENOENT, {MakeUser("alice", 2000)}, ENOENT);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::NonCompliant, result.Value());
}

TEST_F(PasswdGroupsExistTest, GroupEnumerationFailurePropagatesErrorCode)
{
    auto result = Evaluate({MakeGroup(1000)}, EIO, {MakeUser("alice", 1000)}, ENOENT);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EIO, result.Error().code);
}

TEST_F(PasswdGroupsExistTest, PasswdEnumerationFailurePropagatesErrorCode)
{
    auto result = Evaluate({MakeGroup(1000)}, ENOENT, {MakeUser("alice", 1000)}, EIO);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EIO, result.Error().code);
}
