// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <ExactFileObjectCollector.h>
#include <MockContext.h>
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <gtest/gtest.h>
#include <ranges/Count.hpp>
#include <ranges/Unique.hpp>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <vector>

using ComplianceEngine::ExactFileCollectionLimits;
using ComplianceEngine::RootSymlinkPolicy;
using ComplianceEngine::Detail::ExactFileOperations;
namespace VariableResolution = ComplianceEngine::VariableResolution;

namespace
{
std::vector<std::string> Captures(const VariableResolution::ObjectCollection& collection)
{
    std::vector<std::string> captures;
    for (const auto& item : collection.items)
    {
        const auto field = item.fields.find("subexpression");
        if (field != item.fields.end())
        {
            captures.insert(captures.end(), field->second.begin(), field->second.end());
        }
    }
    return captures;
}
} // namespace

TEST(ExactFileObjectCollectorTest, NameserverSelectionPreservesSourceBytesAndOrder)
{
    MockContext context;
    std::string content =
        " nameserver ignored\n"
        "nameserver 192.0.2.1 # retained\r\n"
        "nameserver \n  198.51.100.1\n"
        "nameserver ";
    content += std::string("\0\x80", 2);
    content += "\nnameserver ";
    const auto path = context.MakeTempfile(content);

    const auto result = ComplianceEngine::CollectNameserverObject(path);

    ASSERT_TRUE(result.HasValue());
    EXPECT_TRUE(result.Value().complete);
    EXPECT_EQ((std::vector<std::string>{"192.0.2.1 # retained\r", "198.51.100.1", std::string("\0\x80", 2), ""}), Captures(result.Value()));
}

TEST(ExactFileObjectCollectorTest, ZeroMatchesRemainACompleteEmptyCollection)
{
    MockContext context;
    const auto path = context.MakeTempfile("# no nameservers\n");

    const auto result = ComplianceEngine::CollectNameserverObject(path);

    ASSERT_TRUE(result.HasValue());
    EXPECT_TRUE(result.Value().complete);
    EXPECT_TRUE(result.Value().items.empty());
}

TEST(ExactFileObjectCollectorTest, ContentAndCaptureLimitsFailWithoutPartialPublication)
{
    MockContext context;
    const auto path = context.MakeTempfile("nameserver one\nnameserver two\n");

    ExactFileCollectionLimits contentLimit;
    contentLimit.contentBytes = 4;
    auto result = ComplianceEngine::CollectNameserverObject(path, contentLimit);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(E2BIG, result.Error().code);

    ExactFileCollectionLimits aggregateLimit;
    aggregateLimit.capturedBytes = 5;
    result = ComplianceEngine::CollectNameserverObject(path, aggregateLimit);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(E2BIG, result.Error().code);

    ExactFileCollectionLimits valueLimit;
    valueLimit.values = 1;
    result = ComplianceEngine::CollectNameserverObject(path, valueLimit);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(E2BIG, result.Error().code);

    ExactFileCollectionLimits exactContentLimit;
    exactContentLimit.contentBytes = std::string("nameserver one\nnameserver two\n").size();
    result = ComplianceEngine::CollectNameserverObject(path, exactContentLimit);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ((std::vector<std::string>{"one", "two"}), Captures(result.Value()));

    ExactFileCollectionLimits occurrenceLimit;
    occurrenceLimit.occurrences = 1;
    result = ComplianceEngine::CollectNameserverObject(path, occurrenceLimit);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(E2BIG, result.Error().code);

    ExactFileCollectionLimits captureLimit;
    captureLimit.captureBytes = 2;
    result = ComplianceEngine::CollectNameserverObject(path, captureLimit);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(E2BIG, result.Error().code);
}

TEST(ExactFileObjectCollectorTest, RejectPolicyRefusesFinalSymlink)
{
    MockContext context;
    const auto target = context.MakeTempfile("nameserver 192.0.2.1\n");
    const auto link = context.GetTempdirPath() + "/resolv.conf";
    ASSERT_EQ(0, ::symlink(target.c_str(), link.c_str()));

    auto followed = ComplianceEngine::CollectNameserverObject(link);
    ASSERT_TRUE(followed.HasValue());
    EXPECT_EQ((std::vector<std::string>{"192.0.2.1"}), Captures(followed.Value()));

    const auto rejected = ComplianceEngine::CollectNameserverObject(link, {}, RootSymlinkPolicy::Reject);
    ASSERT_FALSE(rejected.HasValue());
    EXPECT_EQ(ELOOP, rejected.Error().code);
}

TEST(ExactFileObjectCollectorTest, NonregularTargetIsRejected)
{
    MockContext context;
    const auto result = ComplianceEngine::CollectNameserverObject(context.GetTempdirPath());
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EINVAL, result.Error().code);
}

TEST(ExactFileObjectCollectorTest, PinnedDescriptorSurvivesPathReplacement)
{
    MockContext context;
    const auto path = context.MakeTempfile("nameserver original\n");
    const auto pinnedPath = path + ".pinned";
    ExactFileOperations operations;
    const auto openPath = operations.openPath;
    int opens = 0;
    operations.openPath = [&](const char* requested, int flags) {
        const int descriptor = openPath(requested, flags);
        if (opens++ == 0 && descriptor >= 0)
        {
            EXPECT_EQ(path, requested);
            EXPECT_EQ(0, ::rename(path.c_str(), pinnedPath.c_str()));
            std::ofstream replacement(path);
            replacement << "nameserver replacement\n";
        }
        else if (descriptor >= 0)
        {
            EXPECT_EQ(0U, std::string(requested).find("/proc/self/fd/"));
        }
        return descriptor;
    };

    const auto result = ComplianceEngine::Detail::CollectNameserverObjectWithOperations(path, {}, RootSymlinkPolicy::FollowRegular, operations);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ((std::vector<std::string>{"original"}), Captures(result.Value()));
}

TEST(ExactFileObjectCollectorTest, ReadFailureIsAnError)
{
    ExactFileOperations operations;
    operations.openPath = [](const char*, int) { return 10; };
    operations.statDescriptor = [](int, struct stat* metadata) {
        *metadata = {};
        metadata->st_mode = S_IFREG | 0600;
        metadata->st_dev = 1;
        metadata->st_ino = 2;
        return 0;
    };
    operations.readDescriptor = [](int, void*, std::size_t) -> ssize_t {
        errno = EIO;
        return -1;
    };
    operations.closeDescriptor = [](int) { return 0; };

    const auto result = ComplianceEngine::Detail::CollectNameserverObjectWithOperations("/etc/resolv.conf", {}, RootSymlinkPolicy::FollowRegular, operations);

    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EIO, result.Error().code);
}

TEST(ExactFileObjectCollectorTest, RetryExhaustionAndOverreportedReadsAreErrors)
{
    ExactFileOperations operations;
    int opens = 0;
    operations.openPath = [&opens](const char*, int) { return ++opens == 1 ? 10 : 11; };
    operations.statDescriptor = [](int, struct stat* metadata) {
        *metadata = {};
        metadata->st_mode = S_IFREG | 0600;
        metadata->st_dev = 1;
        metadata->st_ino = 2;
        return 0;
    };
    operations.closeDescriptor = [](int) { return 0; };
    operations.readDescriptor = [](int, void*, std::size_t) -> ssize_t {
        errno = EINTR;
        return -1;
    };
    ExactFileCollectionLimits limits;
    limits.readRetries = 1;
    auto result = ComplianceEngine::Detail::CollectNameserverObjectWithOperations("/etc/resolv.conf", limits, RootSymlinkPolicy::FollowRegular, operations);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(E2BIG, result.Error().code);

    opens = 0;
    operations.readDescriptor = [](int, void*, std::size_t size) -> ssize_t { return static_cast<ssize_t>(size + 1); };
    result = ComplianceEngine::Detail::CollectNameserverObjectWithOperations("/etc/resolv.conf", {}, RootSymlinkPolicy::FollowRegular, operations);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EIO, result.Error().code);
}

TEST(ExactFileObjectCollectorTest, InterruptedReadCanRecoverWithinTheRetryLimit)
{
    ExactFileOperations operations;
    const std::string content = "nameserver recovered\n";
    int opens = 0;
    int reads = 0;
    operations.openPath = [&opens](const char*, int) { return ++opens == 1 ? 10 : 11; };
    operations.statDescriptor = [&content](int, struct stat* metadata) {
        *metadata = {};
        metadata->st_mode = S_IFREG | 0600;
        metadata->st_dev = 1;
        metadata->st_ino = 2;
        metadata->st_size = static_cast<off_t>(content.size());
        return 0;
    };
    operations.readDescriptor = [&content, &reads](int, void* buffer, std::size_t size) -> ssize_t {
        if (reads++ == 0)
        {
            errno = EINTR;
            return -1;
        }
        if (reads == 2)
        {
            const std::size_t copied = std::min(size, content.size());
            std::memcpy(buffer, content.data(), copied);
            return static_cast<ssize_t>(copied);
        }
        return 0;
    };
    operations.closeDescriptor = [](int) { return 0; };
    ExactFileCollectionLimits limits;
    limits.readRetries = 1;

    const auto result = ComplianceEngine::Detail::CollectNameserverObjectWithOperations("/etc/resolv.conf", limits, RootSymlinkPolicy::FollowRegular, operations);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ((std::vector<std::string>{"recovered"}), Captures(result.Value()));
    EXPECT_EQ(3, reads);
}

TEST(ExactFileObjectCollectorTest, MetadataMutationAndThrowingOperationsAreErrors)
{
    ExactFileOperations operations;
    int opens = 0;
    int stats = 0;
    operations.openPath = [&opens](const char*, int) { return ++opens == 1 ? 10 : 11; };
    operations.statDescriptor = [&stats](int, struct stat* metadata) {
        *metadata = {};
        metadata->st_mode = S_IFREG | 0600;
        metadata->st_dev = 1;
        metadata->st_ino = 2;
        if (stats++ == 2)
        {
            metadata->st_mtim.tv_nsec = 1;
        }
        return 0;
    };
    operations.readDescriptor = [](int, void*, std::size_t) -> ssize_t { return 0; };
    operations.closeDescriptor = [](int) { return 0; };
    auto result = ComplianceEngine::Detail::CollectNameserverObjectWithOperations("/etc/resolv.conf", {}, RootSymlinkPolicy::FollowRegular, operations);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EAGAIN, result.Error().code);

    ExactFileOperations throwing;
    throwing.openPath = [](const char*, int) -> int { throw std::runtime_error("open failed"); };
    result = ComplianceEngine::Detail::CollectNameserverObjectWithOperations("/etc/resolv.conf", {}, RootSymlinkPolicy::FollowRegular, throwing);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EIO, result.Error().code);
}

TEST(ExactFileObjectCollectorTest, TailReadAndIdentityFailuresAreErrors)
{
    ExactFileOperations operations;
    int opens = 0;
    operations.openPath = [&opens](const char*, int) { return ++opens == 1 ? 10 : 11; };
    operations.statDescriptor = [](int descriptor, struct stat* metadata) {
        *metadata = {};
        metadata->st_mode = S_IFREG | 0600;
        metadata->st_dev = 1;
        metadata->st_ino = descriptor == 10 ? 2 : 3;
        return 0;
    };
    operations.readDescriptor = [](int, void*, std::size_t) -> ssize_t { return 0; };
    operations.closeDescriptor = [](int) { return 0; };

    auto result = ComplianceEngine::Detail::CollectNameserverObjectWithOperations("/etc/resolv.conf", {}, RootSymlinkPolicy::FollowRegular, operations);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EAGAIN, result.Error().code);

    opens = 0;
    const std::string content = "nameserver one\n";
    int reads = 0;
    operations.statDescriptor = [&content](int, struct stat* metadata) {
        *metadata = {};
        metadata->st_mode = S_IFREG | 0600;
        metadata->st_dev = 1;
        metadata->st_ino = 2;
        metadata->st_size = static_cast<off_t>(content.size());
        return 0;
    };
    operations.readDescriptor = [&content, &reads](int, void* buffer, std::size_t size) -> ssize_t {
        if (reads++ == 0)
        {
            const std::size_t copied = std::min(size, content.size());
            std::memcpy(buffer, content.data(), copied);
            return static_cast<ssize_t>(copied);
        }
        errno = EIO;
        return -1;
    };
    result = ComplianceEngine::Detail::CollectNameserverObjectWithOperations("/etc/resolv.conf", {}, RootSymlinkPolicy::FollowRegular, operations);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EIO, result.Error().code);
}

TEST(ExactFileObjectCollectorTest, CloseFailureIsAnError)
{
    ExactFileOperations operations;
    int opens = 0;
    operations.openPath = [&opens](const char*, int) { return ++opens == 1 ? 10 : 11; };
    operations.statDescriptor = [](int, struct stat* metadata) {
        *metadata = {};
        metadata->st_mode = S_IFREG | 0600;
        metadata->st_dev = 1;
        metadata->st_ino = 2;
        return 0;
    };
    operations.readDescriptor = [](int, void*, std::size_t) -> ssize_t { return 0; };
    operations.closeDescriptor = [](int descriptor) {
        if (descriptor == 11)
        {
            errno = EIO;
            return -1;
        }
        return 0;
    };

    const auto result = ComplianceEngine::Detail::CollectNameserverObjectWithOperations("/etc/resolv.conf", {}, RootSymlinkPolicy::FollowRegular, operations);

    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EIO, result.Error().code);
}

TEST(ExactFileObjectCollectorTest, RejectsEmbeddedNulAndInvalidInputsBeforeOpening)
{
    ExactFileOperations operations;
    int opens = 0;
    operations.openPath = [&opens](const char*, int) {
        ++opens;
        return -1;
    };

    const std::string embeddedNul("/etc/resolv.conf\0/decoy", 23);
    auto result = ComplianceEngine::Detail::CollectNameserverObjectWithOperations(embeddedNul, {}, RootSymlinkPolicy::FollowRegular, operations);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EINVAL, result.Error().code);

    result = ComplianceEngine::Detail::CollectNameserverObjectWithOperations("/etc/resolv.conf", {}, static_cast<RootSymlinkPolicy>(2), operations);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EINVAL, result.Error().code);

    ExactFileCollectionLimits invalidLimits;
    invalidLimits.readRetries = 0;
    result = ComplianceEngine::Detail::CollectNameserverObjectWithOperations("/etc/resolv.conf", invalidLimits, RootSymlinkPolicy::FollowRegular, operations);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EINVAL, result.Error().code);
    EXPECT_EQ(0, opens);

    ExactFileOperations incomplete;
    incomplete.readDescriptor = {};
    result = ComplianceEngine::Detail::CollectNameserverObjectWithOperations("/etc/resolv.conf", {}, RootSymlinkPolicy::FollowRegular, incomplete);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EINVAL, result.Error().code);

    ExactFileOperations failedOpen;
    failedOpen.openPath = [](const char*, int) {
        errno = EACCES;
        return -1;
    };
    result = ComplianceEngine::Detail::CollectNameserverObjectWithOperations("/etc/resolv.conf", {}, RootSymlinkPolicy::FollowRegular, failedOpen);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EACCES, result.Error().code);
}

TEST(ExactFileObjectCollectorTest, PrematureEofWithStableMetadataIsAnError)
{
    ExactFileOperations operations;
    int opens = 0;
    operations.openPath = [&opens](const char*, int) { return ++opens == 1 ? 10 : 11; };
    operations.statDescriptor = [](int descriptor, struct stat* metadata) {
        *metadata = {};
        metadata->st_mode = S_IFREG | 0600;
        metadata->st_dev = 1;
        metadata->st_ino = 2;
        metadata->st_size = 20;
        return descriptor == 10 || descriptor == 11 ? 0 : -1;
    };
    operations.readDescriptor = [](int, void*, std::size_t) -> ssize_t { return 0; };
    operations.closeDescriptor = [](int) { return 0; };

    const auto result = ComplianceEngine::Detail::CollectNameserverObjectWithOperations("/etc/resolv.conf", {}, RootSymlinkPolicy::FollowRegular, operations);

    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EIO, result.Error().code);
    EXPECT_EQ(2, opens);
}

TEST(ExactFileObjectCollectorTest, ResolverPipelineCountsDistinctNameservers)
{
    MockContext context;
    const auto path = context.MakeTempfile("nameserver one\nnameserver one\nnameserver two\n");
    auto collection = ComplianceEngine::CollectNameserverObject(path);
    ASSERT_TRUE(collection.HasValue());

    namespace Ranges = ComplianceEngine::Ranges;
    const auto count = Ranges::Count(VariableResolution::ObjectFieldRange(collection.Value(), "object:1", "subexpression"));
    ASSERT_TRUE(count.HasValue());
    EXPECT_EQ(3U, count.Value());
    const auto distinct = Ranges::Count(Ranges::Unique(VariableResolution::ObjectFieldRange(collection.Value(), "object:1", "subexpression")));
    ASSERT_TRUE(distinct.HasValue());
    EXPECT_EQ(2U, distinct.Value());
    const auto passing = ComplianceEngine::CompareTyped(distinct.Value(), std::size_t{2}, ComplianceEngine::TypedComparisonOperation::GreaterOrEqual);
    ASSERT_TRUE(passing.HasValue());
    EXPECT_TRUE(passing.Value());
}
