// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <FileObjectCollector.h>
#include <MockContext.h>
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <gtest/gtest.h>
#include <ranges/Count.hpp>
#include <ranges/Unique.hpp>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <vector>

using ComplianceEngine::FileCollectionPolicy;
using ComplianceEngine::RootSymlinkPolicy;
using testing::_;
using testing::NiceMock;
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

TEST(FileObjectCollectorTest, DefaultContextOpenRejectsCreationAndWriteFlags)
{
    NiceMock<MockContext> context;
    const auto path = context.MakeTempfile("nameserver unchanged\n");
    const auto missing = context.GetTempdirPath() + "/missing";
    for (const int flags : {O_WRONLY, O_RDWR, O_TRUNC, O_CREAT, O_TMPFILE})
    {
        errno = 0;
        EXPECT_EQ(-1, context.ContextInterface::OpenExistingFile(path.c_str(), flags));
        EXPECT_EQ(EINVAL, errno);
    }
    errno = 0;
    EXPECT_EQ(-1, context.ContextInterface::OpenExistingFile(missing.c_str(), O_CREAT | O_RDONLY));
    EXPECT_EQ(EINVAL, errno);
    EXPECT_NE(0, ::access(missing.c_str(), F_OK));

    errno = 0;
    EXPECT_EQ(-1, context.ContextInterface::OpenExistingFile(missing.c_str(), O_RDONLY | O_CLOEXEC));
    EXPECT_EQ(ENOENT, errno);

    const auto result = ComplianceEngine::CollectNameserverObject(context, path);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ((std::vector<std::string>{"unchanged"}), Captures(result.Value()));
}

TEST(FileObjectCollectorTest, ProjectsSelectedCapturesWithoutLosingBytesOrDuplicates)
{
    NiceMock<MockContext> context;
    std::string content =
        " nameserver ignored\n"
        "nameserver 192.0.2.1 # retained\r\n"
        "nameserver 192.0.2.1 # retained\r\n"
        "nameserver \n  198.51.100.1\n"
        "nameserver ";
    content += std::string("\x80", 1);
    content += "\nnameserver ";
    const auto path = context.MakeTempfile(content);

    const auto result = ComplianceEngine::CollectNameserverObject(context, path);

    ASSERT_TRUE(result.HasValue());
    EXPECT_TRUE(result.Value().complete);
    EXPECT_EQ((std::vector<std::string>{"192.0.2.1 # retained\r", "192.0.2.1 # retained\r", "198.51.100.1", std::string("\x80", 1), ""}),
        Captures(result.Value()));
}

TEST(FileObjectCollectorTest, NulAfterValidCapturePreventsSelectionAndClosesBothDescriptors)
{
    NiceMock<MockContext> context;
    for (const auto& suffix : {std::string("\0nameserver later\n", 18), std::string("nameserver a\0b\n", 15), std::string("nameserver last\0", 16)})
    {
        const auto path = context.MakeTempfile("nameserver valid\n" + suffix);
        int closes = 0;
        ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([&](int fd) {
            ++closes;
            return context.ContextInterface::CloseFileDescriptor(fd);
        });
        const auto result = ComplianceEngine::CollectNameserverObject(context, path);
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ(EBADMSG, result.Error().code);
        EXPECT_EQ(2, closes);
    }
}

TEST(FileObjectCollectorTest, NulErrorRemainsPrimaryWhenClosingFails)
{
    NiceMock<MockContext> context;
    const auto path = context.MakeTempfile(std::string("nameserver valid\n") + std::string("nameserver a\0b\n", 15));
    int closes = 0;
    ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([&](int fd) {
        ++closes;
        context.ContextInterface::CloseFileDescriptor(fd);
        if (closes == 1)
        {
            errno = EACCES;
            return -1;
        }
        return 0;
    });
    const auto result = ComplianceEngine::CollectNameserverObject(context, path);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EBADMSG, result.Error().code);
    EXPECT_NE(std::string::npos, result.Error().message.find("close:"));
    EXPECT_EQ(2, closes);
}

TEST(FileObjectCollectorTest, ZeroMatchesRemainACompleteEmptyCollection)
{
    NiceMock<MockContext> context;
    const auto path = context.MakeTempfile("# no nameservers\n");

    const auto result = ComplianceEngine::CollectNameserverObject(context, path);

    ASSERT_TRUE(result.HasValue());
    EXPECT_TRUE(result.Value().complete);
    EXPECT_TRUE(result.Value().items.empty());
}

TEST(FileObjectCollectorTest, ContentAndCaptureLimitsFailWithoutPartialPublication)
{
    NiceMock<MockContext> context;
    const auto path = context.MakeTempfile("nameserver one\nnameserver two\n");

    FileCollectionPolicy contentLimit;
    contentLimit.contentBytes = 4;
    auto result = ComplianceEngine::CollectNameserverObject(context, path, contentLimit);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(E2BIG, result.Error().code);

    FileCollectionPolicy aggregateLimit;
    aggregateLimit.capturedBytes = 5;
    result = ComplianceEngine::CollectNameserverObject(context, path, aggregateLimit);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(E2BIG, result.Error().code);

    FileCollectionPolicy valueLimit;
    valueLimit.values = 1;
    result = ComplianceEngine::CollectNameserverObject(context, path, valueLimit);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(E2BIG, result.Error().code);

    FileCollectionPolicy exactContentLimit;
    exactContentLimit.contentBytes = std::string("nameserver one\nnameserver two\n").size();
    result = ComplianceEngine::CollectNameserverObject(context, path, exactContentLimit);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ((std::vector<std::string>{"one", "two"}), Captures(result.Value()));

    FileCollectionPolicy occurrenceLimit;
    occurrenceLimit.occurrences = 1;
    result = ComplianceEngine::CollectNameserverObject(context, path, occurrenceLimit);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(E2BIG, result.Error().code);

    FileCollectionPolicy captureLimit;
    captureLimit.captureBytes = 2;
    result = ComplianceEngine::CollectNameserverObject(context, path, captureLimit);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(E2BIG, result.Error().code);
}

TEST(FileObjectCollectorTest, SelectionFailureDefersToLaterReadError)
{
    NiceMock<MockContext> context;
    int opens = 0;
    int reads = 0;
    ON_CALL(context, OpenExistingFile(_, _)).WillByDefault([&](const char*, int) { return ++opens == 1 ? 10 : 11; });
    ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([](int, struct stat* metadata) {
        *metadata = {};
        metadata->st_mode = S_IFREG | 0600;
        metadata->st_dev = 1;
        metadata->st_ino = 2;
        return 0;
    });
    ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([&](int, void* buffer, std::size_t size) -> ssize_t {
        if (reads++ == 0)
        {
            const std::string content = "nameserver too-long\n";
            const auto count = std::min(size, content.size());
            std::memcpy(buffer, content.data(), count);
            return static_cast<ssize_t>(count);
        }
        errno = EIO;
        return -1;
    });
    ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([](int) { return 0; });
    FileCollectionPolicy policy;
    policy.captureBytes = 1;

    const auto result = ComplianceEngine::CollectNameserverObject(context, "/etc/resolv.conf", policy);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EIO, result.Error().code);
    EXPECT_EQ(2, reads);
}

TEST(FileObjectCollectorTest, SelectionFailureDefersToExplicitCloseError)
{
    NiceMock<MockContext> context;
    const auto path = context.MakeTempfile("nameserver too-long\n");
    int closes = 0;
    ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([&](int descriptor) {
        ++closes;
        context.ContextInterface::CloseFileDescriptor(descriptor);
        if (closes == 1)
        {
            errno = EACCES;
            return -1;
        }
        return 0;
    });
    FileCollectionPolicy policy;
    policy.captureBytes = 1;

    const auto result = ComplianceEngine::CollectNameserverObject(context, path, policy);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EACCES, result.Error().code);
    EXPECT_EQ(2, closes);
}

TEST(FileObjectCollectorTest, RejectPolicyRefusesFinalSymlink)
{
    NiceMock<MockContext> context;
    const auto target = context.MakeTempfile("nameserver 192.0.2.1\n");
    const auto link = context.GetTempdirPath() + "/resolv.conf";
    ASSERT_EQ(0, ::symlink(target.c_str(), link.c_str()));

    auto followed = ComplianceEngine::CollectNameserverObject(context, link);
    ASSERT_TRUE(followed.HasValue());
    EXPECT_EQ((std::vector<std::string>{"192.0.2.1"}), Captures(followed.Value()));

    FileCollectionPolicy policy;
    policy.rootSymlinks = RootSymlinkPolicy::Reject;
    const auto rejected = ComplianceEngine::CollectNameserverObject(context, link, policy);
    ASSERT_FALSE(rejected.HasValue());
    EXPECT_EQ(ELOOP, rejected.Error().code);
}

TEST(FileObjectCollectorTest, NonregularTargetIsRejected)
{
    NiceMock<MockContext> context;
    const auto result = ComplianceEngine::CollectNameserverObject(context, context.GetTempdirPath());
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EINVAL, result.Error().code);
}

TEST(FileObjectCollectorTest, PinnedDescriptorSurvivesPathReplacement)
{
    NiceMock<MockContext> context;
    const auto path = context.MakeTempfile("nameserver original\n");
    const auto pinnedPath = path + ".pinned";
    int opens = 0;
    ON_CALL(context, OpenExistingFile(_, _)).WillByDefault([&](const char* requested, int flags) {
        const int descriptor = context.ContextInterface::OpenExistingFile(requested, flags);
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
    });

    const auto result = ComplianceEngine::CollectNameserverObject(context, path);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ((std::vector<std::string>{"original"}), Captures(result.Value()));
}

TEST(FileObjectCollectorTest, ReadFailureIsAnError)
{
    NiceMock<MockContext> context;
    ON_CALL(context, OpenExistingFile(_, _)).WillByDefault([](const char*, int) { return 10; });
    ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([](int, struct stat* metadata) {
        *metadata = {};
        metadata->st_mode = S_IFREG | 0600;
        metadata->st_dev = 1;
        metadata->st_ino = 2;
        return 0;
    });
    ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([](int, void*, std::size_t) -> ssize_t {
        errno = EIO;
        return -1;
    });
    ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([](int) { return 0; });

    const auto result = ComplianceEngine::CollectNameserverObject(context, "/etc/resolv.conf");

    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EIO, result.Error().code);
}

TEST(FileObjectCollectorTest, RetryExhaustionAndOverreportedReadsAreErrors)
{
    NiceMock<MockContext> context;
    int opens = 0;
    ON_CALL(context, OpenExistingFile(_, _)).WillByDefault([&opens](const char*, int) { return ++opens == 1 ? 10 : 11; });
    ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([](int, struct stat* metadata) {
        *metadata = {};
        metadata->st_mode = S_IFREG | 0600;
        metadata->st_dev = 1;
        metadata->st_ino = 2;
        return 0;
    });
    ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([](int) { return 0; });
    ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([](int, void*, std::size_t) -> ssize_t {
        errno = EINTR;
        return -1;
    });
    FileCollectionPolicy limits;
    limits.readRetries = 1;
    auto result = ComplianceEngine::CollectNameserverObject(context, "/etc/resolv.conf", limits);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(E2BIG, result.Error().code);

    opens = 0;
    ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([](int, void*, std::size_t size) -> ssize_t { return static_cast<ssize_t>(size + 1); });
    result = ComplianceEngine::CollectNameserverObject(context, "/etc/resolv.conf");
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EIO, result.Error().code);
}

TEST(FileObjectCollectorTest, InterruptedReadCanRecoverWithinTheRetryLimit)
{
    NiceMock<MockContext> context;
    const std::string content = "nameserver recovered\n";
    int opens = 0;
    int reads = 0;
    ON_CALL(context, OpenExistingFile(_, _)).WillByDefault([&opens](const char*, int) { return ++opens == 1 ? 10 : 11; });
    ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([&content](int, struct stat* metadata) {
        *metadata = {};
        metadata->st_mode = S_IFREG | 0600;
        metadata->st_dev = 1;
        metadata->st_ino = 2;
        metadata->st_size = static_cast<off_t>(content.size());
        return 0;
    });
    ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([&content, &reads](int, void* buffer, std::size_t size) -> ssize_t {
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
    });
    ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([](int) { return 0; });
    FileCollectionPolicy limits;
    limits.readRetries = 1;

    const auto result = ComplianceEngine::CollectNameserverObject(context, "/etc/resolv.conf", limits);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ((std::vector<std::string>{"recovered"}), Captures(result.Value()));
    EXPECT_EQ(3, reads);
}

TEST(FileObjectCollectorTest, MetadataMutationAndThrowingOperationsAreErrors)
{
    NiceMock<MockContext> context;
    int opens = 0;
    int stats = 0;
    ON_CALL(context, OpenExistingFile(_, _)).WillByDefault([&opens](const char*, int) { return ++opens == 1 ? 10 : 11; });
    ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([&stats](int, struct stat* metadata) {
        *metadata = {};
        metadata->st_mode = S_IFREG | 0600;
        metadata->st_dev = 1;
        metadata->st_ino = 2;
        if (stats++ == 2)
        {
            metadata->st_mtim.tv_nsec = 1;
        }
        return 0;
    });
    ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([](int, void*, std::size_t) -> ssize_t { return 0; });
    ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([](int) { return 0; });
    auto result = ComplianceEngine::CollectNameserverObject(context, "/etc/resolv.conf");
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EAGAIN, result.Error().code);

    NiceMock<MockContext> throwing;
    ON_CALL(throwing, OpenExistingFile(_, _)).WillByDefault([](const char*, int) -> int { throw std::runtime_error("open failed"); });
    result = ComplianceEngine::CollectNameserverObject(throwing, "/etc/resolv.conf");
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EIO, result.Error().code);
}

TEST(FileObjectCollectorTest, TailReadAndIdentityFailuresAreErrors)
{
    NiceMock<MockContext> context;
    int opens = 0;
    ON_CALL(context, OpenExistingFile(_, _)).WillByDefault([&opens](const char*, int) { return ++opens == 1 ? 10 : 11; });
    ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([](int descriptor, struct stat* metadata) {
        *metadata = {};
        metadata->st_mode = S_IFREG | 0600;
        metadata->st_dev = 1;
        metadata->st_ino = descriptor == 10 ? 2 : 3;
        return 0;
    });
    ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([](int, void*, std::size_t) -> ssize_t { return 0; });
    ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([](int) { return 0; });

    auto result = ComplianceEngine::CollectNameserverObject(context, "/etc/resolv.conf");
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EAGAIN, result.Error().code);

    opens = 0;
    const std::string content = "nameserver one\n";
    int reads = 0;
    ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([&content](int, struct stat* metadata) {
        *metadata = {};
        metadata->st_mode = S_IFREG | 0600;
        metadata->st_dev = 1;
        metadata->st_ino = 2;
        metadata->st_size = static_cast<off_t>(content.size());
        return 0;
    });
    ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([&content, &reads](int, void* buffer, std::size_t size) -> ssize_t {
        if (reads++ == 0)
        {
            const std::size_t copied = std::min(size, content.size());
            std::memcpy(buffer, content.data(), copied);
            return static_cast<ssize_t>(copied);
        }
        errno = EIO;
        return -1;
    });
    result = ComplianceEngine::CollectNameserverObject(context, "/etc/resolv.conf");
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EIO, result.Error().code);
}

TEST(FileObjectCollectorTest, CloseFailureIsAnError)
{
    NiceMock<MockContext> context;
    int opens = 0;
    ON_CALL(context, OpenExistingFile(_, _)).WillByDefault([&opens](const char*, int) { return ++opens == 1 ? 10 : 11; });
    ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([](int, struct stat* metadata) {
        *metadata = {};
        metadata->st_mode = S_IFREG | 0600;
        metadata->st_dev = 1;
        metadata->st_ino = 2;
        return 0;
    });
    ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([](int, void*, std::size_t) -> ssize_t { return 0; });
    ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([](int descriptor) {
        if (descriptor == 11)
        {
            errno = EIO;
            return -1;
        }
        return 0;
    });

    const auto result = ComplianceEngine::CollectNameserverObject(context, "/etc/resolv.conf");

    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EIO, result.Error().code);
}

TEST(FileObjectCollectorTest, ValidCapturesAreNotPublishedWhenFinalCloseFails)
{
    NiceMock<MockContext> context;
    const auto path = context.MakeTempfile("nameserver retained\n");
    int closes = 0;
    ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([&](int fd) {
        ++closes;
        context.ContextInterface::CloseFileDescriptor(fd);
        if (closes == 2)
        {
            errno = EACCES;
            return -1;
        }
        return 0;
    });
    auto result = ComplianceEngine::CollectNameserverObject(context, path);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EACCES, result.Error().code);
    EXPECT_EQ(2, closes);
}

TEST(FileObjectCollectorTest, PinCloseFailureAndReadFailureFinalizeBothDescriptorsOnce)
{
    NiceMock<MockContext> context;
    int opens = 0;
    int pinCloses = 0;
    int dataCloses = 0;
    bool failRead = false;
    ON_CALL(context, OpenExistingFile(_, _)).WillByDefault([&](const char*, int) { return ++opens % 2 ? 10 : 11; });
    ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([](int, struct stat* metadata) {
        *metadata = {};
        metadata->st_mode = S_IFREG | 0600;
        metadata->st_dev = 1;
        metadata->st_ino = 2;
        return 0;
    });
    ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([&](int, void*, std::size_t) -> ssize_t {
        if (failRead)
        {
            errno = EACCES;
            return -1;
        }
        return 0;
    });
    ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([&](int descriptor) {
        if (descriptor == 11)
        {
            ++dataCloses;
            errno = EBADF;
            return -1;
        }
        ++pinCloses;
        errno = EIO;
        return -1;
    });
    auto result = ComplianceEngine::CollectNameserverObject(context, "/etc/resolv.conf");
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EBADF, result.Error().code);
    EXPECT_EQ(1, pinCloses);
    EXPECT_EQ(1, dataCloses);

    failRead = true;
    result = ComplianceEngine::CollectNameserverObject(context, "/etc/resolv.conf");
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EACCES, result.Error().code);
    EXPECT_EQ(2, pinCloses);
    EXPECT_EQ(2, dataCloses);
}

TEST(FileObjectCollectorTest, FailedDataOpenFinalizesPinWithoutReopeningPath)
{
    NiceMock<MockContext> context;
    int opens = 0;
    int pinCloses = 0;
    ON_CALL(context, OpenExistingFile(_, _)).WillByDefault([&](const char* path, int) {
        if (++opens == 1)
        {
            EXPECT_STREQ("/etc/resolv.conf", path);
            return 10;
        }
        EXPECT_EQ(0U, std::string(path).find("/proc/self/fd/"));
        errno = EACCES;
        return -1;
    });
    ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([](int, struct stat* metadata) {
        *metadata = {};
        metadata->st_mode = S_IFREG | 0600;
        return 0;
    });
    ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([&](int descriptor) {
        EXPECT_EQ(10, descriptor);
        ++pinCloses;
        return 0;
    });
    const auto result = ComplianceEngine::CollectNameserverObject(context, "/etc/resolv.conf");
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EACCES, result.Error().code);
    EXPECT_EQ(2, opens);
    EXPECT_EQ(1, pinCloses);
}

TEST(FileObjectCollectorTest, ReportsCleanupFailuresOnEveryAcquiredFailureExit)
{
    enum class FailurePoint
    {
        PinStat,
        Nonregular,
        DataOpen,
        DataStat,
        Identity,
        Read
    };
    for (const auto failure :
        {FailurePoint::PinStat, FailurePoint::Nonregular, FailurePoint::DataOpen, FailurePoint::DataStat, FailurePoint::Identity, FailurePoint::Read})
    {
        NiceMock<MockContext> context;
        int pinCloses = 0;
        int dataCloses = 0;
        int opens = 0;
        ON_CALL(context, OpenExistingFile(_, _)).WillByDefault([&](const char*, int) {
            if (++opens == 1)
                return 10;
            if (failure == FailurePoint::DataOpen)
            {
                errno = EACCES;
                return -1;
            }
            return 11;
        });
        ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([&](int descriptor, struct stat* metadata) {
            if ((failure == FailurePoint::PinStat && descriptor == 10) || (failure == FailurePoint::DataStat && descriptor == 11))
            {
                errno = EACCES;
                return -1;
            }
            *metadata = {};
            metadata->st_mode = failure == FailurePoint::Nonregular ? S_IFDIR : S_IFREG;
            metadata->st_dev = 1;
            metadata->st_ino = failure == FailurePoint::Identity && descriptor == 11 ? 3 : 2;
            return 0;
        });
        ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([](int, void*, std::size_t) -> ssize_t {
            errno = EACCES;
            return -1;
        });
        ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([&](int descriptor) {
            if (descriptor == 11)
            {
                ++dataCloses;
                errno = EBADF;
            }
            else
            {
                ++pinCloses;
                errno = EIO;
            }
            return -1;
        });
        const auto result = ComplianceEngine::CollectNameserverObject(context, "/etc/resolv.conf");
        ASSERT_FALSE(result.HasValue());
        const int primary = failure == FailurePoint::Identity ? EAGAIN : failure == FailurePoint::Nonregular ? EINVAL : EACCES;
        EXPECT_EQ(primary, result.Error().code);
        EXPECT_EQ(1, pinCloses);
        EXPECT_EQ(opens == 2 && failure != FailurePoint::DataOpen ? 1 : 0, dataCloses);
        if (dataCloses)
        {
            EXPECT_NE(std::string::npos, result.Error().message.find("data close: " + std::to_string(EBADF)));
        }
        EXPECT_NE(std::string::npos, result.Error().message.find("pin close: " + std::to_string(EIO)));
    }
}

TEST(FileObjectCollectorTest, DataClosePrimaryStillReportsPinCloseSecondary)
{
    NiceMock<MockContext> context;
    int opens = 0;
    int pinCloses = 0;
    int dataCloses = 0;
    ON_CALL(context, OpenExistingFile(_, _)).WillByDefault([&](const char*, int) { return ++opens == 1 ? 10 : 11; });
    ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([](int, struct stat* metadata) {
        *metadata = {};
        metadata->st_mode = S_IFREG;
        metadata->st_dev = 1;
        metadata->st_ino = 2;
        return 0;
    });
    ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([](int, void*, std::size_t) -> ssize_t { return 0; });
    ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([&](int fd) {
        if (fd == 11)
        {
            ++dataCloses;
            errno = EBADF;
        }
        else
        {
            ++pinCloses;
            errno = EIO;
        }
        return -1;
    });
    const auto result = ComplianceEngine::CollectNameserverObject(context, "/etc/resolv.conf");
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EBADF, result.Error().code);
    EXPECT_NE(std::string::npos, result.Error().message.find("pin close: " + std::to_string(EIO)));
    EXPECT_EQ(1, pinCloses);
    EXPECT_EQ(1, dataCloses);
}

TEST(FileObjectCollectorTest, ReadFailureReportsEachDescriptorCleanupIndependently)
{
    for (const int failingDescriptor : {10, 11})
    {
        NiceMock<MockContext> context;
        int opens = 0;
        int pinCloses = 0;
        int dataCloses = 0;
        ON_CALL(context, OpenExistingFile(_, _)).WillByDefault([&](const char*, int) { return ++opens == 1 ? 10 : 11; });
        ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([](int, struct stat* metadata) {
            *metadata = {};
            metadata->st_mode = S_IFREG;
            metadata->st_dev = 1;
            metadata->st_ino = 2;
            return 0;
        });
        ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([](int, void*, std::size_t) -> ssize_t {
            errno = EACCES;
            return -1;
        });
        ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([&](int fd) {
            ++(fd == 10 ? pinCloses : dataCloses);
            if (fd == failingDescriptor)
            {
                errno = fd == 10 ? EIO : EBADF;
                return -1;
            }

            return 0;
        });
        const auto result = ComplianceEngine::CollectNameserverObject(context, "/etc/resolv.conf");
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ(EACCES, result.Error().code);
        EXPECT_EQ(1, pinCloses);
        EXPECT_EQ(1, dataCloses);
        EXPECT_NE(std::string::npos,
            result.Error().message.find(failingDescriptor == 10 ? "pin close: " + std::to_string(EIO) : "data close: " + std::to_string(EBADF)));
    }
}

TEST(FileObjectCollectorTest, ReadFailureSurvivesThrowingCloseOnBothDescriptors)
{
    NiceMock<MockContext> context;
    int opens = 0;
    int dataCloses = 0;
    int pinCloses = 0;
    ON_CALL(context, OpenExistingFile(_, _)).WillByDefault([&](const char*, int) { return ++opens == 1 ? 10 : 11; });
    ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([](int, struct stat* metadata) {
        *metadata = {};
        metadata->st_mode = S_IFREG;
        metadata->st_dev = 1;
        metadata->st_ino = 2;
        return 0;
    });
    ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([](int, void*, std::size_t) -> ssize_t {
        errno = EACCES;
        return -1;
    });
    ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([&](int fd) -> int {
        ++(fd == 10 ? pinCloses : dataCloses);
        throw std::bad_alloc();
    });
    const auto result = ComplianceEngine::CollectNameserverObject(context, "/etc/resolv.conf");
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EACCES, result.Error().code);
    EXPECT_NE(std::string::npos, result.Error().message.find("data close: " + std::to_string(EIO)));
    EXPECT_NE(std::string::npos, result.Error().message.find("pin close: " + std::to_string(EIO)));
    EXPECT_EQ(1, dataCloses);
    EXPECT_EQ(1, pinCloses);
}

TEST(FileObjectCollectorTest, RejectsEmbeddedNulAndInvalidInputsBeforeOpening)
{
    NiceMock<MockContext> context;
    int opens = 0;
    ON_CALL(context, OpenExistingFile(_, _)).WillByDefault([&opens](const char*, int) {
        ++opens;
        return -1;
    });

    const std::string embeddedNul("/etc/resolv.conf\0/decoy", 23);
    auto result = ComplianceEngine::CollectNameserverObject(context, embeddedNul);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EINVAL, result.Error().code);

    FileCollectionPolicy invalidPolicy;
    invalidPolicy.rootSymlinks = static_cast<RootSymlinkPolicy>(2);
    result = ComplianceEngine::CollectNameserverObject(context, "/etc/resolv.conf", invalidPolicy);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EINVAL, result.Error().code);

    FileCollectionPolicy invalidLimits;
    invalidLimits.readRetries = 0;
    result = ComplianceEngine::CollectNameserverObject(context, "/etc/resolv.conf", invalidLimits);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EINVAL, result.Error().code);
    EXPECT_EQ(0, opens);

    NiceMock<MockContext> failedOpen;
    ON_CALL(failedOpen, OpenExistingFile(_, _)).WillByDefault([](const char*, int) {
        errno = EACCES;
        return -1;
    });
    result = ComplianceEngine::CollectNameserverObject(failedOpen, "/etc/resolv.conf");
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EACCES, result.Error().code);
}

TEST(FileObjectCollectorTest, PrematureEofWithStableMetadataIsAnError)
{
    NiceMock<MockContext> context;
    int opens = 0;
    ON_CALL(context, OpenExistingFile(_, _)).WillByDefault([&opens](const char*, int) { return ++opens == 1 ? 10 : 11; });
    ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([](int descriptor, struct stat* metadata) {
        *metadata = {};
        metadata->st_mode = S_IFREG | 0600;
        metadata->st_dev = 1;
        metadata->st_ino = 2;
        metadata->st_size = 20;
        return descriptor == 10 || descriptor == 11 ? 0 : -1;
    });
    ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([](int, void*, std::size_t) -> ssize_t { return 0; });
    ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([](int) { return 0; });

    const auto result = ComplianceEngine::CollectNameserverObject(context, "/etc/resolv.conf");

    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EIO, result.Error().code);
    EXPECT_EQ(2, opens);
}

TEST(FileObjectCollectorTest, ResolverPipelineCountsDistinctNameservers)
{
    NiceMock<MockContext> context;
    const auto path = context.MakeTempfile("nameserver one\nnameserver one\nnameserver two\n");
    auto collection = ComplianceEngine::CollectNameserverObject(context, path);
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
