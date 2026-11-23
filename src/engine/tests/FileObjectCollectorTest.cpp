// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <DescriptorTestAccess.h>
#include <FileObjectCollector.h>
#include <MockContext.h>
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <filesystem/Descriptor.hpp>
#include <fstream>
#include <gtest/gtest.h>
#include <iterator>
#include <new>
#include <ranges/Count.hpp>
#include <ranges/Unique.hpp>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <type_traits>
#include <unistd.h>
#include <vector>

using ComplianceEngine::FileCollectionPolicy;
using ComplianceEngine::Filesystem::SymlinkPolicy;
using ComplianceEngine::Tests::DescriptorTestAccess;
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
std::string ReadLog(const std::string& path)
{
    std::ifstream log(path);
    EXPECT_TRUE(log.is_open());
    return {std::istreambuf_iterator<char>(log), std::istreambuf_iterator<char>()};
}

void ExpectLoggedOnce(const std::string& text, const std::string& entry)
{
    const auto first = text.find(entry);
    ASSERT_NE(std::string::npos, first);
    EXPECT_EQ(std::string::npos, text.find(entry, first + entry.size()));
}

// Inspect live descriptors before closing them: the resolver also owns
// ancestor/procfs helpers, whose descriptor numbers and close order vary.
bool IsFixture(int fd, const std::string& path, bool data)
{
    struct stat held = {}, fixture = {};
    const int flags = ::fcntl(fd, F_GETFL);
    return flags >= 0 && ::fstat(fd, &held) == 0 && ::stat(path.c_str(), &fixture) == 0 && S_ISREG(held.st_mode) && held.st_dev == fixture.st_dev &&
           held.st_ino == fixture.st_ino && (data ? !(flags & O_PATH) && (flags & O_ACCMODE) == O_RDONLY : (flags & O_PATH) != 0);
}

bool IsLinkPin(int fd, const std::string& path)
{
    struct stat held = {}, link = {};
    return ::fstat(fd, &held) == 0 && ::lstat(path.c_str(), &link) == 0 && S_ISLNK(held.st_mode) && held.st_dev == link.st_dev && held.st_ino == link.st_ino;
}

bool IsAliasDirectory(int fd, const ComplianceEngine::ContextInterface& context)
{
    struct stat held = {}, procfs = {};
    const auto task = DescriptorTestAccess::CurrentThreadId(context);
    if (!task.HasValue())
        return false;
    // The verified alias belongs to the current task, not /proc/self/fd.
    const auto path = "/proc/self/task/" + std::to_string(task.Value()) + "/fd";
    return ::fstat(fd, &held) == 0 && ::stat(path.c_str(), &procfs) == 0 && held.st_dev == procfs.st_dev && held.st_ino == procfs.st_ino;
}

bool IsFixtureParent(int fd, const std::string& path)
{
    struct stat held = {}, parent = {};
    const auto slash = path.find_last_of('/');
    return slash != std::string::npos && ::fstat(fd, &held) == 0 && ::stat(path.substr(0, slash).c_str(), &parent) == 0 &&
           held.st_dev == parent.st_dev && held.st_ino == parent.st_ino;
}
} // namespace

TEST(FileObjectCollectorTest, TypedContextOpenRejectsUnsupportedProfilesWithoutDispatch)
{
    NiceMock<MockContext> context;
    const auto path = context.MakeTempfile("nameserver 192.0.2.1\n");
    const auto missing = context.GetTempdirPath() + "/missing";
    using Profile = ComplianceEngine::ContextInterface::OpenProfile;
    static_assert(!std::is_convertible<int, Profile>::value, "Native open flags must not be a typed profile");
    auto directory = DescriptorTestAccess::OpenAbsolutePin(context, context.GetTempdirPath().c_str());
    ASSERT_TRUE(directory.HasValue());
    EXPECT_CALL(context, OpenNativeAt(testing::_, testing::_, testing::_)).Times(0);
    for (const int flags : {O_WRONLY, O_RDWR, O_TRUNC, O_CREAT, O_TMPFILE})
    {
        const auto rejected = DescriptorTestAccess::OpenAt(context, directory.Value(), "missing", static_cast<Profile>(flags | 0x10000));
        ASSERT_FALSE(rejected.HasValue());
        EXPECT_EQ(EINVAL, rejected.Error().code);
    }
    EXPECT_NE(0, ::access(missing.c_str(), F_OK));

    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    const auto restricted = DescriptorTestAccess::OpenAt(context, directory.Value(), "missing", Profile::ReadFdinfo);
    ASSERT_FALSE(restricted.HasValue());
    EXPECT_EQ(EINVAL, restricted.Error().code);

    const auto result = ComplianceEngine::CollectNameserverObject(context, path);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ((std::vector<std::string>{"192.0.2.1"}), Captures(result.Value()));
}

TEST(FileObjectCollectorTest, ProjectsOrderedAddressTokensWithoutCanonicalDeduplication)
{
    NiceMock<MockContext> context;
    const std::string content =
        "# first-column comment\r\n"
        "; another comment\n"
        "search example.org\r\n"
        "nameserver\t192.0.2.1  \n"
        "nameserver 192.0.2.1\n"
        "nameserver 2001:0db8::1\n"
        "nameserver 2001:db8::1";
    const auto path = context.MakeTempfile(content);

    const auto result = ComplianceEngine::CollectNameserverObject(context, path);

    ASSERT_TRUE(result.HasValue());
    EXPECT_TRUE(result.Value().complete);
    EXPECT_EQ((std::vector<std::string>{"192.0.2.1", "192.0.2.1", "2001:0db8::1", "2001:db8::1"}), Captures(result.Value()));
}

TEST(FileObjectCollectorTest, NulAfterValidCapturePreventsSelectionAndClosesBothDescriptors)
{
    NiceMock<MockContext> context;
    for (const auto& suffix : {std::string("\0nameserver later\n", 18), std::string("nameserver a\0b\n", 15), std::string("nameserver last\0", 16)})
    {
        const auto path = context.MakeTempfile("nameserver valid\n" + suffix);
        int closes = 0;
        ON_CALL(context, CloseNativeDescriptor(_)).WillByDefault([&](int fd) -> ComplianceEngine::Result<void> {
            closes += IsFixture(fd, path, true);
            return context.RealCloseNativeDescriptor(fd);
        });
        const auto result = ComplianceEngine::CollectNameserverObject(context, path);
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ(EBADMSG, result.Error().code);
        EXPECT_EQ(1, closes);
    }
}

TEST(FileObjectCollectorTest, NulErrorRemainsPrimaryWhenClosingFails)
{
    NiceMock<MockContext> context;
    const auto path = context.MakeTempfile(std::string("nameserver valid\n") + std::string("nameserver a\0b\n", 15));
    int closes = 0;
    ON_CALL(context, CloseNativeDescriptor(_)).WillByDefault([&](int fd) -> ComplianceEngine::Result<void> {
        const bool data = IsFixture(fd, path, true);
        context.RealCloseNativeDescriptor(fd);
        if (data)
        {
            ++closes;
            errno = EACCES;
            return ComplianceEngine::Error(errno);
        }
        return ComplianceEngine::Result<void>::Success();
    });
    const auto result = ComplianceEngine::CollectNameserverObject(context, path);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EBADMSG, result.Error().code);
    EXPECT_EQ("Embedded NUL in text file", result.Error().message);
    EXPECT_EQ(1, closes);
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

TEST(FileObjectCollectorTest, MissingNameserverOperandFailsWithOrWithoutFinalLf)
{
    NiceMock<MockContext> context;
    for (const auto& content : {"nameserver ", "nameserver \n", "nameserver \t\n"})
    {
        const auto path = context.MakeTempfile(content);
        const auto result = ComplianceEngine::CollectNameserverObject(context, path);
        ASSERT_FALSE(result.HasValue()) << content;
        EXPECT_EQ(EBADMSG, result.Error().code);
        EXPECT_NE(std::string::npos, result.Error().message.find(path + ": resolv.conf"));
    }
}

TEST(FileObjectCollectorTest, MissingOperandDoesNotCaptureAcrossLines)
{
    NiceMock<MockContext> context;
    const std::string content =
        "# nameserver ignored\n"
        "nameserver \n"
        " \t\n"
        " 198.51.100.1\n"
        "nameserver 192.0.2.1\n";
    const auto path = context.MakeTempfile(content);
    const auto result = ComplianceEngine::CollectNameserverObject(context, path);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EBADMSG, result.Error().code);
    EXPECT_NE(std::string::npos, result.Error().message.find(path + ": resolv.conf"));

    FileCollectionPolicy limit;
    limit.contentBytes = content.size();
    EXPECT_EQ(EBADMSG, ComplianceEngine::CollectNameserverObject(context, path, limit).Error().code);
    --limit.contentBytes;
    EXPECT_EQ(E2BIG, ComplianceEngine::CollectNameserverObject(context, path, limit).Error().code);
}

TEST(FileObjectCollectorTest, MalformedUnrelatedKnownRecordsAlsoFail)
{
    NiceMock<MockContext> context;
    for (const auto& unrelated : {"options ndots:bad\r\n", "sortlist bad/255.0.0.0\n"})
    {
        const auto path = context.MakeTempfile(std::string("nameserver 192.0.2.1\n") + unrelated + "nameserver 2001:db8::1\n");
        const auto rejected = ComplianceEngine::CollectNameserverObject(context, path);
        ASSERT_FALSE(rejected.HasValue()) << unrelated;
        EXPECT_EQ(EBADMSG, rejected.Error().code);
    }
    const auto unknown = context.MakeTempfile("unknown \x80\noptions mystery\nnameserver 192.0.2.1\nnameserver 2001:db8::1\n");
    const auto accepted = ComplianceEngine::CollectNameserverObject(context, unknown);
    ASSERT_TRUE(accepted.HasValue());
    EXPECT_EQ((std::vector<std::string>{"192.0.2.1", "2001:db8::1"}), Captures(accepted.Value()));

    for (const auto& invalid : {"nameserver bad", "nameserver 192.0.2.1\r", "nameserver 192.0.2.1#inline", "nameserver invalid"})
    {
        const auto path = context.MakeTempfile(std::string("nameserver 198.51.100.1\n") + invalid + "\n");
        const auto result = ComplianceEngine::CollectNameserverObject(context, path);
        ASSERT_FALSE(result.HasValue()) << invalid;
        EXPECT_EQ(EBADMSG, result.Error().code) << invalid;
        EXPECT_NE(std::string::npos, result.Error().message.find(path + ": resolv.conf")) << invalid;
    }
}

TEST(FileObjectCollectorTest, GlibcLexingIgnoresUnmatchedLinesAndTrailingNameserverText)
{
    NiceMock<MockContext> context;
    const auto path = context.MakeTempfile(
        " nameserver 192.0.2.99\n"
        "nameserver\n"
        "nameserver\r\n"
        "nameserverx 192.0.2.88\n"
        "search # no inline comment\n"
        "nameserver 192.0.2.1 # ignored; still raw evidence\n"
        "nameserver\t2001:db8::1 ; ignored\n");
    const auto result = ComplianceEngine::CollectNameserverObject(context, path);
    ASSERT_TRUE(result.HasValue());
    EXPECT_TRUE(result.Value().complete);
    EXPECT_EQ((std::vector<std::string>{"192.0.2.1", "2001:db8::1"}), Captures(result.Value()));
}

TEST(FileObjectCollectorTest, ParserLineEntryAndTokenBudgetsRejectUnrelatedContent)
{
    NiceMock<MockContext> context;
    std::string tokenHeavy;
    for (std::size_t i = 0; i < 8191; ++i)
        tokenHeavy += "unknown a b c\n";
    tokenHeavy += "unknown a b c d\n";
    // Neither a valid prefix nor a large valid address can justify silently
    // dropping unrelated lines or tokens.
    for (const auto& content : {std::string("#") + std::string(16384, 'x') + "\nnameserver 192.0.2.1\n", std::string(8193, '\n') + "nameserver 192.0.2.1\n", tokenHeavy})
    {
        const auto path = context.MakeTempfile(content);
        FileCollectionPolicy policy;
        policy.contentBytes = content.size();
        const auto result = ComplianceEngine::CollectNameserverObject(context, path, policy);
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ(E2BIG, result.Error().code);
        EXPECT_NE(std::string::npos, result.Error().message.find("resolv.conf"));
    }
}

TEST(FileObjectCollectorTest, ParserByteBudgetFailsRatherThanPublishPrefix)
{
    NiceMock<MockContext> context;
    std::string bytes;
    for (std::size_t i = 0; i < 65; ++i)
        bytes += "#" + std::string(16382, 'x') + "\n";
    const auto path = context.MakeTempfile(bytes);
    FileCollectionPolicy policy;
    policy.contentBytes = bytes.size();
    const auto exceeded = ComplianceEngine::CollectNameserverObject(context, path, policy);
    ASSERT_FALSE(exceeded.HasValue());
    EXPECT_EQ(E2BIG, exceeded.Error().code);
    EXPECT_NE(std::string::npos, exceeded.Error().message.find("byte limit"));
}

TEST(FileObjectCollectorTest, ContentAndCaptureLimitsFailWithoutPartialPublication)
{
    NiceMock<MockContext> context;
    const std::string content = "nameserver 192.0.2.1\nnameserver 198.51.100.1\n";
    const auto path = context.MakeTempfile(content);

    FileCollectionPolicy contentLimit;
    contentLimit.contentBytes = 4;
    auto result = ComplianceEngine::CollectNameserverObject(context, path, contentLimit);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(E2BIG, result.Error().code);

    FileCollectionPolicy aggregateLimit;
    aggregateLimit.capturedBytes = 15;
    result = ComplianceEngine::CollectNameserverObject(context, path, aggregateLimit);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(E2BIG, result.Error().code);

    FileCollectionPolicy valueLimit;
    valueLimit.values = 1;
    result = ComplianceEngine::CollectNameserverObject(context, path, valueLimit);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(E2BIG, result.Error().code);

    FileCollectionPolicy exactContentLimit;
    exactContentLimit.contentBytes = content.size();
    result = ComplianceEngine::CollectNameserverObject(context, path, exactContentLimit);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ((std::vector<std::string>{"192.0.2.1", "198.51.100.1"}), Captures(result.Value()));

    FileCollectionPolicy occurrenceLimit;
    occurrenceLimit.occurrences = 1;
    result = ComplianceEngine::CollectNameserverObject(context, path, occurrenceLimit);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(E2BIG, result.Error().code);

    FileCollectionPolicy captureLimit;
    captureLimit.captureBytes = 8;
    result = ComplianceEngine::CollectNameserverObject(context, path, captureLimit);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(E2BIG, result.Error().code);
}

TEST(FileObjectCollectorTest, SelectionFailureDefersToLaterReadError)
{
    NiceMock<MockContext> context;
    const auto path = context.MakeTempfile("nameserver 192.0.2.1\n");
    int reads = 0;
    ON_CALL(context, ReadNativeDescriptor(_, _, _)).WillByDefault([&](int fd, void* buffer, std::size_t size) -> ssize_t {
        if (!IsFixture(fd, path, true))
            return context.RealReadNativeDescriptor(fd, buffer, size);
        if (reads++ == 0)
            return context.RealReadNativeDescriptor(fd, buffer, std::min<std::size_t>(size, 21));
        errno = EIO;
        return -1;
    });
    FileCollectionPolicy policy;
    policy.captureBytes = 8;

    const auto result = ComplianceEngine::CollectNameserverObject(context, path, policy);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EIO, result.Error().code);
    EXPECT_EQ(2, reads);
}

TEST(FileObjectCollectorTest, SelectionFailureRemainsPrimaryAfterFailedDisposal)
{
    NiceMock<MockContext> context;
    const auto path = context.MakeTempfile("nameserver 192.0.2.1\n");
    int closes = 0;
    ON_CALL(context, CloseNativeDescriptor(_)).WillByDefault([&](int descriptor) -> ComplianceEngine::Result<void> {
        const bool data = IsFixture(descriptor, path, true);
        context.RealCloseNativeDescriptor(descriptor);
        if (data)
        {
            ++closes;
            errno = EACCES;
            return ComplianceEngine::Error(errno);
        }
        return ComplianceEngine::Result<void>::Success();
    });
    FileCollectionPolicy policy;
    policy.captureBytes = 8;

    const auto result = ComplianceEngine::CollectNameserverObject(context, path, policy);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(E2BIG, result.Error().code);
    EXPECT_EQ(1, closes);
}

TEST(FileObjectCollectorTest, MalformedEvidenceDefersToReachedReadButNotCloseFailures)
{
    NiceMock<MockContext> context;
    const auto path = context.MakeTempfile("nameserver invalid\nnameserver 192.0.2.1\n");
    int dataCloses = 0;
    int reads = 0;
    ON_CALL(context, ReadNativeDescriptor(_, _, _)).WillByDefault([&](int fd, void* buffer, std::size_t size) -> ssize_t {
        if (!IsFixture(fd, path, true))
            return context.RealReadNativeDescriptor(fd, buffer, size);
        if (reads++ == 0)
            return context.RealReadNativeDescriptor(fd, buffer, std::min<std::size_t>(size, 19));
        errno = EIO;
        return -1;
    });
    ON_CALL(context, CloseNativeDescriptor(_)).WillByDefault([&](int fd) -> ComplianceEngine::Result<void> {
        dataCloses += IsFixture(fd, path, true);
        return context.RealCloseNativeDescriptor(fd);
    });
    auto result = ComplianceEngine::CollectNameserverObject(context, path);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EIO, result.Error().code);
    EXPECT_EQ("Failed to read file bytes", result.Error().message);
    EXPECT_EQ(2, reads);
    EXPECT_EQ(1, dataCloses);

    ON_CALL(context, ReadNativeDescriptor(_, _, _)).WillByDefault([&](int fd, void* buffer, std::size_t size) -> ssize_t {
        return context.RealReadNativeDescriptor(fd, buffer, size);
    });
    ON_CALL(context, CloseNativeDescriptor(_)).WillByDefault([&](int fd) -> ComplianceEngine::Result<void> {
        const bool data = IsFixture(fd, path, true);
        context.RealCloseNativeDescriptor(fd);
        if (data)
        {
            ++dataCloses;
            errno = EACCES;
            return ComplianceEngine::Error(errno);
        }
        return ComplianceEngine::Result<void>::Success();
    });
    result = ComplianceEngine::CollectNameserverObject(context, path);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EBADMSG, result.Error().code);
    EXPECT_EQ(2, dataCloses);
}

TEST(FileObjectCollectorTest, PolicyForwardsFollowAndRejectForEveryComponent)
{
    NiceMock<MockContext> context;
    const auto target = context.MakeTempfile("nameserver 192.0.2.1\n");
    const auto directoryLink = context.GetTempdirPath() + "/directory.link";
    const auto finalLink = context.GetTempdirPath() + "/resolv.conf";
    ASSERT_EQ(0, ::symlink(context.GetTempdirPath().c_str(), directoryLink.c_str()));
    ASSERT_EQ(0, ::symlink(target.c_str(), finalLink.c_str()));
    const auto chained = directoryLink + "/resolv.conf";
    int reads = 0, intermediateCloses = 0, finalCloses = 0;
    ON_CALL(context, ReadNativeDescriptor(_, _, _)).WillByDefault([&](int fd, void* buffer, std::size_t size) -> ssize_t {
        reads += IsFixture(fd, target, true);
        return context.RealReadNativeDescriptor(fd, buffer, size);
    });
    ON_CALL(context, CloseNativeDescriptor(_)).WillByDefault([&](int fd) -> ComplianceEngine::Result<void> {
        intermediateCloses += IsLinkPin(fd, directoryLink);
        finalCloses += IsLinkPin(fd, finalLink);
        return context.RealCloseNativeDescriptor(fd);
    });

    auto followed = ComplianceEngine::CollectNameserverObject(context, chained);
    ASSERT_TRUE(followed.HasValue());
    EXPECT_EQ((std::vector<std::string>{"192.0.2.1"}), Captures(followed.Value()));
    EXPECT_GT(reads, 0);
    reads = intermediateCloses = finalCloses = 0;

    FileCollectionPolicy policy;
    policy.symlinks = SymlinkPolicy::DoNotFollow;
    const auto rejected = ComplianceEngine::CollectNameserverObject(context, chained, policy);
    ASSERT_FALSE(rejected.HasValue());
    EXPECT_EQ(ELOOP, rejected.Error().code);
    EXPECT_EQ(0, reads);
    EXPECT_EQ(1, intermediateCloses);
    EXPECT_EQ(0, finalCloses);
    const auto finalRejected = ComplianceEngine::CollectNameserverObject(context, finalLink, policy);
    ASSERT_FALSE(finalRejected.HasValue());
    EXPECT_EQ(ELOOP, finalRejected.Error().code);
    EXPECT_EQ(0, reads);
    EXPECT_EQ(1, intermediateCloses);
    EXPECT_EQ(1, finalCloses);
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
    const auto path = context.MakeTempfile("nameserver 192.0.2.1\n");
    const auto pinnedPath = path + ".pinned";
    int replaced = 0;
    ON_CALL(context, StatNativeDescriptor(_, _)).WillByDefault([&](int fd, struct stat* metadata) {
        const bool pin = IsFixture(fd, path, false);
        const int status = context.RealStatNativeDescriptor(fd, metadata);
        if (pin && status == 0 && !replaced++)
        {
            EXPECT_EQ(0, ::rename(path.c_str(), pinnedPath.c_str()));
            std::ofstream replacement(path);
            replacement << "nameserver 198.51.100.1\n";
        }
        return status;
    });

    const auto result = ComplianceEngine::CollectNameserverObject(context, path);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(1, replaced);
    EXPECT_EQ((std::vector<std::string>{"192.0.2.1"}), Captures(result.Value()));
}

TEST(FileObjectCollectorTest, ReadFailureIsAnError)
{
    NiceMock<MockContext> context;
    const auto path = context.MakeTempfile("nameserver one\n");
    ON_CALL(context, ReadNativeDescriptor(_, _, _)).WillByDefault([&](int fd, void* buffer, std::size_t size) -> ssize_t {
        if (!IsFixture(fd, path, true))
            return context.RealReadNativeDescriptor(fd, buffer, size);
        errno = EIO;
        return -1;
    });
    const auto result = ComplianceEngine::CollectNameserverObject(context, path);

    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EIO, result.Error().code);
}

TEST(FileObjectCollectorTest, RetryExhaustionAndOverreportedReadsAreErrors)
{
    NiceMock<MockContext> context;
    const auto path = context.MakeTempfile("nameserver one\n");
    ON_CALL(context, ReadNativeDescriptor(_, _, _)).WillByDefault([&](int fd, void* buffer, std::size_t size) -> ssize_t {
        if (!IsFixture(fd, path, true))
            return context.RealReadNativeDescriptor(fd, buffer, size);
        errno = EINTR;
        return -1;
    });
    FileCollectionPolicy limits;
    limits.readRetries = 1;
    auto result = ComplianceEngine::CollectNameserverObject(context, path, limits);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(E2BIG, result.Error().code);

    ON_CALL(context, ReadNativeDescriptor(_, _, _)).WillByDefault([&](int fd, void* buffer, std::size_t size) -> ssize_t {
        if (!IsFixture(fd, path, true))
            return context.RealReadNativeDescriptor(fd, buffer, size);
        return static_cast<ssize_t>(size + 1);
    });
    result = ComplianceEngine::CollectNameserverObject(context, path);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EIO, result.Error().code);
}

TEST(FileObjectCollectorTest, InterruptedReadCanRecoverWithinTheRetryLimit)
{
    NiceMock<MockContext> context;
    const std::string content = "nameserver 192.0.2.1\n";
    const auto path = context.MakeTempfile(content);
    int reads = 0;
    ON_CALL(context, ReadNativeDescriptor(_, _, _)).WillByDefault([&](int fd, void* buffer, std::size_t size) -> ssize_t {
        if (!IsFixture(fd, path, true))
            return context.RealReadNativeDescriptor(fd, buffer, size);
        if (reads++ == 0)
        {
            errno = EINTR;
            return -1;
        }
        if (reads == 2)
        {
            return context.RealReadNativeDescriptor(fd, buffer, size);
        }
        return 0;
    });
    FileCollectionPolicy limits;
    limits.readRetries = 1;

    const auto result = ComplianceEngine::CollectNameserverObject(context, path, limits);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ((std::vector<std::string>{"192.0.2.1"}), Captures(result.Value()));
    EXPECT_EQ(3, reads);
}

TEST(FileObjectCollectorTest, MetadataMutationAndFailedNativeOpenReturnErrors)
{
    NiceMock<MockContext> context;
    const auto path = context.MakeTempfile("nameserver one\n");
    int stats = 0;
    ON_CALL(context, StatNativeDescriptor(_, _)).WillByDefault([&](int fd, struct stat* metadata) {
        const int status = context.RealStatNativeDescriptor(fd, metadata);
        if (status == 0 && IsFixture(fd, path, true) && ++stats == 2)
            ++metadata->st_mtim.tv_nsec;
        return status;
    });
    auto result = ComplianceEngine::CollectNameserverObject(context, path);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EAGAIN, result.Error().code);

    NiceMock<MockContext> failingOpen;
    const auto failedPath = failingOpen.MakeTempfile("nameserver one\n");
    const auto basename = failedPath.substr(failedPath.find_last_of("/") + 1);
    int rootOpens = 0;
    int rootFd = -1;
    int targetOpens = 0;
    int parentCloses = 0;
    int parentFd = -1;
    ON_CALL(failingOpen, OpenNativePath(_, _)).WillByDefault([&](const char* name, int flags) {
        const int fd = failingOpen.RealOpenNativePath(name, flags);
        if (std::strcmp(name, "/") == 0)
        {
            ++rootOpens;
            rootFd = fd;
        }
        return fd;
    });
    ON_CALL(failingOpen, OpenNativeAt(_, _, _)).WillByDefault([&](int fd, const char* name, int flags) -> int {
        if (IsFixtureParent(fd, failedPath) && std::strcmp(name, basename.c_str()) == 0)
        {
            ++targetOpens;
            errno = EACCES;
            return -1;
        }
        return failingOpen.RealOpenNativeAt(fd, name, flags);
    });
    ON_CALL(failingOpen, CloseNativeDescriptor(_)).WillByDefault([&](int fd) -> ComplianceEngine::Result<void> {
        if (IsFixtureParent(fd, failedPath))
        {
            ++parentCloses;
            parentFd = fd;
        }
        return failingOpen.RealCloseNativeDescriptor(fd);
    });
    const auto failed = ComplianceEngine::CollectNameserverObject(failingOpen, failedPath);
    ASSERT_FALSE(failed.HasValue());
    EXPECT_EQ(EACCES, failed.Error().code);
    EXPECT_EQ("Cannot pin confined component", failed.Error().message);
    EXPECT_EQ(1, targetOpens);
    EXPECT_EQ(1, rootOpens);
    EXPECT_EQ(1, parentCloses);
    ASSERT_GE(rootFd, 0);
    ASSERT_GE(parentFd, 0);
    EXPECT_EQ(-1, ::fcntl(rootFd, F_GETFD));
    EXPECT_EQ(EBADF, errno);
    EXPECT_EQ(-1, ::fcntl(parentFd, F_GETFD));
    EXPECT_EQ(EBADF, errno);
}

TEST(FileObjectCollectorTest, ReadFailureRemainsPrimaryWhenDataCloseFailsWithoutRetry)
{
    NiceMock<MockContext> context;
    const auto path = context.MakeTempfile("nameserver one\n");
    const auto logPath = context.GetTempdirPath() + "/read-close-failure.log";
    OsConfigLogHandle logHandle = OpenLog(logPath.c_str(), nullptr);
    ASSERT_NE(nullptr, logHandle);
    context.SetLogHandle(logHandle);
    int reads = 0;
    int pinCloses = 0;
    int dataCloses = 0;
    int dataFd = -1;
    ON_CALL(context, ReadNativeDescriptor(_, _, _)).WillByDefault([&](int fd, void* buffer, std::size_t size) -> ssize_t {
        if (!IsFixture(fd, path, true))
            return context.RealReadNativeDescriptor(fd, buffer, size);
        ++reads;
        errno = EACCES;
        return -1;
    });
    ON_CALL(context, CloseNativeDescriptor(_)).WillByDefault([&](int fd) -> ComplianceEngine::Result<void> {
        const bool pin = IsFixture(fd, path, false), data = IsFixture(fd, path, true);
        pinCloses += pin;
        dataCloses += data;
        if (data)
            dataFd = fd;
        auto status = context.RealCloseNativeDescriptor(fd);
        if (data)
        {
            errno = EIO;
            return ComplianceEngine::Error(errno);
        }
        return status;
    });

    const auto result = ComplianceEngine::CollectNameserverObject(context, path);
    CloseLog(&logHandle);
    context.SetLogHandle(nullptr);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EACCES, result.Error().code);
    EXPECT_EQ("Failed to read file bytes", result.Error().message);
    EXPECT_EQ(1, reads);
    EXPECT_EQ(1, pinCloses);
    EXPECT_EQ(1, dataCloses);
    ASSERT_GE(dataFd, 0);
    EXPECT_EQ(-1, ::fcntl(dataFd, F_GETFD));
    EXPECT_EQ(EBADF, errno);
    const auto text = ReadLog(logPath);
    ExpectLoggedOnce(text, "Failed to close filesystem resource: " + std::string(strerror(EIO)));
}

TEST(FileObjectCollectorTest, TailReadAndIdentityFailuresAreErrors)
{
    NiceMock<MockContext> context;
    const auto path = context.MakeTempfile("nameserver one\n");
    ON_CALL(context, StatNativeDescriptor(_, _)).WillByDefault([&](int fd, struct stat* metadata) {
        const int status = context.RealStatNativeDescriptor(fd, metadata);
        if (status == 0 && IsFixture(fd, path, true))
            ++metadata->st_ino;
        return status;
    });
    auto result = ComplianceEngine::CollectNameserverObject(context, path);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EAGAIN, result.Error().code);

    ON_CALL(context, StatNativeDescriptor(_, _)).WillByDefault([&](int fd, struct stat* metadata) {
        return context.RealStatNativeDescriptor(fd, metadata);
    });
    int reads = 0;
    ON_CALL(context, ReadNativeDescriptor(_, _, _)).WillByDefault([&](int fd, void* buffer, std::size_t size) -> ssize_t {
        if (!IsFixture(fd, path, true))
            return context.RealReadNativeDescriptor(fd, buffer, size);
        if (reads++ == 0)
            return context.RealReadNativeDescriptor(fd, buffer, size);
        errno = EIO;
        return -1;
    });
    result = ComplianceEngine::CollectNameserverObject(context, path);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EIO, result.Error().code);
}

TEST(FileObjectCollectorTest, CloseFailureCannotReplaceCompletedEmptyCollection)
{
    NiceMock<MockContext> context;
    const auto path = context.MakeTempfile("# no nameservers\n");
    int dataCloses = 0;
    ON_CALL(context, CloseNativeDescriptor(_)).WillByDefault([&](int descriptor) -> ComplianceEngine::Result<void> {
        const bool data = IsFixture(descriptor, path, true);
        context.RealCloseNativeDescriptor(descriptor);
        if (data)
        {
            ++dataCloses;
            errno = EIO;
            return ComplianceEngine::Error(errno);
        }
        return ComplianceEngine::Result<void>::Success();
    });

    const auto result = ComplianceEngine::CollectNameserverObject(context, path);

    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_TRUE(result->complete);
    EXPECT_EQ(1, dataCloses);
}

TEST(FileObjectCollectorTest, ValidCapturesRemainCompleteWhenFinalCloseFails)
{
    NiceMock<MockContext> context;
    const auto path = context.MakeTempfile("nameserver 192.0.2.1\n");
    int closes = 0;
    ON_CALL(context, CloseNativeDescriptor(_)).WillByDefault([&](int fd) -> ComplianceEngine::Result<void> {
        const bool data = IsFixture(fd, path, true);
        context.RealCloseNativeDescriptor(fd);
        if (data)
        {
            ++closes;
            errno = EACCES;
            return ComplianceEngine::Error(errno);
        }
        return ComplianceEngine::Result<void>::Success();
    });
    auto result = ComplianceEngine::CollectNameserverObject(context, path);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_TRUE(result->complete);
    EXPECT_EQ((std::vector<std::string>{"192.0.2.1"}), Captures(result.Value()));
    EXPECT_EQ(1, closes);
}

TEST(FileObjectCollectorTest, PinCloseFailureDoesNotStopReadAndLaterReadFailureFinalizesBothOnce)
{
    NiceMock<MockContext> context;
    const auto logPath = context.GetTempdirPath() + "/pin-and-read-cleanup.log";
    OsConfigLogHandle logHandle = OpenLog(logPath.c_str(), nullptr);
    ASSERT_NE(nullptr, logHandle);
    context.SetLogHandle(logHandle);
    const auto path = context.MakeTempfile("nameserver 192.0.2.1\n");
    int pinCloses = 0;
    int dataCloses = 0;
    bool failRead = false;
    int reads = 0;
    ON_CALL(context, ReadNativeDescriptor(_, _, _)).WillByDefault([&](int fd, void* buffer, std::size_t size) -> ssize_t {
        if (!IsFixture(fd, path, true))
            return context.RealReadNativeDescriptor(fd, buffer, size);
        ++reads;
        if (failRead)
        {
            errno = EACCES;
            return -1;
        }
        return context.RealReadNativeDescriptor(fd, buffer, size);
    });
    ON_CALL(context, CloseNativeDescriptor(_)).WillByDefault([&](int descriptor) -> ComplianceEngine::Result<void> {
        const bool pin = IsFixture(descriptor, path, false);
        const bool data = IsFixture(descriptor, path, true);
        context.RealCloseNativeDescriptor(descriptor);
        if (data)
        {
            ++dataCloses;
            errno = EBADF;
            return ComplianceEngine::Error(errno);
        }
        if (pin)
        {
            ++pinCloses;
            if (!failRead)
            {
                errno = EIO;
                return ComplianceEngine::Error(errno);
            }
        }
        return ComplianceEngine::Result<void>::Success();
    });
    auto result = ComplianceEngine::CollectNameserverObject(context, path);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_TRUE(result->complete);
    EXPECT_EQ((std::vector<std::string>{"192.0.2.1"}), Captures(result.Value()));
    EXPECT_GT(reads, 0);
    EXPECT_EQ(1, pinCloses);
    EXPECT_EQ(1, dataCloses);

    failRead = true;
    reads = 0;
    result = ComplianceEngine::CollectNameserverObject(context, path);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EACCES, result.Error().code);
    EXPECT_EQ("Failed to read file bytes", result.Error().message);
    EXPECT_EQ(1, reads);
    EXPECT_EQ(2, pinCloses);
    EXPECT_EQ(2, dataCloses);
    CloseLog(&logHandle);
    context.SetLogHandle(nullptr);
    const auto text = ReadLog(logPath);
    ExpectLoggedOnce(text, "Failed to close filesystem resource: " + std::string(strerror(EIO)));
    const auto dataEntry = "Failed to close filesystem resource: " + std::string(strerror(EBADF)) + " (ownership bug)";
    const auto first = text.find(dataEntry);
    ASSERT_NE(std::string::npos, first);
    const auto second = text.find(dataEntry, first + dataEntry.size());
    ASSERT_NE(std::string::npos, second);
    EXPECT_EQ(std::string::npos, text.find(dataEntry, second + dataEntry.size()));
}

TEST(FileObjectCollectorTest, FailedDataOpenFinalizesPinWithoutReopeningPath)
{
    NiceMock<MockContext> context;
    const auto path = context.MakeTempfile("nameserver one\n");
    int aliasOpens = 0;
    int pinCloses = 0;
    ON_CALL(context, OpenNativeAt(_, _, _)).WillByDefault([&](int directory, const char* name, int flags) {
        if (IsAliasDirectory(directory, context) && (flags & O_ACCMODE) == O_RDONLY && !(flags & O_PATH) && !(flags & O_NOFOLLOW))
        {
            ++aliasOpens;
            errno = EACCES;
            return -1;
        }
        return context.RealOpenNativeAt(directory, name, flags);
    });
    ON_CALL(context, CloseNativeDescriptor(_)).WillByDefault([&](int descriptor) -> ComplianceEngine::Result<void> {
        pinCloses += IsFixture(descriptor, path, false);
        return context.RealCloseNativeDescriptor(descriptor);
    });
    const auto result = ComplianceEngine::CollectNameserverObject(context, path);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EACCES, result.Error().code);
    EXPECT_EQ(1, aliasOpens);
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
        const auto path = context.MakeTempfile("nameserver one\n");
        const auto logPath = context.GetTempdirPath() + "/acquired-failure-cleanup.log";
        OsConfigLogHandle logHandle = OpenLog(logPath.c_str(), nullptr);
        ASSERT_NE(nullptr, logHandle);
        context.SetLogHandle(logHandle);
        int pinCloses = 0;
        int dataCloses = 0;
        int aliasOpens = 0;
        ON_CALL(context, OpenNativeAt(_, _, _)).WillByDefault([&](int directory, const char* name, int flags) {
            if (failure == FailurePoint::DataOpen && IsAliasDirectory(directory, context) && (flags & O_ACCMODE) == O_RDONLY && !(flags & O_PATH) &&
                !(flags & O_NOFOLLOW))
            {
                ++aliasOpens;
                errno = EACCES;
                return -1;
            }
            return context.RealOpenNativeAt(directory, name, flags);
        });
        ON_CALL(context, StatNativeDescriptor(_, _)).WillByDefault([&](int fd, struct stat* metadata) {
            const bool pin = IsFixture(fd, path, false), data = IsFixture(fd, path, true);
            if ((failure == FailurePoint::PinStat && pin) || (failure == FailurePoint::DataStat && data))
            {
                errno = EACCES;
                return -1;
            }
            const int status = context.RealStatNativeDescriptor(fd, metadata);
            if (status == 0 && failure == FailurePoint::Nonregular && pin)
                metadata->st_mode = S_IFDIR | 0700;
            if (status == 0 && failure == FailurePoint::Identity && data)
                ++metadata->st_ino;
            return status;
        });
        ON_CALL(context, ReadNativeDescriptor(_, _, _)).WillByDefault([&](int fd, void* buffer, std::size_t size) -> ssize_t {
            if (!IsFixture(fd, path, true))
                return context.RealReadNativeDescriptor(fd, buffer, size);
            errno = EACCES;
            return -1;
        });
        ON_CALL(context, CloseNativeDescriptor(_)).WillByDefault([&](int descriptor) -> ComplianceEngine::Result<void> {
            const bool pin = IsFixture(descriptor, path, false), data = IsFixture(descriptor, path, true);
            context.RealCloseNativeDescriptor(descriptor);
            if (data)
            {
                ++dataCloses;
                errno = EBADF;
                return ComplianceEngine::Error(errno);
            }
            if (pin)
            {
                ++pinCloses;
                if (failure != FailurePoint::Read)
                {
                    errno = EIO;
                    return ComplianceEngine::Error(errno);
                }
                return ComplianceEngine::Result<void>::Success();
            }
            return ComplianceEngine::Result<void>::Success();
        });
        const auto result = ComplianceEngine::CollectNameserverObject(context, path);
        CloseLog(&logHandle);
        context.SetLogHandle(nullptr);
        ASSERT_FALSE(result.HasValue());
        const int primary = failure == FailurePoint::Identity ? EAGAIN : failure == FailurePoint::Nonregular ? EINVAL : EACCES;
        EXPECT_EQ(primary, result.Error().code);
        EXPECT_EQ(1, pinCloses);
        EXPECT_EQ(failure == FailurePoint::PinStat || failure == FailurePoint::Nonregular || failure == FailurePoint::DataOpen ? 0 : 1, dataCloses);
        if (failure == FailurePoint::DataOpen)
        {
            EXPECT_EQ(1, aliasOpens);
        }
        EXPECT_EQ(failure == FailurePoint::Identity   ? "Activated object does not match live pin" :
                  failure == FailurePoint::Nonregular ? "File target is not regular" :
                  failure == FailurePoint::PinStat    ? "Cannot inspect confined component" :
                  failure == FailurePoint::DataStat   ? "Cannot inspect activated object and pin" :
                  failure == FailurePoint::Read       ? "Failed to read file bytes" :
                                                        "Cannot open pinned descriptor alias for reading",
            result.Error().message);
        const auto text = ReadLog(logPath);
        const auto pinError = "Failed to close filesystem resource: " + std::string(strerror(EIO));
        if (failure == FailurePoint::Read)
            EXPECT_EQ(std::string::npos, text.find(pinError));
        else
            ExpectLoggedOnce(text, pinError);
        if (dataCloses)
            ExpectLoggedOnce(text, "Failed to close filesystem resource: " + std::string(strerror(EBADF)) + " (ownership bug)");
    }
}

TEST(FileObjectCollectorTest, DataCloseFailureAfterSuccessfulPinCloseIsDiagnosticOnly)
{
    NiceMock<MockContext> context;
    const auto logPath = context.GetTempdirPath() + "/data-close-cleanup.log";
    OsConfigLogHandle logHandle = OpenLog(logPath.c_str(), nullptr);
    ASSERT_NE(nullptr, logHandle);
    context.SetLogHandle(logHandle);
    const auto path = context.MakeTempfile("nameserver 192.0.2.1\n");
    int pinCloses = 0;
    int dataCloses = 0;
    ON_CALL(context, CloseNativeDescriptor(_)).WillByDefault([&](int fd) -> ComplianceEngine::Result<void> {
        const bool pin = IsFixture(fd, path, false), data = IsFixture(fd, path, true);
        context.RealCloseNativeDescriptor(fd);
        if (data)
        {
            ++dataCloses;
            errno = EBADF;
            return ComplianceEngine::Error(errno);
        }
        if (pin)
            ++pinCloses;
        return ComplianceEngine::Result<void>::Success();
    });
    const auto result = ComplianceEngine::CollectNameserverObject(context, path);
    CloseLog(&logHandle);
    context.SetLogHandle(nullptr);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_TRUE(result->complete);
    EXPECT_EQ((std::vector<std::string>{"192.0.2.1"}), Captures(result.Value()));
    EXPECT_EQ(1, pinCloses);
    EXPECT_EQ(1, dataCloses);
    const auto text = ReadLog(logPath);
    ExpectLoggedOnce(text, "Failed to close filesystem resource: " + std::string(strerror(EBADF)) + " (ownership bug)");
}

TEST(FileObjectCollectorTest, PinAndDataCloseFailuresAreIndependentOfReadErrors)
{
    for (const bool failingPin : {true, false})
    {
        NiceMock<MockContext> context;
        const auto path = context.MakeTempfile("nameserver one\n");
        const auto logPath = context.GetTempdirPath() + "/independent-close-cleanup.log";
        OsConfigLogHandle logHandle = OpenLog(logPath.c_str(), nullptr);
        ASSERT_NE(nullptr, logHandle);
        context.SetLogHandle(logHandle);
        int pinCloses = 0;
        int dataCloses = 0;
        int reads = 0;
        ON_CALL(context, ReadNativeDescriptor(_, _, _)).WillByDefault([&](int fd, void* buffer, std::size_t size) -> ssize_t {
            if (!IsFixture(fd, path, true))
                return context.RealReadNativeDescriptor(fd, buffer, size);
            ++reads;
            errno = EACCES;
            return -1;
        });
        ON_CALL(context, CloseNativeDescriptor(_)).WillByDefault([&](int fd) -> ComplianceEngine::Result<void> {
            const bool pin = IsFixture(fd, path, false), data = IsFixture(fd, path, true);
            pinCloses += pin;
            dataCloses += data;
            context.RealCloseNativeDescriptor(fd);
            if ((failingPin && pin) || (!failingPin && data))
            {
                errno = pin ? EIO : EBADF;
                return ComplianceEngine::Error(errno);
            }

            return ComplianceEngine::Result<void>::Success();
        });
        const auto result = ComplianceEngine::CollectNameserverObject(context, path);
        CloseLog(&logHandle);
        context.SetLogHandle(nullptr);
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ(EACCES, result.Error().code);
        EXPECT_EQ(1, pinCloses);
        EXPECT_EQ(1, dataCloses);
        EXPECT_EQ(1, reads);
        EXPECT_EQ("Failed to read file bytes", result.Error().message);
        const auto text = ReadLog(logPath);
        ExpectLoggedOnce(text, failingPin ? "Failed to close filesystem resource: " + std::string(strerror(EIO)) :
                                            "Failed to close filesystem resource: " + std::string(strerror(EBADF)) + " (ownership bug)");
    }
}

TEST(FileObjectCollectorTest, ReadFailureSurvivesFailedDataClose)
{
    NiceMock<MockContext> context;
    const auto logPath = context.GetTempdirPath() + "/failed-data-close.log";
    OsConfigLogHandle logHandle = OpenLog(logPath.c_str(), nullptr);
    ASSERT_NE(nullptr, logHandle);
    context.SetLogHandle(logHandle);
    const auto path = context.MakeTempfile("nameserver one\n");
    int reads = 0;
    int dataCloses = 0;
    int pinCloses = 0;
    int dataFd = -1;
    ON_CALL(context, ReadNativeDescriptor(_, _, _)).WillByDefault([&](int fd, void* buffer, std::size_t size) -> ssize_t {
        if (!IsFixture(fd, path, true))
            return context.RealReadNativeDescriptor(fd, buffer, size);
        ++reads;
        errno = EACCES;
        return -1;
    });
    ON_CALL(context, CloseNativeDescriptor(_)).WillByDefault([&](int fd) -> ComplianceEngine::Result<void> {
        const bool pin = IsFixture(fd, path, false), data = IsFixture(fd, path, true);
        pinCloses += pin;
        dataCloses += data;
        if (data)
            dataFd = fd;
        auto status = context.RealCloseNativeDescriptor(fd);
        if (data)
        {
            errno = EIO;
            return ComplianceEngine::Error(errno);
        }
        return status;
    });
    const auto result = ComplianceEngine::CollectNameserverObject(context, path);
    CloseLog(&logHandle);
    context.SetLogHandle(nullptr);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EACCES, result.Error().code);
    EXPECT_EQ("Failed to read file bytes", result.Error().message);
    EXPECT_EQ(1, reads);
    EXPECT_EQ(1, dataCloses);
    EXPECT_EQ(1, pinCloses);
    ASSERT_GE(dataFd, 0);
    EXPECT_EQ(-1, ::fcntl(dataFd, F_GETFD));
    EXPECT_EQ(EBADF, errno);
    const auto text = ReadLog(logPath);
    ExpectLoggedOnce(text, "Failed to close filesystem resource: " + std::string(strerror(EIO)));
}

TEST(FileObjectCollectorTest, RejectsEmbeddedNulAndInvalidInputsBeforeOpening)
{
    NiceMock<MockContext> context;
    int opens = 0;
    ON_CALL(context, OpenNativePath(_, _)).WillByDefault([&opens](const char*, int) {
        ++opens;
        return -1;
    });
    ON_CALL(context, OpenNativeAt(_, _, _)).WillByDefault([&opens](int, const char*, int) {
        ++opens;
        return -1;
    });

    const std::string embeddedNul("/etc/resolv.conf\0/decoy", 23);
    auto result = ComplianceEngine::CollectNameserverObject(context, embeddedNul);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EINVAL, result.Error().code);

    FileCollectionPolicy invalidPolicy;
    invalidPolicy.symlinks = static_cast<SymlinkPolicy>(2);
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
    const auto path = failedOpen.MakeTempfile("nameserver one\n");
    int denied = 0;
    ON_CALL(failedOpen, OpenNativeAt(_, _, _)).WillByDefault([&](int directory, const char* component, int flags) {
        if (IsFixtureParent(directory, path) && std::string(component) == path.substr(path.find_last_of('/') + 1) && (flags & O_PATH))
        {
            ++denied;
            errno = EACCES;
            return -1;
        }
        return failedOpen.RealOpenNativeAt(directory, component, flags);
    });
    result = ComplianceEngine::CollectNameserverObject(failedOpen, path);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EACCES, result.Error().code);
    EXPECT_EQ(1, denied);
}

TEST(FileObjectCollectorTest, PrematureEofWithStableMetadataIsAnError)
{
    NiceMock<MockContext> context;
    const auto path = context.MakeTempfile("nameserver one\n");
    int dataStats = 0;
    ON_CALL(context, StatNativeDescriptor(_, _)).WillByDefault([&](int fd, struct stat* metadata) {
        const int status = context.RealStatNativeDescriptor(fd, metadata);
        if (status == 0 && IsFixture(fd, path, true))
        {
            ++dataStats;
            metadata->st_size = 20;
        }
        return status;
    });
    ON_CALL(context, ReadNativeDescriptor(_, _, _)).WillByDefault([&](int fd, void* buffer, std::size_t size) -> ssize_t {
        if (!IsFixture(fd, path, true))
            return context.RealReadNativeDescriptor(fd, buffer, size);
        return 0;
    });

    const auto result = ComplianceEngine::CollectNameserverObject(context, path);

    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EIO, result.Error().code);
    EXPECT_EQ(2, dataStats); // Baseline inspection and EOF verification both use the readable fixture.
}

TEST(FileObjectCollectorTest, ResolverPipelineCountsDistinctNameservers)
{
    NiceMock<MockContext> context;
    const auto path = context.MakeTempfile("nameserver 192.0.2.1\nnameserver 192.0.2.1\nnameserver 2001:db8::1\n");
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
