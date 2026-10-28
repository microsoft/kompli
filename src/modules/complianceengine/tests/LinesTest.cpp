// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <MockContext.h>
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <filesystem/Lines.hpp>
#include <fstream>
#include <gtest/gtest.h>
#include <iterator>
#include <limits>
#include <new>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

using ComplianceEngine::Filesystem::Lines;
using ComplianceEngine::Filesystem::SymlinkFollowing;
using testing::_;
using testing::NiceMock;

namespace
{
Lines::Policy Limited(std::size_t maxBytes, std::size_t retries = 2)
{
    Lines::Policy policy;
    policy.symlinks = SymlinkFollowing::Follow;
    policy.limits.maxBytes = maxBytes;
    policy.limits.maxInterruptedReads = retries;
    return policy;
}

class PathFile : public testing::Test
{
protected:
    void SetUp() override
    {
        path = context.MakeTempfile("");
    }
    void TearDown() override
    {
        ::unlink((path + ".link").c_str());
        ::unlink((path + ".old").c_str());
    }
    void Write(const std::string& bytes)
    {
        const int fd = ::open(path.c_str(), O_WRONLY | O_TRUNC | O_CLOEXEC);
        ASSERT_GE(fd, 0);
        ASSERT_EQ(static_cast<ssize_t>(bytes.size()), ::write(fd, bytes.data(), bytes.size()));
        ASSERT_EQ(0, ::close(fd));
    }
    // The foundation also opens/closes temporary procfs and resolver pins.
    // Target only operational data or O_PATH file pins in fault injection.
    bool IsFileDescriptor(int fd, bool readable, const std::string& fixturePath) const
    {
        struct stat held = {}, fixture = {};
        const int flags = ::fcntl(fd, F_GETFL);
        return flags >= 0 && ::fstat(fd, &held) == 0 && ::stat(fixturePath.c_str(), &fixture) == 0 && S_ISREG(held.st_mode) && held.st_dev == fixture.st_dev &&
               held.st_ino == fixture.st_ino && (readable ? (flags & O_ACCMODE) == O_RDONLY && !(flags & O_PATH) : (flags & O_PATH) != 0);
    }
    bool IsFileDescriptor(int fd, bool readable) const
    {
        return IsFileDescriptor(fd, readable, path);
    }
    bool IsLinkDescriptor(int fd, const std::string& link) const
    {
        struct stat held = {}, fixture = {};
        return ::fstat(fd, &held) == 0 && ::lstat(link.c_str(), &fixture) == 0 && S_ISLNK(held.st_mode) && held.st_dev == fixture.st_dev &&
               held.st_ino == fixture.st_ino;
    }
    bool MakeAncestorTargets(const std::string& ancestor, const std::string& alternate)
    {
        if ((0 != ::mkdir(ancestor.c_str(), 0700)) || (0 != ::mkdir(alternate.c_str(), 0700)))
            return false;
        const std::string original = context.MakeTempfile("original\n");
        const std::string replacement = context.MakeTempfile("alternate\n");
        return (0 == ::rename(original.c_str(), (ancestor + "/target").c_str())) && (0 == ::rename(replacement.c_str(), (alternate + "/target").c_str()));
    }
    // Consume errors as items; never confuse early stop with complete input.
    ComplianceEngine::Result<std::string> Collect(const std::string& source, Lines::Policy policy)
    {
        auto opened = Lines::Open(context, source, std::move(policy));
        if (!opened.HasValue())
            return std::move(opened).Error();
        auto& range = opened.Value();
        std::string bytes;
        bool first = true;
        for (const auto& item : range)
        {
            if (!item.HasValue())
                return item.Error();
            if (!first)
                bytes += '\n';
            first = false;
            bytes += item.Value();
        }
        auto closed = range.Close();
        if (!closed.HasValue())
            return std::move(closed).Error();
        return bytes;
    }
    NiceMock<MockContext> context;
    std::string path;
};
} // namespace

TEST_F(PathFile, DefaultPolicyValuesAndExplicitOverrides)
{
    const Lines::Policy defaults;
    EXPECT_EQ(SymlinkFollowing::Follow, defaults.symlinks);
    EXPECT_EQ(1024U * 1024U, defaults.limits.maxBytes);
    EXPECT_EQ(128U, defaults.limits.maxInterruptedReads);

    Lines::Policy custom;
    custom.symlinks = SymlinkFollowing::DoNotFollow;
    custom.limits.maxBytes = 3;
    custom.limits.maxInterruptedReads = 1;
    EXPECT_EQ(SymlinkFollowing::DoNotFollow, custom.symlinks);
    EXPECT_EQ(3U, custom.limits.maxBytes);
    EXPECT_EQ(1U, custom.limits.maxInterruptedReads);
}

TEST_F(PathFile, OmittedPolicyFollowsFinalSymlinkAndRejectsNul)
{
    Write("plain\n");
    ASSERT_EQ(0, ::symlink(path.c_str(), (path + ".link").c_str()));
    std::string collected;
    auto opened = Lines::Open(context, path + ".link");
    ASSERT_TRUE(opened.HasValue());
    auto& range = opened.Value();
    for (const auto& item : range)
    {
        ASSERT_TRUE(item.HasValue());
        collected += item.Value();
    }
    EXPECT_EQ("plain", collected);
    EXPECT_TRUE(range.Close().HasValue());

    Write(std::string("a\0b", 3));
    int errors = 0;
    auto textOpened = Lines::Open(context, path);
    ASSERT_TRUE(textOpened.HasValue());
    auto& textRange = textOpened.Value();
    for (const auto& item : textRange)
    {
        ++errors;
        ASSERT_FALSE(item.HasValue());
        EXPECT_EQ(EBADMSG, item.Error().code);
    }
    EXPECT_EQ(1, errors);
    EXPECT_TRUE(textRange.Close().HasValue());
    EXPECT_EQ(EBADMSG, Collect(path, Limited(3)).Error().code);
    Lines::Policy reject;
    reject.symlinks = SymlinkFollowing::DoNotFollow;
    EXPECT_EQ(ELOOP, Collect(path + ".link", reject).Error().code);
}

TEST_F(PathFile, DoNotFollowRejectsIntermediateAndFinalSymlinksWithoutReading)
{
    Write("plain\n");
    // Both links occur in the same path; the final link can also be requested alone.
    ASSERT_EQ(0, ::symlink(context.GetTempdirPath().c_str(), (path + ".link").c_str()));
    ASSERT_EQ(0, ::symlink(path.c_str(), (path + ".old").c_str()));
    const auto chained = path + ".link/" + path.substr(path.find_last_of('/') + 1) + ".old";
    int reads = 0, intermediateCloses = 0, finalCloses = 0;
    ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([&](int fd, void* buffer, std::size_t size) -> ssize_t {
        reads += IsFileDescriptor(fd, true);
        return context.ContextInterface::ReadFileDescriptor(fd, buffer, size);
    });
    ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([&](int fd) -> int {
        intermediateCloses += IsLinkDescriptor(fd, path + ".link");
        finalCloses += IsLinkDescriptor(fd, path + ".old");
        return context.ContextInterface::CloseFileDescriptor(fd);
    });
    EXPECT_EQ("plain", Collect(chained, Lines::Policy{}).Value());
    EXPECT_GT(reads, 0);
    reads = intermediateCloses = finalCloses = 0;
    Lines::Policy policy;
    policy.symlinks = SymlinkFollowing::DoNotFollow;
    EXPECT_EQ(ELOOP, Collect(chained, policy).Error().code);
    EXPECT_EQ(1, intermediateCloses);
    EXPECT_EQ(0, finalCloses);
    EXPECT_EQ(0, reads);
    EXPECT_EQ(ELOOP, Collect(path + ".old", policy).Error().code);
    EXPECT_EQ(1, intermediateCloses);
    EXPECT_EQ(1, finalCloses);
    EXPECT_EQ(0, reads);
    EXPECT_EQ("plain", Collect(path, policy).Value());
}

TEST_F(PathFile, DefaultLimitsBoundBytesAndInterruptedReads)
{
    const std::size_t cap = Lines::Policy{}.limits.maxBytes;
    std::size_t requested = 0;
    int probes = 0;
    ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([&](int fd, void* buffer, std::size_t size) -> ssize_t {
        if (!IsFileDescriptor(fd, true))
            return context.ContextInterface::ReadFileDescriptor(fd, buffer, size);
        requested += size;
        if (size == 1)
            ++probes;
        std::memset(buffer, 'x', size);
        return static_cast<ssize_t>(size);
    });
    auto result = Collect(path, Lines::Policy{});
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(E2BIG, result.Error().code);
    EXPECT_EQ(cap + 1, requested);
    EXPECT_EQ(1, probes);

    int attempts = 0;
    ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([&](int fd, void* buffer, std::size_t size) -> ssize_t {
        if (!IsFileDescriptor(fd, true))
            return context.ContextInterface::ReadFileDescriptor(fd, buffer, size);
        ++attempts;
        errno = EINTR;
        return -1;
    });
    result = Collect(path, Lines::Policy{});
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(E2BIG, result.Error().code);
    EXPECT_EQ(129, attempts);
    attempts = 0;
    EXPECT_EQ(E2BIG, Collect(path, Limited(3, 1)).Error().code);
    EXPECT_EQ(2, attempts);
}

TEST_F(PathFile, ValidationAndOpenAreFactoryOperations)
{
    int fileStats = 0;
    ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([&](int fd, struct stat* metadata) {
        if (IsFileDescriptor(fd, false))
        {
            ++fileStats;
            errno = EIO;
            return -1;
        }
        return context.ContextInterface::StatFileDescriptor(fd, metadata);
    });
    auto invalidPath = Lines::Open(context, "relative", Limited(16));
    EXPECT_FALSE(invalidPath.HasValue());
    EXPECT_EQ(0, fileStats);
    for (const auto& name : {std::string(), std::string("relative"), std::string("a\0b", 3)})
        EXPECT_EQ(EINVAL, Collect(name, Limited(16)).Error().code);
    auto invalid = Limited(16);
    invalid.symlinks = static_cast<SymlinkFollowing>(99);
    EXPECT_EQ(EINVAL, Collect(path, invalid).Error().code);
    invalid = Limited(0);
    EXPECT_EQ(EINVAL, Collect(path, invalid).Error().code);
    invalid = Limited(16, 0);
    EXPECT_EQ(EINVAL, Collect(path, invalid).Error().code);
    invalid = Limited(std::numeric_limits<std::size_t>::max());
    EXPECT_EQ(EOVERFLOW, Collect(path, invalid).Error().code);
    EXPECT_EQ(0, fileStats);
    EXPECT_EQ(EIO, Collect(path, Limited(16)).Error().code);
    EXPECT_GE(fileStats, 1);
}

TEST_F(PathFile, EmptyUnterminatedAndBareLines)
{
    EXPECT_EQ("", Collect(path, Limited(1)).Value());
    Write("a\r\n\nlast");
    std::vector<std::string> lines;
    auto opened = Lines::Open(context, path, Limited(8));
    ASSERT_TRUE(opened.HasValue());
    auto& range = opened.Value();
    for (const auto& item : range)
    {
        ASSERT_TRUE(item.HasValue());
        lines.push_back(item.Value());
    }
    EXPECT_TRUE(range.Close().HasValue());
    ASSERT_EQ(3U, lines.size());
    EXPECT_EQ("a\r", lines[0]);
    EXPECT_EQ("", lines[1]);
    EXPECT_EQ("last", lines[2]);
    EXPECT_EQ("a\r\n\nlast", Collect(path, Limited(8)).Value());
}

TEST_F(PathFile, FinalLfDoesNotProducePhantomItemAndCountsTowardByteCap)
{
    const std::vector<std::pair<std::string, std::vector<std::string>>> fixtures = {
        {"", {}}, {"\n", {""}}, {"\n\n", {"", ""}}, {"tail", {"tail"}}, {"tail\n", {"tail"}}, {"tail\n\n", {"tail", ""}}};
    for (const auto& fixture : fixtures)
    {
        const auto& content = fixture.first;
        Write(content);
        auto opened = Lines::Open(context, path, Limited(std::max<std::size_t>(1, content.size())));
        ASSERT_TRUE(opened.HasValue());
        auto& range = opened.Value();
        std::vector<std::string> items;
        for (const auto& item : range)
        {
            ASSERT_TRUE(item.HasValue());
            items.push_back(item.Value());
        }
        EXPECT_EQ(fixture.second, items) << content;
        EXPECT_TRUE(range.Close().HasValue());
        if (content.size() > 1)
        {
            EXPECT_EQ(E2BIG, Collect(path, Limited(content.size() - 1)).Error().code);
        }
    }
}

TEST_F(PathFile, RejectsNulButPreservesHighBitBytes)
{
    const std::string original("a\0\xff\nb", 5);
    Write(original);
    EXPECT_EQ(EBADMSG, Collect(path, Limited(5)).Error().code);
    Write(std::string("\xff\r\n", 3));
    EXPECT_EQ(std::string("\xff\r", 2), Collect(path, Limited(3)).Value());
    EXPECT_EQ(E2BIG, Collect(path, Limited(2)).Error().code);
}

TEST_F(PathFile, NulAtStartMiddleOrEndNeverYieldsAffectedLine)
{
    for (const auto& content : {std::string("\0ab\n", 4), std::string("a\0b\n", 4), std::string("ab\0", 3)})
    {
        Write(content);
        int closes = 0, items = 0;
        ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([&](int fd) {
            if (IsFileDescriptor(fd, true))
                ++closes;
            return context.ContextInterface::CloseFileDescriptor(fd);
        });
        auto opened = Lines::Open(context, path);
        ASSERT_TRUE(opened.HasValue());
        auto& range = opened.Value();
        for (const auto& item : range)
        {
            ++items;
            ASSERT_FALSE(item.HasValue());
            EXPECT_EQ(EBADMSG, item.Error().code);
        }
        EXPECT_EQ(1, items);
        EXPECT_TRUE(range.Close().HasValue());
        EXPECT_TRUE(range.Close().HasValue());
        EXPECT_EQ(1, closes);
    }
}

TEST_F(PathFile, ValidLineThenNulAcrossReadChunksYieldsErrorNotTruncatedLine)
{
    for (const std::size_t padding : {8191U, 8192U, 8193U})
    {
        // The NUL falls at the last byte of a chunk or just into the next.
        const std::string valid = "ok\n";
        Write(valid + std::string(padding - valid.size(), '\xff') + std::string("\0tail\n", 6));
        int closes = 0;
        ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([&](int fd) {
            if (IsFileDescriptor(fd, true))
                ++closes;
            return context.ContextInterface::CloseFileDescriptor(fd);
        });
        auto opened = Lines::Open(context, path, Limited(8200));
        ASSERT_TRUE(opened.HasValue());
        auto& range = opened.Value();
        auto it = range.begin();
        ASSERT_TRUE(it != range.end());
        ASSERT_TRUE(it->HasValue());
        EXPECT_EQ("ok", it->Value());
        ++it;
        ASSERT_TRUE(it != range.end());
        ASSERT_FALSE(it->HasValue());
        EXPECT_EQ(EBADMSG, it->Error().code);
        ++it;
        EXPECT_FALSE(it != range.end());
        EXPECT_TRUE(range.Close().HasValue());
        EXPECT_EQ(1, closes);
    }
}

TEST_F(PathFile, BoundedChunksAndLazyEarlyBreakCloseExactlyOnce)
{
    Write(std::string(20000, 'x') + "\n" + std::string(50000, 'y'));
    int reads = 0, closes = 0;
    std::size_t largest = 0;
    ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([&](int fd, void* buffer, std::size_t size) {
        if (!IsFileDescriptor(fd, true))
            return context.ContextInterface::ReadFileDescriptor(fd, buffer, size);
        ++reads;
        largest = std::max(largest, size);
        return context.ContextInterface::ReadFileDescriptor(fd, buffer, size);
    });
    ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([&](int fd) {
        if (IsFileDescriptor(fd, true))
            ++closes;
        return context.ContextInterface::CloseFileDescriptor(fd);
    });
    auto opened = Lines::Open(context, path, Limited(80000));
    ASSERT_TRUE(opened.HasValue());
    auto& range = opened.Value();
    EXPECT_EQ(0, closes); // All acquisition pins close before factory success.
    EXPECT_EQ(0, reads);
    {
        auto it = range.begin();
        EXPECT_TRUE(it != range.end());
        ASSERT_TRUE(it->HasValue());
        EXPECT_EQ(20000U, it->Value().size());
        EXPECT_EQ(3, reads); // 8 KiB chunks, no forced tail read.
        EXPECT_LE(largest, 8192U);
        auto moved = std::move(it);
        EXPECT_FALSE(it != range.end());
        EXPECT_TRUE(moved != range.end());
    }
    EXPECT_EQ(0, closes);
    EXPECT_FALSE(range.begin() != range.end());
    EXPECT_TRUE(range.Close().HasValue());
    EXPECT_EQ(1, closes);
    EXPECT_TRUE(range.Close().HasValue());
    EXPECT_EQ(1, closes);
}

TEST_F(PathFile, ShortNativeReadsFillOneBoundedChunkBeforeEarlyBreak)
{
    Write("first\nsecond\n");
    std::vector<std::size_t> requests;
    int closes = 0;
    ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([&](int fd, void* buffer, std::size_t size) -> ssize_t {
        if (!IsFileDescriptor(fd, true))
            return context.ContextInterface::ReadFileDescriptor(fd, buffer, size);
        requests.push_back(size);
        return context.ContextInterface::ReadFileDescriptor(fd, buffer, std::min<std::size_t>(size, 2));
    });
    ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([&](int fd) {
        if (IsFileDescriptor(fd, true))
            ++closes;
        return context.ContextInterface::CloseFileDescriptor(fd);
    });
    auto opened = Lines::Open(context, path, Limited(13));
    ASSERT_TRUE(opened.HasValue());
    auto& range = opened.Value();
    auto cursor = range.begin();
    ASSERT_TRUE(cursor != range.end());
    ASSERT_TRUE(cursor->HasValue());
    EXPECT_EQ("first", cursor->Value());
    EXPECT_EQ((std::vector<std::size_t>{13, 11, 9, 7, 5, 3, 1}), requests);
    EXPECT_TRUE(range.Close().HasValue());
    EXPECT_EQ(1, closes);
    EXPECT_EQ(7U, requests.size()); // No EOF probe or new chunk after early close.
}

TEST_F(PathFile, IteratorOwnsOneErrorItemAndEndsAfterAdvance)
{
    Write(std::string("ok\nbad\0tail\n", 12));
    auto opened = Lines::Open(context, path, Limited(12));
    ASSERT_TRUE(opened.HasValue());
    auto& range = opened.Value();
    auto cursor = range.begin();
    ASSERT_TRUE(cursor != range.end());
    ASSERT_TRUE(cursor->HasValue());
    EXPECT_EQ("ok", (*cursor).Value());
    auto moved = std::move(cursor);
    EXPECT_FALSE(cursor != range.end());
    ASSERT_TRUE(moved != range.end());
    EXPECT_EQ("ok", moved->Value());
    ++moved;
    ASSERT_TRUE(moved != range.end());
    ASSERT_FALSE(moved->HasValue());
    EXPECT_EQ(EBADMSG, moved->Error().code);
    ++moved;
    EXPECT_FALSE(moved != range.end());
    EXPECT_FALSE(range.end() != moved);
    EXPECT_TRUE(range.Close().HasValue());
}

TEST_F(PathFile, CloseInvalidatesBufferedIteratorWithoutReadingTail)
{
    Write("first\nsecond\n");
    int reads = 0;
    ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([&](int fd, void* buffer, std::size_t size) {
        if (IsFileDescriptor(fd, true))
            ++reads;
        return context.ContextInterface::ReadFileDescriptor(fd, buffer, size);
    });
    auto opened = Lines::Open(context, path, Limited(13));
    ASSERT_TRUE(opened.HasValue());
    auto& range = opened.Value();
    auto cursor = range.begin();
    ASSERT_TRUE(cursor != range.end());
    EXPECT_EQ("first", cursor->Value());
    const int before = reads;
    EXPECT_TRUE(range.Close().HasValue());
    EXPECT_FALSE(cursor != range.end());
    EXPECT_FALSE(range.end() != cursor);
    EXPECT_FALSE(range.begin() != range.end());
    EXPECT_EQ(before, reads);
}

TEST_F(PathFile, ExactChunkCapProbesOnceAndCumulativeInterruptsIncludeProbe)
{
    Write(std::string(8192, 'x'));
    std::vector<std::size_t> requests;
    ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([&](int fd, void* buffer, std::size_t size) {
        if (IsFileDescriptor(fd, true))
            requests.push_back(size);
        return context.ContextInterface::ReadFileDescriptor(fd, buffer, size);
    });
    EXPECT_EQ(std::string(8192, 'x'), Collect(path, Limited(8192)).Value());
    EXPECT_EQ((std::vector<std::size_t>{8192, 1}), requests);
    Write(std::string(8193, 'x'));
    requests.clear();
    EXPECT_EQ(E2BIG, Collect(path, Limited(8192)).Error().code);
    EXPECT_EQ((std::vector<std::size_t>{8192, 1}), requests);

    Write(std::string(8192, 'x'));
    int interrupts = 0;
    ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([&](int fd, void* buffer, std::size_t size) -> ssize_t {
        if (!IsFileDescriptor(fd, true))
            return context.ContextInterface::ReadFileDescriptor(fd, buffer, size);
        if ((size == 8192 && interrupts == 0) || (size == 1 && interrupts == 1))
        {
            ++interrupts;
            errno = EINTR;
            return -1;
        }
        return context.ContextInterface::ReadFileDescriptor(fd, buffer, size);
    });
    auto result = Collect(path, Limited(8192, 1));
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(E2BIG, result.Error().code);
    EXPECT_EQ("File read interrupt retry limit exceeded", result.Error().message);
    EXPECT_EQ(2, interrupts);
}

TEST_F(PathFile, InterruptedReadBudgetIsSharedAcrossDataChunks)
{
    Write(std::string(8193, 'x'));
    std::vector<std::size_t> requests;
    ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([&](int fd, void* buffer, std::size_t size) -> ssize_t {
        if (!IsFileDescriptor(fd, true))
            return context.ContextInterface::ReadFileDescriptor(fd, buffer, size);
        requests.push_back(size);
        if (requests.size() == 1 || requests.size() == 3)
        {
            errno = EINTR;
            return -1;
        }
        return context.ContextInterface::ReadFileDescriptor(fd, buffer, size);
    });
    auto result = Collect(path, Limited(8193, 1));
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(E2BIG, result.Error().code);
    EXPECT_EQ("File read interrupt retry limit exceeded", result.Error().message);
    EXPECT_EQ((std::vector<std::size_t>{8192, 8192, 1}), requests);
}

TEST_F(PathFile, RangeMoveAndEarlyCloseNeverReadTail)
{
    Write("one\nsecond\n");
    int reads = 0, closes = 0;
    ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([&](int fd, void* buffer, std::size_t size) {
        if (!IsFileDescriptor(fd, true))
            return context.ContextInterface::ReadFileDescriptor(fd, buffer, size);
        ++reads;
        return context.ContextInterface::ReadFileDescriptor(fd, buffer, size);
    });
    ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([&](int fd) {
        if (IsFileDescriptor(fd, true))
            ++closes;
        return context.ContextInterface::CloseFileDescriptor(fd);
    });
    {
        auto opened = Lines::Open(context, path, Limited(11));
        ASSERT_TRUE(opened.HasValue());
        EXPECT_EQ(0, closes);
        EXPECT_EQ(0, reads);
        auto& original = opened.Value();
        Lines moved(std::move(original));
        EXPECT_TRUE(original.Close().HasValue());
        EXPECT_EQ(0, closes);
        auto cursor = moved.begin();
        ASSERT_TRUE(cursor->HasValue());
        EXPECT_EQ("one", cursor->Value());
        const int before = reads;
        EXPECT_TRUE(moved.Close().HasValue());
        EXPECT_EQ(before, reads);
        EXPECT_EQ(1, closes);
        EXPECT_FALSE(cursor != moved.end());
        EXPECT_FALSE(moved.begin() != moved.end());
        EXPECT_TRUE(moved.Close().HasValue());
        EXPECT_EQ(1, closes);
    }
    EXPECT_EQ(1, closes);
    {
        auto opened = Lines::Open(context, path, Limited(11));
        ASSERT_TRUE(opened.HasValue());
        EXPECT_EQ(1, closes);
        // Destruction of an unopened range is a nonthrowing closure fallback.
    }
    EXPECT_EQ(2, closes);
}

TEST_F(PathFile, RepeatedFailedCloseSucceedsWithoutRetry)
{
    Write("a\n");
    int closes = 0;
    ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([&](int fd) {
        const bool data = IsFileDescriptor(fd, true);
        if (data)
            ++closes;
        context.ContextInterface::CloseFileDescriptor(fd);
        if (!data)
            return 0;
        errno = EBADF;
        return -1;
    });
    {
        auto opened = Lines::Open(context, path, Limited(2));
        ASSERT_TRUE(opened.HasValue());
        auto& range = opened.Value();
        auto cursor = range.begin();
        ASSERT_TRUE(cursor->HasValue());
        ++cursor;
        EXPECT_FALSE(cursor != range.end());
        EXPECT_EQ(0, closes); // Even verified EOF does not close data.
        auto first = range.Close();
        ASSERT_FALSE(first.HasValue());
        EXPECT_EQ(EBADF, first.Error().code);
        EXPECT_EQ("Cannot close readable file", first.Error().message);
        auto again = range.Close();
        EXPECT_TRUE(again.HasValue());
    }
    EXPECT_EQ(1, closes);
}

TEST_F(PathFile, FailedExplicitCloseLogsDescriptorErrorOnlyOnce)
{
    Write("a\n");
    const std::string logPath = context.GetTempdirPath() + "/reader-close.log";
    OsConfigLogHandle logHandle = OpenLog(logPath.c_str(), nullptr);
    ASSERT_NE(nullptr, logHandle);
    context.SetLogHandle(logHandle);

    int closes = 0;
    ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([&](int fd) {
        const bool data = IsFileDescriptor(fd, true);
        if (data)
            ++closes;
        context.ContextInterface::CloseFileDescriptor(fd);
        if (!data)
            return 0;
        errno = EBADF;
        return -1;
    });
    auto opened = Lines::Open(context, path);
    EXPECT_TRUE(opened.HasValue());
    if (opened.HasValue())
    {
        auto& range = opened.Value();
        auto first = range.Close();
        EXPECT_FALSE(first.HasValue());
        auto again = range.Close();
        EXPECT_TRUE(again.HasValue());
        if (!first.HasValue())
        {
            EXPECT_EQ(EBADF, first.Error().code);
            EXPECT_EQ("Cannot close readable file", first.Error().message);
        }
    }
    EXPECT_EQ(1, closes);
    CloseLog(&logHandle);
    context.SetLogHandle(nullptr);
    std::ifstream log(logPath);
    ASSERT_TRUE(log.is_open());
    const std::string text((std::istreambuf_iterator<char>(log)), std::istreambuf_iterator<char>());
    const auto expected = "Failed to close directory activation: " + std::to_string(EBADF);
    const auto firstOccurrence = text.find(expected);
    ASSERT_NE(std::string::npos, firstOccurrence);
    EXPECT_EQ(std::string::npos, text.find(expected, firstOccurrence + expected.size()));
    EXPECT_EQ(std::string::npos, text.find("Failed to close pinned descriptor"));
}

TEST_F(PathFile, DestructionAndMoveAssignmentLogDataFailureOncePerRange)
{
    Write("x");
    const std::string logPath = context.GetTempdirPath() + "/reader-destructor.log";
    OsConfigLogHandle logHandle = OpenLog(logPath.c_str(), nullptr);
    ASSERT_NE(nullptr, logHandle);
    context.SetLogHandle(logHandle);
    int closes = 0;
    ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([&](int fd) {
        const bool data = IsFileDescriptor(fd, true);
        if (data)
            ++closes;
        context.ContextInterface::CloseFileDescriptor(fd);
        if (!data)
            return 0;
        errno = EBADF;
        return -1;
    });
    {
        auto first = Lines::Open(context, path);
        auto second = Lines::Open(context, path);
        ASSERT_TRUE(first.HasValue());
        ASSERT_TRUE(second.HasValue());
        first.Value() = std::move(second.Value()); // finalizes old state
        EXPECT_EQ(1, closes);
        EXPECT_TRUE(second.Value().Close().HasValue());
        // Finalize the transferred state by destruction, without explicit Close.
    }
    EXPECT_EQ(2, closes);
    CloseLog(&logHandle);
    context.SetLogHandle(nullptr);
    std::ifstream log(logPath);
    ASSERT_TRUE(log.is_open());
    const std::string text((std::istreambuf_iterator<char>(log)), std::istreambuf_iterator<char>());
    const auto expected = "Failed to close directory activation: " + std::to_string(EBADF);
    const auto firstOccurrence = text.find(expected);
    ASSERT_NE(std::string::npos, firstOccurrence);
    const auto secondOccurrence = text.find(expected, firstOccurrence + expected.size());
    ASSERT_NE(std::string::npos, secondOccurrence);
    EXPECT_EQ(std::string::npos, text.find(expected, secondOccurrence + expected.size()));
    EXPECT_EQ(std::string::npos, text.find("Failed to close pinned descriptor"));
}

TEST_F(PathFile, DestructorSuppressesThrowingDataCloseAndLogsOnce)
{
    Write("x");
    const std::string logPath = context.GetTempdirPath() + "/reader-throwing-close.log";
    OsConfigLogHandle logHandle = OpenLog(logPath.c_str(), nullptr);
    ASSERT_NE(nullptr, logHandle);
    context.SetLogHandle(logHandle);
    int closes = 0;
    ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([&](int fd) -> int {
        const bool data = IsFileDescriptor(fd, true);
        if (data)
            ++closes;
        context.ContextInterface::CloseFileDescriptor(fd);
        if (!data)
            return 0;
        throw std::runtime_error("injected data close failure");
    });
    {
        auto opened = Lines::Open(context, path);
        ASSERT_TRUE(opened.HasValue());
    }
    EXPECT_EQ(1, closes);
    CloseLog(&logHandle);
    context.SetLogHandle(nullptr);
    std::ifstream log(logPath);
    ASSERT_TRUE(log.is_open());
    const std::string text((std::istreambuf_iterator<char>(log)), std::istreambuf_iterator<char>());
    const auto expected = "Failed to close directory activation: " + std::to_string(EIO);
    const auto occurrence = text.find(expected);
    ASSERT_NE(std::string::npos, occurrence);
    EXPECT_EQ(std::string::npos, text.find(expected, occurrence + expected.size()));
}

TEST_F(PathFile, MoveAssignmentClosesOldOwnershipAndTransfersNew)
{
    Write("x");
    int closes = 0;
    ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([&](int fd) {
        if (IsFileDescriptor(fd, true))
            ++closes;
        return context.ContextInterface::CloseFileDescriptor(fd);
    });
    auto first = Lines::Open(context, path);
    auto second = Lines::Open(context, path);
    ASSERT_TRUE(first.HasValue());
    ASSERT_TRUE(second.HasValue());
    first.Value() = std::move(second.Value());
    EXPECT_EQ(1, closes);
    EXPECT_TRUE(second.Value().Close().HasValue());
    EXPECT_EQ(1, closes);
    EXPECT_TRUE(first.Value().Close().HasValue());
    EXPECT_EQ(2, closes);
}

TEST_F(PathFile, CloseBeforeBeginDoesNotReadOrReopen)
{
    int reads = 0, closes = 0;
    ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([&](int fd, void* buffer, std::size_t size) {
        if (!IsFileDescriptor(fd, true))
            return context.ContextInterface::ReadFileDescriptor(fd, buffer, size);
        ++reads;
        return context.ContextInterface::ReadFileDescriptor(fd, buffer, size);
    });
    ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([&](int fd) {
        if (IsFileDescriptor(fd, true))
            ++closes;
        return context.ContextInterface::CloseFileDescriptor(fd);
    });
    auto opened = Lines::Open(context, path);
    ASSERT_TRUE(opened.HasValue());
    auto& range = opened.Value();
    EXPECT_EQ(0, closes);
    EXPECT_EQ(0, reads);
    EXPECT_TRUE(range.Close().HasValue());
    EXPECT_EQ(1, closes);
    EXPECT_FALSE(range.begin() != range.end());
    EXPECT_EQ(0, reads);
}

TEST_F(PathFile, FactoryFailureClosesAcquiredPinAndReportsPrimary)
{
    const std::string logPath = context.GetTempdirPath() + "/reader-factory-close.log";
    OsConfigLogHandle logHandle = OpenLog(logPath.c_str(), nullptr);
    ASSERT_NE(nullptr, logHandle);
    context.SetLogHandle(logHandle);
    int dataStats = 0, pinCloses = 0, dataCloses = 0;
    ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([&](int fd, struct stat* metadata) {
        if (IsFileDescriptor(fd, true) && ++dataStats == 1)
        {
            errno = EACCES;
            return -1;
        }
        return context.ContextInterface::StatFileDescriptor(fd, metadata);
    });
    ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([&](int fd) {
        const bool pin = IsFileDescriptor(fd, false);
        const bool data = IsFileDescriptor(fd, true);
        pinCloses += pin;
        dataCloses += data;
        context.ContextInterface::CloseFileDescriptor(fd);
        if (pin)
        {
            errno = EBADF;
            return -1;
        }
        return 0;
    });
    auto opened = Lines::Open(context, path);
    ASSERT_FALSE(opened.HasValue());
    EXPECT_EQ(EACCES, opened.Error().code);
    EXPECT_EQ(1, dataStats);
    EXPECT_GE(pinCloses, 1);
    EXPECT_EQ(1, dataCloses);
    CloseLog(&logHandle);
    context.SetLogHandle(nullptr);
    std::ifstream log(logPath);
    ASSERT_TRUE(log.is_open());
    const std::string text((std::istreambuf_iterator<char>(log)), std::istreambuf_iterator<char>());
    const auto expected = "Failed to close pinned descriptors for " + path + ": " + std::to_string(EBADF);
    const auto occurrence = text.find(expected);
    ASSERT_NE(std::string::npos, occurrence);
    EXPECT_EQ(std::string::npos, text.find(expected, occurrence + expected.size()));
}

TEST_F(PathFile, FactoryClosesPinAfterIdentityCheckBeforeReturnOrRead)
{
    Write("content\n");
    int pin = -1, data = -1, reads = 0;
    int dataCloses = 0;
    ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([&](int fd, struct stat* metadata) {
        if (IsFileDescriptor(fd, true))
            data = fd;
        return context.ContextInterface::StatFileDescriptor(fd, metadata);
    });
    ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([&](int fd) {
        if (IsFileDescriptor(fd, false))
            pin = fd;
        if (IsFileDescriptor(fd, true))
            ++dataCloses;
        return context.ContextInterface::CloseFileDescriptor(fd);
    });
    ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([&](int fd, void* buffer, std::size_t size) {
        if (!IsFileDescriptor(fd, true))
            return context.ContextInterface::ReadFileDescriptor(fd, buffer, size);
        ++reads;
        return context.ContextInterface::ReadFileDescriptor(fd, buffer, size);
    });
    auto opened = Lines::Open(context, path);
    ASSERT_TRUE(opened.HasValue());
    ASSERT_GE(pin, 0);
    ASSERT_GE(data, 0);
    EXPECT_NE(pin, data);
    EXPECT_EQ(-1, ::fcntl(pin, F_GETFD));
    EXPECT_NE(-1, ::fcntl(data, F_GETFD));
    EXPECT_EQ(0, reads);
    EXPECT_EQ(0, dataCloses);
    EXPECT_TRUE(opened.Value().Close().HasValue());
    EXPECT_EQ(1, dataCloses);
    EXPECT_TRUE(opened.Value().Close().HasValue());
    EXPECT_EQ(1, dataCloses);
}

TEST_F(PathFile, EarlyStatFailuresCloseEveryAcquiredDescriptor)
{
    Write("a");
    for (const bool failReadable : {false, true})
    {
        int stats = 0;
        std::vector<int> observed, closed;
        ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([&](int fd, struct stat* metadata) {
            if (IsFileDescriptor(fd, failReadable))
            {
                ++stats;
                observed.push_back(fd);
                errno = EACCES;
                return -1;
            }
            return context.ContextInterface::StatFileDescriptor(fd, metadata);
        });
        ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([&](int fd) {
            if (IsFileDescriptor(fd, failReadable))
                closed.push_back(fd);
            return context.ContextInterface::CloseFileDescriptor(fd);
        });
        auto opened = Lines::Open(context, path);
        ASSERT_FALSE(opened.HasValue());
        EXPECT_EQ(EACCES, opened.Error().code);
        EXPECT_GE(stats, 1);
        ASSERT_FALSE(observed.empty());
        EXPECT_NE(closed.end(), std::find(closed.begin(), closed.end(), observed.front()));
        EXPECT_EQ(-1, ::fcntl(observed.front(), F_GETFD));
    }
}

TEST_F(PathFile, FailedPinCloseIsPrimaryAndStillLogsDataCleanupFailure)
{
    Write("a");
    int dataStats = 0, pinCloses = 0, dataCloses = 0, reads = 0;
    const std::string logPath = context.GetTempdirPath() + "/reader-pin-close.log";
    OsConfigLogHandle logHandle = OpenLog(logPath.c_str(), nullptr);
    ASSERT_NE(nullptr, logHandle);
    context.SetLogHandle(logHandle);
    ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([&](int fd, struct stat* metadata) {
        if (IsFileDescriptor(fd, true))
            ++dataStats;
        return context.ContextInterface::StatFileDescriptor(fd, metadata);
    });
    ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([&](int fd) {
        const bool pin = IsFileDescriptor(fd, false);
        const bool data = IsFileDescriptor(fd, true);
        pinCloses += pin;
        dataCloses += data;
        context.ContextInterface::CloseFileDescriptor(fd);
        if (pin)
        {
            errno = EACCES;
            return -1;
        }
        if (data)
        {
            errno = EBADF;
            return -1;
        }
        return 0;
    });
    ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([&](int fd, void* buffer, std::size_t size) -> ssize_t {
        if (!IsFileDescriptor(fd, true))
            return context.ContextInterface::ReadFileDescriptor(fd, buffer, size);
        ++reads;
        return 0;
    });
    auto opened = Lines::Open(context, path);
    ASSERT_FALSE(opened.HasValue());
    EXPECT_EQ(EACCES, opened.Error().code);
    EXPECT_EQ("Failed to close pinned descriptor", opened.Error().message);
    EXPECT_GE(pinCloses, 1);
    EXPECT_EQ(1, dataCloses);
    EXPECT_EQ(0, reads);
    CloseLog(&logHandle);
    context.SetLogHandle(nullptr);
    std::ifstream log(logPath);
    ASSERT_TRUE(log.is_open());
    const std::string text((std::istreambuf_iterator<char>(log)), std::istreambuf_iterator<char>());
    EXPECT_NE(std::string::npos, text.find("Failed to close internal filesystem descriptor: " + std::to_string(EACCES)));
    EXPECT_EQ(std::string::npos, text.find("Failed to close pinned descriptors for " + path + ": " + std::to_string(EACCES)));
    const auto dataError = "Failed to close directory activation: " + std::to_string(EBADF);
    const auto dataOccurrence = text.find(dataError);
    ASSERT_NE(std::string::npos, dataOccurrence);
    EXPECT_EQ(std::string::npos, text.find(dataError, dataOccurrence + dataError.size()));
}

TEST_F(PathFile, CheckedAcquisitionReleaseAttemptsAllPinsAndLogsSecondaryFailure)
{
    Write("a");
    const std::string logPath = context.GetTempdirPath() + "/reader-secondary-close.log";
    OsConfigLogHandle logHandle = OpenLog(logPath.c_str(), nullptr);
    ASSERT_NE(nullptr, logHandle);
    context.SetLogHandle(logHandle);
    int dataStats = 0, failedPins = 0, dataCloses = 0;
    bool releasingPins = false;
    ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([&](int fd, struct stat* metadata) {
        if (IsFileDescriptor(fd, true) && ++dataStats == 2)
            releasingPins = true;
        return context.ContextInterface::StatFileDescriptor(fd, metadata);
    });
    ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([&](int fd) {
        const bool data = IsFileDescriptor(fd, true);
        const bool fail = releasingPins && !data;
        dataCloses += data;
        context.ContextInterface::CloseFileDescriptor(fd);
        if (fail)
        {
            errno = ++failedPins == 1 ? EACCES : EIO;
            return -1;
        }
        return 0;
    });
    auto opened = Lines::Open(context, path);
    ASSERT_FALSE(opened.HasValue());
    EXPECT_EQ(EACCES, opened.Error().code);
    EXPECT_EQ("Failed to close pinned descriptor", opened.Error().message);
    EXPECT_GE(failedPins, 2);
    EXPECT_EQ(1, dataCloses);
    CloseLog(&logHandle);
    context.SetLogHandle(nullptr);
    std::ifstream log(logPath);
    ASSERT_TRUE(log.is_open());
    const std::string text((std::istreambuf_iterator<char>(log)), std::istreambuf_iterator<char>());
    EXPECT_NE(std::string::npos, text.find("Secondary filesystem pin close failure: " + std::to_string(EIO)));
    EXPECT_NE(std::string::npos, text.find("Failed to close internal filesystem descriptor: " + std::to_string(EACCES)));
}

TEST_F(PathFile, ThrowingAcquisitionAndPinCleanupDoNotLeakOrReplacePrimary)
{
    Write("a");
    int dataStats = 0, pinCloses = 0, dataCloses = 0;
    ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([&](int fd, struct stat* metadata) -> int {
        if (IsFileDescriptor(fd, true) && ++dataStats == 1)
            throw std::runtime_error("inspect data");
        return context.ContextInterface::StatFileDescriptor(fd, metadata);
    });
    ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([&](int fd) -> int {
        const bool pin = IsFileDescriptor(fd, false);
        const bool data = IsFileDescriptor(fd, true);
        pinCloses += pin;
        dataCloses += data;
        context.ContextInterface::CloseFileDescriptor(fd);
        if (pin)
            throw std::runtime_error("pin cleanup");
        return 0;
    });
    try
    {
        (void)Lines::Open(context, path);
        FAIL() << "Data stat should throw";
    }
    catch (const std::runtime_error& error)
    {
        EXPECT_STREQ("inspect data", error.what());
    }
    EXPECT_EQ(1, dataStats);
    EXPECT_GE(pinCloses, 1);
    EXPECT_EQ(1, dataCloses);
    ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([&](int fd, struct stat* metadata) {
        if (IsFileDescriptor(fd, true))
            ++dataStats;
        return context.ContextInterface::StatFileDescriptor(fd, metadata);
    });
    dataStats = pinCloses = dataCloses = 0;
    auto opened = Lines::Open(context, path);
    ASSERT_FALSE(opened.HasValue());
    EXPECT_EQ(EIO, opened.Error().code); // Opaque close catches, caches, never retries.
    EXPECT_GE(pinCloses, 1);
    EXPECT_EQ(1, dataCloses);
}

TEST_F(PathFile, ChunkBoundaryAndTrailingNewlineAreVerifiedWithoutExtraEmptyLine)
{
    Write(std::string(8191, 'a') + "\n\n");
    auto opened = Lines::Open(context, path, Limited(8193));
    ASSERT_TRUE(opened.HasValue());
    std::vector<std::string> lines;
    auto& range = opened.Value();
    for (const auto& item : range)
    {
        ASSERT_TRUE(item.HasValue());
        lines.push_back(item.Value());
    }
    ASSERT_EQ(2U, lines.size());
    EXPECT_EQ(std::string(8191, 'a'), lines[0]);
    EXPECT_EQ("", lines[1]);
    EXPECT_TRUE(range.Close().HasValue());
}

TEST_F(PathFile, PinnedInodeSymlinkAndNonregular)
{
    Write("original");
    bool replaced = false;
    ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([&](int fd, struct stat* metadata) {
        const int status = context.ContextInterface::StatFileDescriptor(fd, metadata);
        if (status == 0 && !replaced && IsFileDescriptor(fd, false) && ::rename(path.c_str(), (path + ".old").c_str()) == 0)
        {
            const int replacement = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
            if (replacement >= 0)
            {
                replaced = ::write(replacement, "new", 3) == 3;
                ::close(replacement);
            }
        }
        return status;
    });
    EXPECT_EQ("original", Collect(path, Limited(8)).Value());
    ASSERT_TRUE(replaced);
    ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([&](int fd, struct stat* metadata) {
        return context.ContextInterface::StatFileDescriptor(fd, metadata);
    });
    ASSERT_EQ(0, ::symlink(path.c_str(), (path + ".link").c_str()));
    EXPECT_EQ("new", Collect(path + ".link", Limited(3)).Value());
    auto reject = Limited(3);
    reject.symlinks = SymlinkFollowing::DoNotFollow;
    EXPECT_EQ(ELOOP, Collect(path + ".link", reject).Error().code);
    EXPECT_EQ(EINVAL, Collect(context.GetTempdirPath(), Limited(3)).Error().code);
}

TEST_F(PathFile, AncestorReplacementBeforeAcquisitionRespectsLinkPolicy)
{
    // Swap before descent: reject the new ancestor link, rather than reading
    // from the replacement directory. Follow still selects the replacement.
    const std::string root = context.GetTempdirPath();
    const std::string ancestor = root + "/ancestor";
    const std::string alternate = root + "/alternate";
    const std::string parked = root + "/ancestor.old";
    const std::string requested = ancestor + "/target";
    ASSERT_TRUE(MakeAncestorTargets(ancestor, alternate));

    bool swapped = false;
    int reads = 0, linkCloses = 0;
    ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([&](int fd, void* buffer, std::size_t size) -> ssize_t {
        reads += IsFileDescriptor(fd, true, alternate + "/target");
        return context.ContextInterface::ReadFileDescriptor(fd, buffer, size);
    });
    ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([&](int fd) -> int {
        linkCloses += IsLinkDescriptor(fd, ancestor);
        return context.ContextInterface::CloseFileDescriptor(fd);
    });
    struct stat processRoot = {};
    ASSERT_EQ(0, ::stat("/", &processRoot));
    ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([&](int fd, struct stat* metadata) {
        const int status = context.ContextInterface::StatFileDescriptor(fd, metadata);
        if (!swapped && status == 0 && metadata->st_dev == processRoot.st_dev && metadata->st_ino == processRoot.st_ino)
        {
            swapped = true;
            EXPECT_EQ(0, ::rename(ancestor.c_str(), parked.c_str()));
            EXPECT_EQ(0, ::symlink(alternate.c_str(), ancestor.c_str()));
        }
        return status;
    });

    auto reject = Limited(16);
    reject.symlinks = SymlinkFollowing::DoNotFollow;
    auto result = Collect(requested, reject);
    ASSERT_FALSE(result.HasValue());
    EXPECT_TRUE(swapped);
    EXPECT_EQ(ELOOP, result.Error().code);
    EXPECT_EQ(0, reads);
    EXPECT_EQ(1, linkCloses);
    EXPECT_EQ("alternate", Collect(requested, Limited(16)).Value());
}

TEST_F(PathFile, AncestorReplacementAfterAcquisitionKeepsPinnedFile)
{
    // Once acquired, replacement cannot redirect the pinned file's bytes.
    const std::string root = context.GetTempdirPath();
    const std::string ancestor = root + "/ancestor";
    const std::string alternate = root + "/alternate";
    const std::string parked = root + "/ancestor.old";
    const std::string requested = ancestor + "/target";
    ASSERT_TRUE(MakeAncestorTargets(ancestor, alternate));

    bool swapped = false;
    ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([&](int fd, struct stat* metadata) {
        const int status = context.ContextInterface::StatFileDescriptor(fd, metadata);
        if (!swapped && status == 0 && IsFileDescriptor(fd, false, requested))
        {
            swapped = true;
            EXPECT_EQ(0, ::rename(ancestor.c_str(), parked.c_str()));
            EXPECT_EQ(0, ::symlink(alternate.c_str(), ancestor.c_str()));
        }
        return status;
    });

    auto result = Collect(requested, Limited(16));
    ASSERT_TRUE(result.HasValue());
    EXPECT_TRUE(swapped);
    EXPECT_EQ("original", result.Value());
}

TEST_F(PathFile, VerificationAndFinalAdvanceReportErrors)
{
    Write("abc\n");
    int stats = 0;
    ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([&](int fd, struct stat* metadata) {
        const int status = context.ContextInterface::StatFileDescriptor(fd, metadata);
        if (status == 0 && IsFileDescriptor(fd, true) && ++stats == 2)
            ++metadata->st_ino;
        return status;
    });
    EXPECT_EQ(EAGAIN, Collect(path, Limited(4)).Error().code);
    int reads = 0;
    ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([&](int fd, void* buffer, std::size_t size) {
        reads += IsFileDescriptor(fd, true);
        return context.ContextInterface::ReadFileDescriptor(fd, buffer, size);
    });
    ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([&](int fd, struct stat* metadata) {
        const int status = context.ContextInterface::StatFileDescriptor(fd, metadata);
        if (status == 0 && IsFileDescriptor(fd, true) && reads > 0)
            ++metadata->st_mtim.tv_nsec;
        return status;
    });
    auto opened = Lines::Open(context, path, Limited(4));
    ASSERT_TRUE(opened.HasValue());
    auto& range = opened.Value();
    auto cursor = range.begin();
    ASSERT_TRUE(cursor->HasValue());
    EXPECT_EQ("abc", cursor->Value());
    ++cursor;
    ASSERT_TRUE(cursor != range.end());
    EXPECT_FALSE(cursor->HasValue());
    EXPECT_EQ(EAGAIN, cursor->Error().code);
    EXPECT_GT(reads, 0);
    ++cursor;
    EXPECT_FALSE(cursor != range.end());
    EXPECT_TRUE(range.Close().HasValue());
    ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([&](int fd, struct stat* metadata) {
        return context.ContextInterface::StatFileDescriptor(fd, metadata);
    });
    ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([&](int fd, void* buffer, std::size_t size) -> ssize_t {
        if (!IsFileDescriptor(fd, true))
            return context.ContextInterface::ReadFileDescriptor(fd, buffer, size);
        return 0;
    });
    EXPECT_EQ(EIO, Collect(path, Limited(4)).Error().code);
}

TEST_F(PathFile, ErrorsOnIntermediateReadsAndRetryLimit)
{
    Write("a\n" + std::string(8190, 'x') + "b\n");
    int reads = 0;
    ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([&](int fd, void* buffer, std::size_t size) -> ssize_t {
        if (!IsFileDescriptor(fd, true))
            return context.ContextInterface::ReadFileDescriptor(fd, buffer, size);
        if (++reads == 1)
        {
            return context.ContextInterface::ReadFileDescriptor(fd, buffer, size);
        }
        errno = EACCES;
        return -1;
    });
    auto opened = Lines::Open(context, path, Limited(8194));
    ASSERT_TRUE(opened.HasValue());
    auto& range = opened.Value();
    auto it = range.begin();
    ASSERT_TRUE(it->HasValue());
    ++it;
    ASSERT_FALSE(it->HasValue());
    EXPECT_EQ(EACCES, it->Error().code);
    ++it;
    EXPECT_FALSE(it != range.end());
    EXPECT_TRUE(range.Close().HasValue());
    ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([&](int fd, void* buffer, std::size_t size) -> ssize_t {
        if (!IsFileDescriptor(fd, true))
            return context.ContextInterface::ReadFileDescriptor(fd, buffer, size);
        errno = EINTR;
        return -1;
    });
    EXPECT_EQ(E2BIG, Collect(path, Limited(4, 1)).Error().code);
    ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([&](int fd, void* buffer, std::size_t size) -> ssize_t {
        if (!IsFileDescriptor(fd, true))
            return context.ContextInterface::ReadFileDescriptor(fd, buffer, size);
        return static_cast<ssize_t>(size + 1);
    });
    EXPECT_EQ(EIO, Collect(path, Limited(4)).Error().code);
}

TEST_F(PathFile, DataCloseErrorIsPrimaryAfterSuccessButNotAfterReadFailure)
{
    Write("abc\n");
    int dataCloses = 0;
    ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([&](int fd) {
        const bool data = IsFileDescriptor(fd, true);
        context.ContextInterface::CloseFileDescriptor(fd);
        if (data)
        {
            ++dataCloses;
            errno = EBADF;
            return -1;
        }
        return 0;
    });
    auto result = Collect(path, Limited(4));
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EBADF, result.Error().code);
    EXPECT_EQ("Cannot close readable file", result.Error().message);
    EXPECT_EQ(1, dataCloses);
    ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([&](int fd, void* buffer, std::size_t size) -> ssize_t {
        if (!IsFileDescriptor(fd, true))
            return context.ContextInterface::ReadFileDescriptor(fd, buffer, size);
        errno = EIO;
        return -1;
    });
    result = Collect(path, Limited(4));
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EIO, result.Error().code);
    EXPECT_EQ("Failed to read file bytes", result.Error().message);
    EXPECT_EQ(2, dataCloses);
}

TEST_F(PathFile, LastUnterminatedLineIsNotPublishedWhenVerificationOrCloseFails)
{
    Write("tail");
    int reads = 0;
    ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([&](int fd, void* buffer, std::size_t size) {
        reads += IsFileDescriptor(fd, true);
        return context.ContextInterface::ReadFileDescriptor(fd, buffer, size);
    });
    ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([&](int fd, struct stat* metadata) {
        const int status = context.ContextInterface::StatFileDescriptor(fd, metadata);
        if (status == 0 && IsFileDescriptor(fd, true) && reads > 0)
            ++metadata->st_ctim.tv_nsec;
        return status;
    });
    auto opened = Lines::Open(context, path, Limited(4));
    ASSERT_TRUE(opened.HasValue());
    auto& range = opened.Value();
    int lines = 0;
    for (const auto& item : range)
    {
        ++lines;
        ASSERT_FALSE(item.HasValue());
        EXPECT_EQ(EAGAIN, item.Error().code);
    }
    EXPECT_EQ(1, lines);
    EXPECT_GT(reads, 0);
    EXPECT_TRUE(range.Close().HasValue());
    ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([&](int fd, struct stat* metadata) {
        return context.ContextInterface::StatFileDescriptor(fd, metadata);
    });
    int closes = 0;
    ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([&](int fd) -> int {
        const bool data = IsFileDescriptor(fd, true);
        closes += data;
        context.ContextInterface::CloseFileDescriptor(fd);
        if (data)
            throw std::runtime_error("close");
        return 0;
    });
    // A failed close no longer suppresses the verified unterminated line.
    auto tail = Lines::Open(context, path, Limited(4));
    ASSERT_TRUE(tail.HasValue());
    auto& tailRange = tail.Value();
    auto cursor = tailRange.begin();
    ASSERT_TRUE(cursor->HasValue());
    EXPECT_EQ("tail", cursor->Value());
    ++cursor;
    EXPECT_FALSE(cursor != tailRange.end());
    auto closed = tailRange.Close();
    ASSERT_FALSE(closed.HasValue());
    EXPECT_EQ(EIO, closed.Error().code);
    EXPECT_EQ(1, closes); // Data close is not retried after throwing.
}

TEST_F(PathFile, ThrowingOpenAndEofStatPropagateAndCloseOwnedDescriptors)
{
    Write("a");
    int stats = 0, closes = 0;
    ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([&](int fd, struct stat* metadata) -> int {
        if (IsFileDescriptor(fd, true) && ++stats == 2)
            throw std::bad_alloc();
        return context.ContextInterface::StatFileDescriptor(fd, metadata);
    });
    ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([&](int fd) {
        if (IsFileDescriptor(fd, true))
            ++closes;
        return context.ContextInterface::CloseFileDescriptor(fd);
    });
    EXPECT_THROW(Collect(path, Limited(1)), std::bad_alloc);
    EXPECT_EQ(1, closes);
    closes = 0;
    stats = 0;
    int reads = 0;
    ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([&](int fd, void* buffer, std::size_t size) {
        reads += IsFileDescriptor(fd, true);
        return context.ContextInterface::ReadFileDescriptor(fd, buffer, size);
    });
    ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([&](int fd, struct stat* metadata) -> int {
        if (IsFileDescriptor(fd, true) && reads > 0)
            throw std::runtime_error("stat");
        if (IsFileDescriptor(fd, true))
            ++stats;
        return context.ContextInterface::StatFileDescriptor(fd, metadata);
    });
    EXPECT_THROW(Collect(path, Limited(1)), std::runtime_error);
    EXPECT_GT(reads, 0);
    EXPECT_EQ(1, closes);
}

TEST_F(PathFile, ThrowingReadDuringIterationPropagatesAndClosesData)
{
    Write("first\n" + std::string(8192 - std::string("first\n").size(), 'x') + "second\n");
    int reads = 0, closes = 0;
    ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([&](int fd, void* buffer, std::size_t size) -> ssize_t {
        if (!IsFileDescriptor(fd, true))
            return context.ContextInterface::ReadFileDescriptor(fd, buffer, size);
        if (++reads == 1)
        {
            return context.ContextInterface::ReadFileDescriptor(fd, buffer, size);
        }
        throw std::runtime_error("read failed");
    });
    ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([&](int fd) {
        if (IsFileDescriptor(fd, true))
            ++closes;
        return context.ContextInterface::CloseFileDescriptor(fd);
    });
    {
        auto opened = Lines::Open(context, path, Limited(8199));
        ASSERT_TRUE(opened.HasValue());
        auto cursor = opened.Value().begin();
        ASSERT_TRUE(cursor->HasValue());
        EXPECT_EQ("first", cursor->Value());
        EXPECT_THROW(++cursor, std::runtime_error);
    }
    EXPECT_EQ(2, reads);
    EXPECT_EQ(1, closes);
}
