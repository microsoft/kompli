// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <MockContext.h>
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <filesystem/FileReader.hpp>
#include <gtest/gtest.h>
#include <limits>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

using namespace FileReader;
using testing::_;
using testing::NiceMock;

namespace
{
Policy Limited(std::size_t maxBytes, std::size_t retries = 2)
{
    Policy policy;
    policy.symlinks = SymlinksPolicy::FollowFinal;
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
    // Consume errors as items; never confuse early stop with complete input.
    ComplianceEngine::Result<std::string> Collect(const std::string& source, Policy policy)
    {
        auto opened = Lines(context, source, std::move(policy));
        if (!opened.HasValue())
            return std::move(opened).Error();
        auto& range = opened.Value();
        std::string bytes;
        for (const auto& item : range)
        {
            if (!item.HasValue())
            {
                auto error = item.Error();
                auto closed = range.Close();
                if (!closed.HasValue())
                    error.message += " [close: " + closed.Error().message + "]";
                return error;
            }
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
    const Policy defaults;
    EXPECT_EQ(SymlinksPolicy::FollowFinal, defaults.symlinks);
    EXPECT_EQ(1024U * 1024U, defaults.limits.maxBytes);
    EXPECT_EQ(128U, defaults.limits.maxInterruptedReads);

    Policy custom;
    custom.symlinks = SymlinksPolicy::RejectFinal;
    custom.limits.maxBytes = 3;
    custom.limits.maxInterruptedReads = 1;
    EXPECT_EQ(SymlinksPolicy::RejectFinal, custom.symlinks);
    EXPECT_EQ(3U, custom.limits.maxBytes);
    EXPECT_EQ(1U, custom.limits.maxInterruptedReads);
}

TEST_F(PathFile, OmittedPolicyFollowsFinalSymlinkAndRejectsNul)
{
    Write("plain\n");
    ASSERT_EQ(0, ::symlink(path.c_str(), (path + ".link").c_str()));
    std::string collected;
    auto opened = Lines(context, path + ".link");
    ASSERT_TRUE(opened.HasValue());
    auto& range = opened.Value();
    for (const auto& item : range)
    {
        ASSERT_TRUE(item.HasValue());
        collected += item.Value();
    }
    EXPECT_EQ("plain\n", collected);
    EXPECT_TRUE(range.Close().HasValue());

    Write(std::string("a\0b", 3));
    int errors = 0;
    auto textOpened = Lines(context, path);
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
    Policy reject;
    reject.symlinks = SymlinksPolicy::RejectFinal;
    EXPECT_EQ(ELOOP, Collect(path + ".link", reject).Error().code);
}

TEST_F(PathFile, DefaultLimitsBoundBytesAndInterruptedReads)
{
    const std::size_t cap = Policy{}.limits.maxBytes;
    std::size_t requested = 0;
    int probes = 0;
    ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([&](int, void* buffer, std::size_t size) -> ssize_t {
        requested += size;
        if (size == 1)
            ++probes;
        std::memset(buffer, 'x', size);
        return static_cast<ssize_t>(size);
    });
    auto result = Collect(path, Policy{});
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(E2BIG, result.Error().code);
    EXPECT_EQ(cap + 1, requested);
    EXPECT_EQ(1, probes);

    int attempts = 0;
    ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([&](int, void*, std::size_t) -> ssize_t {
        ++attempts;
        errno = EINTR;
        return -1;
    });
    result = Collect(path, Policy{});
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(E2BIG, result.Error().code);
    EXPECT_EQ(129, attempts);
    attempts = 0;
    EXPECT_EQ(E2BIG, Collect(path, Limited(3, 1)).Error().code);
    EXPECT_EQ(2, attempts);
}

TEST_F(PathFile, ValidationAndOpenAreFactoryOperations)
{
    int opens = 0;
    ON_CALL(context, OpenExistingFile(_, _)).WillByDefault([&](const char*, int) {
        ++opens;
        errno = EIO;
        return -1;
    });
    auto invalidPath = Lines(context, "relative", Limited(16));
    EXPECT_FALSE(invalidPath.HasValue());
    EXPECT_EQ(0, opens);
    for (const auto& name : {std::string(), std::string("relative"), std::string("a\0b", 3)})
        EXPECT_EQ(EINVAL, Collect(name, Limited(16)).Error().code);
    auto invalid = Limited(16);
    invalid.symlinks = static_cast<SymlinksPolicy>(99);
    EXPECT_EQ(EINVAL, Collect(path, invalid).Error().code);
    invalid = Limited(0);
    EXPECT_EQ(EINVAL, Collect(path, invalid).Error().code);
    invalid = Limited(16, 0);
    EXPECT_EQ(EINVAL, Collect(path, invalid).Error().code);
    invalid = Limited(std::numeric_limits<std::size_t>::max());
    EXPECT_EQ(EOVERFLOW, Collect(path, invalid).Error().code);
    EXPECT_EQ(0, opens);
    EXPECT_EQ(EIO, Collect(path, Limited(16)).Error().code);
    EXPECT_EQ(1, opens);
}

TEST_F(PathFile, EmptyUnterminatedAndOriginalNewlines)
{
    EXPECT_EQ("", Collect(path, Limited(1)).Value());
    Write("a\r\n\nlast");
    std::vector<std::string> lines;
    auto opened = Lines(context, path, Limited(8));
    ASSERT_TRUE(opened.HasValue());
    auto& range = opened.Value();
    for (const auto& item : range)
    {
        ASSERT_TRUE(item.HasValue());
        lines.push_back(item.Value());
    }
    EXPECT_TRUE(range.Close().HasValue());
    ASSERT_EQ(3U, lines.size());
    EXPECT_EQ("a\r\n", lines[0]);
    EXPECT_EQ("\n", lines[1]);
    EXPECT_EQ("last", lines[2]);
    EXPECT_EQ("a\r\n\nlast", Collect(path, Limited(8)).Value());
}

TEST_F(PathFile, RejectsNulButPreservesHighBitBytes)
{
    const std::string original("a\0\xff\nb", 5);
    Write(original);
    EXPECT_EQ(EBADMSG, Collect(path, Limited(5)).Error().code);
    Write(std::string("\xff\r\n", 3));
    EXPECT_EQ(std::string("\xff\r\n", 3), Collect(path, Limited(3)).Value());
    EXPECT_EQ(E2BIG, Collect(path, Limited(2)).Error().code);
}

TEST_F(PathFile, NulAtStartMiddleOrEndNeverYieldsAffectedLine)
{
    for (const auto& content : {std::string("\0ab\n", 4), std::string("a\0b\n", 4), std::string("ab\0", 3)})
    {
        Write(content);
        int closes = 0, items = 0;
        ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([&](int fd) {
            ++closes;
            return context.ContextInterface::CloseFileDescriptor(fd);
        });
        auto opened = Lines(context, path);
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
        EXPECT_EQ(2, closes);
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
            ++closes;
            return context.ContextInterface::CloseFileDescriptor(fd);
        });
        auto opened = Lines(context, path, Limited(8200));
        ASSERT_TRUE(opened.HasValue());
        auto& range = opened.Value();
        auto it = range.begin();
        ASSERT_TRUE(it != range.end());
        ASSERT_TRUE(it->HasValue());
        EXPECT_EQ(valid, it->Value());
        ++it;
        ASSERT_TRUE(it != range.end());
        ASSERT_FALSE(it->HasValue());
        EXPECT_EQ(EBADMSG, it->Error().code);
        ++it;
        EXPECT_FALSE(it != range.end());
        EXPECT_TRUE(range.Close().HasValue());
        EXPECT_EQ(2, closes);
    }
}

TEST_F(PathFile, BoundedChunksAndLazyEarlyBreakCloseExactlyOnce)
{
    Write(std::string(20000, 'x') + "\n" + std::string(50000, 'y'));
    int reads = 0, opens = 0, closes = 0;
    std::size_t largest = 0;
    ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([&](int fd, void* buffer, std::size_t size) {
        ++reads;
        largest = std::max(largest, size);
        return context.ContextInterface::ReadFileDescriptor(fd, buffer, size);
    });
    ON_CALL(context, OpenExistingFile(_, _)).WillByDefault([&](const char* name, int flags) {
        ++opens;
        return context.ContextInterface::OpenExistingFile(name, flags);
    });
    ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([&](int fd) {
        ++closes;
        return context.ContextInterface::CloseFileDescriptor(fd);
    });
    auto opened = Lines(context, path, Limited(80000));
    ASSERT_TRUE(opened.HasValue());
    auto& range = opened.Value();
    EXPECT_EQ(2, opens);
    EXPECT_EQ(0, reads);
    {
        auto it = range.begin();
        EXPECT_TRUE(it != range.end());
        ASSERT_TRUE(it->HasValue());
        EXPECT_EQ(20001U, it->Value().size());
        EXPECT_EQ(2, opens);
        EXPECT_EQ(3, reads); // 8 KiB chunks, no forced tail read.
        EXPECT_LE(largest, 8192U);
        auto moved = std::move(it);
        EXPECT_FALSE(it != range.end());
        EXPECT_TRUE(moved != range.end());
    }
    EXPECT_EQ(0, closes);
    EXPECT_FALSE(range.begin() != range.end());
    EXPECT_TRUE(range.Close().HasValue());
    EXPECT_EQ(2, closes);
    EXPECT_TRUE(range.Close().HasValue());
    EXPECT_EQ(2, closes);
}

TEST_F(PathFile, RangeMoveAndEarlyCloseNeverReadTail)
{
    Write("one\nsecond\n");
    int reads = 0, closes = 0, opens = 0;
    ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([&](int fd, void* buffer, std::size_t size) {
        ++reads;
        return context.ContextInterface::ReadFileDescriptor(fd, buffer, size);
    });
    ON_CALL(context, OpenExistingFile(_, _)).WillByDefault([&](const char* name, int flags) {
        ++opens;
        return context.ContextInterface::OpenExistingFile(name, flags);
    });
    ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([&](int fd) {
        ++closes;
        return context.ContextInterface::CloseFileDescriptor(fd);
    });
    {
        auto opened = Lines(context, path, Limited(11));
        ASSERT_TRUE(opened.HasValue());
        EXPECT_EQ(2, opens);
        EXPECT_EQ(0, reads);
        auto& original = opened.Value();
        LinesRange moved(std::move(original));
        EXPECT_TRUE(original.Close().HasValue());
        EXPECT_EQ(0, closes);
        auto cursor = moved.begin();
        ASSERT_TRUE(cursor->HasValue());
        EXPECT_EQ("one\n", cursor->Value());
        const int before = reads;
        EXPECT_TRUE(moved.Close().HasValue());
        EXPECT_EQ(before, reads);
        EXPECT_EQ(2, closes);
        EXPECT_FALSE(cursor != moved.end());
        EXPECT_FALSE(moved.begin() != moved.end());
        EXPECT_TRUE(moved.Close().HasValue());
        EXPECT_EQ(2, closes);
    }
    EXPECT_EQ(2, closes);
    {
        auto opened = Lines(context, path, Limited(11));
        ASSERT_TRUE(opened.HasValue());
        EXPECT_EQ(2, closes);
        // Destruction of an unopened range is a nonthrowing closure fallback.
    }
    EXPECT_EQ(4, closes);
}

TEST_F(PathFile, RepeatedFailedCloseReportsOriginalOutcomeWithoutRetry)
{
    Write("a\n");
    int closes = 0;
    ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([&](int fd) {
        ++closes;
        context.ContextInterface::CloseFileDescriptor(fd);
        errno = closes == 1 ? EBADF : EACCES;
        return -1;
    });
    auto opened = Lines(context, path, Limited(2));
    ASSERT_TRUE(opened.HasValue());
    auto& range = opened.Value();
    auto cursor = range.begin();
    ASSERT_TRUE(cursor->HasValue());
    ++cursor;
    EXPECT_FALSE(cursor != range.end());
    EXPECT_EQ(0, closes); // Even verified EOF is not finalization.
    auto first = range.Close();
    ASSERT_FALSE(first.HasValue());
    EXPECT_EQ(EBADF, first.Error().code);
    EXPECT_NE(std::string::npos, first.Error().message.find("pin close: 13"));
    auto again = range.Close();
    ASSERT_FALSE(again.HasValue());
    EXPECT_EQ(first.Error().code, again.Error().code);
    EXPECT_EQ(first.Error().message, again.Error().message);
    EXPECT_EQ(2, closes);
}

TEST_F(PathFile, MoveAssignmentClosesOldOwnershipAndTransfersNew)
{
    Write("x");
    int closes = 0;
    ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([&](int fd) {
        ++closes;
        return context.ContextInterface::CloseFileDescriptor(fd);
    });
    auto first = Lines(context, path);
    auto second = Lines(context, path);
    ASSERT_TRUE(first.HasValue());
    ASSERT_TRUE(second.HasValue());
    first.Value() = std::move(second.Value());
    EXPECT_EQ(2, closes);
    EXPECT_TRUE(second.Value().Close().HasValue());
    EXPECT_EQ(2, closes);
    EXPECT_TRUE(first.Value().Close().HasValue());
    EXPECT_EQ(4, closes);
}

TEST_F(PathFile, CloseBeforeBeginDoesNotReadOrReopen)
{
    int opens = 0, reads = 0, closes = 0;
    ON_CALL(context, OpenExistingFile(_, _)).WillByDefault([&](const char* name, int flags) {
        ++opens;
        return context.ContextInterface::OpenExistingFile(name, flags);
    });
    ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([&](int fd, void* buffer, std::size_t size) {
        ++reads;
        return context.ContextInterface::ReadFileDescriptor(fd, buffer, size);
    });
    ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([&](int fd) {
        ++closes;
        return context.ContextInterface::CloseFileDescriptor(fd);
    });
    auto opened = Lines(context, path);
    ASSERT_TRUE(opened.HasValue());
    auto& range = opened.Value();
    EXPECT_EQ(2, opens);
    EXPECT_EQ(0, reads);
    EXPECT_TRUE(range.Close().HasValue());
    EXPECT_EQ(2, closes);
    EXPECT_FALSE(range.begin() != range.end());
    EXPECT_EQ(2, opens);
    EXPECT_EQ(0, reads);
}

TEST_F(PathFile, FactoryFailureClosesAcquiredPinAndReportsPrimary)
{
    int opens = 0, closes = 0, reads = 0;
    ON_CALL(context, OpenExistingFile(_, _)).WillByDefault([&](const char* name, int flags) {
        if (++opens == 2)
        {
            errno = EACCES;
            return -1;
        }
        return context.ContextInterface::OpenExistingFile(name, flags);
    });
    ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([&](int fd) {
        ++closes;
        context.ContextInterface::CloseFileDescriptor(fd);
        errno = EBADF;
        return -1;
    });
    ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([&](int, void*, std::size_t) -> ssize_t {
        ++reads;
        return 0;
    });
    auto opened = Lines(context, path);
    ASSERT_FALSE(opened.HasValue());
    EXPECT_EQ(EACCES, opened.Error().code);
    EXPECT_NE(std::string::npos, opened.Error().message.find("pin close: 9"));
    EXPECT_EQ(1, closes);
    EXPECT_EQ(0, reads);
}

TEST_F(PathFile, ChunkBoundaryAndTrailingNewlineAreVerifiedWithoutExtraEmptyLine)
{
    Write(std::string(8191, 'a') + "\n\n");
    auto opened = Lines(context, path, Limited(8193));
    ASSERT_TRUE(opened.HasValue());
    std::vector<std::string> lines;
    auto& range = opened.Value();
    for (const auto& item : range)
    {
        ASSERT_TRUE(item.HasValue());
        lines.push_back(item.Value());
    }
    ASSERT_EQ(2U, lines.size());
    EXPECT_EQ(std::string(8191, 'a') + "\n", lines[0]);
    EXPECT_EQ("\n", lines[1]);
    EXPECT_TRUE(range.Close().HasValue());
}

TEST_F(PathFile, PinnedInodeSymlinkAndNonregular)
{
    Write("original");
    bool replaced = false;
    int opens = 0;
    ON_CALL(context, OpenExistingFile(_, _)).WillByDefault([&](const char* name, int flags) {
        const int fd = context.ContextInterface::OpenExistingFile(name, flags);
        if (fd >= 0 && opens++ == 0 && ::rename(path.c_str(), (path + ".old").c_str()) == 0)
        {
            const int replacement = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
            if (replacement >= 0)
            {
                replaced = ::write(replacement, "new", 3) == 3;
                ::close(replacement);
            }
        }
        return fd;
    });
    EXPECT_EQ("original", Collect(path, Limited(8)).Value());
    ASSERT_TRUE(replaced);
    ON_CALL(context, OpenExistingFile(_, _)).WillByDefault([&](const char* name, int flags) {
        return context.ContextInterface::OpenExistingFile(name, flags);
    });
    ASSERT_EQ(0, ::symlink(path.c_str(), (path + ".link").c_str()));
    EXPECT_EQ("new", Collect(path + ".link", Limited(3)).Value());
    auto reject = Limited(3);
    reject.symlinks = SymlinksPolicy::RejectFinal;
    EXPECT_EQ(ELOOP, Collect(path + ".link", reject).Error().code);
    EXPECT_EQ(EINVAL, Collect(context.GetTempdirPath(), Limited(3)).Error().code);
}

TEST_F(PathFile, VerificationAndFinalAdvanceReportErrors)
{
    Write("abc\n");
    int stats = 0;
    ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([&](int fd, struct stat* metadata) {
        const int status = context.ContextInterface::StatFileDescriptor(fd, metadata);
        if (status == 0 && ++stats == 2)
            ++metadata->st_ino;
        return status;
    });
    EXPECT_EQ(EAGAIN, Collect(path, Limited(4)).Error().code);
    stats = 0;
    ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([&](int fd, struct stat* metadata) {
        const int status = context.ContextInterface::StatFileDescriptor(fd, metadata);
        if (status == 0 && ++stats == 3)
            ++metadata->st_mtim.tv_nsec;
        return status;
    });
    auto opened = Lines(context, path, Limited(4));
    ASSERT_TRUE(opened.HasValue());
    auto& range = opened.Value();
    auto cursor = range.begin();
    ASSERT_TRUE(cursor->HasValue());
    EXPECT_EQ("abc\n", cursor->Value());
    ++cursor;
    ASSERT_TRUE(cursor != range.end());
    EXPECT_FALSE(cursor->HasValue());
    EXPECT_EQ(EAGAIN, cursor->Error().code);
    ++cursor;
    EXPECT_FALSE(cursor != range.end());
    EXPECT_TRUE(range.Close().HasValue());
    ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([&](int fd, struct stat* metadata) {
        return context.ContextInterface::StatFileDescriptor(fd, metadata);
    });
    ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([](int, void*, std::size_t) -> ssize_t { return 0; });
    EXPECT_EQ(EIO, Collect(path, Limited(4)).Error().code);
}

TEST_F(PathFile, ErrorsOnIntermediateReadsAndRetryLimit)
{
    Write("a\nb\n");
    int reads = 0;
    ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([&](int, void* buffer, std::size_t) -> ssize_t {
        if (++reads == 1)
        {
            std::memcpy(buffer, "a\n", 2);
            return 2;
        }
        errno = EACCES;
        return -1;
    });
    auto opened = Lines(context, path, Limited(4));
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
    ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([](int, void*, std::size_t) -> ssize_t {
        errno = EINTR;
        return -1;
    });
    EXPECT_EQ(E2BIG, Collect(path, Limited(4, 1)).Error().code);
    ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([](int, void*, std::size_t size) -> ssize_t { return static_cast<ssize_t>(size + 1); });
    EXPECT_EQ(EIO, Collect(path, Limited(4)).Error().code);
}

TEST_F(PathFile, BothCloseErrorsLabelledOnSuccessAndFailure)
{
    Write("abc\n");
    int pin = -1, data = -1, pinCloses = 0, dataCloses = 0;
    ON_CALL(context, OpenExistingFile(_, _)).WillByDefault([&](const char* name, int flags) {
        const int fd = context.ContextInterface::OpenExistingFile(name, flags);
        (pin < 0 ? pin : data) = fd;
        return fd;
    });
    ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([&](int fd) {
        context.ContextInterface::CloseFileDescriptor(fd);
        if (fd == data)
        {
            ++dataCloses;
            errno = EBADF;
        }
        else
        {
            ++pinCloses;
            errno = EACCES;
        }
        return -1;
    });
    auto result = Collect(path, Limited(4));
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EBADF, result.Error().code);
    EXPECT_NE(std::string::npos, result.Error().message.find("pin close: 13"));
    EXPECT_EQ(1, dataCloses);
    EXPECT_EQ(1, pinCloses);
    pin = data = -1;
    ON_CALL(context, ReadFileDescriptor(_, _, _)).WillByDefault([](int, void*, std::size_t) -> ssize_t {
        errno = EIO;
        return -1;
    });
    result = Collect(path, Limited(4));
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EIO, result.Error().code);
    EXPECT_NE(std::string::npos, result.Error().message.find("data close: 9"));
    EXPECT_NE(std::string::npos, result.Error().message.find("pin close: 13"));
    EXPECT_EQ(2, dataCloses);
    EXPECT_EQ(2, pinCloses);
}

TEST_F(PathFile, LastUnterminatedLineIsNotPublishedWhenVerificationOrCloseFails)
{
    Write("tail");
    int stats = 0;
    ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([&](int fd, struct stat* metadata) {
        const int status = context.ContextInterface::StatFileDescriptor(fd, metadata);
        if (status == 0 && ++stats == 3)
            ++metadata->st_ctim.tv_nsec;
        return status;
    });
    auto opened = Lines(context, path, Limited(4));
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
    EXPECT_TRUE(range.Close().HasValue());
    ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([&](int fd, struct stat* metadata) {
        return context.ContextInterface::StatFileDescriptor(fd, metadata);
    });
    int closes = 0;
    ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([&](int fd) -> int {
        ++closes;
        context.ContextInterface::CloseFileDescriptor(fd);
        if (closes == 1)
            throw std::runtime_error("close");
        return 0;
    });
    // A failed close no longer suppresses the verified unterminated line.
    auto tail = Lines(context, path, Limited(4));
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
    EXPECT_EQ(2, closes);
}

TEST_F(PathFile, ThrowingOpenAndStatCloseOwnedDescriptors)
{
    Write("a");
    int opens = 0, closes = 0;
    ON_CALL(context, OpenExistingFile(_, _)).WillByDefault([&](const char* name, int flags) -> int {
        if (++opens == 2)
            throw std::bad_alloc();
        return context.ContextInterface::OpenExistingFile(name, flags);
    });
    ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([&](int fd) {
        ++closes;
        return context.ContextInterface::CloseFileDescriptor(fd);
    });
    EXPECT_EQ(ENOMEM, Collect(path, Limited(1)).Error().code);
    EXPECT_EQ(1, closes);
    ON_CALL(context, OpenExistingFile(_, _)).WillByDefault([&](const char* name, int flags) {
        return context.ContextInterface::OpenExistingFile(name, flags);
    });
    int stats = 0;
    closes = 0;
    ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([&](int fd, struct stat* metadata) -> int {
        if (++stats == 3)
            throw std::runtime_error("stat");
        return context.ContextInterface::StatFileDescriptor(fd, metadata);
    });
    EXPECT_EQ(EIO, Collect(path, Limited(1)).Error().code);
    EXPECT_EQ(2, closes);
}
