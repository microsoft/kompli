// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "Evaluator.h"
#include "MockContext.h"

#include <NoDuplicateEntries.h>
#include <ScopeGuard.h>
#include <algorithm>
#include <cerrno>
#include <fcntl.h>
#include <fstream>
#include <gtest/gtest.h>
#include <iterator>
#include <string>
#include <sys/param.h>
#include <sys/stat.h>
#include <unistd.h>

using ComplianceEngine::AuditNoDuplicateEntries;
using ComplianceEngine::Error;
using ComplianceEngine::IndicatorsTree;
using ComplianceEngine::NoDuplicateEntriesParams;
using ComplianceEngine::Result;
using ComplianceEngine::Status;
using std::map;
using std::string;
using ::testing::_;

class EnsureNoDuplicateEntriesExistTest : public ::testing::Test
{
protected:
    bool IsData(int fd, const string& path) const
    {
        struct stat held = {}, fixture = {};
        const int flags = ::fcntl(fd, F_GETFL);
        return flags >= 0 && !(flags & O_PATH) && (flags & O_ACCMODE) == O_RDONLY && ::fstat(fd, &held) == 0 && ::stat(path.c_str(), &fixture) == 0 &&
               held.st_dev == fixture.st_dev && held.st_ino == fixture.st_ino;
    }
    MockContext mContext;
    IndicatorsTree mIndicators;
    std::string mTempdir;

    void SetUp() override
    {
        mTempdir = mContext.GetTempdirPath() + "/no-duplicate-entries";
        ASSERT_EQ(0, mkdir(mTempdir.c_str(), 0700));
        mIndicators.Push("EnsureNoDuplicateEntriesExist");
    }

    std::string CreateTestFile(const std::string& content)
    {
        std::string filename = mTempdir + "/testfile.txt";
        std::ofstream file(filename);
        if (!file.is_open())
        {
            OsConfigLogError(mContext.GetLogHandle(), "Failed to create test file %s: %s", filename.c_str(), strerror(errno));
            return {};
        }
        file << content;
        file.close();
        return filename;
    }

    void RemoveTestFile(const std::string& filename)
    {
        if (remove(filename.c_str()) != 0)
        {
            OsConfigLogError(mContext.GetLogHandle(), "Failed to remove test file %s: %s", filename.c_str(), strerror(errno));
        }
    }
};

TEST_F(EnsureNoDuplicateEntriesExistTest, InvalidArguments_1)
{
    NoDuplicateEntriesParams params;
    params.filename = "testfile.txt";
    params.delimiter = ",,";
    auto result = AuditNoDuplicateEntries(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    ASSERT_EQ(result.Error().code, EINVAL);
    ASSERT_EQ(result.Error().message, "Delimiter must be a single character");
}

TEST_F(EnsureNoDuplicateEntriesExistTest, InvalidArguments_2)
{
    NoDuplicateEntriesParams params;
    params.filename = "testfile.txt";
    params.delimiter = ",";
    params.column = -1; // Negative value
    auto result = AuditNoDuplicateEntries(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    ASSERT_EQ(result.Error().code, EINVAL);
    ASSERT_EQ(result.Error().message, "Column must be a non-negative integer");
}

TEST_F(EnsureNoDuplicateEntriesExistTest, MissingInputFile)
{
    NoDuplicateEntriesParams params;
    params.filename = "testfile.txt";
    params.delimiter = ",";
    params.column = 0;
    auto result = AuditNoDuplicateEntries(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    ASSERT_EQ(result.Error().code, ENOENT);
    ASSERT_EQ(result.Error().message, "Failed to open file: testfile.txt");
}

TEST_F(EnsureNoDuplicateEntriesExistTest, EmptyInputFile)
{
    auto filename = CreateTestFile("");
    NoDuplicateEntriesParams params;
    params.filename = filename;
    params.delimiter = ",";
    params.column = 0;
    auto result = AuditNoDuplicateEntries(params, mIndicators, mContext);
    RemoveTestFile(filename);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureNoDuplicateEntriesExistTest, NoDuplicateEntries)
{
    auto filename = CreateTestFile("value1,value2,value3\nvalue4,value5,value6\n");
    NoDuplicateEntriesParams params;
    params.filename = filename;
    params.delimiter = ",";
    params.column = 0;
    auto result = AuditNoDuplicateEntries(params, mIndicators, mContext);
    RemoveTestFile(filename);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureNoDuplicateEntriesExistTest, DuplicateEntries)
{
    auto filename = CreateTestFile("value1,value2,value3\nvalue1,value5,value6\n");
    NoDuplicateEntriesParams params;
    params.filename = filename;
    params.delimiter = ",";
    params.column = 0;
    auto result = AuditNoDuplicateEntries(params, mIndicators, mContext);
    RemoveTestFile(filename);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureNoDuplicateEntriesExistTest, NoDuplicateEntries_SecondColumn)
{
    auto filename = CreateTestFile("value1,value2,value3\nvalue1,value5,value6\nvalue2,value8,value9\n");
    NoDuplicateEntriesParams params;
    params.filename = filename;
    params.delimiter = ",";
    params.column = 1;
    auto result = AuditNoDuplicateEntries(params, mIndicators, mContext);
    RemoveTestFile(filename);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureNoDuplicateEntriesExistTest, DuplicateEntries_SecondColumn)
{
    auto filename = CreateTestFile("value1,value2,value3\nvalue1,value5,value6\nvalue2,value2,value9\n");
    NoDuplicateEntriesParams params;
    params.filename = filename;
    params.delimiter = ",";
    params.column = 1;
    auto result = AuditNoDuplicateEntries(params, mIndicators, mContext);
    RemoveTestFile(filename);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(EnsureNoDuplicateEntriesExistTest, NoDuplicateEntries_MessageWithoutContext)
{
    auto filename = CreateTestFile("value1,value2,value3\nvalue4,value5,value6\n");
    NoDuplicateEntriesParams params;
    params.filename = filename;
    params.delimiter = ",";
    params.column = 0;
    AuditNoDuplicateEntries(params, mIndicators, mContext);
    RemoveTestFile(filename);
    ASSERT_TRUE(mIndicators.GetRootNode() != nullptr);
    ASSERT_FALSE(mIndicators.GetRootNode()->indicators.empty());
    auto formattedMessage = mIndicators.Back().indicators.back().message;
    ASSERT_TRUE(formattedMessage.find("No duplicate entries found in") != std::string::npos);
}

TEST_F(EnsureNoDuplicateEntriesExistTest, NoDuplicateEntries_MessageWithContext)
{
    auto filename = CreateTestFile("value1,value2,value3\nvalue4,value5,value6\n");
    NoDuplicateEntriesParams params;
    params.filename = filename;
    params.delimiter = ",";
    params.column = 0;
    params.context = "test entries";
    AuditNoDuplicateEntries(params, mIndicators, mContext);
    RemoveTestFile(filename);
    ASSERT_TRUE(mIndicators.GetRootNode() != nullptr);
    ASSERT_FALSE(mIndicators.GetRootNode()->indicators.empty());
    auto formattedMessage = mIndicators.Back().indicators.back().message;
    ASSERT_TRUE(formattedMessage.find("No duplicate test entries found in") != std::string::npos);
}

TEST_F(EnsureNoDuplicateEntriesExistTest, PreservesColumnParsingCrAndSortedDuplicateIndicators)
{
    auto filename = CreateTestFile("first,z\r\nsecond,a\nthird,z\r\nfourth,a\n");
    ScopeGuard removeFile([&] { RemoveTestFile(filename); });
    NoDuplicateEntriesParams params;
    params.filename = filename;
    params.delimiter = ",";
    params.column = 1;
    auto result = AuditNoDuplicateEntries(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::NonCompliant, result.Value());
    const auto& emitted = mIndicators.Back().indicators;
    ASSERT_EQ(2U, emitted.size());
    EXPECT_EQ("Duplicate entry: 'a'", emitted[0].message);
    EXPECT_EQ("Duplicate entry: 'z\r'", emitted[1].message);
}

TEST_F(EnsureNoDuplicateEntriesExistTest, InternalEmptyColumnAndUnterminatedFinalLineArePreserved)
{
    auto filename = CreateTestFile("first,,end\nsecond,,end");
    ScopeGuard removeFile([&] { RemoveTestFile(filename); });
    NoDuplicateEntriesParams params;
    params.filename = filename;
    params.delimiter = ",";
    params.column = 1;
    auto result = AuditNoDuplicateEntries(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::NonCompliant, result.Value());
    const auto& emitted = mIndicators.Back().indicators;
    ASSERT_EQ(1U, emitted.size());
    EXPECT_EQ("Duplicate entry: ''", emitted[0].message);
}

TEST_F(EnsureNoDuplicateEntriesExistTest, EmptyColumnStillFailsWithExistingError)
{
    auto filename = CreateTestFile("first,a\nsecond,\n");
    ScopeGuard removeFile([&] { RemoveTestFile(filename); });
    NoDuplicateEntriesParams params;
    params.filename = filename;
    params.delimiter = ",";
    params.column = 1;
    auto result = AuditNoDuplicateEntries(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EINVAL, result.Error().code);
    EXPECT_EQ("Column index out of bounds", result.Error().message);
    EXPECT_TRUE(mIndicators.Back().indicators.empty());
}

TEST_F(EnsureNoDuplicateEntriesExistTest, InvalidPathAndNonregularInputKeepOpenFailureContract)
{
    NoDuplicateEntriesParams params;
    params.delimiter = ",";
    params.filename = "relative/path";
    auto relative = AuditNoDuplicateEntries(params, mIndicators, mContext);
    ASSERT_FALSE(relative.HasValue());
    EXPECT_EQ(ENOENT, relative.Error().code);
    EXPECT_EQ("Failed to open file: relative/path", relative.Error().message);

    params.filename = mTempdir;
    auto directory = AuditNoDuplicateEntries(params, mIndicators, mContext);
    ASSERT_FALSE(directory.HasValue());
    EXPECT_EQ(ENOENT, directory.Error().code);
    EXPECT_EQ("Failed to open file: " + mTempdir, directory.Error().message);
    EXPECT_TRUE(mIndicators.Back().indicators.empty());
}

TEST_F(EnsureNoDuplicateEntriesExistTest, FailedOpenRetainsHistoricalEnoentContract)
{
    NoDuplicateEntriesParams params;
    params.filename = mTempdir + "/missing";
    params.delimiter = ",";
    auto missing = AuditNoDuplicateEntries(params, mIndicators, mContext);
    ASSERT_FALSE(missing.HasValue());
    EXPECT_EQ(ENOENT, missing.Error().code);
    EXPECT_EQ("Failed to open file: " + params.filename, missing.Error().message);

    const auto filename = CreateTestFile("alpha\n");
    ScopeGuard removeFile([&] { RemoveTestFile(filename); });
    params.filename = filename;
    int deniedOpens = 0;
    ON_CALL(mContext, OpenNativeAt(_, _, _)).WillByDefault([&](int directory, const char* component, int flags) {
        struct stat held = {}, parent = {};
        const bool fixtureParent =
            ::fstat(directory, &held) == 0 && ::stat(mTempdir.c_str(), &parent) == 0 && held.st_dev == parent.st_dev && held.st_ino == parent.st_ino;
        if (fixtureParent && string(component) == "testfile.txt" && (flags & O_PATH))
        {
            ++deniedOpens;
            errno = EACCES;
            return -1;
        }
        return mContext.ContextInterface::OpenNativeAt(directory, component, flags);
    });
    auto denied = AuditNoDuplicateEntries(params, mIndicators, mContext);
    ASSERT_FALSE(denied.HasValue());
    EXPECT_EQ(ENOENT, denied.Error().code);
    EXPECT_EQ("Failed to open file: " + params.filename, denied.Error().message);
    EXPECT_EQ(1, deniedOpens);
    EXPECT_TRUE(mIndicators.Back().indicators.empty());
}

TEST_F(EnsureNoDuplicateEntriesExistTest, ReachedReadFailureRejectsPartialResultAndPreservesPrimaryError)
{
    auto filename = CreateTestFile("alpha\nalpha\n");
    ScopeGuard removeFile([&] { RemoveTestFile(filename); });
    const string logPath = mTempdir + "/read-and-close.log";
    OsConfigLogHandle logHandle = OpenLog(logPath.c_str(), nullptr);
    ASSERT_NE(nullptr, logHandle);
    mContext.SetLogHandle(logHandle);
    int reads = 0, closes = 0;
    ON_CALL(mContext, ReadFileDescriptor(_, _, _)).WillByDefault([&](int fd, void* buffer, std::size_t size) -> ssize_t {
        if (!IsData(fd, filename))
            return mContext.ContextInterface::ReadFileDescriptor(fd, buffer, size);
        if (++reads == 1)
            return mContext.ContextInterface::ReadFileDescriptor(fd, buffer, std::min<std::size_t>(size, 6));
        errno = EIO;
        return -1;
    });
    ON_CALL(mContext, CloseFileDescriptor(_)).WillByDefault([&](int fd) {
        const bool data = IsData(fd, filename);
        mContext.ContextInterface::CloseFileDescriptor(fd);
        if (data)
        {
            ++closes;
            errno = EBADF;
            return -1;
        }
        return 0;
    });
    NoDuplicateEntriesParams params;
    params.filename = filename;
    params.delimiter = ",";
    auto result = AuditNoDuplicateEntries(params, mIndicators, mContext);
    CloseLog(&logHandle);
    mContext.SetLogHandle(nullptr);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EIO, result.Error().code);
    EXPECT_EQ("Failed to read file bytes", result.Error().message);
    EXPECT_EQ(2, reads);
    EXPECT_EQ(1, closes);
    EXPECT_TRUE(mIndicators.Back().indicators.empty());
    std::ifstream log(logPath);
    ASSERT_TRUE(log.is_open());
    const string text((std::istreambuf_iterator<char>(log)), std::istreambuf_iterator<char>());
    const string closeEntry = "Failed to close data descriptor for " + filename + ": " + std::to_string(EBADF);
    const auto first = text.find(closeEntry);
    ASSERT_NE(string::npos, first);
    EXPECT_EQ(string::npos, text.find(closeEntry, first + closeEntry.size()));
    EXPECT_NE(string::npos, text.find("Failed to read " + filename));
}

TEST_F(EnsureNoDuplicateEntriesExistTest, ReachedNulRejectsPartialResult)
{
    auto filename = CreateTestFile(std::string("alpha\nalpha") + std::string(1, '\0') + "\n");
    ScopeGuard removeFile([&] { RemoveTestFile(filename); });
    NoDuplicateEntriesParams params;
    params.filename = filename;
    params.delimiter = ",";
    auto result = AuditNoDuplicateEntries(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EBADMSG, result.Error().code);
    EXPECT_EQ("Embedded NUL in text file", result.Error().message);
    EXPECT_TRUE(mIndicators.Back().indicators.empty());
}

TEST_F(EnsureNoDuplicateEntriesExistTest, ExactDefaultByteLimitSucceedsButExcessIsRejected)
{
    constexpr std::size_t cap = 1024 * 1024;
    auto filename = CreateTestFile("alpha\n" + std::string(cap - 6, 'x'));
    ScopeGuard removeFile([&] { RemoveTestFile(filename); });
    NoDuplicateEntriesParams params;
    params.filename = filename;
    params.delimiter = ",";
    auto exact = AuditNoDuplicateEntries(params, mIndicators, mContext);
    ASSERT_TRUE(exact.HasValue());
    EXPECT_EQ(Status::Compliant, exact.Value());

    mIndicators.Back().indicators.clear();
    CreateTestFile("alpha\n" + std::string(cap - 5, 'x'));
    auto excessive = AuditNoDuplicateEntries(params, mIndicators, mContext);
    ASSERT_FALSE(excessive.HasValue());
    EXPECT_EQ(E2BIG, excessive.Error().code);
    EXPECT_EQ("File byte limit exceeded", excessive.Error().message);
    EXPECT_TRUE(mIndicators.Back().indicators.empty());
}

TEST_F(EnsureNoDuplicateEntriesExistTest, CloseFailureRejectsDuplicateVerdict)
{
    auto filename = CreateTestFile("alpha\nalpha\n");
    ScopeGuard removeFile([&] { RemoveTestFile(filename); });
    int closes = 0;
    ON_CALL(mContext, CloseFileDescriptor(_)).WillByDefault([&](int fd) {
        const bool data = IsData(fd, filename);
        mContext.ContextInterface::CloseFileDescriptor(fd);
        if (data)
        {
            ++closes;
            errno = EIO;
            return -1;
        }
        return 0;
    });
    NoDuplicateEntriesParams params;
    params.filename = filename;
    params.delimiter = ",";
    auto result = AuditNoDuplicateEntries(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EIO, result.Error().code);
    EXPECT_EQ("Failed to close data descriptor", result.Error().message);
    EXPECT_EQ(1, closes);
    EXPECT_TRUE(mIndicators.Back().indicators.empty());
}
