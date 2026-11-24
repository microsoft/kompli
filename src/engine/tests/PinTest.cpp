// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Pin layer: Pin/Metadata/ReadableFile runtime coverage. The Pin layer
// has no production caller of its own (every pathname consumer needs
// Path), so this suite acquires Pins directly through the test-only
// PinTestAccess bridge (filesystem/Pin.hpp's
// PinProcessRoot/AcquirePinnedObject), never through Path. Includes stay
// Descriptor/Pin layer (plus MockContext.h/gtest/gmock/std) so this file
// never depends on Path/FTW.

#include <ContextInterface.h>
#include <DescriptorTestAccess.h>
#include <MockContext.h>
#include <PinTestAccess.h>
#include <cerrno>
#include <fcntl.h>
#include <filesystem/Descriptor.hpp>
#include <filesystem/Pin.hpp>
#include <filesystem/PrefixLimits.hpp>
#include <filesystem/ReadableFile.hpp>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

namespace
{
using ComplianceEngine::ContextInterface;
using ComplianceEngine::Result;
using ComplianceEngine::Filesystem::PrefixLimits;
using ComplianceEngine::Filesystem::ReadableFile;
using ComplianceEngine::Filesystem::Type;
using ComplianceEngine::Filesystem::Detail::Pin;
using ComplianceEngine::Tests::DescriptorTestAccess;
using ComplianceEngine::Tests::PinTestAccess;
using testing::_;
using testing::AnyNumber;
using testing::Return;
using testing::StrEq;
using testing::StrictMock;

// Small, Descriptor-layer-only readlink probe identical in spirit to the
// Path-layer PathTestSupport.h's DescriptorTarget, but not shared with it:
// a Pin-layer file must not depend on a Path-layer header, and this is the
// only file at this layer that needs it.
std::string FileDescriptorTarget(int descriptor)
{
    const std::string alias = "/proc/self/fd/" + std::to_string(descriptor);
    char target[512] = {};
    const ssize_t length = ::readlink(alias.c_str(), target, sizeof(target));
    return (0 < length) ? std::string(target, static_cast<std::size_t>(length)) : std::string();
}

class PinTest : public testing::Test
{
protected:
    StrictMock<MockContext> context;
    PrefixLimits limits;

    // ContextInterface::OpenAbsolutePin accepts only the literal "/", and
    // Pin::PinProcessRoot always passes that literal, so a fixture wanting a
    // temporary directory instead redirects the one native open underneath
    // it (OpenNativePath); everything downstream (stat, procfs mount
    // verification) then runs unmodified against the real, redirected
    // descriptor. The resulting Pin's Metadata reports lookup/effective
    // name "/" regardless of the real path -- no case below checks those
    // name strings.
    void RedirectRootToTempdir()
    {
        const std::string directory = context.GetTempdirPath();
        EXPECT_CALL(context, OpenNativePath(StrEq("/"), _)).Times(AnyNumber()).WillRepeatedly([directory](const char*, int flags) {
            return ::open(directory.c_str(), flags);
        });
    }

    Result<Pin> AcquireRootPin()
    {
        context.AllowIncidentalNativeAccess();
        RedirectRootToTempdir();
        return PinTestAccess::AcquireRoot(context, limits);
    }

    // `file` must already exist under context.GetTempdirPath() (e.g. via
    // context.MakeTempfile()); `root` must already be acquired through
    // AcquireRootPin() on this same context.
    Result<Pin> AcquireFilePin(const Pin& root, const std::string& file)
    {
        const std::string name = file.substr(file.find_last_of('/') + 1);
        auto directory = DescriptorTestAccess::OpenAbsolutePin(context, "/");
        if (!directory.HasValue())
            return std::move(directory).Error();
        auto opened = DescriptorTestAccess::OpenAt(context, directory.Value(), name.c_str(), ContextInterface::OpenProfile::PinChild);
        if (!opened.HasValue())
            return std::move(opened).Error();
        return PinTestAccess::AcquireSibling(context, std::move(opened).Value(), Type::RegularFile, root, limits.fdinfoBytes);
    }
};

// (a) Metadata()/Stat() agree with an independent stat(2) oracle, for both
// a directory and a regular file -- a hand-computed oracle, not a reuse of
// the production formula under test.
TEST_F(PinTest, MetadataAndStatAgreeWithIndependentOracle)
{
    {
        SCOPED_TRACE("directory");
        auto pin = AcquireRootPin();
        ASSERT_TRUE(pin.HasValue()) << pin.Error().message;
        struct stat oracle = {};
        ASSERT_EQ(0, ::stat(context.GetTempdirPath().c_str(), &oracle));
        const auto metadata = pin.Value().Metadata();
        EXPECT_EQ(Type::Directory, metadata.FileType());
        EXPECT_EQ(oracle.st_dev, metadata.Stat().st_dev);
        EXPECT_EQ(oracle.st_ino, metadata.Stat().st_ino);
        EXPECT_EQ(oracle.st_mode, metadata.Stat().st_mode);
        auto stat = pin.Value().Stat();
        ASSERT_TRUE(stat.HasValue()) << stat.Error().message;
        EXPECT_EQ(oracle.st_dev, stat.Value().st_dev);
        EXPECT_EQ(oracle.st_ino, stat.Value().st_ino);
    }
    {
        SCOPED_TRACE("regular file");
        auto root = AcquireRootPin();
        ASSERT_TRUE(root.HasValue()) << root.Error().message;
        const std::string file = context.MakeTempfile("pin-oracle");
        auto pin = AcquireFilePin(root.Value(), file);
        ASSERT_TRUE(pin.HasValue()) << pin.Error().message;
        struct stat oracle = {};
        ASSERT_EQ(0, ::stat(file.c_str(), &oracle));
        const auto metadata = pin.Value().Metadata();
        EXPECT_EQ(Type::RegularFile, metadata.FileType());
        EXPECT_EQ(oracle.st_dev, metadata.Stat().st_dev);
        EXPECT_EQ(oracle.st_ino, metadata.Stat().st_ino);
        EXPECT_EQ(oracle.st_mode, metadata.Stat().st_mode);
        auto stat = pin.Value().Stat();
        ASSERT_TRUE(stat.HasValue()) << stat.Error().message;
        EXPECT_EQ(oracle.st_dev, stat.Value().st_dev);
        EXPECT_EQ(oracle.st_ino, stat.Value().st_ino);
    }
}

// (b) OpenReadOnly() activates a ReadableFile that reads the exact bytes
// written, reports EOF once exhausted, and honors its Policy's interrupted-
// read retry bound (zero permits one native attempt but no retry).
TEST_F(PinTest, OpenReadOnlyReadsExactBytesReportsEofAndRespectsPolicy)
{
    auto root = AcquireRootPin();
    ASSERT_TRUE(root.HasValue()) << root.Error().message;
    const std::string content = "pin-readable-content";
    const std::string file = context.MakeTempfile(content);
    auto pin = AcquireFilePin(root.Value(), file);
    ASSERT_TRUE(pin.HasValue()) << pin.Error().message;
    auto readable = pin.Value().OpenReadOnly();
    ASSERT_TRUE(readable.HasValue()) << readable.Error().message;
    auto read = readable.Value().Read(content.size());
    ASSERT_TRUE(read.HasValue()) << read.Error().message;
    ASSERT_TRUE(read.Value().HasValue());
    EXPECT_EQ(content, read.Value().Value());
    EXPECT_FALSE(readable.Value().AtEnd());
    auto eof = readable.Value().Read(1);
    ASSERT_TRUE(eof.HasValue()) << eof.Error().message;
    EXPECT_FALSE(eof.Value().HasValue());
    EXPECT_TRUE(readable.Value().AtEnd());

    const std::string secondFile = context.MakeTempfile(content);
    auto secondPin = AcquireFilePin(root.Value(), secondFile);
    ASSERT_TRUE(secondPin.HasValue()) << secondPin.Error().message;
    auto bounded = secondPin.Value().OpenReadOnly(ReadableFile::Policy(0));
    ASSERT_TRUE(bounded.HasValue()) << bounded.Error().message;
    int attempts = 0;
    EXPECT_CALL(context, ReadNativeDescriptor(_, _, _)).WillOnce([&](int, void*, std::size_t) {
        ++attempts;
        errno = EINTR;
        return -1;
    });
    auto interrupted = bounded.Value().Read(content.size());
    ASSERT_FALSE(interrupted.HasValue());
    EXPECT_EQ(EINTR, interrupted.Error().code);
    EXPECT_EQ(1, attempts);
}

// (c) A wrong-object alias (an inode/type mismatch injected through the
// MockContext native seam that backs the procfs alias open) fails closed.
TEST_F(PinTest, WrongObjectAliasFailsClosed)
{
    auto root = AcquireRootPin();
    ASSERT_TRUE(root.HasValue()) << root.Error().message;
    const std::string file = context.MakeTempfile("held");
    const std::string other = context.MakeTempfile("different");
    auto pin = AcquireFilePin(root.Value(), file);
    ASSERT_TRUE(pin.HasValue()) << pin.Error().message;
    EXPECT_CALL(context, OpenNativeAt(_, _, _)).WillRepeatedly([&](int directory, const char* name, int flags) {
        const std::string parent = FileDescriptorTarget(directory);
        if (parent.find("/fd") != std::string::npos && parent.find("/fdinfo") == std::string::npos &&
            std::string(name).find_first_not_of("0123456789") == std::string::npos)
        {
            return context.RealOpenNativePath(other.c_str(), flags);
        }
        return context.RealOpenNativeAt(directory, name, flags);
    });
    auto read = pin.Value().OpenReadOnly();
    ASSERT_FALSE(read.HasValue());
    EXPECT_EQ(EAGAIN, read.Error().code);
}

// (d) Procfs verification failure (the task identity read that
// ProcfsDescriptorAccess::Make needs) fails closed with an explicit error,
// not a crash or a silently-accepted activation.
TEST_F(PinTest, ProcfsVerificationFailureFailsClosedWithExplicitError)
{
    auto root = AcquireRootPin();
    ASSERT_TRUE(root.HasValue()) << root.Error().message;
    const std::string file = context.MakeTempfile("procfs-failure");
    auto pin = AcquireFilePin(root.Value(), file);
    ASSERT_TRUE(pin.HasValue()) << pin.Error().message;
    EXPECT_CALL(context, NativeProcessId()).WillRepeatedly(Return(-1));
    auto read = pin.Value().OpenReadOnly();
    ASSERT_FALSE(read.HasValue());
    EXPECT_FALSE(read.Error().message.empty());
}

// (e) SetOwnership/SetMode dispatch through the pinned native seams
// (ChownPinnedFileDescriptor/ChmodPinnedAlias) with exact StrictMock
// expectations, never a by-name syscall. Changing to the caller's own
// uid/gid needs no elevated privilege (mirrors the existing
// PathKernelIntegrationTest.NativeProcfsAndPinnedOperations precedent), so
// this does not need a root-only GTEST_SKIP.
TEST_F(PinTest, SetOwnershipAndSetModeDispatchThroughPinnedNativeSeams)
{
    auto root = AcquireRootPin();
    ASSERT_TRUE(root.HasValue()) << root.Error().message;
    const std::string file = context.MakeTempfile("dispatch");
    auto pin = AcquireFilePin(root.Value(), file);
    ASSERT_TRUE(pin.HasValue()) << pin.Error().message;

    const uid_t owner = ::geteuid();
    const gid_t group = ::getegid();
    EXPECT_CALL(context, ChownPinnedFileDescriptor(_, owner, group)).Times(1).WillOnce([&](int descriptor, uid_t, gid_t) {
        return context.RealChownPinnedFileDescriptor(descriptor, owner, group);
    });
    auto chowned = pin.Value().SetOwnership(ComplianceEngine::Filesystem::UserId(owner), ComplianceEngine::Filesystem::GroupId(group));
    ASSERT_TRUE(chowned.HasValue()) << chowned.Error().message;

    EXPECT_CALL(context, ChmodPinnedAlias(_, _, 0600)).Times(1).WillOnce([&](int procfsDirectory, const char* decimalAlias, mode_t mode) {
        return context.RealChmodPinnedAlias(procfsDirectory, decimalAlias, mode);
    });
    auto chmoded = pin.Value().SetMode(0600);
    ASSERT_TRUE(chmoded.HasValue()) << chmoded.Error().message;

    struct stat changed = {};
    ASSERT_EQ(0, ::stat(file.c_str(), &changed));
    EXPECT_EQ(0600, changed.st_mode & 0777);
    EXPECT_EQ(owner, changed.st_uid);
    EXPECT_EQ(group, changed.st_gid);
}

// (f) A moved-from Pin throws std::logic_error before any native dispatch
// (a consumed-owner rejection, inherited from the Descriptor it wraps:
// moved-from state is consumed and every state-reading operation checks
// liveness first). Metadata() is deliberately not checked here: it only
// returns the already-held mMetadata copy and never touches the native
// descriptor, so it is not part of this contract.
TEST_F(PinTest, MovedFromPinThrowsBeforeNativeDispatch)
{
    auto root = AcquireRootPin();
    ASSERT_TRUE(root.HasValue()) << root.Error().message;
    const std::string file = context.MakeTempfile("moved-from-pin");
    auto acquired = AcquireFilePin(root.Value(), file);
    ASSERT_TRUE(acquired.HasValue()) << acquired.Error().message;
    Pin movedFrom = std::move(acquired).Value();
    Pin retained(std::move(movedFrom));
    EXPECT_CALL(context, StatNativeDescriptor(_, _)).Times(0);
    EXPECT_CALL(context, StatusFlagsDescriptor(_)).Times(0);
    EXPECT_CALL(context, DescriptorFlagsDescriptor(_)).Times(0);
    EXPECT_CALL(context, ChownPinnedFileDescriptor(_, _, _)).Times(0);
    EXPECT_CALL(context, ChmodPinnedAlias(_, _, _)).Times(0);
    EXPECT_THROW((void)movedFrom.Stat(), std::logic_error);
    EXPECT_THROW((void)movedFrom.SetMode(0600), std::logic_error);
    EXPECT_THROW((void)movedFrom.SetOwnership(ComplianceEngine::Filesystem::UserId(0), ComplianceEngine::Filesystem::GroupId(0)), std::logic_error);
    EXPECT_THROW((void)movedFrom.OpenReadOnly(), std::logic_error);
}

// (f, continued) A moved-from ReadableFile does NOT throw: Close() and a
// move both reset the same Optional<Descriptor> (see ReadableFile.hpp's own
// documentation), so "moved-from" and "closed" are the identical state by
// design, and Read()/Stat() report it the same way either state does -- a
// graceful Result error (EBADF), not an exception. This differs from Pin's
// own contract above; both are checked as they actually behave.
TEST_F(PinTest, MovedFromReadableFileReturnsClosedErrorBeforeNativeDispatch)
{
    auto root = AcquireRootPin();
    ASSERT_TRUE(root.HasValue()) << root.Error().message;
    const std::string file = context.MakeTempfile("moved-from-reader");
    auto pin = AcquireFilePin(root.Value(), file);
    ASSERT_TRUE(pin.HasValue()) << pin.Error().message;
    auto opened = pin.Value().OpenReadOnly();
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    ReadableFile movedFrom = std::move(opened).Value();
    ReadableFile retained(std::move(movedFrom));
    EXPECT_CALL(context, ReadNativeDescriptor(_, _, _)).Times(0);
    EXPECT_CALL(context, StatNativeDescriptor(_, _)).Times(0);
    auto read = movedFrom.Read(1);
    ASSERT_FALSE(read.HasValue());
    EXPECT_EQ(EBADF, read.Error().code);
    auto stat = movedFrom.Stat();
    ASSERT_FALSE(stat.HasValue());
    EXPECT_EQ(EBADF, stat.Error().code);
    EXPECT_FALSE(movedFrom.AtEnd());
}

// (g) Close happens exactly once, with no retry, even when the native close
// itself fails: filesystem and descriptor code must never retry a failed
// close.
TEST_F(PinTest, CloseHappensExactlyOnceWithNoRetry)
{
    auto root = AcquireRootPin();
    ASSERT_TRUE(root.HasValue()) << root.Error().message;
    int closeAttempts = 0;
    {
        const std::string file = context.MakeTempfile("close-once");
        auto pin = AcquireFilePin(root.Value(), file);
        ASSERT_TRUE(pin.HasValue()) << pin.Error().message;
        const int fileDescriptor = PinTestAccess::NativeDescriptor(pin.Value());
        // The matcher is this exact fd, not `_`, so root's own close (at
        // function exit, via AcquireRootPin's AllowIncidentalNativeAccess)
        // never reaches this expectation -- it matches the separate
        // catch-all instead. AnyNumber() (no RetiresOnSaturation) means a
        // second close of this same fd, i.e. a retry, lands on this same
        // expectation too rather than quietly falling through to that
        // catch-all, so closeAttempts below counts every close this fd
        // actually sees. Every invocation reports EIO (the native close
        // keeps failing), but only the first one really ::close()s the fd,
        // so the real descriptor is not leaked regardless of how many
        // times this is called.
        EXPECT_CALL(context, CloseNativeDescriptor(fileDescriptor)).Times(AnyNumber()).WillRepeatedly([&closeAttempts](int descriptor) {
            if (0 == closeAttempts++)
                ::close(descriptor);
            return ComplianceEngine::Error(EIO);
        });
        // `pin` destructs at the end of this scope.
    }
    // A retrying implementation would call CloseNativeDescriptor(fileDescriptor)
    // a second time, bumping closeAttempts to 2 and failing this assertion;
    // closing exactly once leaves it at exactly 1.
    EXPECT_EQ(1, closeAttempts);
}
} // namespace
