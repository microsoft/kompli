// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "Evaluator.h"
#include "MockContext.h"

#include <FilePermissions.h>
#include <LogFilePermissions.h>
#include <cerrno>
#include <dirent.h>
#include <filesystem/FilesystemCollection.hpp>
#include <fstream>
#include <grp.h>
#include <gtest/gtest.h>
#include <iterator>
#include <linux/limits.h>
#include <pwd.h>
#include <set>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

using ComplianceEngine::AuditLogFilePermissions;
using ComplianceEngine::EnforcePinnedFilePermissions;
using ComplianceEngine::Error;
using ComplianceEngine::FilePermissionsParams;
using ComplianceEngine::IndicatorsTree;
using ComplianceEngine::LogFilePermissionsParams;
using ComplianceEngine::Pattern;
using ComplianceEngine::RemediateLogFilePermissions;
using ComplianceEngine::Result;
using ComplianceEngine::Status;

namespace
{
// Test helper: acquires a live pin for a regular-file child of
// `directory` directly through the pinned filesystem route, bypassing
// LogFilePermissions' own hardcoded log-file owner rules. This lets a test
// construct FilePermissionsParams with an achievable (unprivileged) owner
// requirement while still exercising the same shared pinned-remediation
// implementation LogFilePermissions uses. Uses the streaming FTW::Files
// range directly (not the retained CollectFilesystem convenience wrapper,
// whose published entries are detached snapshots without a live pin).
ComplianceEngine::Optional<ComplianceEngine::Filesystem::Path::Component> AcquireRegularFilePin(ComplianceEngine::ContextInterface& context,
    const std::string& directory, const std::string& filename)
{
    using namespace ComplianceEngine::Filesystem;
    FilesystemCollectionRequest request(directory, FilesystemRootKind::Directory);
    request.direction = FilesystemDirection::Down;
    request.yieldType = FilesystemYieldType::RegularFiles;
    auto resolved = ResolveFilesystemCollectionRequest(request);
    if (!resolved.HasValue())
    {
        return {};
    }
    auto root = Path::Make(context, resolved.Value().rootPath, CollectionRootPolicy(resolved.Value()), CollectionRootLimits(resolved.Value()));
    if (!root.HasValue() || !root.Value().Is<Path>())
    {
        return {};
    }
    auto opened = FTW::Files(ComplianceEngine::As<Path>(std::move(root).Value()), resolved.Value().rootPath, CollectionContinuation(resolved.Value()));
    if (!opened.HasValue())
    {
        return {};
    }
    auto files = std::move(opened).Value();
    const std::string target = directory + "/" + filename;
    ComplianceEngine::Optional<Path::Component> found;
    for (const auto& entry : files)
    {
        if (entry.HasValue() && entry.Value().path == target)
        {
            found = entry.Value().LiveComponent();
            break;
        }
    }
    files.Stop();
    return found;
}
} // namespace

// These range/error tests do not require privileged user and group setup.
class LogFileRangeTest : public ::testing::Test
{
protected:
    ::testing::StrictMock<MockContext> context;
    IndicatorsTree indicators;
    std::string testDir = context.GetTempdirPath() + "/logfile-range";

    void SetUp() override
    {
        ASSERT_EQ(0, mkdir(testDir.c_str(), 0700));
        context.SetSpecialFilePath("/etc/shells", context.MakeTempfile("/bin/bash\n"));
        context.SetSpecialFilePath("/etc/passwd", context.MakeTempfile("root:x:0:0:root:/root:/bin/bash\n"));
        indicators.Push("LogFilePermissions");
        // No test in this fixture sets its own EXPECT_CALL: each customizes
        // behavior via ON_CALL only (fault injection, argument-filtered
        // overrides), and every count it cares about (deniedPins, entries,
        // closeAttempts) is enforced by hand with EXPECT_EQ, not gMock
        // cardinality. A single any-argument catch-all per seam group is
        // therefore safe for the whole fixture.
        context.AllowIncidentalNativeAccess();
    }

    Result<Status> Run(bool remediate, const std::string& path = "")
    {
        LogFilePermissionsParams params;
        params.path = path.empty() ? testDir : path;
        return remediate ? RemediateLogFilePermissions(params, indicators, context) : AuditLogFilePermissions(params, indicators, context);
    }
};

TEST_F(LogFileRangeTest, AuditContinuesPastViolationsAndSelectsOnlyRegularFiles)
{
    ASSERT_EQ(0, mkdir((testDir + "/nested").c_str(), 0700));
    const std::string first = testDir + "/bad.log";
    const std::string second = testDir + "/nested/.hidden.log";
    std::ofstream(first) << "first";
    std::ofstream(second) << "second";
    ASSERT_EQ(0, chmod(first.c_str(), 0777));
    ASSERT_EQ(0, chmod(second.c_str(), 0777));
    ASSERT_EQ(0, symlink(first.c_str(), (testDir + "/link.log").c_str()));
    ASSERT_EQ(0, mkfifo((testDir + "/pipe.log").c_str(), 0600));

    const auto result = Run(false);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::NonCompliant, result.Value());
    ASSERT_NE(nullptr, indicators.GetRootNode());
    EXPECT_EQ(2u, indicators.GetRootNode()->children.size());
}

TEST_F(LogFileRangeTest, VanishingRegularFileHasMissingVerdictWithoutReopening)
{
    // The pinned directory reports regular-file names; they vanish before
    // child acquisition. Neither audit nor remediation receives a fake pin.
    ON_CALL(context, ReadDirectory(::testing::_)).WillByDefault([this](DIR * stream) -> struct dirent* {
        struct dirent* entry = readdir(stream);
        if (entry && ((std::string(entry->d_name) == "first.log") || (std::string(entry->d_name) == "second.log")))
        {
            entry->d_type = DT_REG; // deterministic type hint, not a file pin
            EXPECT_EQ(0, unlink((testDir + "/" + entry->d_name).c_str()));
        }
        return entry;
    });

    for (bool remediate : {false, true})
    {
        for (const char* name : {"first.log", "second.log"})
        {
            std::ofstream(testDir + "/" + name) << "log";
        }
        const auto result = Run(remediate);
        ASSERT_TRUE(result.HasValue()) << result.Error().message;
        EXPECT_EQ(Status::NonCompliant, result.Value());
        ASSERT_NE(nullptr, indicators.GetRootNode());
        EXPECT_EQ(remediate ? 4u : 2u, indicators.GetRootNode()->children.size());
    }
}

TEST_F(LogFileRangeTest, FactoryFailuresPropagateForAuditAndRemediation)
{
    for (bool remediate : {false, true})
    {
        const auto absent = Run(remediate, testDir + "/missing");
        ASSERT_TRUE(absent.HasValue());
        EXPECT_EQ(Status::Compliant, absent.Value());
    }
    // The root name is pinned through its parent; no LstatPath lookup is made.
    std::size_t deniedPins = 0;
    ON_CALL(context, OpenNativeAt(::testing::_, ::testing::StrEq("logfile-range"), ::testing::_)).WillByDefault([&deniedPins](int, const char*, int) {
        ++deniedPins;
        errno = EACCES;
        return -1;
    });
    for (bool remediate : {false, true})
    {
        const auto result = Run(remediate);
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ(EACCES, result.Error().code);
    }
    EXPECT_EQ(2u, deniedPins);
    ON_CALL(context, OpenNativeAt(::testing::_, ::testing::StrEq("logfile-range"), ::testing::_)).WillByDefault([this](int directory, const char* name, int flags) {
        return context.RealOpenNativeAt(directory, name, flags);
    });
    struct stat expected = {};
    ASSERT_EQ(0, stat(testDir.c_str(), &expected));
    ON_CALL(context, StatNativeDescriptor(::testing::_, ::testing::_)).WillByDefault([this, expected](int descriptor, struct stat* metadata) {
        struct stat actual = {};
        if ((0 == fstat(descriptor, &actual)) && (actual.st_dev == expected.st_dev) && (actual.st_ino == expected.st_ino))
        {
            errno = EACCES;
            return -1;
        }
        return context.RealStatNativeDescriptor(descriptor, metadata);
    });
    for (bool remediate : {false, true})
    {
        const auto result = Run(remediate);
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ(EACCES, result.Error().code);
    }
}

TEST_F(LogFileRangeTest, ReadFailureFromHeldRootPropagates)
{
    ON_CALL(context, ReadDirectory(::testing::_)).WillByDefault([](DIR*) -> struct dirent* {
        errno = EACCES;
        return nullptr;
    });
    for (bool remediate : {false, true})
    {
        const auto result = Run(remediate);
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ(EACCES, result.Error().code);
    }
}

TEST_F(LogFileRangeTest, ReachedItemErrorAfterNoncomplianceOutranksCleanupFailure)
{
    const std::string file = testDir + "/bad.log";
    std::ofstream(file) << "log";
    ASSERT_EQ(0, chmod(file.c_str(), 0777));
    std::size_t entries = 0;
    ON_CALL(context, ReadDirectory(::testing::_)).WillByDefault([&entries](DIR * stream) -> struct dirent* {
        if (entries == 1)
        {
            errno = EACCES;
            return nullptr;
        }
        struct dirent* entry = readdir(stream);
        if (entry && std::string(entry->d_name) != "." && std::string(entry->d_name) != "..")
        {
            ++entries;
        }
        return entry;
    });
    ON_CALL(context, CloseDirectory(::testing::_)).WillByDefault([](DIR* stream) {
        const int result = closedir(stream);
        const int nativeCode = errno;
        return ComplianceEngine::Error(result == 0 ? EIO : nativeCode);
    });

    const auto result = Run(false);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EACCES, result.Error().code);
    EXPECT_EQ(1u, entries);
    ASSERT_NE(nullptr, indicators.GetRootNode());
    EXPECT_EQ(1u, indicators.GetRootNode()->children.size());
}

TEST_F(LogFileRangeTest, CloseFailureDoesNotOverrideVerdictForEitherPath)
{
    const std::string file = testDir + "/bad.log";
    const auto logPath = context.GetTempdirPath() + "/logfile-close.log";
    OsConfigLogHandle logHandle = OpenLog(logPath.c_str(), nullptr);
    ASSERT_NE(nullptr, logHandle);
    context.SetLogHandle(logHandle);
    int closeAttempts = 0;
    ON_CALL(context, CloseDirectory(::testing::_)).WillByDefault([&](DIR* stream) {
        ++closeAttempts;
        const int result = closedir(stream);
        const int nativeCode = errno;
        return ComplianceEngine::Error(result == 0 ? EIO : nativeCode);
    });
    for (bool remediate : {false, true})
    {
        std::ofstream(file) << "log";
        ASSERT_EQ(0, chmod(file.c_str(), 0777));
        if (remediate)
        {
            // Exercise a compliant empty range, not a privileged ownership
            // mutation that can fail before the checked cursor close.
            ASSERT_EQ(0, unlink(file.c_str()));
        }
        const auto result = Run(remediate);
        ASSERT_TRUE(result.HasValue()) << result.Error().message;
        EXPECT_EQ(remediate ? Status::Compliant : Status::NonCompliant, result.Value());
    }
    EXPECT_EQ(1u, indicators.GetRootNode()->children.size());
    EXPECT_EQ(2, closeAttempts);
    CloseLog(&logHandle);
    context.SetLogHandle(nullptr);
    std::ifstream log(logPath);
    ASSERT_TRUE(log.is_open());
    const std::string text((std::istreambuf_iterator<char>(log)), std::istreambuf_iterator<char>());
    const auto diagnostic = "Failed to close filesystem resource: " + std::string(strerror(EIO));
    const auto first = text.find(diagnostic);
    ASSERT_NE(std::string::npos, first);
    const auto second = text.find(diagnostic, first + diagnostic.size());
    ASSERT_NE(std::string::npos, second);
    EXPECT_EQ(std::string::npos, text.find(diagnostic, second + diagnostic.size()));
}

TEST_F(LogFileRangeTest, DescendantErrorIsReachedDespiteDirectoryFiltering)
{
    const std::string nested = testDir + "/nested";
    ASSERT_EQ(0, mkdir(nested.c_str(), 0700));
    struct stat expected = {};
    ASSERT_EQ(0, stat(nested.c_str(), &expected));
    ON_CALL(context, ReadDirectory(::testing::_)).WillByDefault([expected](DIR * stream) -> struct dirent* {
        struct stat actual = {};
        if ((0 == fstat(dirfd(stream), &actual)) && (actual.st_dev == expected.st_dev) && (actual.st_ino == expected.st_ino))
        {
            errno = EACCES;
            return nullptr;
        }
        return readdir(stream);
    });
    for (bool remediate : {false, true})
    {
        const auto result = Run(remediate);
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ(EACCES, result.Error().code);
    }
}

TEST_F(LogFileRangeTest, RootDirectoryLinkIsFollowedAndDepthThirtyThreeErrors)
{
    const std::string linkedRoot = context.GetTempdirPath() + "/linked-log-root";
    ASSERT_EQ(0, symlink(testDir.c_str(), linkedRoot.c_str()));
    const std::string file = testDir + "/bad.log";
    std::ofstream(file) << "log";
    ASSERT_EQ(0, chmod(file.c_str(), 0777));
    const auto linked = Run(false, linkedRoot);
    ASSERT_TRUE(linked.HasValue());
    EXPECT_EQ(Status::NonCompliant, linked.Value());

    std::string directory = testDir;
    for (int depth = 0; depth < 33; ++depth)
    {
        directory += "/d";
        ASSERT_EQ(0, mkdir(directory.c_str(), 0700));
    }
    const auto tooDeep = Run(false);
    ASSERT_FALSE(tooDeep.HasValue());
    // The unraised 16-cursor budget fails explicitly before depth 33.
    EXPECT_EQ(EMFILE, tooDeep.Error().code);
}

// A hard link inside the scanned tree to a file outside it is an
// ordinary directory entry; Path confinement and sealed descriptor authority
// accept it by design (no symlink is followed and no name leaves the
// barrier). Remediation must refuse to mutate the held pin rather than
// following the link to the outside inode. The consumer's owner rule
// (root|syslog) expects root, so an unprivileged run cannot observe a real
// ownership change; the oracle is therefore the mutation seams themselves.
TEST_F(LogFileRangeTest, TM12HardLinkedFileWithinScannedTreeRefusesMutation)
{
    const std::string outside = context.GetTempdirPath() + "/tm12-outside.log";
    std::ofstream(outside) << "log";
    ASSERT_EQ(0, chmod(outside.c_str(), 0777));
    const std::string linked = testDir + "/linked.log";
    ASSERT_EQ(0, link(outside.c_str(), linked.c_str()));

    EXPECT_CALL(context, ChownPinnedFileDescriptor(::testing::_, ::testing::_, ::testing::_)).Times(0);
    EXPECT_CALL(context, ChmodPinnedAlias(::testing::_, ::testing::_, ::testing::_)).Times(0);

    const auto result = Run(true);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(Status::NonCompliant, result.Value());

    struct stat after = {};
    ASSERT_EQ(0, stat(outside.c_str(), &after));
    EXPECT_EQ(0777, after.st_mode & 0777);
}

// An unlink of the inside name between acquisition and the fresh
// pre-mutation check must not defeat the refusal. A fresh-only check would
// be fooled here (by the time any fresh stat runs, only the outside name
// remains, showing one link); the acquisition-time count, recorded once by
// FTW when the pin was taken, still shows two and must still refuse.
TEST_F(LogFileRangeTest, TM12UnlinkAfterAcquisitionStillRefusesViaAcquisitionTimeLinkCount)
{
    const std::string outside = context.GetTempdirPath() + "/tm12-outside-unlink.log";
    std::ofstream(outside) << "log";
    ASSERT_EQ(0, chmod(outside.c_str(), 0777));
    const std::string linked = testDir + "/linked-unlink.log";
    ASSERT_EQ(0, link(outside.c_str(), linked.c_str()));
    struct stat target = {};
    ASSERT_EQ(0, stat(outside.c_str(), &target));

    // Let the first stat matching this inode (the acquisition snapshot) pass
    // through unmodified, then unlink the inside name on the next one (the
    // first fresh pre-mutation check), simulating an attacker racing the
    // directory entry away right after acquisition.
    bool sawAcquisitionStat = false;
    bool unlinkedInside = false;
    ON_CALL(context, StatNativeDescriptor(::testing::_, ::testing::_)).WillByDefault([&](int descriptor, struct stat* metadata) {
        struct stat actual = {};
        if (!unlinkedInside && 0 == fstat(descriptor, &actual) && actual.st_dev == target.st_dev && actual.st_ino == target.st_ino)
        {
            if (!sawAcquisitionStat)
            {
                sawAcquisitionStat = true;
            }
            else
            {
                unlinkedInside = true;
                EXPECT_EQ(0, unlink(linked.c_str()));
            }
        }
        return context.RealStatNativeDescriptor(descriptor, metadata);
    });

    EXPECT_CALL(context, ChownPinnedFileDescriptor(::testing::_, ::testing::_, ::testing::_)).Times(0);
    EXPECT_CALL(context, ChmodPinnedAlias(::testing::_, ::testing::_, ::testing::_)).Times(0);

    const auto result = Run(true);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(Status::NonCompliant, result.Value());
    EXPECT_TRUE(sawAcquisitionStat);
    EXPECT_TRUE(unlinkedInside);
    EXPECT_NE(0, access(linked.c_str(), F_OK));
}

// Ownership and mode are separate mutation steps, each preceded by
// its own fresh check. A link added between them (simulated here right as
// ownership "succeeds") must make the mode step refuse after ownership has
// already changed; the verdict is NonCompliant, not Compliant -- the
// operation is not atomic.
TEST_F(LogFileRangeTest, TM12LinkAddedBetweenOwnershipAndModeStagesRefusesModeAfterOwnershipChanged)
{
    const std::string target = testDir + "/needs-both.log";
    std::ofstream(target) << "log";
    ASSERT_EQ(0, chmod(target.c_str(), 0777));
    // As root the new file is already root:root and would need no ownership
    // change; give it a non-root owner so the ownership stage runs either way.
    if (0 == geteuid())
    {
        ASSERT_EQ(0, chown(target.c_str(), 1, 1));
    }
    struct stat before = {};
    ASSERT_EQ(0, stat(target.c_str(), &before));
    ASSERT_NE(0u, before.st_uid);
    const std::string extraLink = context.GetTempdirPath() + "/tm12-extra-link.log";

    // Simulates a privileged chown succeeding (an unprivileged real chown to
    // root would fail with EPERM); the property under test is the
    // subsequent mode-stage refusal, not the ownership outcome itself. The
    // group is not pinned: the rule keeps an already-accepted primary group.
    EXPECT_CALL(context, ChownPinnedFileDescriptor(::testing::_, 0, ::testing::_)).Times(1).WillOnce([&](int descriptor, uid_t, gid_t) {
        struct stat pinned = {};
        EXPECT_EQ(0, fstat(descriptor, &pinned));
        EXPECT_EQ(0, link(target.c_str(), extraLink.c_str()));
        return 0;
    });
    EXPECT_CALL(context, ChmodPinnedAlias(::testing::_, ::testing::_, ::testing::_)).Times(0);

    const auto result = Run(true);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(Status::NonCompliant, result.Value());

    struct stat after = {};
    ASSERT_EQ(0, stat(target.c_str(), &after));
    EXPECT_EQ(0777, after.st_mode & 0777);
}

// Green-baseline control: a hard-linked file that already satisfies
// the rule must stay Compliant, with no mutation attempt at all. This uses
// the pinned route directly (bypassing LogFilePermissions' hardcoded
// root-owned pattern rules) so full compliance is achievable without
// privilege: the only property under test is that the refusal is checked
// "only when a change is needed" (rule 2) -- an up-front, unconditional
// refusal would turn this test red.
TEST_F(LogFileRangeTest, TM12CompliantHardLinkedFileStaysCompliantWithoutMutation)
{
    struct passwd* self = getpwuid(getuid());
    ASSERT_NE(nullptr, self);
    const std::string outside = context.GetTempdirPath() + "/tm12-outside-compliant.log";
    std::ofstream(outside) << "log";
    ASSERT_EQ(0, chmod(outside.c_str(), 0600));
    const std::string linked = testDir + "/compliant-linked.log";
    ASSERT_EQ(0, link(outside.c_str(), linked.c_str()));

    FilePermissionsParams params;
    params.path = linked;
    auto ownerPattern = Pattern::Make(self->pw_name);
    ASSERT_TRUE(ownerPattern.HasValue());
    params.owner = {{ownerPattern.Value()}};
    params.mask = 0177;

    auto pin = AcquireRegularFilePin(context, testDir, "compliant-linked.log");
    ASSERT_TRUE(pin.HasValue());

    EXPECT_CALL(context, ChownPinnedFileDescriptor(::testing::_, ::testing::_, ::testing::_)).Times(0);
    EXPECT_CALL(context, ChmodPinnedAlias(::testing::_, ::testing::_, ::testing::_)).Times(0);

    auto result = EnforcePinnedFilePermissions(params, pin.Value(), indicators, context);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(Status::Compliant, result.Value());
}

class EnsureLogfileAccessTest : public ::testing::Test
{
protected:
    std::string testDir;
    ::testing::StrictMock<MockContext> mContext;
    IndicatorsTree indicators;
    ComplianceEngine::NestedListFormatter mFormatter;

    void SetUp() override
    {
        if (0 != getuid())
        {
            GTEST_SKIP() << "This test suite requires root privileges or fakeroot";
        }
        SetLoggingLevel(LoggingLevelDebug);
        // Create necessary groups/users for testing
        system("groupadd bin >/dev/null");
        system("useradd -g bin bin >/dev/null");
        system("groupadd adm >/dev/null");
        system("groupadd utmp >/dev/null");
        system("useradd -g adm syslog >/dev/null");
        system("groupadd systemd-journal >/dev/null");

        // A daemon/service account: no valid interactive login shell.
        system("groupadd logdaemon >/dev/null 2>&1");
        system("useradd -M -g logdaemon -s /usr/sbin/nologin logdaemon >/dev/null 2>&1");

        // A regular interactive account: has a valid login shell.
        system("groupadd loguser >/dev/null 2>&1");
        system("useradd -M -g loguser -s /bin/bash loguser >/dev/null 2>&1");

        testDir = mContext.GetTempdirPath() + "/log-file-permissions";
        ASSERT_EQ(0, mkdir(testDir.c_str(), 0700));
        indicators.Push("EnsureLogfileAccess");
        // Every test in this fixture that reaches the mutation seams
        // (ChownPinnedFileDescriptor/ChmodPinnedAlias) constrains them
        // itself via ExpectPinnedRemediation() below with its own exact
        // EXPECT_CALL; AllowIncidentalNativeAccess() deliberately excludes
        // those two seams (see MockContext.h).
        mContext.AllowIncidentalNativeAccess();
    }

    void CreateLogFile(const std::string& filename, const std::string& owner, const std::string& group, mode_t permissions)
    {
        std::string filePath = testDir + "/" + filename;
        std::ofstream file(filePath);
        file << "test log content\n";
        file.close();

        struct passwd* pwd = getpwnam(owner.c_str());
        uid_t ownerId = (pwd != nullptr) ? pwd->pw_uid : 0; // Default to root if user not found

        struct group* grp = getgrnam(group.c_str());
        gid_t groupId = (grp != nullptr) ? grp->gr_gid : 0; // Default to root if group not found

        ASSERT_EQ(chmod(filePath.c_str(), permissions), 0);
        ASSERT_EQ(chown(filePath.c_str(), ownerId, groupId), 0);
    }

    void CreateSubdir(const std::string& dirname)
    {
        std::string dirPath = testDir + "/" + dirname;
        ASSERT_EQ(mkdir(dirPath.c_str(), 0755), 0);
    }

    void CreateSymlink(const std::string& linkname, const std::string& target)
    {
        std::string linkPath = testDir + "/" + linkname;
        ASSERT_EQ(symlink(target.c_str(), linkPath.c_str()), 0);
    }

    void VerifyFilePermissions(const std::string& filename, uid_t expectedOwner, gid_t expectedGroup, mode_t expectedPerms)
    {
        std::string filePath = testDir + "/" + filename;
        struct stat statInfo;
        ASSERT_EQ(stat(filePath.c_str(), &statInfo), 0);
        EXPECT_EQ(statInfo.st_uid, expectedOwner);
        EXPECT_EQ(statInfo.st_gid, expectedGroup);
        EXPECT_EQ(statInfo.st_mode & 0777, expectedPerms);
    }

    // Declare exact mutation-seam expectations for a remediation that must
    // chmod (and, when ownership isn't already compliant, chown) exactly
    // the given files, identified by inode rather than call order/argument
    // so a mistargeted or duplicate mutation is caught even though the
    // calls are otherwise indistinguishable (same owner/group/mode).
    void ExpectPinnedRemediation(const std::vector<std::string>& files)
    {
        for (const auto& file : files)
        {
            struct stat target = {};
            ASSERT_EQ(0, ::stat((testDir + "/" + file).c_str(), &target));
            // Precondition: the fixture creates this file non-compliant, so
            // remediation must chmod it exactly once.
            ASSERT_NE(0640u, static_cast<unsigned>(target.st_mode & 07777));
            mExpectedChmodTargets.insert({target.st_dev, target.st_ino});
            // CreateLogFile falls back to root:root when the host lacks the
            // 'bin' account; ownership is then already compliant (root
            // matches the owner/group patterns' first item) and no chown is
            // expected for this file. This makes the expectation
            // host-independent.
            if (target.st_uid != 0 || target.st_gid != 0)
            {
                mExpectedChownTargets.insert({target.st_dev, target.st_ino});
            }
        }

        // Owner/group fall back to the first ("root") item of the pattern
        // lists (FilePermissions.h: the first one is used for remediation),
        // hence the exact (0, 0) chown argument match. Production passes
        // the full observed st_mode (type bits included; mask 0137 already
        // applied to these fixture modes) to ChmodPinnedAlias, so the
        // expected mode is S_IFREG | 0640, not a bare 0640. Each
        // WillRepeatedly invocation resolves the *call's own*
        // descriptor/alias argument to an inode via fstat/fstatat (never
        // trusting call order) and records it; the post-hoc set comparison
        // in CheckPinnedRemediationTargets() then proves every call
        // targeted a distinct expected file. Delegating to Real* lets the
        // existing post-state assertions observe the actual mutation.
        const int chownCount = static_cast<int>(mExpectedChownTargets.size());
        if (chownCount > 0)
        {
            EXPECT_CALL(mContext, ChownPinnedFileDescriptor(::testing::_, 0, 0)).Times(chownCount).WillRepeatedly([this](int descriptor, uid_t owner, gid_t group) {
                struct stat pinned = {};
                EXPECT_EQ(0, ::fstat(descriptor, &pinned));
                mObservedChownTargets.insert({pinned.st_dev, pinned.st_ino});
                return mContext.RealChownPinnedFileDescriptor(descriptor, owner, group);
            });
        }
        else
        {
            EXPECT_CALL(mContext, ChownPinnedFileDescriptor(::testing::_, 0, 0)).Times(0);
        }

        EXPECT_CALL(mContext, ChmodPinnedAlias(::testing::_, ::testing::_, static_cast<mode_t>(S_IFREG | 0640)))
            .Times(static_cast<int>(files.size()))
            .WillRepeatedly([this](int procfsDirectory, const char* decimalAlias, mode_t mode) {
                struct stat pinned = {};
                EXPECT_EQ(0, ::fstatat(procfsDirectory, decimalAlias, &pinned, 0));
                mObservedChmodTargets.insert({pinned.st_dev, pinned.st_ino});
                return mContext.RealChmodPinnedAlias(procfsDirectory, decimalAlias, mode);
            });
    }

    void CheckPinnedRemediationTargets()
    {
        EXPECT_EQ(mExpectedChownTargets, mObservedChownTargets);
        EXPECT_EQ(mExpectedChmodTargets, mObservedChmodTargets);
    }

    std::multiset<std::pair<dev_t, ino_t>> mExpectedChownTargets;
    std::multiset<std::pair<dev_t, ino_t>> mObservedChownTargets;
    std::multiset<std::pair<dev_t, ino_t>> mExpectedChmodTargets;
    std::multiset<std::pair<dev_t, ino_t>> mObservedChmodTargets;
};

// Test audit with missing directory
TEST_F(EnsureLogfileAccessTest, AuditMissingDirectory)
{
    LogFilePermissionsParams params;
    params.path = "/nonexistent/log/directory";

    auto result = AuditLogFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant); // Missing directory should be compliant
}

TEST_F(EnsureLogfileAccessTest, AuditRegularFileRootPropagatesTraversalError)
{
    const auto root = testDir + "/root-file";
    std::ofstream(root) << "not a directory\n";
    LogFilePermissionsParams params;
    params.path = root;

    const auto result = AuditLogFilePermissions(params, indicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(ENOTDIR, result.Error().code);
}

// Test audit with default path (using test directory)
TEST_F(EnsureLogfileAccessTest, AuditEmptyDirectory)
{
    LogFilePermissionsParams params;
    params.path = testDir;

    auto result = AuditLogFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

// Test audit with correct mask for various log file patterns
TEST_F(EnsureLogfileAccessTest, AuditCorrectPermissions)
{
    // Create files with correct mask according to patterns
    CreateLogFile("syslog", "syslog", "adm", 0640);   // syslog user, adm group, 640
    CreateLogFile("auth.log", "syslog", "adm", 0640); // matches *auth* pattern
    CreateLogFile("secure", "syslog", "adm", 0640);   // matches *secure* pattern
    CreateLogFile("messages", "syslog", "adm", 0640); // matches *message* pattern
    CreateLogFile("test.log", "syslog", "adm", 0640); // matches *.log pattern (default)
    CreateLogFile("wtmp", "root", "utmp", 0664);      // matches wtmp pattern
    CreateLogFile("lastlog", "root", "utmp", 0664);   // matches lastlog pattern

    LogFilePermissionsParams params;
    params.path = testDir;

    auto result = AuditLogFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

// Test audit with incorrect mask
TEST_F(EnsureLogfileAccessTest, AuditIncorrectPermissions)
{
    // Create file with wrong mask
    CreateLogFile("auth.log", "bin", "bin", 0777); // Wrong owner, group, and mask

    LogFilePermissionsParams params;
    params.path = testDir;

    auto result = AuditLogFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

// Test audit with mixed correct and incorrect mask
TEST_F(EnsureLogfileAccessTest, AuditMixedPermissions)
{
    // Create some files with correct mask
    CreateLogFile("syslog", "syslog", "adm", 0640);
    CreateLogFile("messages", "syslog", "adm", 0640);

    // Create some files with incorrect mask
    CreateLogFile("auth.log", "bin", "bin", 0777);
    CreateLogFile("secure", "bin", "bin", 0666);

    LogFilePermissionsParams params;
    params.path = testDir;

    auto result = AuditLogFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

// Test audit ignores directories
TEST_F(EnsureLogfileAccessTest, AuditIgnoresDirectories)
{
    CreateSubdir("subdir");
    CreateLogFile("syslog", "syslog", "adm", 0640);

    LogFilePermissionsParams params;
    params.path = testDir;

    auto result = AuditLogFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

// Test audit ignores symbolic links
TEST_F(EnsureLogfileAccessTest, AuditIgnoresSymlinks)
{
    CreateLogFile("real.log", "syslog", "adm", 0640);
    CreateSymlink("link.log", "real.log");

    LogFilePermissionsParams params;
    params.path = testDir;

    auto result = AuditLogFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

// Test pattern matching for specific log file types
TEST_F(EnsureLogfileAccessTest, AuditPatternMatching)
{
    // Test various patterns
    CreateLogFile("secure", "syslog", "adm", 0640);                    // Should match *secure* pattern
    CreateLogFile("secure.1", "syslog", "adm", 0640);                  // Should match *secure* pattern
    CreateLogFile("auth.log", "syslog", "adm", 0640);                  // Should match *auth* pattern
    CreateLogFile("something.log", "syslog", "adm", 0640);             // Should match *.log pattern
    CreateLogFile("journal.journal", "root", "systemd-journal", 0640); // Should match *.journal pattern
    CreateLogFile("random_file", "syslog", "adm", 0640);               // Should match default pattern

    LogFilePermissionsParams params;
    params.path = testDir;

    auto result = AuditLogFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

// Test recursive directory traversal
TEST_F(EnsureLogfileAccessTest, AuditRecursiveDirectories)
{
    CreateSubdir("apache2");
    CreateLogFile("apache2/access.log", "syslog", "adm", 0640);
    CreateLogFile("apache2/error.log", "syslog", "adm", 0640);

    CreateSubdir("mail");
    CreateLogFile("mail/mail.log", "syslog", "adm", 0640);

    LogFilePermissionsParams params;
    params.path = testDir;

    auto result = AuditLogFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureLogfileAccessTest, NestedViolationIsAuditedAndRemediated)
{
    CreateSubdir("nested");
    CreateLogFile("nested/auth.log", "bin", "bin", 0777);
    LogFilePermissionsParams params;
    params.path = testDir;

    const auto audit = AuditLogFilePermissions(params, indicators, mContext);

    ASSERT_TRUE(audit.HasValue());
    EXPECT_EQ(Status::NonCompliant, audit.Value());

    ExpectPinnedRemediation({"nested/auth.log"});

    const auto remediation = RemediateLogFilePermissions(params, indicators, mContext);

    ASSERT_TRUE(remediation.HasValue());
    EXPECT_EQ(Status::Compliant, remediation.Value());
    CheckPinnedRemediationTargets();
    struct stat status;
    ASSERT_EQ(0, ::stat((testDir + "/nested/auth.log").c_str(), &status));
    EXPECT_EQ(static_cast<mode_t>(0640), status.st_mode & 0777);

    const auto postAudit = AuditLogFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(postAudit.HasValue());
    EXPECT_EQ(Status::Compliant, postAudit.Value());
}

// Test remediation of incorrect mask
TEST_F(EnsureLogfileAccessTest, RemediateIncorrectPermissions)
{
    // Create file with wrong mask
    CreateLogFile("auth.log", "bin", "bin", 0777);

    LogFilePermissionsParams params;
    params.path = testDir;

    ExpectPinnedRemediation({"auth.log"});

    auto result = RemediateLogFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
    CheckPinnedRemediationTargets();

    // Verify the file now has correct mask (auth.log should be root|syslog:root|adm:640)
    std::string filePath = testDir + "/auth.log";
    struct stat statInfo;
    ASSERT_EQ(stat(filePath.c_str(), &statInfo), 0);

    // Check that mask is now 640
    EXPECT_EQ(statInfo.st_mode & 0777, 0640u);
    // Owner should be root(0) or syslog(101)
    EXPECT_TRUE(statInfo.st_uid == 0 || statInfo.st_uid == 101);
    // Group should be root(0) or adm(4)
    EXPECT_TRUE(statInfo.st_gid == 0 || statInfo.st_gid == 4);
}

// Test remediation with missing directory
TEST_F(EnsureLogfileAccessTest, RemediateMissingDirectory)
{
    LogFilePermissionsParams params;
    params.path = "/nonexistent/log/directory";

    auto result = RemediateLogFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant); // Missing directory should be compliant
}

// Test remediation with already correct mask
TEST_F(EnsureLogfileAccessTest, RemediateAlreadyCorrect)
{
    CreateLogFile("syslog", "syslog", "adm", 0640);

    LogFilePermissionsParams params;
    params.path = testDir;

    auto result = RemediateLogFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);

    // Verify mask haven't changed
    struct passwd* pwd = getpwnam("syslog");
    uid_t syslogUid = (pwd != nullptr) ? pwd->pw_uid : 0;
    struct group* grp = getgrnam("adm");
    gid_t admGid = (grp != nullptr) ? grp->gr_gid : 0;
    VerifyFilePermissions("syslog", syslogUid, admGid, 0640);
}

// Test remediation of multiple files
TEST_F(EnsureLogfileAccessTest, RemediateMultipleFiles)
{
    // Create files with various wrong mask
    CreateLogFile("auth.log", "bin", "bin", 0777);
    CreateLogFile("secure", "bin", "bin", 0666);
    CreateLogFile("syslog", "bin", "bin", 0644);
    CreateLogFile("test.log", "bin", "bin", 0755);

    LogFilePermissionsParams params;
    params.path = testDir;

    std::vector<std::string> files = {"auth.log", "secure", "syslog", "test.log"};
    ExpectPinnedRemediation(files);

    auto result = RemediateLogFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
    CheckPinnedRemediationTargets();

    // Verify all files now have appropriate mask
    for (const auto& file : files)
    {
        std::string filePath = testDir + "/" + file;
        struct stat statInfo;
        ASSERT_EQ(stat(filePath.c_str(), &statInfo), 0);
        EXPECT_EQ(statInfo.st_mode & 0777, 0640u);
    }
}

// Test remediation preserves files that should be ignored
TEST_F(EnsureLogfileAccessTest, RemediateIgnoresSpecialFiles)
{
    CreateSubdir("subdir");
    CreateSymlink("link.log", mContext.GetTempdirPath() + "/missing-target");
    CreateLogFile("regular.log", "bin", "bin", 0777); // This should be fixed

    LogFilePermissionsParams params;
    params.path = testDir;

    ExpectPinnedRemediation({"regular.log"});

    auto result = RemediateLogFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
    CheckPinnedRemediationTargets();

    // Verify regular.log was fixed to valid owner/group combination
    std::string filePath = testDir + "/regular.log";
    struct stat statInfo;
    ASSERT_EQ(stat(filePath.c_str(), &statInfo), 0);
    // Owner should be root(0) or syslog(101)
    EXPECT_TRUE(statInfo.st_uid == 0 || statInfo.st_uid == 101);
    // Group should be root(0) or adm(4)
    EXPECT_TRUE(statInfo.st_gid == 0 || statInfo.st_gid == 4);
    // Mask should be 640
    EXPECT_EQ(statInfo.st_mode & 0777, 0640u);

    // Verify symlink and directory are unchanged
    std::string linkPath = testDir + "/link.log";
    std::string dirPath = testDir + "/subdir";
    struct stat linkStat, dirStat;
    ASSERT_EQ(lstat(linkPath.c_str(), &linkStat), 0);
    ASSERT_EQ(stat(dirPath.c_str(), &dirStat), 0);
    EXPECT_TRUE(S_ISLNK(linkStat.st_mode));
    EXPECT_TRUE(S_ISDIR(dirStat.st_mode));
}

// Root-gated real control: with a hard link to the scanned file from
// outside the tree, remediation must leave the real file's owner and mode
// untouched; once the outside link is removed, the same file (same inside
// name) is remediated normally.
TEST_F(EnsureLogfileAccessTest, TM12HardLinkedLogfileIsNotRemediatedWhileUnlinkedCopyIs)
{
    CreateLogFile("tm12-hardlink.log", "bin", "bin", 0777);
    const std::string targetPath = testDir + "/tm12-hardlink.log";
    const std::string outsideLink = mContext.GetTempdirPath() + "/tm12-log-outside";
    ASSERT_EQ(0, ::link(targetPath.c_str(), outsideLink.c_str()));
    struct stat before = {};
    ASSERT_EQ(0, ::stat(targetPath.c_str(), &before));

    LogFilePermissionsParams params;
    params.path = testDir;

    EXPECT_CALL(mContext, ChownPinnedFileDescriptor(::testing::_, ::testing::_, ::testing::_)).Times(0);
    EXPECT_CALL(mContext, ChmodPinnedAlias(::testing::_, ::testing::_, ::testing::_)).Times(0);
    auto linked = RemediateLogFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(linked.HasValue()) << linked.Error().message;
    EXPECT_EQ(Status::NonCompliant, linked.Value());
    struct stat afterLinked = {};
    ASSERT_EQ(0, ::stat(targetPath.c_str(), &afterLinked));
    EXPECT_EQ(before.st_uid, afterLinked.st_uid);
    EXPECT_EQ(before.st_gid, afterLinked.st_gid);
    EXPECT_EQ(before.st_mode, afterLinked.st_mode);

    ASSERT_EQ(0, ::unlink(outsideLink.c_str()));
    ExpectPinnedRemediation({"tm12-hardlink.log"});
    auto unlinked = RemediateLogFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(unlinked.HasValue()) << unlinked.Error().message;
    EXPECT_EQ(Status::Compliant, unlinked.Value());
    CheckPinnedRemediationTargets();
    struct stat afterSecond = {};
    ASSERT_EQ(0, ::stat(targetPath.c_str(), &afterSecond));
    EXPECT_TRUE(afterSecond.st_uid == 0 || afterSecond.st_uid == 101);
    EXPECT_TRUE(afterSecond.st_gid == 0 || afterSecond.st_gid == 4);
    EXPECT_EQ(afterSecond.st_mode & 0777, 0640u);
}

// Test default path behavior
TEST_F(EnsureLogfileAccessTest, DefaultPath)
{
    LogFilePermissionsParams params; // No path specified, should use /var/log

    // Audit-only: this test must never remediate the real host /var/log (a
    // remediation call here would chown/chmod whatever the test host
    // actually has there, which is never acceptable from an automated test).
    // Since we can't create files in /var/log in tests, this should just not crash.
    auto auditResult = AuditLogFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(auditResult.HasValue()); // Should handle missing /var/log gracefully
}

// Test specific pattern edge cases
TEST_F(EnsureLogfileAccessTest, SpecificPatternEdgeCases)
{
    // Test case sensitivity (fnmatch with FNM_CASEFOLD should be case-insensitive)
    CreateLogFile("AUTH.LOG", "syslog", "adm", 0640);
    CreateLogFile("SECURE", "syslog", "adm", 0640);
    CreateLogFile("TEST.LOG", "syslog", "adm", 0640);

    LogFilePermissionsParams params;
    params.path = testDir;

    auto result = AuditLogFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

// Test wtmp/btmp special mask
TEST_F(EnsureLogfileAccessTest, SpecialSystemLogFiles)
{
    CreateLogFile("wtmp", "root", "utmp", 0664);    // root:utmp:664
    CreateLogFile("btmp", "root", "utmp", 0664);    // root:utmp:664
    CreateLogFile("lastlog", "root", "utmp", 0664); // root:root|utmp:664
    CreateLogFile("faillog", "root", "adm", 0640);  // root:adm:640 (uses default pattern)

    LogFilePermissionsParams params;
    params.path = testDir;

    auto result = AuditLogFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureLogfileAccessTest, AptLogFilesMayBeWorldReadable)
{
    std::string aptDir = testDir + "/apt";
    ASSERT_EQ(mkdir(aptDir.c_str(), 0755), 0);
    CreateLogFile("apt/history.log", "root", "adm", 0644);
    CreateLogFile("apt/eipp.log.xz", "root", "root", 0644);

    mContext.SetSpecialFilePath("/var/log", testDir);

    LogFilePermissionsParams params;
    params.path = testDir;

    auto result = AuditLogFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

// A file matching no known pattern that is owned by a daemon/service account (one without a valid
// login shell) only needs an acceptable permission mask; its owner/group are not constrained.
TEST_F(EnsureLogfileAccessTest, AuditDaemonOwnedFileWithNonDefaultOwnershipIsCompliant)
{
    if (getpwnam("logdaemon") == nullptr)
    {
        GTEST_SKIP() << "requires the 'logdaemon' service account to be created";
    }

    // Constrain the set of valid login shells so that /usr/sbin/nologin is not one of them.
    mContext.SetSpecialFilePath("/etc/shells", mContext.MakeTempfile("/bin/sh\n/bin/bash\n"));

    // Default-pattern file owned by a daemon account with a mask-compliant mode (0640 & 0137 == 0).
    CreateLogFile("customservice.log", "logdaemon", "logdaemon", 0640);

    LogFilePermissionsParams params;
    params.path = testDir;

    auto result = AuditLogFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

// A root-owned file matching no known pattern is likewise only checked against the mask, regardless
// of its group (root is treated as a daemon/service account).
TEST_F(EnsureLogfileAccessTest, AuditRootOwnedFileWithNonDefaultGroupIsCompliant)
{
    mContext.SetSpecialFilePath("/etc/shells", mContext.MakeTempfile("/bin/sh\n/bin/bash\n"));

    // Group is neither root nor adm, but ownership is not enforced for daemon-owned files.
    CreateLogFile("customservice.log", "root", "bin", 0640);

    LogFilePermissionsParams params;
    params.path = testDir;

    auto result = AuditLogFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

// A daemon-owned default-pattern file must still satisfy the permission mask.
TEST_F(EnsureLogfileAccessTest, AuditDaemonOwnedFileWithBadMaskIsNonCompliant)
{
    if (getpwnam("logdaemon") == nullptr)
    {
        GTEST_SKIP() << "requires the 'logdaemon' service account to be created";
    }

    mContext.SetSpecialFilePath("/etc/shells", mContext.MakeTempfile("/bin/sh\n/bin/bash\n"));

    // 0644 & 0137 != 0 (world-readable), so the mask check fails even though the owner is a daemon.
    CreateLogFile("customservice.log", "logdaemon", "logdaemon", 0644);

    LogFilePermissionsParams params;
    params.path = testDir;

    auto result = AuditLogFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}

// A file matching no known pattern owned by a regular interactive account must satisfy the default
// ownership (root|syslog : root|adm) even when the permission mask is acceptable.
TEST_F(EnsureLogfileAccessTest, AuditInteractiveUserOwnedFileEnforcesOwnership)
{
    if (getpwnam("loguser") == nullptr)
    {
        GTEST_SKIP() << "requires the 'loguser' interactive account to be created";
    }

    // /bin/bash is a valid login shell, so 'loguser' is not treated as a daemon account.
    mContext.SetSpecialFilePath("/etc/shells", mContext.MakeTempfile("/bin/sh\n/bin/bash\n"));

    // Mask 0640 is fine, but loguser:loguser is not an allowed default owner/group.
    CreateLogFile("customservice.log", "loguser", "loguser", 0640);

    LogFilePermissionsParams params;
    params.path = testDir;

    auto result = AuditLogFilePermissions(params, indicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
}
