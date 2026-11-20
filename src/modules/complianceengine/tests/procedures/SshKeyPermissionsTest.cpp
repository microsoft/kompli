// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Clean minimal test file begins
#include "Evaluator.h"
#include "MockContext.h"

#include <FilePermissions.h>
#include <SshKeyPermissions.h>
#include <cerrno>
#include <fcntl.h>
#include <filesystem/FilesystemCollection.hpp>
#include <fstream>
#include <gtest/gtest.h>
#include <iterator>
#include <map>
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>

using ComplianceEngine::AuditSshKeyPermissions;
using ComplianceEngine::EnforcePinnedFilePermissions;
using ComplianceEngine::FilePermissionsParams;
using ComplianceEngine::IndicatorsTree;
using ComplianceEngine::Pattern;
using ComplianceEngine::RemediateSshKeyPermissions;
using ComplianceEngine::SshKeyPermissionsParams;
using ComplianceEngine::SshKeyType;
using ComplianceEngine::Status;

static const char kPublicKeySample[] = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyMaterial user@example\n";
static const char kPrivateKeyHeader[] = "-----BEGIN OPENSSH PRIVATE KEY-----\n";

namespace
{
// TM-12 test helper: acquires a live pin for a regular-file child of
// `directory` directly through the pinned filesystem route, bypassing
// SshKeyPermissions' own hardcoded root-owned rules. This lets a test
// construct FilePermissionsParams with an achievable (unprivileged) owner
// requirement while still exercising the same shared pinned-remediation
// implementation SshKeyPermissions uses. Uses the streaming FTW::Files
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

TEST(SshKeyRangeTest, MissingRootRemainsCompliantAndDeniedRootIsAnError)
{
    ::testing::StrictMock<MockContext> context;
    IndicatorsTree indicators;
    indicators.Push("SSH");
    const std::string root = context.GetTempdirPath() + "/missing-ssh";
    context.SetSpecialFilePath("/etc/ssh", root);
    // No EXPECT_CALL in this test constrains any native seam; the only
    // customization is an ON_CALL default-action override on OpenNativeAt
    // for a specific pin name, which doesn't add an expectation of its own.
    context.AllowIncidentalNativeAccess();
    SshKeyPermissionsParams params;
    params.type = SshKeyType::Public;
    const auto absent = AuditSshKeyPermissions(params, indicators, context);
    ASSERT_TRUE(absent.HasValue());
    EXPECT_EQ(Status::Compliant, absent.Value());

    // Fail direct acquisition of the missing root name, not a retired
    // pathname stat; EACCES must remain an error rather than typed Missing.
    std::size_t deniedPins = 0;
    ON_CALL(context, OpenNativeAt(::testing::_, ::testing::StrEq("missing-ssh"), ::testing::_)).WillByDefault([&deniedPins](int, const char*, int) {
        ++deniedPins;
        errno = EACCES;
        return -1;
    });
    const auto denied = RemediateSshKeyPermissions(params, indicators, context);
    ASSERT_FALSE(denied.HasValue());
    EXPECT_EQ(EACCES, denied.Error().code);
    EXPECT_EQ(1u, deniedPins);
}

TEST(SshKeyRangeTest, FirstNoncomplianceBreaksWithoutReadingRemainderAndCloseDoesNotOverride)
{
    ::testing::StrictMock<MockContext> context;
    IndicatorsTree indicators;
    indicators.Push("SSH");
    const std::string root = context.GetTempdirPath() + "/ssh";
    ASSERT_EQ(0, mkdir(root.c_str(), 0700));
    const std::string key = root + "/key";
    std::ofstream(key) << kPublicKeySample;
    context.SetSpecialFilePath("/etc/ssh", root);
    // GetFileContents is a separate, non-native seam this helper doesn't
    // cover; ReadDirectory/CloseDirectory below only get ON_CALL default-
    // action overrides, not their own EXPECT_CALL, so the catch-all is safe.
    context.AllowIncidentalNativeAccess();
    EXPECT_CALL(context, GetFileContents(::testing::_)).Times(0);
    std::size_t entries = 0;
    ON_CALL(context, ReadDirectory(::testing::_)).WillByDefault([&entries](DIR * directory) -> struct dirent* {
        if (entries == 1)
        {
            errno = EIO;
            return nullptr;
        }
        struct dirent* item = readdir(directory);
        if (item && std::string(item->d_name) != "." && std::string(item->d_name) != "..")
        {
            ++entries;
        }
        return item;
    });
    SshKeyPermissionsParams params;
    params.type = SshKeyType::Public;
    const auto verdict = AuditSshKeyPermissions(params, indicators, context);
    ASSERT_TRUE(verdict.HasValue());
    EXPECT_EQ(Status::NonCompliant, verdict.Value());
    EXPECT_EQ(1u, entries);

    const auto logPath = context.GetTempdirPath() + "/ssh-key-close.log";
    OsConfigLogHandle logHandle = OpenLog(logPath.c_str(), nullptr);
    ASSERT_NE(nullptr, logHandle);
    context.SetLogHandle(logHandle);
    int closeAttempts = 0;
    ON_CALL(context, CloseDirectory(::testing::_)).WillByDefault([&](DIR* stream) {
        ++closeAttempts;
        const int result = closedir(stream);
        if (0 == result)
        {
            errno = EIO;
            return ComplianceEngine::Result<void>(ComplianceEngine::Error(EIO));
        }
        return ComplianceEngine::Result<void>(ComplianceEngine::Error(errno));
    });
    entries = 0;
    const auto closeResult = AuditSshKeyPermissions(params, indicators, context);
    ASSERT_TRUE(closeResult.HasValue()) << closeResult.Error().message;
    EXPECT_EQ(Status::NonCompliant, closeResult.Value());
    EXPECT_EQ(1u, entries);
    EXPECT_EQ(1, closeAttempts);
    CloseLog(&logHandle);
    context.SetLogHandle(nullptr);
    std::ifstream log(logPath);
    ASSERT_TRUE(log.is_open());
    const std::string text((std::istreambuf_iterator<char>(log)), std::istreambuf_iterator<char>());
    const auto diagnostic = "Failed to close filesystem resource: " + std::string(strerror(EIO));
    const auto first = text.find(diagnostic);
    ASSERT_NE(std::string::npos, first);
    EXPECT_EQ(std::string::npos, text.find(diagnostic, first + diagnostic.size()));
}

TEST(SshKeyRangeTest, ReplacementAfterPinCannotRedirectClassificationOrRemediation)
{
    ::testing::StrictMock<MockContext> context;
    IndicatorsTree indicators;
    indicators.Push("SSH");
    const std::string root = context.GetTempdirPath() + "/ssh";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    const std::string key = root + "/key";
    const std::string held = context.GetTempdirPath() + "/held-ssh-key";
    const std::string replacement = context.GetTempdirPath() + "/replacement-ssh-key";
    std::ofstream(key) << kPublicKeySample;
    std::ofstream(replacement) << "not a key\n";
    ASSERT_EQ(0, ::chmod(key.c_str(), 0666));
    ASSERT_EQ(0, ::chmod(replacement.c_str(), 0666));
    struct stat original = {};
    ASSERT_EQ(0, ::stat(key.c_str(), &original));
    context.SetSpecialFilePath("/etc/ssh", root);
    // OpenNativeAt is excluded: this test constrains it below with its own
    // full-wildcard EXPECT_CALL/WillRepeatedly (the file-swap side effect).
    // ChownPinnedFileDescriptor/ChmodPinnedAlias aren't covered by this
    // helper at all -- they get their own EXPECT_CALL further down.
    context.AllowProcfsBootstrap();
    EXPECT_CALL(context, OpenNativePath(::testing::_, ::testing::_)).Times(::testing::AnyNumber());
    context.AllowDescriptorInspection();
    context.AllowFileRead();
    context.AllowDescriptorClose();
    context.AllowDirectoryEnumeration();
    context.AllowIdentityLookup();
    EXPECT_CALL(context, GetFileContents(::testing::_)).Times(0);
    bool swapped = false;
    EXPECT_CALL(context, OpenNativeAt(::testing::_, ::testing::_, ::testing::_)).WillRepeatedly([&](int directory, const char* name, int flags) {
        const int fd = context.RealOpenNativeAt(directory, name, flags);
        if (!swapped && fd >= 0 && std::string(name) == "key" && (flags & O_PATH))
        {
            swapped = true;
            EXPECT_EQ(0, ::rename(key.c_str(), held.c_str()));
            EXPECT_EQ(0, ::rename(replacement.c_str(), key.c_str()));
        }
        return fd;
    });
    SshKeyPermissionsParams params;
    params.type = SshKeyType::Public;
    auto audit = AuditSshKeyPermissions(params, indicators, context);
    ASSERT_TRUE(audit.HasValue()) << audit.Error().message;
    EXPECT_EQ(Status::NonCompliant, audit.Value());
    ASSERT_TRUE(swapped);

    // Restore names so the same deterministic swap exercises the mutation
    // phase on a second traversal, without touching the old held inode.
    ASSERT_EQ(0, ::rename(key.c_str(), replacement.c_str()));
    ASSERT_EQ(0, ::rename(held.c_str(), key.c_str()));
    swapped = false;
    // Owner/group fall back to root:root (SshKeyPermissions.cpp: owner is
    // {"root"}, group is {"root", "ssh_keys"}); a non-root run's file is
    // owned by the invoking user, so exactly one chown is expected. Under
    // fakeroot/real root the file is already root:root, so none is.
    const int chownCount = (original.st_uid != 0 || original.st_gid != 0) ? 1 : 0;
    if (chownCount == 1)
    {
        EXPECT_CALL(context, ChownPinnedFileDescriptor(::testing::_, 0, 0)).Times(1).WillOnce([&](int descriptor, uid_t, gid_t) {
            struct stat pinned = {};
            EXPECT_EQ(0, ::fstat(descriptor, &pinned));
            EXPECT_EQ(original.st_dev, pinned.st_dev);
            EXPECT_EQ(original.st_ino, pinned.st_ino);
            // Returns 0 without delegating to the real chown: an
            // unprivileged process attempting chown to root would fail
            // with EPERM.
            return 0;
        });
    }
    else
    {
        EXPECT_CALL(context, ChownPinnedFileDescriptor(::testing::_, 0, 0)).Times(0);
    }
    // Public key mask 0133 applied to 0666 -> 0644; the post-state
    // assertions below already expect 0644.
    EXPECT_CALL(context, ChmodPinnedAlias(::testing::_, ::testing::_, static_cast<mode_t>(S_IFREG | 0644))).Times(1).WillOnce([&](int procfsDirectory, const char* decimalAlias, mode_t mode) {
        struct stat pinned = {};
        EXPECT_EQ(0, ::fstatat(procfsDirectory, decimalAlias, &pinned, 0));
        EXPECT_EQ(original.st_dev, pinned.st_dev);
        EXPECT_EQ(original.st_ino, pinned.st_ino);
        return context.RealChmodPinnedAlias(procfsDirectory, decimalAlias, mode);
    });
    auto remediate = RemediateSshKeyPermissions(params, indicators, context);
    ASSERT_TRUE(remediate.HasValue()) << remediate.Error().message;
    EXPECT_TRUE(swapped);
    struct stat changed = {}, untouched = {};
    ASSERT_EQ(0, ::stat(held.c_str(), &changed));
    ASSERT_EQ(0, ::stat(key.c_str(), &untouched));
    EXPECT_EQ(original.st_ino, changed.st_ino);
    EXPECT_NE(original.st_ino, untouched.st_ino);
    EXPECT_EQ(0644, changed.st_mode & 0777);
    EXPECT_EQ(0666, untouched.st_mode & 0777);
}

TEST(SshKeyRangeTest, RequiredNonYieldedDirectoryFailureAndReachedReadErrorPropagate)
{
    ::testing::StrictMock<MockContext> context;
    IndicatorsTree indicators;
    indicators.Push("SSH");
    const std::string root = context.GetTempdirPath() + "/ssh";
    ASSERT_EQ(0, mkdir(root.c_str(), 0700));
    const std::string nested = root + "/nested";
    ASSERT_EQ(0, mkdir(nested.c_str(), 0700));
    context.SetSpecialFilePath("/etc/ssh", root);
    // No EXPECT_CALL in this test constrains any native seam; both
    // ReadDirectory overrides below are ON_CALL default actions only.
    context.AllowIncidentalNativeAccess();
    struct stat expectedNested = {};
    ASSERT_EQ(0, stat(nested.c_str(), &expectedNested));
    ON_CALL(context, ReadDirectory(::testing::_)).WillByDefault([expectedNested](DIR * stream) -> struct dirent* {
        struct stat actual = {};
        if (0 == fstat(dirfd(stream), &actual) && actual.st_dev == expectedNested.st_dev && actual.st_ino == expectedNested.st_ino)
        {
            errno = EACCES;
            return nullptr;
        }
        return readdir(stream);
    });
    SshKeyPermissionsParams params;
    params.type = SshKeyType::Private;
    const auto blocked = RemediateSshKeyPermissions(params, indicators, context);
    ASSERT_FALSE(blocked.HasValue());
    EXPECT_EQ(EACCES, blocked.Error().code);

    ON_CALL(context, ReadDirectory(::testing::_)).WillByDefault([](DIR*) -> struct dirent* {
        errno = EIO;
        return nullptr;
    });
    const auto readError = AuditSshKeyPermissions(params, indicators, context);
    ASSERT_FALSE(readError.HasValue());
    EXPECT_EQ(EIO, readError.Error().code);
}

TEST(SshKeyRangeTest, OriginalKeyReadErrorOutranksDestructorCloseFailure)
{
    ::testing::StrictMock<MockContext> context;
    IndicatorsTree indicators;
    indicators.Push("SSH");
    const std::string root = context.GetTempdirPath() + "/ssh";
    ASSERT_EQ(0, mkdir(root.c_str(), 0700));
    const std::string key = root + "/key";
    std::ofstream(key) << kPrivateKeyHeader;
    context.SetSpecialFilePath("/etc/ssh", root);
    struct stat expectedKey = {};
    ASSERT_EQ(0, ::stat(key.c_str(), &expectedKey));
    // ReadFileDescriptor is excluded: this test constrains it below with its
    // own full-wildcard EXPECT_CALL/WillRepeatedly (the read-fault
    // injection). CloseDirectory only gets an ON_CALL default-action
    // override, not its own EXPECT_CALL, so it stays in the catch-all.
    context.AllowProcfsBootstrap();
    context.AllowNativeOpen();
    context.AllowDescriptorInspection();
    context.AllowDescriptorClose();
    context.AllowDirectoryEnumeration();
    context.AllowIdentityLookup();
    EXPECT_CALL(context, GetFileContents(::testing::_)).Times(0);
    EXPECT_CALL(context, ReadFileDescriptor(::testing::_, ::testing::_, ::testing::_)).WillRepeatedly([&](int fd, void* data, std::size_t size) {
        struct stat actual = {};
        if (::fstat(fd, &actual) == 0 && actual.st_dev == expectedKey.st_dev && actual.st_ino == expectedKey.st_ino)
        {
            errno = EACCES;
            return static_cast<ssize_t>(-1);
        }
        return context.RealReadFileDescriptor(fd, data, size);
    });
    ON_CALL(context, CloseDirectory(::testing::_)).WillByDefault([](DIR* stream) {
        const int result = closedir(stream);
        if (0 == result)
        {
            errno = EIO;
            return ComplianceEngine::Result<void>(ComplianceEngine::Error(EIO));
        }
        return ComplianceEngine::Result<void>(ComplianceEngine::Error(errno));
    });
    SshKeyPermissionsParams params;
    params.type = SshKeyType::Private;
    const auto result = RemediateSshKeyPermissions(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EACCES, result.Error().code);
    EXPECT_EQ("Cannot read acquired file", result.Error().message);
}

TEST(SshKeyRangeTest, DeepTraversalRejectsDescriptorBudgetEvenThoughDirectoriesAreNotYielded)
{
    ::testing::StrictMock<MockContext> context;
    IndicatorsTree indicators;
    indicators.Push("SSH");
    std::string directory = context.GetTempdirPath() + "/ssh";
    ASSERT_EQ(0, mkdir(directory.c_str(), 0700));
    context.SetSpecialFilePath("/etc/ssh", directory);
    // No test-specific expectation in this test; it only exercises the
    // descriptor-budget rejection path.
    context.AllowIncidentalNativeAccess();
    for (int depth = 0; depth < 33; ++depth)
    {
        directory += "/d";
        ASSERT_EQ(0, mkdir(directory.c_str(), 0700));
    }
    SshKeyPermissionsParams params;
    params.type = SshKeyType::Public;
    const auto result = AuditSshKeyPermissions(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EMFILE, result.Error().code);
    EXPECT_EQ("Filesystem pin retention exceeds descriptor budget", result.Error().message);
}

TEST(SshKeyRangeTest, RootSymlinkIsFollowedButInteriorDirectorySymlinkIsNot)
{
    ::testing::StrictMock<MockContext> context;
    IndicatorsTree indicators;
    indicators.Push("SSH");
    const std::string root = context.GetTempdirPath() + "/ssh";
    ASSERT_EQ(0, mkdir(root.c_str(), 0700));
    const std::string outside = context.GetTempdirPath() + "/outside";
    ASSERT_EQ(0, mkdir(outside.c_str(), 0700));
    std::ofstream(outside + "/key") << kPublicKeySample;
    ASSERT_EQ(0, symlink(outside.c_str(), (root + "/linked").c_str()));
    const std::string alias = context.GetTempdirPath() + "/ssh-alias";
    ASSERT_EQ(0, symlink(root.c_str(), alias.c_str()));
    context.SetSpecialFilePath("/etc/ssh", alias);
    // GetFileContents is a separate, non-native seam this helper doesn't
    // cover.
    context.AllowIncidentalNativeAccess();
    EXPECT_CALL(context, GetFileContents(::testing::_)).Times(0);
    SshKeyPermissionsParams params;
    params.type = SshKeyType::Public;
    const auto result = AuditSshKeyPermissions(params, indicators, context);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());
}

// TM-12: a hard link inside the scanned SSH key tree to a file outside it
// is an ordinary directory entry; Path confinement and sealed descriptor
// authority accept it by design. Remediation must refuse to mutate the
// held pin rather than following the link to the outside inode. The
// consumer's owner rule (root/root|ssh_keys) expects root, so an
// unprivileged run cannot observe a real ownership change; the oracle is
// therefore the mutation seams themselves.
TEST(SshKeyRangeTest, TM12HardLinkedKeyWithinScannedTreeRefusesMutation)
{
    ::testing::StrictMock<MockContext> context;
    IndicatorsTree indicators;
    indicators.Push("SSH");
    const std::string root = context.GetTempdirPath() + "/ssh";
    ASSERT_EQ(0, mkdir(root.c_str(), 0700));
    context.SetSpecialFilePath("/etc/ssh", root);
    context.AllowIncidentalNativeAccess();

    const std::string outside = context.GetTempdirPath() + "/tm12-ssh-outside";
    std::ofstream(outside) << kPublicKeySample;
    ASSERT_EQ(0, chmod(outside.c_str(), 0777));
    const std::string linked = root + "/key";
    ASSERT_EQ(0, link(outside.c_str(), linked.c_str()));

    EXPECT_CALL(context, ChownPinnedFileDescriptor(::testing::_, ::testing::_, ::testing::_)).Times(0);
    EXPECT_CALL(context, ChmodPinnedAlias(::testing::_, ::testing::_, ::testing::_)).Times(0);

    SshKeyPermissionsParams params;
    params.type = SshKeyType::Public;
    const auto result = RemediateSshKeyPermissions(params, indicators, context);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(Status::NonCompliant, result.Value());

    struct stat after = {};
    ASSERT_EQ(0, stat(outside.c_str(), &after));
    EXPECT_EQ(0777, after.st_mode & 0777);
}

// TM-12: an unlink of the inside name between acquisition and the fresh
// pre-mutation check must not defeat the refusal. A fresh-only check would
// be fooled here (by the time any fresh stat runs, only the outside name
// remains, showing one link); the acquisition-time count, recorded once by
// FTW when the pin was taken, still shows two and must still refuse.
TEST(SshKeyRangeTest, TM12UnlinkAfterAcquisitionStillRefusesViaAcquisitionTimeLinkCount)
{
    ::testing::StrictMock<MockContext> context;
    IndicatorsTree indicators;
    indicators.Push("SSH");
    const std::string root = context.GetTempdirPath() + "/ssh";
    ASSERT_EQ(0, mkdir(root.c_str(), 0700));
    context.SetSpecialFilePath("/etc/ssh", root);
    context.AllowIncidentalNativeAccess();

    const std::string outside = context.GetTempdirPath() + "/tm12-ssh-outside-unlink";
    std::ofstream(outside) << kPublicKeySample;
    ASSERT_EQ(0, chmod(outside.c_str(), 0777));
    const std::string linked = root + "/key";
    ASSERT_EQ(0, link(outside.c_str(), linked.c_str()));
    struct stat target = {};
    ASSERT_EQ(0, stat(outside.c_str(), &target));

    bool sawAcquisitionStat = false;
    bool unlinkedInside = false;
    ON_CALL(context, StatFileDescriptor(::testing::_, ::testing::_)).WillByDefault([&](int descriptor, struct stat* metadata) {
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
        return context.RealStatFileDescriptor(descriptor, metadata);
    });

    EXPECT_CALL(context, ChownPinnedFileDescriptor(::testing::_, ::testing::_, ::testing::_)).Times(0);
    EXPECT_CALL(context, ChmodPinnedAlias(::testing::_, ::testing::_, ::testing::_)).Times(0);

    SshKeyPermissionsParams params;
    params.type = SshKeyType::Public;
    const auto result = RemediateSshKeyPermissions(params, indicators, context);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(Status::NonCompliant, result.Value());
    EXPECT_TRUE(sawAcquisitionStat);
    EXPECT_TRUE(unlinkedInside);
}

// TM-12: ownership and mode are separate mutation steps, each preceded by
// its own fresh check. A link added between them (simulated here right as
// ownership "succeeds") must make the mode step refuse after ownership has
// already changed; the verdict is NonCompliant, not Compliant -- the
// operation is not atomic.
TEST(SshKeyRangeTest, TM12LinkAddedBetweenOwnershipAndModeStagesRefusesModeAfterOwnershipChanged)
{
    ::testing::StrictMock<MockContext> context;
    IndicatorsTree indicators;
    indicators.Push("SSH");
    const std::string root = context.GetTempdirPath() + "/ssh";
    ASSERT_EQ(0, mkdir(root.c_str(), 0700));
    context.SetSpecialFilePath("/etc/ssh", root);
    context.AllowIncidentalNativeAccess();

    const std::string target = root + "/key";
    std::ofstream(target) << kPublicKeySample;
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
    const std::string extraLink = context.GetTempdirPath() + "/tm12-ssh-extra-link";

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

    SshKeyPermissionsParams params;
    params.type = SshKeyType::Public;
    const auto result = RemediateSshKeyPermissions(params, indicators, context);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(Status::NonCompliant, result.Value());

    struct stat after = {};
    ASSERT_EQ(0, stat(target.c_str(), &after));
    EXPECT_EQ(0777, after.st_mode & 0777);
}

// TM-12 green-baseline control: a hard-linked file that already satisfies
// the rule must stay Compliant, with no mutation attempt at all. This uses
// the pinned route directly (bypassing SshKeyPermissions' hardcoded
// root-owned rules) so full compliance is achievable without privilege: the
// only property under test is that the refusal is checked "only when a
// change is needed" (rule 2) -- an up-front, unconditional refusal would
// turn this test red.
TEST(SshKeyRangeTest, TM12CompliantHardLinkedKeyStaysCompliantWithoutMutation)
{
    ::testing::StrictMock<MockContext> context;
    IndicatorsTree indicators;
    indicators.Push("SSH");
    const std::string root = context.GetTempdirPath() + "/ssh";
    ASSERT_EQ(0, mkdir(root.c_str(), 0700));
    context.AllowIncidentalNativeAccess();

    struct passwd* self = getpwuid(getuid());
    ASSERT_NE(nullptr, self);
    const std::string outside = context.GetTempdirPath() + "/tm12-ssh-outside-compliant";
    std::ofstream(outside) << kPublicKeySample;
    ASSERT_EQ(0, chmod(outside.c_str(), 0600));
    const std::string linked = root + "/compliant-key";
    ASSERT_EQ(0, link(outside.c_str(), linked.c_str()));

    FilePermissionsParams params;
    params.path = linked;
    auto ownerPattern = Pattern::Make(self->pw_name);
    ASSERT_TRUE(ownerPattern.HasValue());
    params.owner = {{ownerPattern.Value()}};
    params.mask = 0177;

    auto pin = AcquireRegularFilePin(context, root, "compliant-key");
    ASSERT_TRUE(pin.HasValue());

    EXPECT_CALL(context, ChownPinnedFileDescriptor(::testing::_, ::testing::_, ::testing::_)).Times(0);
    EXPECT_CALL(context, ChmodPinnedAlias(::testing::_, ::testing::_, ::testing::_)).Times(0);

    auto result = EnforcePinnedFilePermissions(params, pin.Value(), indicators, context);
    ASSERT_TRUE(result.HasValue()) << result.Error().message;
    EXPECT_EQ(Status::Compliant, result.Value());
}

class EnsureSshKeyPermsTest : public ::testing::Test
{
protected:
    ::testing::StrictMock<MockContext> mContext;
    IndicatorsTree mIndicators;
    std::string mSshDir;
    std::size_t mKeyReads = 0;
    std::size_t mExpectedKeyReads = 0;
    void SetUp() override
    {
        mIndicators.Push("EnsureSshKeyPerms");
        mSshDir = mContext.GetFilesystemScannerRoot() + std::string("/etc/ssh");
        ASSERT_EQ(0, ::mkdir((mContext.GetFilesystemScannerRoot() + std::string("/etc")).c_str(), 0755));
        ASSERT_EQ(0, ::mkdir(mSshDir.c_str(), 0755));
        mContext.SetSpecialFilePath("/etc/ssh", mSshDir);
        EXPECT_CALL(mContext, GetFileContents(::testing::_)).Times(0);
        // ReadFileDescriptor is excluded here: every test that reads a key
        // constrains it itself via ExpectPinnedKeyReads() below with its own
        // full-wildcard EXPECT_CALL/WillRepeatedly; a test with no key to
        // read (no ExpectPinnedKeyReads call) declares AllowFileRead()
        // itself instead.
        mContext.AllowProcfsBootstrap();
        mContext.AllowNativeOpen();
        mContext.AllowDescriptorInspection();
        mContext.AllowDescriptorClose();
        mContext.AllowDirectoryEnumeration();
        mContext.AllowIdentityLookup();
    }

    void ExpectPinnedKeyReads(const std::string& path, std::size_t count, int readError = 0)
    {
        struct stat expectedKey = {};
        ASSERT_EQ(0, ::stat(path.c_str(), &expectedKey));
        mKeyReads = 0;
        mExpectedKeyReads = count;
        EXPECT_CALL(mContext, ReadFileDescriptor(::testing::_, ::testing::_, ::testing::_))
            .WillRepeatedly([this, expectedKey, readError](int fd, void* data, std::size_t size) -> ssize_t {
                struct stat actual = {};
                if (::fstat(fd, &actual) == 0 && actual.st_dev == expectedKey.st_dev && actual.st_ino == expectedKey.st_ino)
                {
                    ++mKeyReads;
                    if (readError != 0)
                    {
                        errno = readError;
                        return -1;
                    }
                }
                return mContext.RealReadFileDescriptor(fd, data, size);
            });
    }

    void CheckPinnedKeyReadCount()
    {
        EXPECT_EQ(mExpectedKeyReads, mKeyReads);
    }
};

TEST_F(EnsureSshKeyPermsTest, PublicKeyCompliant)
{
    if (0 != ::geteuid())
        GTEST_SKIP() << "Actual root ownership is required for a compliant-owner result";
    std::string keyPath = mSshDir + "/id_ed25519.pub";
    {
        std::ofstream f(keyPath);
        f << kPublicKeySample;
    }
    ExpectPinnedKeyReads(keyPath, 2);
    ASSERT_EQ(0, ::chmod(keyPath.c_str(), (0644 & ~0133)));
    SshKeyPermissionsParams params;
    params.type = SshKeyType::Public;

    auto result = AuditSshKeyPermissions(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
    CheckPinnedKeyReadCount();
}

TEST_F(EnsureSshKeyPermsTest, RegularFileRootPropagatesTraversalError)
{
    const auto root = mContext.GetTempdirPath() + "/ssh-root-file";
    std::ofstream(root) << "not a directory\n";
    mContext.SetSpecialFilePath("/etc/ssh", root);
    // No key to read in this test (the root itself is rejected first); the
    // fixture excludes ReadFileDescriptor from its catch-all because other
    // tests constrain it via ExpectPinnedKeyReads().
    mContext.AllowFileRead();
    SshKeyPermissionsParams params;
    params.type = SshKeyType::Public;

    const auto result = AuditSshKeyPermissions(params, mIndicators, mContext);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(ENOTDIR, result.Error().code);
}

TEST_F(EnsureSshKeyPermsTest, AuditFailedKeyReadPropagatesErrorWithoutIndicator)
{
    const std::string keyPath = mSshDir + "/id_ed25519.pub";
    std::ofstream key(keyPath);
    ASSERT_TRUE(key.is_open());
    key << kPublicKeySample;
    key.close();
    ASSERT_TRUE(key.good());
    ExpectPinnedKeyReads(keyPath, 1, EACCES);
    SshKeyPermissionsParams params;
    params.type = SshKeyType::Public;

    const auto result = AuditSshKeyPermissions(params, mIndicators, mContext);

    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EACCES, result.Error().code);
    EXPECT_EQ("Cannot read acquired file", result.Error().message);
    EXPECT_TRUE(mIndicators.Back().indicators.empty());
    CheckPinnedKeyReadCount();
}

TEST_F(EnsureSshKeyPermsTest, RemediationFailedKeyReadPropagatesErrorWithoutIndicator)
{
    const std::string keyPath = mSshDir + "/id_ed25519";
    std::ofstream key(keyPath);
    ASSERT_TRUE(key.is_open());
    key << kPrivateKeyHeader;
    key.close();
    ASSERT_TRUE(key.good());
    ExpectPinnedKeyReads(keyPath, 1, EIO);
    SshKeyPermissionsParams params;
    params.type = SshKeyType::Private;

    const auto result = RemediateSshKeyPermissions(params, mIndicators, mContext);

    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EIO, result.Error().code);
    EXPECT_EQ("Cannot read acquired file", result.Error().message);
    EXPECT_TRUE(mIndicators.Back().indicators.empty());
    CheckPinnedKeyReadCount();
}

TEST_F(EnsureSshKeyPermsTest, PublicKeyNonCompliantBitMask)
{
    std::string keyPath = mSshDir + "/id_test.pub";
    {
        std::ofstream f(keyPath);
        f << kPublicKeySample;
    }
    ExpectPinnedKeyReads(keyPath, 2);
    ASSERT_EQ(0, ::chmod(keyPath.c_str(), 0644 | 0020)); // forbidden group write bit
    SshKeyPermissionsParams params;
    params.type = SshKeyType::Public;
    auto result = AuditSshKeyPermissions(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::NonCompliant);
    CheckPinnedKeyReadCount();
}

TEST_F(EnsureSshKeyPermsTest, PrivateKeyCompliant)
{
    if (0 != ::geteuid())
        GTEST_SKIP() << "Actual root ownership is required for a compliant-owner result";
    std::string keyPath = mSshDir + "/id_ed25519";
    {
        std::ofstream f(keyPath);
        f << kPrivateKeyHeader << "...payload...\n";
    }
    ExpectPinnedKeyReads(keyPath, 2);
    ASSERT_EQ(0, ::chmod(keyPath.c_str(), 0600));
    SshKeyPermissionsParams params;
    params.type = SshKeyType::Private;
    auto result = AuditSshKeyPermissions(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
    CheckPinnedKeyReadCount();
}

TEST_F(EnsureSshKeyPermsTest, PrivateKeyRemediation)
{
    if (0 != ::geteuid())
        GTEST_SKIP() << "Actual root ownership is required for this ownership remediation";
    std::string keyPath = mSshDir + "/id_ed25519";
    {
        std::ofstream f(keyPath);
        f << kPrivateKeyHeader << "...payload...\n";
    }
    ExpectPinnedKeyReads(keyPath, 4);
    ASSERT_EQ(0, ::chmod(keyPath.c_str(), 0777)); // bad perms
    struct stat keyIdentity = {};
    ASSERT_EQ(0, ::stat(keyPath.c_str(), &keyIdentity));
    // Precondition: the key was created by root in this private fixture
    // directory, so ownership is already compliant and only the mode is
    // remediated below.
    ASSERT_EQ(0u, keyIdentity.st_uid) << "test precondition: key must already be root-owned";
    ASSERT_EQ(0u, keyIdentity.st_gid) << "test precondition: key must already be root-group-owned";
    EXPECT_CALL(mContext, ChownPinnedFileDescriptor(::testing::_, ::testing::_, ::testing::_)).Times(0);
    // 0777 & ~0137 = 0640.
    EXPECT_CALL(mContext, ChmodPinnedAlias(::testing::_, ::testing::_, static_cast<mode_t>(S_IFREG | 0640)))
        .Times(1)
        .WillOnce([this, keyIdentity](int procfsDirectory, const char* decimalAlias, mode_t mode) {
            struct stat pinned = {};
            EXPECT_EQ(0, ::fstatat(procfsDirectory, decimalAlias, &pinned, 0));
            EXPECT_EQ(keyIdentity.st_dev, pinned.st_dev);
            EXPECT_EQ(keyIdentity.st_ino, pinned.st_ino);
            return mContext.RealChmodPinnedAlias(procfsDirectory, decimalAlias, mode);
        });
    SshKeyPermissionsParams params;
    params.type = SshKeyType::Private;
    auto remediate = RemediateSshKeyPermissions(params, mIndicators, mContext);
    ASSERT_TRUE(remediate.HasValue());
    ASSERT_EQ(remediate.Value(), Status::Compliant);
    struct stat st;
    ASSERT_EQ(0, stat(keyPath.c_str(), &st));
    ASSERT_EQ(0u, (st.st_mode & 0137));
    auto post = AuditSshKeyPermissions(params, mIndicators, mContext);
    ASSERT_TRUE(post.HasValue());
    ASSERT_EQ(post.Value(), Status::Compliant);
    CheckPinnedKeyReadCount();
}

// TM-12 root-gated real control: with a hard link to the key from outside
// the scanned tree, remediation must leave the real file's mode untouched
// (ownership is already root:root in this fixture); once the outside link
// is removed, the same key (same inside name) is remediated normally.
TEST_F(EnsureSshKeyPermsTest, TM12HardLinkedKeyIsNotRemediatedWhileUnlinkedCopyIs)
{
    if (0 != ::geteuid())
        GTEST_SKIP() << "Actual root ownership and chown are required for this control";
    std::string keyPath = mSshDir + "/id_ed25519_tm12";
    {
        std::ofstream f(keyPath);
        f << kPrivateKeyHeader << "...payload...\n";
    }
    ASSERT_EQ(0, ::chmod(keyPath.c_str(), 0777));
    struct stat keyIdentity = {};
    ASSERT_EQ(0, ::stat(keyPath.c_str(), &keyIdentity));
    ASSERT_EQ(0u, keyIdentity.st_uid) << "test precondition: key must already be root-owned";
    ASSERT_EQ(0u, keyIdentity.st_gid) << "test precondition: key must already be root-group-owned";

    const std::string outsideLink = mContext.GetTempdirPath() + "/tm12-ssh-outside-link";
    ASSERT_EQ(0, ::link(keyPath.c_str(), outsideLink.c_str()));

    mContext.AllowFileRead();
    EXPECT_CALL(mContext, ChownPinnedFileDescriptor(::testing::_, ::testing::_, ::testing::_)).Times(0);
    EXPECT_CALL(mContext, ChmodPinnedAlias(::testing::_, ::testing::_, ::testing::_)).Times(0);

    SshKeyPermissionsParams params;
    params.type = SshKeyType::Private;
    auto linked = RemediateSshKeyPermissions(params, mIndicators, mContext);
    ASSERT_TRUE(linked.HasValue()) << linked.Error().message;
    EXPECT_EQ(Status::NonCompliant, linked.Value());
    struct stat stillBad = {};
    ASSERT_EQ(0, ::stat(keyPath.c_str(), &stillBad));
    EXPECT_EQ(0777, stillBad.st_mode & 0777);

    ASSERT_EQ(0, ::unlink(outsideLink.c_str()));
    EXPECT_CALL(mContext, ChownPinnedFileDescriptor(::testing::_, ::testing::_, ::testing::_)).Times(0); // already root:root
    EXPECT_CALL(mContext, ChmodPinnedAlias(::testing::_, ::testing::_, static_cast<mode_t>(S_IFREG | 0640)))
        .Times(1)
        .WillOnce([this](int procfsDirectory, const char* decimalAlias, mode_t mode) {
            return mContext.RealChmodPinnedAlias(procfsDirectory, decimalAlias, mode);
        });
    auto unlinked = RemediateSshKeyPermissions(params, mIndicators, mContext);
    ASSERT_TRUE(unlinked.HasValue()) << unlinked.Error().message;
    EXPECT_EQ(Status::Compliant, unlinked.Value());
    struct stat fixed = {};
    ASSERT_EQ(0, ::stat(keyPath.c_str(), &fixed));
    EXPECT_EQ(0640, fixed.st_mode & 0777);
}

TEST_F(EnsureSshKeyPermsTest, RemediationNoKeys)
{
    // No key to read in this test (the directory is empty); the fixture
    // excludes ReadFileDescriptor from its catch-all because other tests
    // constrain it via ExpectPinnedKeyReads().
    mContext.AllowFileRead();
    SshKeyPermissionsParams params;
    params.type = SshKeyType::Public;
    auto result = RemediateSshKeyPermissions(params, mIndicators, mContext);
    ASSERT_TRUE(result.HasValue());
    ASSERT_EQ(result.Value(), Status::Compliant);
}

TEST_F(EnsureSshKeyPermsTest, NestedRecognizedKeyIsChecked)
{
    const std::string nested = mSshDir + "/nested";
    ASSERT_EQ(0, ::mkdir(nested.c_str(), 0755));
    const std::string keyPath = nested + "/host-key";
    std::ofstream(keyPath) << kPrivateKeyHeader << "payload\n";
    ASSERT_EQ(0, ::chmod(keyPath.c_str(), 0777));
    ExpectPinnedKeyReads(keyPath, 2);
    SshKeyPermissionsParams params;
    params.type = SshKeyType::Private;

    const auto result = AuditSshKeyPermissions(params, mIndicators, mContext);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::NonCompliant, result.Value());
    CheckPinnedKeyReadCount();
}

TEST_F(EnsureSshKeyPermsTest, SimilarlyNamedNonKeyIsIgnored)
{
    const std::string decoyPath = mSshDir + "/host-key.pub";
    std::ofstream(decoyPath) << "not a key\n";
    ASSERT_EQ(0, ::chmod(decoyPath.c_str(), 0777));
    ExpectPinnedKeyReads(decoyPath, 2);
    SshKeyPermissionsParams params;
    params.type = SshKeyType::Public;

    const auto result = AuditSshKeyPermissions(params, mIndicators, mContext);

    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(Status::Compliant, result.Value());
    CheckPinnedKeyReadCount();
}
