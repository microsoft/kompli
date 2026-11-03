// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <MockContext.h>
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <filesystem/FilesystemHelpers.hpp>
#include <filesystem/Handle.hpp>
#include <filesystem/HandleActivationAccess.hpp>
#include <filesystem/Path.hpp>
#include <filesystem/PathLinkAccess.hpp>
#include <filesystem/ProcfsDescriptorAccess.hpp>
#include <filesystem/ReadableFile.hpp>
#include <fstream>
#include <gtest/gtest.h>
#include <iterator>
#include <limits>
#include <linux/magic.h>
#include <memory>
#include <sched.h>
#include <set>
#include <stdexcept>
#include <string>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <type_traits>
#include <unistd.h>
#include <utility>

using ComplianceEngine::As;
using ComplianceEngine::InPlaceType;
using ComplianceEngine::Variant;
using ComplianceEngine::Filesystem::ExtensionPolicy;
using ComplianceEngine::Filesystem::Handle;
using ComplianceEngine::Filesystem::MountPolicy;
using ComplianceEngine::Filesystem::NonFollowedLinkAction;
using ComplianceEngine::Filesystem::Path;
using ComplianceEngine::Filesystem::ResolverLimits;
using ComplianceEngine::Filesystem::SymlinkPolicy;
using ComplianceEngine::Filesystem::UnsupportedTypeAction;
using ComplianceEngine::Filesystem::Detail::Descriptor;
using ComplianceEngine::Filesystem::Detail::IsSingleChildComponent;
using ComplianceEngine::Filesystem::Detail::ParseMountId;
using ComplianceEngine::Filesystem::Detail::ProcfsDescriptorAccess;
using ComplianceEngine::Filesystem::Detail::ReadPinnedLink;
using testing::_;
using testing::NiceMock;

template <typename T, typename = void>
struct HasRawGet : std::false_type
{
};
template <typename T>
struct HasRawGet<T, std::void_t<decltype(std::declval<const T&>().Get())>> : std::true_type
{
};
template <typename T, typename = void>
struct HasRawRelease : std::false_type
{
};
template <typename T>
struct HasRawRelease<T, std::void_t<decltype(std::declval<T&>().Release())>> : std::true_type
{
};
template <typename T, typename = void>
struct HasRawTake : std::false_type
{
};
template <typename T>
struct HasRawTake<T, std::void_t<decltype(T::Take(std::declval<const ComplianceEngine::ContextInterface&>(), 0))>> : std::true_type
{
};
static_assert(!HasRawGet<Descriptor>::value && !HasRawRelease<Descriptor>::value && !HasRawTake<Descriptor>::value,
    "Native descriptors have no public extraction or adoption");
static_assert(!std::is_convertible<Descriptor, int>::value, "Native descriptors have no integer conversion");
static_assert(!std::is_constructible<Descriptor, const ComplianceEngine::ContextInterface&, int, const char*>::value, "Native adoption is private");
template <typename T, typename = void>
struct CanBorrowNames : std::false_type
{
};
template <typename T>
struct CanBorrowNames<T, std::void_t<decltype(std::declval<T>().LookupName()), decltype(std::declval<T>().EffectiveName())>> : std::true_type
{
};
static_assert(!CanBorrowNames<Handle&>::value && !CanBorrowNames<const Handle&>::value && !CanBorrowNames<Handle&&>::value && !CanBorrowNames<const Handle&&>::value,
    "Detached handles do not retain full historical names");
static_assert(std::is_same<decltype(std::declval<Handle&&>().AcquiredMetadata()), struct stat>::value,
    "Temporary acquisition metadata is copied by value");
static_assert(std::is_same<decltype(std::declval<const Handle&>().Stat()), ComplianceEngine::Result<struct stat>>::value,
    "Ordinary metadata inspection is fresh and fallible");

using PathOutcome = Variant<Path, Path::RejectionReason>;
static_assert(std::is_same<decltype(Path::Make(std::declval<const ComplianceEngine::ContextInterface&>(), std::declval<std::string>(),
                               std::declval<Path::Policy>(), std::declval<ResolverLimits>())),
                  ComplianceEngine::Result<PathOutcome>>::value,
    "Path::Make returns a direct typed outcome");
static_assert(!std::is_default_constructible<PathOutcome>::value, "A path outcome must carry an alternative");
static_assert(!std::is_copy_constructible<PathOutcome>::value, "A path outcome owns a move-only path");
static_assert(!std::is_copy_assignable<PathOutcome>::value, "A path outcome cannot be copied");
static_assert(std::is_nothrow_move_constructible<PathOutcome>::value, "path outcome move construction is nonthrowing");
static_assert(std::is_nothrow_move_assignable<PathOutcome>::value, "path outcome move assignment is nonthrowing");
static_assert(std::is_nothrow_destructible<PathOutcome>::value, "path outcome destruction is nonthrowing");
using PinnedComponents = decltype(std::declval<const Path&>().Components());
using PinnedIterator = decltype(std::declval<PinnedComponents>().begin());
static_assert(std::is_same<typename std::iterator_traits<PinnedIterator>::value_type, Path::Component>::value, "Pinned range yields components");
static_assert(std::is_same<decltype(*std::declval<PinnedIterator>()), Path::Component&>::value, "Component ranges contain owning values");
static_assert(!std::is_constructible<Path::Component, Handle&&>::value, "Only Path may adopt handles into components");
static_assert(std::is_default_constructible<Path::Component>::value, "Empty component values remain available");
static_assert(std::is_copy_constructible<Path::Component>::value, "Component copies retain one acquired pin");
static_assert(std::is_move_constructible<Path::Component>::value, "Component values remain movable");
static_assert(std::is_same<decltype(std::declval<const Path&>().Leaf()), Path::Component>::value, "Leaf returns an owning value");
static_assert(std::is_same<decltype((std::declval<const Path::Component&>().lookupName)), const std::string&>::value &&
                  std::is_same<decltype((std::declval<const Path::Component&>().effectiveName)), const std::string&>::value,
    "A borrowed component exposes original and effective names");
template <typename T, typename = void>
struct HasLookupParent : std::false_type
{
};
template <typename T>
struct HasLookupParent<T, std::void_t<decltype(std::declval<T>().lookupParent)>> : std::true_type
{
};
template <typename T, typename = void>
struct HasGeneration : std::false_type
{
};
template <typename T>
struct HasGeneration<T, std::void_t<decltype(std::declval<T>().generation)>> : std::true_type
{
};
static_assert(!HasLookupParent<Path::Component>::value && !HasGeneration<Path::Component>::value,
    "Internal ancestry and restoration generations are not public component state");
template <typename T, typename = void>
struct CanBorrowTemporaryComponents : std::false_type
{
};
template <typename T>
struct CanBorrowTemporaryComponents<T, std::void_t<decltype(std::declval<T>().Components())>> : std::true_type
{
};
static_assert(CanBorrowTemporaryComponents<Path&&>::value && CanBorrowTemporaryComponents<const Path&&>::value,
    "A temporary Path can return independently owned component values");

namespace
{
Path::Policy CrossMountPathPolicy(SymlinkPolicy following = SymlinkPolicy::DoNotFollow)
{
    Path::Policy policy;
    policy.symlinks = following;
    policy.mounts = MountPolicy::AllowCrossing;
    policy.fileLinks = following;
    policy.directoryLinks = following;
    return policy;
}

// Change only the mock fdinfo record, never the native mount namespace.
void AlterFdinfoMountId(void* buffer, ssize_t bytes)
{
    const std::string record(static_cast<const char*>(buffer), static_cast<std::size_t>(bytes));
    const auto at = record.find("mnt_id:");
    ASSERT_NE(std::string::npos, at);
    auto digit = record.find_first_of("0123456789", at + 7);
    ASSERT_NE(std::string::npos, digit);
    static_cast<char*>(buffer)[digit] = record[digit] == '9' ? '8' : '9';
}

class OwnedTestDescriptor
{
public:
    explicit OwnedTestDescriptor(int descriptor)
        : mDescriptor(descriptor)
    {
    }
    ~OwnedTestDescriptor()
    {
        if (0 <= mDescriptor)
        {
            ::close(mDescriptor);
        }
    }
    int Get() const
    {
        return mDescriptor;
    }

private:
    const int mDescriptor;
};

std::size_t CountOpenDescriptors()
{
    DIR* directory = ::opendir("/proc/self/fd");
    if (nullptr == directory)
    {
        return 0;
    }
    std::size_t count = 0;
    while (nullptr != ::readdir(directory))
    {
        ++count;
    }
    ::closedir(directory);
    return count;
}

class PathAliasTest : public testing::Test
{
protected:
    NiceMock<MockContext> context;

    static ResolverLimits AmpleLimits()
    {
        ResolverLimits limits;
        limits.shared.components = 100;
        limits.shared.retainedBytes = 262144;
        limits.linkExpansions = 8;
        return limits;
    }
};

static_assert(std::is_same<decltype(std::declval<Path&>().Push(std::declval<std::string>(), std::declval<ExtensionPolicy>())),
                  ComplianceEngine::Result<Variant<const Path&, Path::RejectionReason>>>::value,
    "Push returns a borrowed accepted path or a rejection");
static_assert(std::is_same<decltype(std::declval<Path&>().Push(std::declval<std::string>(), std::declval<Path::Policy>())),
                  ComplianceEngine::Result<Variant<const Path&, Path::RejectionReason>>>::value,
    "Absolute acquisition Push returns a borrowed accepted path or a rejection");
static_assert(!std::is_copy_constructible<Variant<const Path&, Path::RejectionReason>>::value, "Push outcome is move-only");

namespace
{
ExtensionPolicy ChildPolicy(SymlinkPolicy following, MountPolicy mounts)
{
    ExtensionPolicy policy;
    policy.fileLinks = following;
    policy.directoryLinks = following;
    policy.mounts = mounts;
    return policy;
}
} // namespace
// Tests that require an accepted pin distinguish typed missing and policy
// exclusion from acquisition errors.
ComplianceEngine::Result<Path> SelectAcceptedPath(const ComplianceEngine::ContextInterface& context, const std::string& path, Path::Policy policy, ResolverLimits limits)
{
    auto selected = Path::Make(context, path, policy, limits);
    if (!selected.HasValue())
        return std::move(selected).Error();
    if (!selected.Value().Is<Path>())
        return ComplianceEngine::Error("Test requires an accepted path",
            As<Path::RejectionReason>(selected.Value()) == Path::RejectionReason::Missing ? ENOENT : ELOOP);
    Path accepted = As<Path>(std::move(selected.Value()));
    auto frozen = accepted.FreezeRoot();
    if (!frozen.HasValue())
        return std::move(frozen).Error();
    return std::move(accepted);
}

TEST_F(PathAliasTest, ExplicitFreezeNarrowsProcessSentinelAndPoppedRootCannotReactivate)
{
    const std::string directory = context.GetTempdirPath();
    ASSERT_EQ(0, ::mkdir((directory + "/pre-freeze-root").c_str(), 0700));
    const std::size_t before = CountOpenDescriptors();
    auto acquired = Path::Make(context, directory, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(acquired.HasValue()) << acquired.Error().message;
    ASSERT_TRUE(acquired.Value().Is<Path>());
    Path path = As<Path>(std::move(acquired).Value());
    EXPECT_FALSE(path.IsFrozen());
    EXPECT_EQ(0U, path.Size());
    EXPECT_THROW(path.Root(), std::logic_error);
    EXPECT_THROW(path.Leaf(), std::logic_error);
    EXPECT_THROW(path.Components(), std::logic_error);
    EXPECT_THROW(path.ToString(), std::logic_error);
    EXPECT_EQ(EINVAL, path.AcquireChild("pre-freeze-root", ChildPolicy(SymlinkPolicy::DoNotFollow, MountPolicy::AllowCrossing)).Error().code);
    EXPECT_EQ(EINVAL, path.Pop().Error().code);
    ExtensionPolicy child = ChildPolicy(SymlinkPolicy::DoNotFollow, MountPolicy::AllowCrossing);
    auto outside = path.Push("pre-freeze-root", child);
    ASSERT_TRUE(outside.HasValue()) << outside.Error().message;
    ASSERT_TRUE(outside.Value().Is<const Path&>());
    EXPECT_THROW(path.Components(), std::logic_error);
    ASSERT_TRUE(path.FreezeRoot().HasValue());
    EXPECT_TRUE(path.IsFrozen());
    EXPECT_EQ(directory + "/pre-freeze-root", path.ToString());
    EXPECT_EQ(EINVAL, path.FreezeRoot().Error().code);
    auto detached = path.Pop();
    ASSERT_TRUE(detached.HasValue()) << detached.Error().message;
    EXPECT_EQ(0U, path.Size());
    EXPECT_EQ(0U, path.RetainedDescriptors());
    EXPECT_TRUE(path.Components().empty());
    EXPECT_EQ(EINVAL, path.Push("tmp", child).Error().code);
    EXPECT_EQ(EINVAL, path.AcquireChild("tmp", child).Error().code);
    Path moved(std::move(path));
    EXPECT_EQ(EINVAL, path.Push("tmp", child).Error().code);
    EXPECT_TRUE(path.Components().empty());
    EXPECT_TRUE(moved.Close().HasValue());
    EXPECT_TRUE(detached.Value().Close().HasValue());
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, ComponentsOwnActivePhysicalPinsInRootToLeafOrder)
{
    const std::string root = context.GetTempdirPath() + "/components";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/a").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/a/b").c_str(), 0700));
    ASSERT_EQ(0, ::symlink("a/b", (root + "/link").c_str()));
    auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    auto rootPin = path.Root();
    const auto follow = ChildPolicy(SymlinkPolicy::Follow, MountPolicy::AllowCrossing);
    ASSERT_TRUE(path.Push("link", follow).HasValue());
    ASSERT_EQ(3U, path.Size());
    const auto descriptors = CountOpenDescriptors();
    const auto retained = path.RetainedDescriptors();
    const auto bytes = path.RetainedBytes();
    const auto components = path.Components();
    auto it = components.begin();
    ASSERT_NE(it, components.end());
    EXPECT_EQ(rootPin.AcquiredMetadata().st_ino, it->AcquiredMetadata().st_ino);
    EXPECT_EQ(root, it->lookupName);
    EXPECT_EQ(root, it->effectiveName);
    ++it;
    ASSERT_NE(it, components.end());
    EXPECT_EQ("a", it->lookupName);
    EXPECT_EQ("a", it->effectiveName);
    ++it;
    ASSERT_NE(it, components.end());
    EXPECT_EQ(path.Leaf().AcquiredMetadata().st_ino, it->AcquiredMetadata().st_ino);
    EXPECT_EQ("b", it->effectiveName);
    EXPECT_EQ((root + "/a/b"), path.ToString());
    ++it;
    EXPECT_EQ(components.end(), it);
    EXPECT_EQ(descriptors, CountOpenDescriptors()); // copies do not duplicate native pins
    EXPECT_EQ(retained, path.RetainedDescriptors());
    EXPECT_EQ(bytes, path.RetainedBytes());
    auto removed = path.Pop();
    ASSERT_TRUE(removed.HasValue()) << removed.Error().message;
    EXPECT_TRUE(removed.Value().Close().HasValue());
    auto surviving = path.Components();
    EXPECT_EQ(2, std::distance(surviving.begin(), surviving.end()));
    auto ancestor = surviving.begin();
    ++ancestor;
    EXPECT_EQ("a", ancestor->effectiveName);
    ASSERT_TRUE(path.Close().HasValue());
    EXPECT_TRUE(path.Components().empty());
    EXPECT_TRUE(components.back().Stat().HasValue()); // retained values outlive the location
}

TEST_F(PathAliasTest, ComponentCopiesShareOnePinAndLastExplicitReleaseIsChecked)
{
    const std::string root = context.GetTempdirPath() + "/shared-component";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    const auto before = CountOpenDescriptors();
    auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    const auto charged = path.RetainedDescriptors();
    Path::Component first = path.Leaf();
    Path::Component second = first;
    EXPECT_EQ(charged, path.RetainedDescriptors());
    EXPECT_EQ(before + 1, CountOpenDescriptors());
    EXPECT_CALL(context, CloseFileDescriptor(_)).Times(0);
    ASSERT_TRUE(path.Close().HasValue());
    ASSERT_TRUE(first.Close().HasValue());
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    EXPECT_EQ(before + 1, CountOpenDescriptors());
    EXPECT_TRUE(second.Stat().HasValue());
    EXPECT_CALL(context, CloseFileDescriptor(_)).Times(1).WillOnce([&](int fd) { return context.RealCloseFileDescriptor(fd); });
    EXPECT_TRUE(second.Close().HasValue());
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, FreezeFileRootAndRejectPreFreezeSelectedFileAccess)
{
    const std::string file = context.MakeTempfile("file");
    auto acquired = Path::Make(context, file, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(acquired.HasValue()) << acquired.Error().message;
    Path path = As<Path>(std::move(acquired).Value());
    EXPECT_THROW(path.Leaf(), std::logic_error);
    ASSERT_TRUE(path.FreezeRoot().HasValue());
    EXPECT_EQ(Handle::Type::RegularFile, path.Root().AcquiredType());
    auto components = path.Components();
    ASSERT_NE(components.begin(), components.end());
    EXPECT_EQ(path.Root().AcquiredMetadata().st_ino, components.begin()->AcquiredMetadata().st_ino);
    EXPECT_EQ(1, std::distance(components.begin(), components.end()));
    EXPECT_EQ(file, path.ToString());
    auto root = path.Pop();
    ASSERT_TRUE(root.HasValue()) << root.Error().message;
    EXPECT_TRUE(root.Value().Close().HasValue());
    auto trailing = Path::Make(context, file + "/", CrossMountPathPolicy(), AmpleLimits());
    ASSERT_FALSE(trailing.HasValue());
    EXPECT_EQ(ENOTDIR, trailing.Error().code);
}

TEST_F(PathAliasTest, AbsolutePushSelectsLeafOnlyFromPristineProcessSentinel)
{
    const std::string file = context.MakeTempfile("absolute-push");
    const std::size_t before = CountOpenDescriptors();
    auto opened = Path::Make(context, "/", CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = As<Path>(std::move(opened).Value());
    auto acquired = path.Push(file, CrossMountPathPolicy());
    ASSERT_TRUE(acquired.HasValue()) << acquired.Error().message;
    ASSERT_TRUE(acquired.Value().Is<const Path&>());
    EXPECT_EQ(&path, &acquired.Value().Get<const Path&>());
    EXPECT_FALSE(path.IsFrozen());
    EXPECT_EQ(EINVAL, path.Push(file, CrossMountPathPolicy()).Error().code);
    ASSERT_TRUE(path.FreezeRoot().HasValue());
    EXPECT_EQ(file, path.ToString());
    EXPECT_EQ(Handle::Type::RegularFile, path.Leaf().AcquiredType());
    EXPECT_EQ(EINVAL, path.Push("/", CrossMountPathPolicy()).Error().code);
    auto detached = path.Pop();
    ASSERT_TRUE(detached.HasValue()) << detached.Error().message;
    EXPECT_EQ(EINVAL, path.Push(file, CrossMountPathPolicy()).Error().code);
    ASSERT_TRUE(detached.Value().Close().HasValue());
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, AbsolutePushValidatesBeforeMutationAndKeepsPartialPrefixConfined)
{
    const std::string directory = context.GetTempdirPath();
    auto opened = Path::Make(context, "/", CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = As<Path>(std::move(opened).Value());
    const std::size_t initialBytes = path.RetainedBytes();
    const std::size_t initialPins = path.RetainedDescriptors();
    EXPECT_EQ(EINVAL, path.Push("relative", CrossMountPathPolicy()).Error().code);
    EXPECT_EQ(EINVAL, path.Push(directory + "/../other", CrossMountPathPolicy()).Error().code);
    EXPECT_EQ(EINVAL, path.Push(directory + std::string("\0bad", 4), CrossMountPathPolicy()).Error().code);
    auto badPolicy = CrossMountPathPolicy();
    badPolicy.symlinks = static_cast<SymlinkPolicy>(-1);
    EXPECT_EQ(EINVAL, path.Push(directory, badPolicy).Error().code);
    EXPECT_EQ(initialBytes, path.RetainedBytes());
    EXPECT_EQ(initialPins, path.RetainedDescriptors());
    const std::string missing = directory + "/absent-absolute-push";
    auto rejected = path.Push(missing, CrossMountPathPolicy());
    ASSERT_TRUE(rejected.HasValue()) << rejected.Error().message;
    ASSERT_TRUE(rejected.Value().Is<Path::RejectionReason>());
    EXPECT_EQ(Path::RejectionReason::Missing, rejected.Value().Get<Path::RejectionReason>());
    EXPECT_EQ(EINVAL, path.Push(directory, CrossMountPathPolicy()).Error().code);
    EXPECT_LE(path.RetainedBytes(), path.Limits().shared.retainedBytes);
    ASSERT_TRUE(path.FreezeRoot().HasValue());
    EXPECT_EQ(directory, path.ToString());
    ASSERT_TRUE(path.Close().HasValue());
}

TEST_F(PathAliasTest, AbsolutePushSharesFollowCounterAndEnforcesTrailingDirectory)
{
    const std::string root = context.GetTempdirPath() + "/absolute-push-links";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/target").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/target/final").c_str(), 0700));
    ASSERT_EQ(0, ::symlink("target", (root + "/first").c_str()));
    ASSERT_EQ(0, ::symlink("final", (root + "/target/second").c_str()));
    ResolverLimits limits = AmpleLimits();
    limits.linkExpansions = 1;
    auto opened = Path::Make(context, "/", CrossMountPathPolicy(), limits);
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = As<Path>(std::move(opened).Value());
    auto exceeded = path.Push(root + "/first/second", CrossMountPathPolicy(SymlinkPolicy::Follow));
    ASSERT_FALSE(exceeded.HasValue());
    EXPECT_EQ(ELOOP, exceeded.Error().code);
    EXPECT_EQ(EINVAL, path.Push("/", CrossMountPathPolicy()).Error().code);
    ASSERT_TRUE(path.FreezeRoot().HasValue());
    EXPECT_EQ(root + "/target", path.ToString());
    ASSERT_TRUE(path.Close().HasValue());

    limits.linkExpansions = 2;
    auto fresh = Path::Make(context, "/", CrossMountPathPolicy(), limits);
    ASSERT_TRUE(fresh.HasValue()) << fresh.Error().message;
    Path selected = As<Path>(std::move(fresh).Value());
    auto success = selected.Push(root + "/first/second/", CrossMountPathPolicy(SymlinkPolicy::Follow));
    ASSERT_TRUE(success.HasValue()) << success.Error().message;
    ASSERT_TRUE(selected.FreezeRoot().HasValue());
    EXPECT_EQ(root + "/target/final", selected.ToString());
    ASSERT_TRUE(selected.Close().HasValue());

    const std::string file = context.MakeTempfile("trailing-push");
    auto forFile = Path::Make(context, "/", CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(forFile.HasValue()) << forFile.Error().message;
    Path filePath = As<Path>(std::move(forFile).Value());
    auto trailing = filePath.Push(file + "/", CrossMountPathPolicy());
    ASSERT_FALSE(trailing.HasValue());
    EXPECT_EQ(ENOTDIR, trailing.Error().code);
    EXPECT_EQ(EINVAL, filePath.Push(file, CrossMountPathPolicy()).Error().code);
    ASSERT_TRUE(filePath.Close().HasValue());
}

TEST_F(PathAliasTest, FailedFreezeCleanupLeavesNoBoundaryAndDoesNotRetryClose)
{
    const std::size_t before = CountOpenDescriptors();
    auto acquired = Path::Make(context, context.GetTempdirPath(), CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(acquired.HasValue()) << acquired.Error().message;
    Path path = As<Path>(std::move(acquired).Value());
    struct stat root = {};
    ASSERT_EQ(0, ::stat("/", &root));
    int rootCloses = 0;
    ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([&](int fd) {
        struct stat held = {};
        const bool rootPin = ::fstat(fd, &held) == 0 && held.st_dev == root.st_dev && held.st_ino == root.st_ino;
        const int result = context.RealCloseFileDescriptor(fd);
        if (rootPin)
        {
            ++rootCloses;
            errno = EIO;
            return -1;
        }
        return result;
    });
    auto frozen = path.FreezeRoot();
    ASSERT_FALSE(frozen.HasValue());
    EXPECT_EQ(EIO, frozen.Error().code);
    EXPECT_EQ(1, rootCloses);
    EXPECT_FALSE(path.IsFrozen());
    EXPECT_EQ(0U, path.Size());
    EXPECT_EQ(0U, path.RetainedDescriptors());
    EXPECT_EQ(EINVAL, path.Push("child", ExtensionPolicy{}).Error().code);
    EXPECT_EQ(EINVAL, path.AcquireChild("child", ExtensionPolicy{}).Error().code);
    EXPECT_TRUE(path.Close().HasValue());
    EXPECT_EQ(1, rootCloses);
    EXPECT_EQ(before, CountOpenDescriptors());
}
TEST_F(PathAliasTest, MakeSharesFollowLimitAcrossRootComponentsAndPushResetsIt)
{
    const std::string root = context.GetTempdirPath() + "/follow-budget";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/target").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/target/final").c_str(), 0700));
    ASSERT_EQ(0, ::symlink("target", (root + "/first").c_str()));
    ASSERT_EQ(0, ::symlink("final", (root + "/target/second").c_str()));
    ASSERT_EQ(0, ::symlink("target", (root + "/other").c_str()));

    ResolverLimits limits = AmpleLimits();
    limits.linkExpansions = 1;
    auto exhausted = Path::Make(context, root + "/first/second", CrossMountPathPolicy(SymlinkPolicy::Follow), limits);
    ASSERT_FALSE(exhausted.HasValue());
    EXPECT_EQ(ELOOP, exhausted.Error().code);

    limits.linkExpansions = 2;
    auto accepted = SelectAcceptedPath(context, root + "/first/second", CrossMountPathPolicy(SymlinkPolicy::Follow), limits);
    ASSERT_TRUE(accepted.HasValue()) << accepted.Error().message;
    EXPECT_EQ(root + "/target/final", accepted.Value().ToString());
    limits.linkExpansions = 3;
    auto surplus = SelectAcceptedPath(context, root + "/first/second", CrossMountPathPolicy(SymlinkPolicy::Follow), limits);
    ASSERT_TRUE(surplus.HasValue()) << surplus.Error().message;
    EXPECT_EQ(root + "/target/final", surplus.Value().ToString());

    limits.linkExpansions = 1;
    auto parent = SelectAcceptedPath(context, root, CrossMountPathPolicy(SymlinkPolicy::Follow), limits);
    ASSERT_TRUE(parent.HasValue()) << parent.Error().message;
    Path path = std::move(parent).Value();
    ExtensionPolicy following;
    following.fileLinks = SymlinkPolicy::Follow;
    following.directoryLinks = SymlinkPolicy::Follow;
    following.mounts = MountPolicy::AllowCrossing;
    auto first = path.Push("first", following);
    ASSERT_TRUE(first.HasValue()) << first.Error().message;
    ASSERT_TRUE(path.Pop().HasValue());
    auto second = path.Push("other", following);
    ASSERT_TRUE(second.HasValue()) << second.Error().message;
}

TEST_F(PathAliasTest, AcyclicDotFanoutStopsAtTotalFollowsWithoutGrowingDirectoryDepth)
{
    const std::string root = context.GetTempdirPath() + "/fanout";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    ASSERT_EQ(0, ::symlink(".", (root + "/s0").c_str()));
    for (int i = 1; i <= 4; ++i)
    {
        const std::string prior = "s" + std::to_string(i - 1);
        ASSERT_EQ(0, ::symlink((prior + "/" + prior).c_str(), (root + "/s" + std::to_string(i)).c_str()));
    }

    ResolverLimits limits = AmpleLimits();
    limits.linkExpansions = 7; // s2 follows exactly 1 + 2 + 4 links
    auto accepted = SelectAcceptedPath(context, root, CrossMountPathPolicy(SymlinkPolicy::Follow), limits);
    ASSERT_TRUE(accepted.HasValue()) << accepted.Error().message;
    Path path = std::move(accepted).Value();
    ExtensionPolicy following;
    following.fileLinks = SymlinkPolicy::Follow;
    following.directoryLinks = SymlinkPolicy::Follow;
    following.mounts = MountPolicy::AllowCrossing;
    auto within = path.Push("s2", following);
    ASSERT_TRUE(within.HasValue()) << within.Error().message;
    // A dot-only target leaves the physical stack at the root; Pop would
    // detach that root rather than undoing a logical Push.
    EXPECT_EQ(1U, path.Size());
    const auto before = path.ToString();
    auto exceeded = path.Push("s3", following);
    ASSERT_FALSE(exceeded.HasValue());
    EXPECT_EQ(ELOOP, exceeded.Error().code);
    EXPECT_EQ(before, path.ToString());
    EXPECT_EQ(1U, path.Size());
}

TEST_F(PathAliasTest, NestedLinkScheduleHasExactlySixtyFourFrameCeiling)
{
    const std::string root = context.GetTempdirPath() + "/bounded-frames";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/target").c_str(), 0700));
    for (const auto& chain : {std::pair<const char*, int>{"ok", 63}, {"too", 64}, {"long", 65}})
        for (int i = chain.second - 1; i >= 0; --i)
        {
            const std::string target = i + 1 == chain.second ? "target" : std::string(chain.first) + std::to_string(i + 1);
            ASSERT_EQ(0, ::symlink(target.c_str(), (root + "/" + chain.first + std::to_string(i)).c_str()));
        }
    ResolverLimits limits = AmpleLimits();
    limits.linkExpansions = 128; // isolate the independent static frame limit
    auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(), limits);
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    const auto follow = ChildPolicy(SymlinkPolicy::Follow, MountPolicy::AllowCrossing);
    ASSERT_TRUE(path.Push("ok0", follow).HasValue());
    EXPECT_EQ(root + "/target", path.ToString());
    ASSERT_TRUE(path.Pop().HasValue());
    for (const char* name : {"too0", "long0"})
    {
        auto rejected = path.Push(name, follow);
        ASSERT_FALSE(rejected.HasValue());
        EXPECT_EQ(ELOOP, rejected.Error().code);
        EXPECT_EQ(root, path.ToString());
        EXPECT_EQ(1U, path.Size());
    }
}
// Exercise ownership on a context-acquired pin without native adoption.
ComplianceEngine::Result<Descriptor> VerifiedTestDescriptor(const ComplianceEngine::ContextInterface& context)
{
    return context.OpenAbsolutePin("/proc");
}
template <typename T>
struct HasPublicNativeAdoption
{
    template <typename U>
    static auto Check(int) -> decltype(U::Take(std::declval<const ComplianceEngine::ContextInterface&>(), 0), std::true_type{});
    template <typename>
    static std::false_type Check(...);
    static constexpr bool value = decltype(Check<T>(0))::value;
};
std::string DescriptorTarget(int descriptor)
{
    const std::string alias = "/proc/self/fd/" + std::to_string(descriptor);
    char target[512] = {};
    const ssize_t length = ::readlink(alias.c_str(), target, sizeof(target));
    return (0 < length) ? std::string(target, static_cast<std::size_t>(length)) : std::string();
}
bool IsProcfsHelper(int descriptor)
{
    struct statfs filesystem = {};
    return (0 == ::fstatfs(descriptor, &filesystem)) && (PROC_SUPER_MAGIC == filesystem.f_type);
}

// Only constructed in the forked, private mount namespace. Unmount before
// MockContext removes its unique fixture directory.
class ScopedBindMount
{
public:
    explicit ScopedBindMount(std::string target)
        : mTarget(std::move(target))
    {
    }
    ~ScopedBindMount()
    {
        if (mMounted)
        {
            EXPECT_EQ(0, ::umount(mTarget.c_str())) << mTarget << ": " << std::strerror(errno);
        }
    }
    bool Bind(const std::string& source)
    {
        if (0 != ::mount(source.c_str(), mTarget.c_str(), nullptr, MS_BIND, nullptr))
        {
            return false;
        }
        mMounted = true;
        return true;
    }

private:
    std::string mTarget;
    bool mMounted = false;
};

// Reserved for unavailable namespace/mount capability during optional local
// runs. CI explicitly requires this test and treats this status as a failure.
const int unavailableMountCapability = 77;

int MountSetupFailure(const char* operation)
{
    const int error = errno;
    std::fprintf(stderr, "%s: %s (%d)\n", operation, std::strerror(error), error);
    if ((EPERM == error) || (EACCES == error))
    {
        return unavailableMountCapability;
    }
    return 1;
}

ComplianceEngine::Result<std::uint64_t> KernelMountId(int descriptor)
{
    std::ifstream info("/proc/self/fdinfo/" + std::to_string(descriptor));
    if (!info.is_open())
    {
        return ComplianceEngine::Error("Cannot open kernel fdinfo", errno);
    }
    const std::string contents(std::istreambuf_iterator<char>{info}, std::istreambuf_iterator<char>{});
    if (info.bad())
    {
        return ComplianceEngine::Error("Cannot read kernel fdinfo", EIO);
    }
    return ParseMountId(contents);
}

void CheckRealBindMounts(const NiceMock<MockContext>& context, const std::string& accepted)
{
    ResolverLimits limits;
    limits.shared.targetBytes = 4096;
    limits.shared.components = 100;
    limits.shared.work = 100000;
    limits.shared.liveDescriptors = 256;
    limits.shared.retainedBytes = 262144;
    limits.shared.fdinfoBytes = 4096;
    limits.linkTargetBytes = 4096;
    limits.linkExpansions = 8;
    limits.depth = 128;
    // Authorize the selected root mount separately; only descendants stay.
    auto opened = SelectAcceptedPath(context, accepted, CrossMountPathPolicy(), limits);
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();

    const std::string crossing = accepted + "/cross";
    OwnedTestDescriptor outer(::open(context.GetTempdirPath().c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC));
    OwnedTestDescriptor root(::open(accepted.c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC));
    OwnedTestDescriptor child(::open(crossing.c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC));
    ASSERT_GE(outer.Get(), 0);
    ASSERT_GE(root.Get(), 0);
    ASSERT_GE(child.Get(), 0);
    struct stat rootStat = {}, childStat = {};
    ASSERT_EQ(0, ::fstat(root.Get(), &rootStat));
    ASSERT_EQ(0, ::fstat(child.Get(), &childStat));
    EXPECT_EQ(rootStat.st_dev, childStat.st_dev);
    auto outerId = KernelMountId(outer.Get());
    auto rootId = KernelMountId(root.Get());
    auto childId = KernelMountId(child.Get());
    ASSERT_TRUE(outerId.HasValue()) << outerId.Error().message;
    ASSERT_TRUE(rootId.HasValue()) << rootId.Error().message;
    ASSERT_TRUE(childId.HasValue()) << childId.Error().message;
    EXPECT_NE(outerId.Value(), rootId.Value()); // The accepted root is itself a mount.
    EXPECT_NE(rootId.Value(), childId.Value()); // Bind mounts can share st_dev.
    auto pinnedRootId = path.Root().MountIdentity();
    ASSERT_TRUE(pinnedRootId.HasValue()) << pinnedRootId.Error().message;
    EXPECT_EQ(rootId.Value(), pinnedRootId.Value());

    ExtensionPolicy stay = ChildPolicy(SymlinkPolicy::DoNotFollow, MountPolicy::StayOnRootMount);
    ExtensionPolicy allow = ChildPolicy(SymlinkPolicy::DoNotFollow, MountPolicy::AllowCrossing);
    auto inside = path.Push("inside", stay);
    ASSERT_TRUE(inside.HasValue()) << inside.Error().message;
    ASSERT_TRUE(path.Pop().HasValue());
    auto denied = path.Push("cross", stay);
    ASSERT_FALSE(denied.HasValue());
    EXPECT_EQ(EXDEV, denied.Error().code);
    EXPECT_EQ("Component crosses accepted root mount", denied.Error().message);
    EXPECT_EQ(1U, path.Size());
    auto allowed = path.Push("cross", allow);
    ASSERT_TRUE(allowed.HasValue()) << allowed.Error().message;
    auto pinnedChildId = path.Leaf().MountIdentity();
    ASSERT_TRUE(pinnedChildId.HasValue()) << pinnedChildId.Error().message;
    EXPECT_EQ(childId.Value(), pinnedChildId.Value());
    auto file = path.Push("payload", allow);
    ASSERT_TRUE(file.HasValue()) << file.Error().message;
    auto readable = path.Leaf().OpenReadOnly();
    ASSERT_TRUE(readable.HasValue()) << readable.Error().message;
    auto data = readable.Value().Read(32);
    ASSERT_TRUE(data.HasValue()) << data.Error().message;
    ASSERT_TRUE(data.Value().HasValue());
    EXPECT_EQ("bound", data.Value().Value());
}

int RunIsolatedBindMountRegression()
{
    if (0 != ::unshare(CLONE_NEWNS))
    {
        return MountSetupFailure("unshare(CLONE_NEWNS)");
    }
    // This must precede all fixture mounts: inherited shared propagation
    // must not send child-namespace mounts back to the parent or host.
    if (0 != ::mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr))
    {
        return MountSetupFailure("make child mount propagation private");
    }

    NiceMock<MockContext> context;
    const std::string base = context.GetTempdirPath();
    const std::string source = base + "/source";
    const std::string accepted = base + "/accepted";
    const std::string other = base + "/other";
    if ((0 != ::mkdir(source.c_str(), 0700)) || (0 != ::mkdir(accepted.c_str(), 0700)) || (0 != ::mkdir(other.c_str(), 0700)) ||
        (0 != ::mkdir((source + "/cross").c_str(), 0700)))
    {
        ADD_FAILURE() << "Cannot create isolated fixture: " << std::strerror(errno);
        return 1;
    }
    {
        std::ofstream inside(source + "/inside");
        std::ofstream payload(other + "/payload");
        inside << "inside";
        payload << "bound";
        inside.close();
        payload.close();
        if (!inside || !payload)
        {
            ADD_FAILURE() << "Cannot write isolated fixture files";
            return 1;
        }
    }
    ScopedBindMount root(accepted);
    if (!root.Bind(source))
    {
        return MountSetupFailure("bind accepted root");
    }
    ScopedBindMount crossing(accepted + "/cross");
    if (!crossing.Bind(other))
    {
        return MountSetupFailure("bind descendant");
    }
    CheckRealBindMounts(context, accepted);
    return 0;
}
} // namespace

TEST_F(PathAliasTest, ProcessRootNativeOpenFailureAndThrowDoNotEscapeOrLeak)
{
    const auto before = CountOpenDescriptors();
    EXPECT_CALL(context, OpenNativePath(testing::StrEq("/"), _)).WillOnce([](const char*, int) {
        errno = EACCES;
        return -1;
    });
    auto denied = SelectAcceptedPath(context, "/", CrossMountPathPolicy(), AmpleLimits());
    ASSERT_FALSE(denied.HasValue());
    EXPECT_EQ(EACCES, denied.Error().code);
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    EXPECT_CALL(context, OpenNativePath(testing::StrEq("/"), _)).WillOnce([](const char*, int) -> int { throw std::runtime_error("native open fault"); });
    EXPECT_THROW((void)SelectAcceptedPath(context, "/", CrossMountPathPolicy(), AmpleLimits()), std::runtime_error);
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, ConfinedChildNativeOpenFailureDoesNotReopenTargetName)
{
    const std::string root = context.GetTempdirPath();
    const std::string source = context.MakeTempfile("held");
    const std::string name = source.substr(source.find_last_of('/') + 1);
    auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    const auto before = CountOpenDescriptors();
    EXPECT_CALL(context, OpenNativePath(_, _)).WillRepeatedly([&](const char* path, int flags) { return context.RealOpenNativePath(path, flags); });
    EXPECT_CALL(context, OpenNativePath(testing::StrEq(source.c_str()), _)).Times(0);
    EXPECT_CALL(context, OpenNativeAt(_, _, _)).WillRepeatedly([&](int directory, const char* path, int flags) {
        return context.RealOpenNativeAt(directory, path, flags);
    });
    EXPECT_CALL(context, OpenNativeAt(_, testing::StrEq(name.c_str()), _)).WillOnce([](int, const char*, int flags) {
        EXPECT_NE(0, flags & O_PATH);
        errno = ENOENT;
        return -1;
    });
    auto pushed = path.Push(name, ChildPolicy(SymlinkPolicy::DoNotFollow, MountPolicy::AllowCrossing));
    ASSERT_FALSE(pushed.HasValue());
    EXPECT_EQ(ENOENT, pushed.Error().code);
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, ProcfsHelpersCloseCheckedOnceAndFirstFailureWins)
{
    const auto before = CountOpenDescriptors();
    std::size_t failed = 0;
    EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int descriptor) {
        const bool helper = IsProcfsHelper(descriptor);
        const int status = ::close(descriptor);
        EXPECT_EQ(0, status);
        if (helper && failed < 2)
        {
            errno = (0 == failed++) ? EACCES : EIO;
            return -1;
        }

        return status;
    });
    auto opened = SelectAcceptedPath(context, "/", CrossMountPathPolicy(), AmpleLimits());
    ASSERT_FALSE(opened.HasValue());
    EXPECT_EQ(EACCES, opened.Error().code);
    EXPECT_EQ(2U, failed);
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, ProcfsDescriptorAccessCloseAttemptsEveryOwnerAndDoesNotRetry)
{
    const auto before = CountOpenDescriptors();
    ComplianceEngine::Filesystem::Detail::ProcfsDescriptorAccess procfs(context);
    ASSERT_TRUE(procfs.Open().HasValue());
    std::size_t attempted = 0;
    EXPECT_CALL(context, CloseFileDescriptor(_)).Times(3).WillRepeatedly([&](int descriptor) {
        EXPECT_EQ(0, ::close(descriptor));
        if (attempted++ < 2)
        {
            errno = (attempted == 1) ? EACCES : EIO;
            return -1;
        }
        return 0;
    });
    auto closed = procfs.Close();
    ASSERT_FALSE(closed.HasValue());
    EXPECT_EQ(EACCES, closed.Error().code);
    EXPECT_EQ(3U, attempted);
    EXPECT_TRUE(procfs.Close().Value());
    EXPECT_FALSE(procfs.FdinfoDirectory().HasValue());
    EXPECT_FALSE(procfs.ProcDirectory().HasValue());
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, TemporaryCloseFailureIsNotRetriedAfterDescriptorReuse)
{
    auto acquired = VerifiedTestDescriptor(context);
    ASSERT_TRUE(acquired.HasValue()) << acquired.Error().message;
    Descriptor helper = std::move(acquired).Value();
    EXPECT_CALL(context, CloseFileDescriptor(_)).Times(1).WillOnce([](int owned) {
        EXPECT_EQ(0, ::close(owned));
        errno = EIO;
        return -1;
    });
    auto first = helper.Close();
    ASSERT_FALSE(first.HasValue());
    EXPECT_EQ(EIO, first.Error().code);
    EXPECT_TRUE(helper.Close().HasValue());
    EXPECT_FALSE(helper.HasValue());
}

TEST_F(PathAliasTest, DescriptorEmptyAfterMoveOrClose)
{
    auto opened = context.OpenAbsolutePin("/proc");
    ASSERT_TRUE(opened.HasValue());
    Descriptor owner(std::move(opened).Value());
    EXPECT_FALSE(opened.Value().HasValue());
    EXPECT_TRUE(owner.Close().HasValue());
    EXPECT_FALSE(owner.HasValue());
    EXPECT_TRUE(owner.Close().HasValue());
}

TEST_F(PathAliasTest, ContextBoundaryRejectsEmptyAndForeignOwnersWithoutNativeCalls)
{
    NiceMock<MockContext> foreign;
    auto foreignOpened = foreign.OpenAbsolutePin("/");
    ASSERT_TRUE(foreignOpened.HasValue());
    Descriptor owned = std::move(foreignOpened).Value();
    Descriptor empty = context.EmptyDescriptor();
    EXPECT_CALL(context, OpenNativeAt(_, _, _)).Times(0);
    EXPECT_CALL(context, StatFileDescriptor(_, _)).Times(0);
    EXPECT_CALL(context, ReadFileDescriptor(_, _, _)).Times(0);
    EXPECT_CALL(context, DuplicateDescriptor(_)).Times(0);
    EXPECT_CALL(context, FdOpenDirectory(_)).Times(0);
    EXPECT_CALL(context, CloseFileDescriptor(_)).Times(0);
    struct stat snapshot = {};
    errno = 0;
    EXPECT_EQ(-1, context.StatFile(empty, &snapshot));
    EXPECT_EQ(EBADF, errno);
    errno = 0;
    EXPECT_EQ(-1, context.ReadFile(empty, nullptr, 0));
    EXPECT_EQ(EBADF, errno);
    EXPECT_EQ(EBADF, context.Duplicate(empty).Error().code);
    EXPECT_EQ(EBADF, context.OpenAt(empty, "file", ComplianceEngine::ContextInterface::OpenProfile::PinChild).Error().code);
    EXPECT_EQ(EBADF, context.OpenDirectoryCursor(std::move(empty)).Error().code);
    EXPECT_EQ(EINVAL, context.Duplicate(owned).Error().code);
    EXPECT_EQ(EINVAL, context.OpenAt(owned, "file", ComplianceEngine::ContextInterface::OpenProfile::PinChild).Error().code);
    errno = 0;
    EXPECT_EQ(-1, context.StatFile(owned, &snapshot));
    EXPECT_EQ(EINVAL, errno);
    errno = 0;
    EXPECT_EQ(-1, context.CloseOwnedDescriptor(owned));
    EXPECT_EQ(EINVAL, errno);
    EXPECT_TRUE(owned.HasValue());
    EXPECT_TRUE(foreign.CloseOwnedDescriptor(owned) == 0);
}

TEST_F(PathAliasTest, DescriptorReplacementAndEmptyMoveCloseOnlyOnce)
{
    const auto before = CountOpenDescriptors();
    auto firstResult = VerifiedTestDescriptor(context);
    ASSERT_TRUE(firstResult.HasValue()) << firstResult.Error().message;
    Descriptor owner = std::move(firstResult).Value();
    int first = -1;
    {
        auto secondResult = VerifiedTestDescriptor(context);
        ASSERT_TRUE(secondResult.HasValue()) << secondResult.Error().message;
        Descriptor secondOwner = std::move(secondResult).Value();
        EXPECT_CALL(context, CloseFileDescriptor(_)).Times(2).WillRepeatedly([&](int owned) {
            if (first < 0)
                first = owned;
            return ::close(owned);
        });
        owner = std::move(secondOwner);
        EXPECT_FALSE(secondOwner.HasValue());
        EXPECT_TRUE(owner.HasValue());
        EXPECT_EQ(&context, &owner.Context());
        EXPECT_EQ(-1, ::fcntl(first, F_GETFD));
        owner = std::move(secondOwner);
        EXPECT_FALSE(owner.HasValue());
        EXPECT_TRUE(owner.Close().Value());
    }
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, DirectoryTransferConsumesOwnerOnce)
{
    const auto before = CountOpenDescriptors();
    auto acquired = context.OpenAbsolutePin(context.GetTempdirPath().c_str());
    ASSERT_TRUE(acquired.HasValue());
    Descriptor owner = std::move(acquired).Value();
    ProcfsDescriptorAccess procfs(context);
    ASSERT_TRUE(procfs.Open().HasValue());
    auto operational = context.OpenAlias(procfs, owner, true);
    ASSERT_TRUE(operational.HasValue());
    auto duplicate = context.Duplicate(operational.Value());
    ASSERT_TRUE(duplicate.HasValue());
    EXPECT_CALL(context, FdOpenDirectory(_)).Times(1);
    {
        auto cursor = context.OpenDirectoryCursor(std::move(duplicate).Value());
        ASSERT_TRUE(cursor.HasValue());
        EXPECT_FALSE(duplicate.Value().HasValue());
        EXPECT_TRUE(cursor.Value().Close().HasValue());
    }
    EXPECT_TRUE(operational.Value().Close().HasValue());
    EXPECT_TRUE(procfs.Close().HasValue());
    EXPECT_TRUE(owner.Close().HasValue());
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, DirectoryTransferFailureLeavesOwnerForExactlyOneClose)
{
    const auto before = CountOpenDescriptors();
    auto opened = context.OpenAbsolutePin(context.GetTempdirPath().c_str());
    ASSERT_TRUE(opened.HasValue());
    Descriptor pin = std::move(opened).Value();
    ProcfsDescriptorAccess procfs(context);
    ASSERT_TRUE(procfs.Open().HasValue());
    auto active = context.OpenAlias(procfs, pin, true);
    ASSERT_TRUE(active.HasValue());
    auto duplicated = context.Duplicate(active.Value());
    ASSERT_TRUE(duplicated.HasValue());
    EXPECT_TRUE(active.Value().Close().HasValue());
    EXPECT_TRUE(procfs.Close().HasValue());
    EXPECT_TRUE(pin.Close().HasValue());
    int observed = -1;
    EXPECT_CALL(context, FdOpenDirectory(_)).Times(1).WillOnce([&](int fd) -> DIR* {
        observed = fd;
        errno = ENOTDIR;
        return nullptr;
    });
    EXPECT_CALL(context, CloseFileDescriptor(_)).Times(1).WillOnce([&](int fd) {
        EXPECT_EQ(observed, fd);
        return ::close(fd);
    });
    Descriptor streamDescriptor = std::move(duplicated).Value();
    auto failed = context.OpenDirectoryCursor(std::move(streamDescriptor));
    ASSERT_FALSE(failed.HasValue());
    EXPECT_EQ(ENOTDIR, failed.Error().code);
    EXPECT_TRUE(streamDescriptor.HasValue());
    EXPECT_TRUE(streamDescriptor.Close().Value());
    EXPECT_FALSE(streamDescriptor.HasValue());
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, TypedOpenAndDuplicateSetCloseOnExecAtomically)
{
    EXPECT_CALL(context, OpenNativePath(_, _)).WillOnce([&](const char* path, int flags) {
        EXPECT_EQ((O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC), flags);
        return context.RealOpenNativePath(path, flags);
    });
    auto opened = context.OpenAbsolutePin("/");
    ASSERT_TRUE(opened.HasValue());
    Descriptor owner = std::move(opened).Value();
    EXPECT_NE(0, context.DescriptorFlags(owner) & FD_CLOEXEC);
    EXPECT_CALL(context, DuplicateDescriptor(_)).WillOnce([&](int fd) {
        const int duplicated = context.RealDuplicateDescriptor(fd);
        EXPECT_NE(-1, duplicated);
        if (duplicated >= 0)
            EXPECT_NE(0, ::fcntl(duplicated, F_GETFD) & FD_CLOEXEC);
        return duplicated;
    });
    auto duplicate = context.Duplicate(owner);
    ASSERT_TRUE(duplicate.HasValue());
    EXPECT_NE(0, context.DescriptorFlags(duplicate.Value()) & FD_CLOEXEC);
}

TEST_F(PathAliasTest, DescriptorMovesOwnershipWithoutDoubleClose)
{
    static_assert(!std::is_copy_constructible<Descriptor>::value, "Native descriptors cannot be copied");
    static_assert(!std::is_constructible<Descriptor, const ComplianceEngine::ContextInterface&, int>::value, "Native adoption requires Take");
    static_assert(std::is_nothrow_move_constructible<Descriptor>::value, "Moving ownership cannot throw");
    static_assert(std::is_nothrow_move_assignable<Descriptor>::value, "Replacing ownership cannot throw");
    NiceMock<MockContext> foreignContext;
    const auto before = CountOpenDescriptors();
    auto firstResult = VerifiedTestDescriptor(context);
    ASSERT_TRUE(firstResult.HasValue()) << firstResult.Error().message;
    Descriptor owner = std::move(firstResult).Value();
    int first = -1;
    auto replacementResult = VerifiedTestDescriptor(context);
    ASSERT_TRUE(replacementResult.HasValue()) << replacementResult.Error().message;
    Descriptor replacementOwner = std::move(replacementResult).Value();
    int replacement = -1;
    auto incomingResult = VerifiedTestDescriptor(foreignContext);
    ASSERT_TRUE(incomingResult.HasValue()) << incomingResult.Error().message;
    Descriptor source = std::move(incomingResult).Value();
    EXPECT_CALL(context, CloseFileDescriptor(_)).Times(2).WillRepeatedly([&](int descriptor) {
        if (first < 0)
            first = descriptor;
        else
            replacement = descriptor;
        return ::close(descriptor);
    });
    EXPECT_CALL(foreignContext, CloseFileDescriptor(_)).Times(1).WillOnce([](int descriptor) { return ::close(descriptor); });
    {
        owner = std::move(replacementOwner);
        EXPECT_FALSE(replacementOwner.HasValue());
        EXPECT_TRUE(owner.HasValue());
        EXPECT_EQ(-1, ::fcntl(first, F_GETFD));
        owner = std::move(source);
        EXPECT_FALSE(source.HasValue());
        EXPECT_TRUE(owner.HasValue());
        EXPECT_EQ(&foreignContext, &owner.Context());
        EXPECT_EQ(-1, ::fcntl(replacement, F_GETFD));
        Descriptor transferred(std::move(owner));
        EXPECT_FALSE(owner.HasValue());
        EXPECT_TRUE(transferred.HasValue());
        EXPECT_EQ(&foreignContext, &transferred.Context());
        Descriptor& sameOwner = transferred;
        transferred = std::move(sameOwner);
        EXPECT_TRUE(transferred.HasValue());
    }
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, PrimaryFdinfoReadErrorOutranksHelperCloseFailure)
{
    const auto before = CountOpenDescriptors();
    bool failedRead = false, failedClose = false;
    EXPECT_CALL(context, ReadFileDescriptor(_, _, _)).WillRepeatedly([&](int descriptor, void* buffer, std::size_t size) -> ssize_t {
        if (!failedRead && (0 == DescriptorTarget(descriptor).find("/proc/")) && (std::string::npos != DescriptorTarget(descriptor).find("/fdinfo/")))
        {
            failedRead = true;
            errno = ENOSPC;
            return -1;
        }
        return ::read(descriptor, buffer, size);
    });
    EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int descriptor) {
        const bool helper = IsProcfsHelper(descriptor);
        const int status = ::close(descriptor);
        EXPECT_EQ(0, status);
        if (helper && failedRead && !failedClose)
        {
            failedClose = true;
            errno = EIO;
            return -1;
        }
        return status;
    });
    auto opened = SelectAcceptedPath(context, "/", CrossMountPathPolicy(), AmpleLimits());
    ASSERT_FALSE(opened.HasValue());
    EXPECT_EQ(ENOSPC, opened.Error().code);
    EXPECT_TRUE(failedRead);
    EXPECT_TRUE(failedClose);
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, InspectionAndChildAcquisitionReportHelperCloseFailure)
{
    const std::string source = context.MakeTempfile("held");
    const std::string name = source.substr(source.find_last_of('/') + 1);
    auto opened = SelectAcceptedPath(context, context.GetTempdirPath(), CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    const auto before = CountOpenDescriptors();
    bool childOpened = false;
    EXPECT_CALL(context, OpenNativeAt(_, _, _)).WillRepeatedly([&](int directory, const char* component, int flags) {
        const int descriptor = context.RealOpenNativeAt(directory, component, flags);
        if ((0 <= descriptor) && (name == component) && (0 != (flags & O_PATH)))
        {
            childOpened = true;
        }
        return descriptor;
    });
    bool failed = false;
    EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int descriptor) {
        const bool procfs = IsProcfsHelper(descriptor);
        const int status = ::close(descriptor);
        EXPECT_EQ(0, status);
        if (procfs && !failed && childOpened)
        {
            failed = true;
            errno = EACCES;
            return -1;
        }
        return status;
    });
    auto acquired = path.Push(name, ChildPolicy(SymlinkPolicy::DoNotFollow, MountPolicy::AllowCrossing));
    ASSERT_FALSE(acquired.HasValue());
    EXPECT_EQ(EACCES, acquired.Error().code);
    EXPECT_TRUE(childOpened);
    EXPECT_TRUE(failed);
    EXPECT_EQ(before, CountOpenDescriptors());
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    failed = false;
    EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int descriptor) {
        const bool procfs = IsProcfsHelper(descriptor);
        const int status = ::close(descriptor);
        EXPECT_EQ(0, status);
        if (procfs && !failed)
        {
            failed = true;
            errno = EIO;
            return -1;
        }
        return status;
    });
    auto inspection = path.Root().Stat();
    ASSERT_FALSE(inspection.HasValue());
    EXPECT_EQ(EIO, inspection.Error().code);
    EXPECT_EQ(before, CountOpenDescriptors());
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
}

TEST_F(PathAliasTest, PrimaryChildStatErrorOutranksItsTemporaryCloseFailure)
{
    const std::string source = context.MakeTempfile("held");
    const std::string name = source.substr(source.find_last_of('/') + 1);
    auto opened = SelectAcceptedPath(context, context.GetTempdirPath(), CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    const auto before = CountOpenDescriptors();
    int observedChild = -1;
    EXPECT_CALL(context, OpenNativeAt(_, _, _)).WillRepeatedly([&](int directory, const char* component, int flags) {
        const int descriptor = context.RealOpenNativeAt(directory, component, flags);
        if ((0 <= descriptor) && (name == component) && (0 != (flags & O_PATH)))
        {
            observedChild = descriptor;
        }
        return descriptor;
    });
    EXPECT_CALL(context, StatFileDescriptor(_, _)).WillRepeatedly([&](int descriptor, struct stat* metadata) {
        if (descriptor == observedChild)
        {
            errno = EACCES;
            return -1;
        }
        return context.RealStatFileDescriptor(descriptor, metadata);
    });
    bool closeFailed = false;
    EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int descriptor) {
        const bool isChild = (descriptor == observedChild);
        const int status = ::close(descriptor);
        EXPECT_EQ(0, status);
        if (isChild)
        {
            closeFailed = true;
            errno = EIO;
            return -1;
        }
        return status;
    });
    auto acquired = path.Push(name, ChildPolicy(SymlinkPolicy::DoNotFollow, MountPolicy::AllowCrossing));
    ASSERT_FALSE(acquired.HasValue());
    EXPECT_EQ(EACCES, acquired.Error().code);
    EXPECT_TRUE(closeFailed);
    EXPECT_EQ(before, CountOpenDescriptors());
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
}

TEST_F(PathAliasTest, DirectoryActivationTransfersVerifiedOwnerWithoutDuplicate)
{
    auto opened = SelectAcceptedPath(context, context.GetTempdirPath(), CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    const auto before = CountOpenDescriptors();
    const auto pins = path.RetainedDescriptors();
    int alias = -1;
    EXPECT_CALL(context, OpenNativeAt(_, _, _)).WillRepeatedly([&](int directory, const char* name, int flags) {
        const int descriptor = context.RealOpenNativeAt(directory, name, flags);
        if ((0 <= descriptor) && (0 == (flags & O_PATH)) && (0 == (flags & O_NOFOLLOW)) && (0 != (flags & O_DIRECTORY)))
        {
            alias = descriptor;
        }
        return descriptor;
    });
    bool closedStream = false;
    EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int descriptor) {
        EXPECT_NE(descriptor, alias);
        const int status = ::close(descriptor);
        EXPECT_EQ(0, status);
        return status;
    });
    EXPECT_CALL(context, CloseDirectory(_)).WillOnce([&](DIR* stream) {
        closedStream = true;
        return ::closedir(stream);
    });
    auto cursor = path.Leaf().OpenChildren();
    ASSERT_TRUE(cursor.HasValue()) << cursor.Error().message;
    ASSERT_TRUE(path.Close().HasValue());
    EXPECT_TRUE(cursor.Value().Next().HasValue());
    EXPECT_TRUE(cursor.Value().Close().HasValue());
    EXPECT_TRUE(closedStream);
    EXPECT_EQ(before - pins, CountOpenDescriptors());
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
}

TEST_F(PathAliasTest, FailedDirectoryTransferPreservesNativeErrorAndClosesOwnerOnce)
{
    auto opened = SelectAcceptedPath(context, context.GetTempdirPath(), CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    int operational = -1;
    int cleanupAttempts = 0;
    EXPECT_CALL(context, FdOpenDirectory(_)).Times(1).WillOnce([&](int descriptor) -> DIR* {
        operational = descriptor;
        errno = EACCES;
        return nullptr;
    });
    EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int descriptor) {
        EXPECT_EQ(0, ::close(descriptor));
        if (descriptor == operational)
        {
            ++cleanupAttempts;
            errno = EIO;
            return -1;
        }
        return 0;
    });
    auto cursor = path.Leaf().OpenChildren();
    ASSERT_FALSE(cursor.HasValue());
    EXPECT_EQ(EACCES, cursor.Error().code);
    EXPECT_EQ(1, cleanupAttempts);
    EXPECT_TRUE(path.Close().HasValue());
    EXPECT_EQ(1, cleanupAttempts);
}

TEST_F(PathAliasTest, DirectoryCursorFailedCloseIsNotReplayedOrRetried)
{
    auto opened = SelectAcceptedPath(context, context.GetTempdirPath(), CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    const auto before = CountOpenDescriptors();
    auto cursor = path.Leaf().OpenChildren();
    ASSERT_TRUE(cursor.HasValue());
    EXPECT_CALL(context, CloseDirectory(_)).Times(1).WillOnce([](DIR* stream) {
        EXPECT_EQ(0, ::closedir(stream));
        errno = EIO;
        return -1;
    });
    auto closed = cursor.Value().Close();
    ASSERT_FALSE(closed.HasValue());
    EXPECT_EQ(EIO, closed.Error().code);
    auto repeated = cursor.Value().Close();
    ASSERT_TRUE(repeated.HasValue());
    auto moved = std::move(cursor).Value();
    EXPECT_TRUE(moved.Close().HasValue());
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, DirectoryCursorExplicitExceptionAndNoexceptReplacementReleaseOnce)
{
    auto opened = SelectAcceptedPath(context, context.GetTempdirPath(), CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    auto first = path.Leaf().OpenChildren();
    auto second = path.Leaf().OpenChildren();
    ASSERT_TRUE(first.HasValue());
    ASSERT_TRUE(second.HasValue());
    const auto before = CountOpenDescriptors();
    EXPECT_CALL(context, CloseDirectory(_))
        .Times(2)
        .WillOnce([](DIR* stream) -> int {
            EXPECT_EQ(0, ::closedir(stream));
            throw std::runtime_error("cursor post-close fault");
        })
        .WillOnce([](DIR* stream) { return ::closedir(stream); });
    first.Value() = std::move(second.Value()); // displaced owner closes inside its guarded destructor
    EXPECT_TRUE(second.Value().Close().HasValue());
    try
    {
        // The transferred stream now owns the second, still live directory.
        // Inject a separate explicit-close exception below if its close fails.
        EXPECT_TRUE(first.Value().Close().HasValue());
    }
    catch (...)
    {
        FAIL() << "The second native close should succeed";
    }
    EXPECT_EQ(before - 2, CountOpenDescriptors());
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    auto third = path.Leaf().OpenChildren();
    ASSERT_TRUE(third.HasValue());
    EXPECT_CALL(context, CloseDirectory(_)).Times(1).WillOnce([](DIR* stream) -> int {
        EXPECT_EQ(0, ::closedir(stream));
        throw std::runtime_error("explicit cursor fault");
    });
    try
    {
        (void)third.Value().Close();
        FAIL() << "Explicit cursor close must propagate";
    }
    catch (const std::runtime_error& error)
    {
        EXPECT_STREQ("explicit cursor fault", error.what());
    }
    EXPECT_TRUE(third.Value().Close().HasValue());
    EXPECT_TRUE(path.Close().HasValue());
}

TEST_F(PathAliasTest, DirectoryCursorExplicitLogExceptionPropagatesWithoutRetry)
{
    struct FaultyLogContext : NiceMock<MockContext>
    {
        OsConfigLogHandle GetLogHandle() const override
        {
            if (throwOnLog)
                throw std::runtime_error("cursor log fault");
            return MockContext::GetLogHandle();
        }
        bool throwOnLog = false;
    } selected;
    auto opened = SelectAcceptedPath(selected, selected.GetTempdirPath(), CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    auto cursor = path.Leaf().OpenChildren();
    ASSERT_TRUE(cursor.HasValue());
    EXPECT_CALL(selected, CloseDirectory(_)).Times(1).WillOnce([](DIR* stream) {
        EXPECT_EQ(0, ::closedir(stream));
        errno = EACCES;
        return -1;
    });
    selected.throwOnLog = true;
    try
    {
        (void)cursor.Value().Close();
        FAIL() << "The log-accessor exception must propagate";
    }
    catch (const std::runtime_error& error)
    {
        EXPECT_STREQ("cursor log fault", error.what());
    }
    selected.throwOnLog = false;
    EXPECT_TRUE(cursor.Value().Close().HasValue());
    EXPECT_TRUE(path.Close().HasValue());
}

TEST_F(PathAliasTest, HeldTargetsReadMountOnlyAtAcquisition)
{
    const std::string file = context.MakeTempfile("held");
    const std::string name = file.substr(file.find_last_of('/') + 1);
    int records = 0;
    EXPECT_CALL(context, ReadFileDescriptor(_, _, _)).WillRepeatedly([&](int fd, void* buffer, std::size_t count) {
        const ssize_t bytes = context.RealReadFileDescriptor(fd, buffer, count);
        if (bytes > 0 && DescriptorTarget(fd).find("/fdinfo/") != std::string::npos &&
            std::string(static_cast<char*>(buffer), static_cast<std::size_t>(bytes)).find("mnt_id:") != std::string::npos)
            ++records;
        return bytes;
    });
    auto opened = SelectAcceptedPath(context, file, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    const int afterAcquisition = records;
    EXPECT_GE(afterAcquisition, 2); // Process root and independently acquired components.
    EXPECT_TRUE(path.Leaf().MountIdentity().HasValue());
    EXPECT_TRUE(path.Leaf().Stat().HasValue());
    auto active = path.Leaf().OpenReadOnly();
    ASSERT_TRUE(active.HasValue()) << active.Error().message;
    EXPECT_TRUE(active.Value().Close().HasValue());
    EXPECT_TRUE(path.Leaf().SetMode(0600).HasValue());
    EXPECT_TRUE(path.Leaf().SetOwnership(::geteuid(), ::getegid()).HasValue());
    EXPECT_EQ(afterAcquisition, records);
    auto popped = path.Pop();
    ASSERT_TRUE(popped.HasValue());
    Path::Component moved = std::move(popped).Value();
    EXPECT_TRUE(moved.MountIdentity().HasValue());
    EXPECT_TRUE(moved.OpenReadOnly().HasValue());
    EXPECT_EQ(afterAcquisition, records);
    EXPECT_TRUE(moved.Close().HasValue());
    EXPECT_FALSE(moved.HasValue());
    auto root = SelectAcceptedPath(context, context.GetTempdirPath(), CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(root.HasValue());
    const int beforeChild = records;
    ASSERT_TRUE(root.Value().Push(name, ChildPolicy(SymlinkPolicy::DoNotFollow, MountPolicy::AllowCrossing)).HasValue());
    EXPECT_EQ(beforeChild + 1, records); // Distinct newly acquired target.
    EXPECT_TRUE(root.Value().Leaf().OpenReadOnly().HasValue());
    EXPECT_EQ(beforeChild + 1, records);
}

TEST_F(PathAliasTest, ProcessRootAndChildEachHaveOneMountObservation)
{
    int observations = 0;
    EXPECT_CALL(context, ReadFileDescriptor(_, _, _)).WillRepeatedly([&](int fd, void* buffer, std::size_t count) {
        const ssize_t bytes = context.RealReadFileDescriptor(fd, buffer, count);
        if (bytes > 0 && DescriptorTarget(fd).find("/fdinfo/") != std::string::npos &&
            std::string(static_cast<char*>(buffer), static_cast<std::size_t>(bytes)).find("mnt_id:") != std::string::npos)
            ++observations;
        return bytes;
    });
    auto opened = SelectAcceptedPath(context, "/", CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    EXPECT_EQ(1, observations);
    EXPECT_TRUE(path.Root().MountIdentity().HasValue());
    EXPECT_TRUE(path.Root().OpenChildren().HasValue());
    EXPECT_EQ(1, observations);
    auto child = path.Push("proc", ChildPolicy(SymlinkPolicy::DoNotFollow, MountPolicy::AllowCrossing));
    ASSERT_TRUE(child.HasValue()) << child.Error().message;
    EXPECT_EQ(2, observations);
    EXPECT_TRUE(path.Leaf().MountIdentity().HasValue());
    EXPECT_EQ(2, observations);
    EXPECT_TRUE(path.Pop().HasValue());
    EXPECT_TRUE(path.Root().OpenChildren().HasValue());
    EXPECT_EQ(2, observations);
}

TEST_F(PathAliasTest, WrongObjectProcfdAliasesAreRejectedBeforeMutation)
{
    const std::string file = context.MakeTempfile("held");
    const std::string other = context.MakeTempfile("different");
    auto opened = SelectAcceptedPath(context, file, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    int substituted = 0;
    EXPECT_CALL(context, OpenNativeAt(_, _, _)).WillRepeatedly([&](int directory, const char* name, int flags) {
        const std::string parent = DescriptorTarget(directory);
        if (parent.find("/fd") != std::string::npos && parent.find("/fdinfo") == std::string::npos &&
            std::string(name).find_first_not_of("0123456789") == std::string::npos)
        {
            ++substituted;
            return context.RealOpenNativePath(other.c_str(), flags);
        }
        return context.RealOpenNativeAt(directory, name, flags);
    });
    auto read = path.Leaf().OpenReadOnly();
    ASSERT_FALSE(read.HasValue());
    EXPECT_EQ(EAGAIN, read.Error().code);
    EXPECT_CALL(context, ChmodPinnedAlias(_, _, _)).Times(0);
    auto changed = path.Leaf().SetMode(0400);
    ASSERT_FALSE(changed.HasValue());
    EXPECT_EQ(EAGAIN, changed.Error().code);
    EXPECT_EQ(2, substituted);
    struct stat after = {};
    ASSERT_EQ(0, ::stat(file.c_str(), &after));
    EXPECT_NE(0400, after.st_mode & 0777);
}

TEST_F(PathAliasTest, InspectionBudgetIsValidatedBeforeAcquisitionAndSurvivesPopMove)
{
    ResolverLimits limits = AmpleLimits();
    limits.shared.fdinfoBytes = 0;
    EXPECT_CALL(context, OpenNativePath(_, _)).Times(0);
    auto invalid = Path::Make(context, "/", CrossMountPathPolicy(), limits);
    ASSERT_FALSE(invalid.HasValue());
    EXPECT_EQ(EINVAL, invalid.Error().code);
    limits.shared.fdinfoBytes = std::numeric_limits<std::size_t>::max();
    auto oversized = Path::Make(context, "/", CrossMountPathPolicy(), limits);
    ASSERT_FALSE(oversized.HasValue());
    EXPECT_EQ(EINVAL, oversized.Error().code);
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));

    limits.shared.fdinfoBytes = 1;
    auto exhausted = Path::Make(context, "/", CrossMountPathPolicy(), limits);
    ASSERT_FALSE(exhausted.HasValue());
    EXPECT_EQ(E2BIG, exhausted.Error().code);

    limits.shared.fdinfoBytes = 4096;
    auto opened = SelectAcceptedPath(context, "/", CrossMountPathPolicy(), limits);
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    auto popped = opened.Value().Pop();
    ASSERT_TRUE(popped.HasValue());
    Path::Component held = std::move(popped).Value();
    Path::Component moved = std::move(held);
    EXPECT_FALSE(held.HasValue());
    EXPECT_TRUE(moved.Stat().HasValue());
    EXPECT_TRUE(moved.MountIdentity().HasValue());
    EXPECT_TRUE(moved.Close().HasValue());
    EXPECT_FALSE(moved.HasValue());
}

TEST_F(PathAliasTest, FrozenAbsoluteBindingDoesNotOpenProcessRootAgain)
{
    const std::string root = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    const std::string file = context.MakeTempfile("held");
    ASSERT_EQ(0, ::rename(file.c_str(), (root + "/inside").c_str()));
    ASSERT_EQ(0, ::symlink((root + "/inside").c_str(), (root + "/absolute").c_str()));
    auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    const auto before = CountOpenDescriptors();
    EXPECT_CALL(context, OpenNativePath(_, _)).WillRepeatedly([&](const char* name, int flags) { return context.RealOpenNativePath(name, flags); });
    EXPECT_CALL(context, OpenNativePath(testing::StrEq("/"), _)).Times(0);
    auto pushed = path.Push("absolute", ChildPolicy(SymlinkPolicy::Follow, MountPolicy::AllowCrossing));
    ASSERT_TRUE(pushed.HasValue()) << pushed.Error().message;
    EXPECT_EQ(root + "/inside", path.ToString());
    EXPECT_EQ(2U, path.Size());
    ASSERT_TRUE(path.Pop().HasValue());
    EXPECT_EQ(before, CountOpenDescriptors());
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
}

TEST(PathTest, RejectsNonChildComponentsBeforeAnyAcquisition)
{
    EXPECT_FALSE(IsSingleChildComponent(""));
    EXPECT_FALSE(IsSingleChildComponent("."));
    EXPECT_FALSE(IsSingleChildComponent(".."));
    EXPECT_FALSE(IsSingleChildComponent("/"));
    EXPECT_FALSE(IsSingleChildComponent("a/b"));
    EXPECT_FALSE(IsSingleChildComponent("../other"));
    EXPECT_FALSE(IsSingleChildComponent(std::string("a\0b", 3)));
    EXPECT_FALSE(IsSingleChildComponent(std::string("\0", 1)));

    EXPECT_TRUE(IsSingleChildComponent("a"));
    EXPECT_TRUE(IsSingleChildComponent("..hidden"));
    EXPECT_TRUE(IsSingleChildComponent("a\\b"));
    EXPECT_TRUE(IsSingleChildComponent(std::string(255, 'x')));
}

TEST(PathTest, DoesNotOfferUncheckedDescriptorConstructionOrCopy)
{
    static_assert(!HasPublicNativeAdoption<Descriptor>::value, "Native adoption is private to acquisition owners");
    static_assert(!std::is_default_constructible<Handle>::value, "A handle requires a checked acquisition");
    static_assert(!std::is_constructible<Handle, int>::value, "A raw fd cannot construct a handle");
    static_assert(!std::is_copy_constructible<Handle>::value, "A pinned descriptor cannot be copied");
    static_assert(!std::is_copy_assignable<Handle>::value, "A pinned descriptor cannot be copied");
    static_assert(std::is_move_constructible<Handle>::value, "A pinned descriptor can transfer ownership");
    static_assert(std::is_move_assignable<Handle>::value, "A pinned descriptor can transfer ownership");
    static_assert(!std::is_default_constructible<Path>::value, "No unapproved root constructor is exposed");
}

TEST(PathTest, ProcfsMountIdRejectsMissingAmbiguousAndMalformedInformation)
{
    const auto valid = ParseMountId("pos:\t0\nflags:\t010000000\nmnt_id:\t123\nino:\t5\n");
    ASSERT_TRUE(valid.HasValue());
    EXPECT_EQ(123U, valid.Value());
    const std::string invalid[] = {"", "pos:\t0\n", "mnt_id:0\n", "mnt_id: \n", "mnt_id:12x\n", "mnt_id:-1\n", "mnt_id:18446744073709551616\n",
        "mnt_id:1\nmnt_id:2\n", "mnt_id:12", std::string("mnt_id:1\n\0", 10)};
    for (const auto& information : invalid)
    {
        const auto result = ParseMountId(information);
        ASSERT_FALSE(result.HasValue()) << information;
        EXPECT_EQ(EPROTO, result.Error().code);
    }
}

TEST(PathKernelIntegrationTest, NativeProcfsAndPinnedOperations)
{
    struct utsname kernel = {};
    ASSERT_EQ(0, ::uname(&kernel));
    struct statfs procfs = {};
    ASSERT_EQ(0, ::statfs("/proc/self/fdinfo", &procfs));
    ASSERT_EQ(PROC_SUPER_MAGIC, procfs.f_type);
    std::printf("M-71 kernel=%s release=%s procfs=0x%lx\n", kernel.sysname, kernel.release, static_cast<unsigned long>(procfs.f_type));

    NiceMock<MockContext> context;
    const std::string source = context.MakeTempfile("kernel-procfs");
    const std::string name = source.substr(source.find_last_of('/') + 1);
    ResolverLimits limits;
    limits.shared.targetBytes = 4096;
    limits.shared.components = 100;
    limits.shared.work = 100000;
    limits.shared.liveDescriptors = 256;
    limits.shared.retainedBytes = 262144;
    limits.shared.fdinfoBytes = 4096;
    limits.linkTargetBytes = 4096;
    limits.linkExpansions = 8;
    limits.depth = 128;
    auto opened = SelectAcceptedPath(context, context.GetTempdirPath(), CrossMountPathPolicy(), limits);
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    auto rootId = path.Root().MountIdentity();
    ASSERT_TRUE(rootId.HasValue()) << rootId.Error().message;
    auto children = path.Root().OpenChildren();
    ASSERT_TRUE(children.HasValue()) << children.Error().message;
    bool found = false;
    for (;;)
    {
        auto entry = children.Value().Next();
        ASSERT_TRUE(entry.HasValue()) << entry.Error().message;
        if (!entry.Value().HasValue())
        {
            break;
        }
        found = found || (name == entry.Value().Value());
    }
    EXPECT_TRUE(found);
    ExtensionPolicy stay = ChildPolicy(SymlinkPolicy::DoNotFollow, MountPolicy::StayOnRootMount);
    auto pushed = path.Push(name, stay);
    ASSERT_TRUE(pushed.HasValue()) << pushed.Error().message;
    auto leafId = path.Leaf().MountIdentity();
    ASSERT_TRUE(leafId.HasValue()) << leafId.Error().message;
    EXPECT_EQ(rootId.Value(), leafId.Value());
    auto metadata = path.Leaf().Stat();
    ASSERT_TRUE(metadata.HasValue()) << metadata.Error().message;
    EXPECT_TRUE(S_ISREG(metadata.Value().st_mode));
    auto readable = path.Leaf().OpenReadOnly();
    ASSERT_TRUE(readable.HasValue()) << readable.Error().message;
    auto read = readable.Value().Read(32);
    ASSERT_TRUE(read.HasValue()) << read.Error().message;
    ASSERT_TRUE(read.Value().HasValue());
    EXPECT_EQ("kernel-procfs", read.Value().Value());
    auto mode = path.Leaf().SetMode(0600);
    ASSERT_TRUE(mode.HasValue()) << mode.Error().message;
    auto owner = path.Leaf().SetOwnership(::geteuid(), ::getegid());
    ASSERT_TRUE(owner.HasValue()) << owner.Error().message;
    struct stat changed = {};
    ASSERT_EQ(0, ::stat(source.c_str(), &changed));
    EXPECT_EQ(0600, changed.st_mode & 0777);
    EXPECT_EQ(::geteuid(), changed.st_uid);
    EXPECT_EQ(::getegid(), changed.st_gid);
}

TEST(PathKernelIntegrationTest, SameDeviceBindMountBoundaryInPrivateChildNamespace)
{
    // Neither unshare nor mount runs in the CTest/GTest process. A failure to
    // isolate or privatize propagation stops before creating any bind mount.
    std::fflush(nullptr);
    const pid_t child = ::fork();
    ASSERT_GE(child, 0) << std::strerror(errno);
    if (0 == child)
    {
        const int outcome = RunIsolatedBindMountRegression();
        const int status = testing::Test::HasFailure() ? 1 : outcome;
        std::fflush(nullptr);
        ::_exit(status);
    }
    int status = 0;
    ASSERT_EQ(child, ::waitpid(child, &status, 0)) << std::strerror(errno);
    ASSERT_TRUE(WIFEXITED(status)) << "Mount fixture child was interrupted: " << status;
    const char* requirement = std::getenv("KOMPLI_REQUIRE_M71_MOUNT");
    const bool required = (nullptr != requirement) && (0 == std::strcmp("1", requirement));
    if ((unavailableMountCapability == WEXITSTATUS(status)) && !required)
    {
        GTEST_SKIP() << "Private mount namespace/bind mount unavailable locally; CI/VM gate requires KOMPLI_REQUIRE_M71_MOUNT=1";
    }
    EXPECT_EQ(0, WEXITSTATUS(status)) << "Child mount regression failed (77 = required kernel capability unavailable)";
}

TEST_F(PathAliasTest, MoveTransfersOwnershipAndFailedCloseIsNotRetried)
{
    const std::string source = context.MakeTempfile("contents");
    const std::string component = source.substr(source.find_last_of('/') + 1);
    const std::size_t before = CountOpenDescriptors();
    {
        auto acquired = [&]() -> ComplianceEngine::Result<Path::Component> {
            auto opened = SelectAcceptedPath(context, context.GetTempdirPath(), CrossMountPathPolicy(), AmpleLimits());
            if (!opened.HasValue())
            {
                return std::move(opened).Error();
            }
            Path path = std::move(opened).Value();
            auto pushed = path.Push(component, ChildPolicy(SymlinkPolicy::DoNotFollow, MountPolicy::AllowCrossing));
            if (!pushed.HasValue())
            {
                return std::move(pushed).Error();
            }
            return path.Pop();
        }();
        ASSERT_TRUE(acquired.HasValue());
        EXPECT_CALL(context, CloseFileDescriptor(_)).Times(1).WillOnce([](int descriptor) {
            const int status = ::close(descriptor);
            EXPECT_EQ(0, status);
            errno = EIO;
            return -1;
        });
        Path::Component first = std::move(acquired).Value();
        Path::Component second = std::move(first);
        EXPECT_EQ(Handle::Type::RegularFile, second.AcquiredType());
    }
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, FrozenAbsoluteBindingKeepsOriginalRootAfterReplacement)
{
    const std::string rootPath = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(rootPath.c_str(), 0700));
    ASSERT_EQ(0, ::symlink((rootPath + "/inside").c_str(), (rootPath + "/absolute").c_str()));
    const std::string file = context.MakeTempfile("contents");
    ASSERT_EQ(0, ::rename(file.c_str(), (rootPath + "/inside").c_str()));
    const std::size_t before = CountOpenDescriptors();
    {
        auto opened = SelectAcceptedPath(context, rootPath, CrossMountPathPolicy(), AmpleLimits());
        ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
        Path path = std::move(opened).Value();
        ExtensionPolicy follow = ChildPolicy(SymlinkPolicy::Follow, MountPolicy::AllowCrossing);
        auto accepted = path.Push("absolute", follow);
        ASSERT_TRUE(accepted.HasValue()) << accepted.Error().message;
        ASSERT_TRUE(path.Pop().HasValue());
        ASSERT_EQ(0, ::unlink((rootPath + "/absolute").c_str()));
        ASSERT_EQ(0, ::symlink("/etc/passwd", (rootPath + "/absolute").c_str()));
        auto outside = path.Push("absolute", follow);
        ASSERT_FALSE(outside.HasValue());
        EXPECT_EQ(EXDEV, outside.Error().code);
        ASSERT_EQ(0, ::unlink((rootPath + "/absolute").c_str()));
        ASSERT_EQ(0, ::symlink((rootPath + "/inside").c_str(), (rootPath + "/absolute").c_str()));
        ASSERT_EQ(0, ::rename(rootPath.c_str(), (rootPath + ".former").c_str()));
        ASSERT_EQ(0, ::mkdir(rootPath.c_str(), 0700));
        const std::string replacement = context.MakeTempfile("other");
        ASSERT_EQ(0, ::rename(replacement.c_str(), (rootPath + "/inside").c_str()));
        ASSERT_EQ(0, ::symlink((rootPath + "/inside").c_str(), (rootPath + "/absolute").c_str()));
        struct stat original = {};
        ASSERT_EQ(0, ::stat((rootPath + ".former/inside").c_str(), &original));
        EXPECT_CALL(context, OpenNativePath(_, _)).WillRepeatedly([&](const char* name, int flags) { return context.RealOpenNativePath(name, flags); });
        EXPECT_CALL(context, OpenNativePath(testing::StrEq("/"), _)).Times(0);
        auto substituted = path.Push("absolute", follow);
        ASSERT_TRUE(substituted.HasValue()) << substituted.Error().message;
        EXPECT_EQ(original.st_ino, path.Leaf().AcquiredMetadata().st_ino);
        EXPECT_EQ(rootPath + "/inside", path.ToString());
    }
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, AcquiredRootAliasesRenderEffectiveNameAndRejectOverlappingAbsoluteBindings)
{
    const std::string root = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    ASSERT_EQ(0, ::symlink(".", (root + "/self").c_str()));
    const std::string file = context.MakeTempfile("original");
    ASSERT_EQ(0, ::rename(file.c_str(), (root + "/file").c_str()));
    ASSERT_EQ(0, ::symlink((root + "/self/file").c_str(), (root + "/ambiguous").c_str()));
    ASSERT_EQ(0, ::mkdir((root + "/other").c_str(), 0700));
    auto opened = SelectAcceptedPath(context, root + "/self", CrossMountPathPolicy(SymlinkPolicy::Follow), AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    EXPECT_EQ(root, path.ToString());
    EXPECT_EQ(path.Root().AcquiredMetadata().st_ino, path.Leaf().AcquiredMetadata().st_ino);
    ASSERT_EQ(0, ::unlink((root + "/self").c_str()));
    ASSERT_EQ(0, ::symlink("other", (root + "/self").c_str()));
    auto conflict = path.Push("ambiguous", ChildPolicy(SymlinkPolicy::Follow, MountPolicy::AllowCrossing));
    ASSERT_FALSE(conflict.HasValue());
    EXPECT_EQ(EXDEV, conflict.Error().code);
    EXPECT_EQ(root, path.ToString());
    EXPECT_EQ(1U, path.Size());
}

TEST_F(PathAliasTest, DisjointRootAliasesUseTheSamePinAndRejectPrefixCollisions)
{
    const std::string root = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/data").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/entry2").c_str(), 0700));
    ASSERT_EQ(0, ::symlink("data", (root + "/entry").c_str()));
    const std::string file = context.MakeTempfile("payload");
    ASSERT_EQ(0, ::rename(file.c_str(), (root + "/data/file").c_str()));
    ASSERT_EQ(0, ::symlink((root + "/entry/file").c_str(), (root + "/data/logical").c_str()));
    ASSERT_EQ(0, ::symlink((root + "/data/file").c_str(), (root + "/data/effective").c_str()));
    ASSERT_EQ(0, ::symlink((root + "/entry2/file").c_str(), (root + "/data/collision").c_str()));
    auto opened = SelectAcceptedPath(context, root + "/entry", CrossMountPathPolicy(SymlinkPolicy::Follow), AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    EXPECT_EQ(root + "/data", path.ToString());
    const auto follow = ChildPolicy(SymlinkPolicy::Follow, MountPolicy::AllowCrossing);
    for (const char* name : {"logical", "effective"})
    {
        auto pushed = path.Push(name, follow);
        ASSERT_TRUE(pushed.HasValue()) << pushed.Error().message;
        EXPECT_EQ(root + "/data/file", path.ToString());
        ASSERT_TRUE(path.Pop().HasValue());
    }
    auto collision = path.Push("collision", follow);
    ASSERT_FALSE(collision.HasValue());
    EXPECT_EQ(EXDEV, collision.Error().code);
}

TEST_F(PathAliasTest, SymlinkParentComponentsFollowPinnedFilesystemOrder)
{
    const std::string root = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/x").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/x/y").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/x/b").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/b").c_str(), 0700));
    ASSERT_EQ(0, ::symlink("x/y", (root + "/a").c_str()));
    ASSERT_EQ(0, ::symlink("a/../b", (root + "/via").c_str()));
    ASSERT_EQ(0, ::symlink("../rogue", (root + "/escape").c_str()));
    const std::string file = context.MakeTempfile("regular");
    ASSERT_EQ(0, ::rename(file.c_str(), (root + "/regular").c_str()));
    ASSERT_EQ(0, ::symlink("regular/../b", (root + "/notdir").c_str()));
    auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    const auto follow = ChildPolicy(SymlinkPolicy::Follow, MountPolicy::AllowCrossing);
    ASSERT_TRUE(path.Push("via", follow).HasValue());
    EXPECT_EQ(root + "/x/b", path.ToString());
    ASSERT_TRUE(path.Pop().HasValue());
    ASSERT_TRUE(path.Pop().HasValue());
    EXPECT_EQ(EXDEV, path.Push("escape", follow).Error().code);
    EXPECT_EQ(ENOTDIR, path.Push("notdir", follow).Error().code);
    EXPECT_EQ(1U, path.Size());
}

TEST_F(PathAliasTest, HeldAliasNameExpiresOnPopAndUnacquiredEntriesRemainMutable)
{
    const std::string root = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/a").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/b").c_str(), 0700));
    const std::string a = context.MakeTempfile("a");
    const std::string b = context.MakeTempfile("b");
    ASSERT_EQ(0, ::rename(a.c_str(), (root + "/a/file").c_str()));
    ASSERT_EQ(0, ::rename(b.c_str(), (root + "/b/file").c_str()));
    ASSERT_EQ(0, ::symlink("a", (root + "/alias").c_str()));
    ASSERT_EQ(0, ::symlink((root + "/alias/file").c_str(), (root + "/a/absolute").c_str()));
    ASSERT_EQ(0, ::symlink((root + "/alias/file").c_str(), (root + "/absolute").c_str()));
    struct stat original = {}, replacement = {};
    ASSERT_EQ(0, ::stat((root + "/a/file").c_str(), &original));
    ASSERT_EQ(0, ::stat((root + "/b/file").c_str(), &replacement));
    auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    const auto follow = ChildPolicy(SymlinkPolicy::Follow, MountPolicy::AllowCrossing);
    ASSERT_TRUE(path.Push("alias", follow).HasValue());
    ASSERT_EQ(0, ::unlink((root + "/alias").c_str()));
    ASSERT_EQ(0, ::symlink("b", (root + "/alias").c_str()));
    ASSERT_TRUE(path.Push("absolute", follow).HasValue());
    EXPECT_EQ(original.st_ino, path.Leaf().AcquiredMetadata().st_ino);
    EXPECT_EQ(root + "/a/file", path.ToString());
    ASSERT_TRUE(path.Pop().HasValue());
    ASSERT_TRUE(path.Pop().HasValue());
    ASSERT_TRUE(path.Push("absolute", follow).HasValue());
    EXPECT_EQ(replacement.st_ino, path.Leaf().AcquiredMetadata().st_ino);
    EXPECT_EQ(root + "/b/file", path.ToString());
}

TEST_F(PathAliasTest, RenamedIntermediatePinnedAncestorIsNotReopenedByAbsoluteTarget)
{
    const std::string root = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/a").c_str(), 0700));
    const std::string oldFile = context.MakeTempfile("old");
    const std::string newFile = context.MakeTempfile("new");
    ASSERT_EQ(0, ::rename(oldFile.c_str(), (root + "/a/file").c_str()));
    ASSERT_EQ(0, ::symlink((root + "/a/file").c_str(), (root + "/a/absolute").c_str()));
    struct stat expected = {}, substitute = {};
    ASSERT_EQ(0, ::stat((root + "/a/file").c_str(), &expected));
    auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    const auto plain = ChildPolicy(SymlinkPolicy::DoNotFollow, MountPolicy::AllowCrossing);
    const auto follow = ChildPolicy(SymlinkPolicy::Follow, MountPolicy::AllowCrossing);
    ASSERT_TRUE(path.Push("a", plain).HasValue());
    ASSERT_EQ(0, ::rename((root + "/a").c_str(), (root + "/former").c_str()));
    ASSERT_EQ(0, ::mkdir((root + "/a").c_str(), 0700));
    ASSERT_EQ(0, ::rename(newFile.c_str(), (root + "/a/file").c_str()));
    ASSERT_EQ(0, ::stat((root + "/a/file").c_str(), &substitute));
    ASSERT_TRUE(path.Push("absolute", follow).HasValue());
    EXPECT_EQ(expected.st_ino, path.Leaf().AcquiredMetadata().st_ino);
    EXPECT_EQ(root + "/a/file", path.ToString());
    ASSERT_TRUE(path.Pop().HasValue());
    ASSERT_TRUE(path.Pop().HasValue());
    ASSERT_TRUE(path.Push("a", plain).HasValue());
    ASSERT_TRUE(path.Push("file", plain).HasValue());
    EXPECT_EQ(substitute.st_ino, path.Leaf().AcquiredMetadata().st_ino);
}

TEST_F(PathAliasTest, ConfinedResolverFollowsRelativeAndRecognizedAbsoluteLinks)
{
    const std::string rootPath = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(rootPath.c_str(), 0700));
    const std::string file = context.MakeTempfile("contents");
    ASSERT_EQ(0, ::rename(file.c_str(), (rootPath + "/inside").c_str()));
    ASSERT_EQ(0, ::symlink("inside", (rootPath + "/relative").c_str()));
    ASSERT_EQ(0, ::symlink((rootPath + "/inside").c_str(), (rootPath + "/absolute").c_str()));
    ASSERT_EQ(0, ::symlink("/etc/passwd", (rootPath + "/outside").c_str()));
    ASSERT_EQ(0, ::symlink("../etc/passwd", (rootPath + "/escape").c_str()));
    ASSERT_EQ(0, ::symlink("loop", (rootPath + "/loop").c_str()));
    ASSERT_EQ(0, ::symlink("inside/", (rootPath + "/trailing").c_str()));
    ASSERT_EQ(0, ::symlink("relative", (rootPath + "/double").c_str()));
    ResolverLimits limits;
    limits.shared.targetBytes = 4096;
    limits.shared.components = 100;
    limits.shared.work = 100000;
    limits.shared.liveDescriptors = 256;
    limits.shared.retainedBytes = 262144;
    limits.shared.fdinfoBytes = 4096;
    limits.linkTargetBytes = 4096;
    limits.linkExpansions = 8;
    limits.depth = 128;
    auto opened = SelectAcceptedPath(context, rootPath, CrossMountPathPolicy(), limits);
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    ExtensionPolicy strict = ChildPolicy(SymlinkPolicy::DoNotFollow, MountPolicy::AllowCrossing);
    ExtensionPolicy follow = ChildPolicy(SymlinkPolicy::Follow, MountPolicy::AllowCrossing);
    ExtensionPolicy stay = ChildPolicy(SymlinkPolicy::Follow, MountPolicy::StayOnRootMount);
    struct stat original = {};
    ASSERT_EQ(0, ::stat((rootPath + "/inside").c_str(), &original));
    const std::size_t before = CountOpenDescriptors();
    {
        auto relative = path.Push("relative", stay);
        ASSERT_TRUE(relative.HasValue()) << relative.Error().message;
        EXPECT_EQ(original.st_ino, path.Leaf().AcquiredMetadata().st_ino);
        ASSERT_TRUE(path.Pop().HasValue());
        auto absolute = path.Push("absolute", follow);
        ASSERT_TRUE(absolute.HasValue()) << absolute.Error().message;
        EXPECT_EQ(original.st_ino, path.Leaf().AcquiredMetadata().st_ino);
        ASSERT_TRUE(path.Pop().HasValue());
        auto outside = path.Push("outside", follow);
        ASSERT_FALSE(outside.HasValue());
        EXPECT_EQ(EXDEV, outside.Error().code);
        auto escaped = path.Push("escape", follow);
        ASSERT_FALSE(escaped.HasValue());
        EXPECT_EQ(EXDEV, escaped.Error().code);
        auto disallowed = path.Push("relative", strict);
        ASSERT_FALSE(disallowed.HasValue());
        EXPECT_EQ(ELOOP, disallowed.Error().code);
        auto loop = path.Push("loop", follow);
        ASSERT_FALSE(loop.HasValue());
        EXPECT_EQ(ELOOP, loop.Error().code);
        ResolverLimits oneLink = AmpleLimits();
        oneLink.linkExpansions = 1;
        auto reopened = SelectAcceptedPath(context, rootPath, CrossMountPathPolicy(), oneLink);
        ASSERT_TRUE(reopened.HasValue());
        Path bounded = std::move(reopened).Value();
        auto beyondLink = bounded.Push("double", follow);
        ASSERT_FALSE(beyondLink.HasValue());
        EXPECT_EQ(ELOOP, beyondLink.Error().code);
        oneLink.linkExpansions = 2;
        auto two = SelectAcceptedPath(context, rootPath, CrossMountPathPolicy(), oneLink);
        ASSERT_TRUE(two.HasValue());
        Path allowed = std::move(two).Value();
        auto exactlyTwo = allowed.Push("double", follow);
        ASSERT_TRUE(exactlyTwo.HasValue()) << exactlyTwo.Error().message;
        EXPECT_EQ(original.st_ino, allowed.Leaf().AcquiredMetadata().st_ino);
        auto trailing = path.Push("trailing", follow);
        ASSERT_FALSE(trailing.HasValue());
        EXPECT_EQ(ENOTDIR, trailing.Error().code);
    }
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, ResolverUsesPinnedLinkWhenNameChangesDuringInspection)
{
    const std::string rootPath = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(rootPath.c_str(), 0700));
    const std::string file = context.MakeTempfile("contents");
    ASSERT_EQ(0, ::rename(file.c_str(), (rootPath + "/inside").c_str()));
    ASSERT_EQ(0, ::symlink("inside", (rootPath + "/link").c_str()));
    auto opened = SelectAcceptedPath(context, rootPath, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    bool replaced = false;
    ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([&](int descriptor, struct stat* snapshot) {
        const int status = context.RealStatFileDescriptor(descriptor, snapshot);
        if ((0 == status) && S_ISLNK(snapshot->st_mode) && !replaced)
        {
            replaced = true;
            EXPECT_EQ(0, ::rename((rootPath + "/link").c_str(), (rootPath + "/former").c_str()));
            EXPECT_EQ(0, ::mkfifo((rootPath + "/link").c_str(), 0600));
        }
        return status;
    });
    const std::size_t before = CountOpenDescriptors();
    auto resolved = path.Push("link", ChildPolicy(SymlinkPolicy::Follow, MountPolicy::StayOnRootMount));
    ASSERT_TRUE(resolved.HasValue()) << resolved.Error().message;
    EXPECT_TRUE(replaced);
    struct stat expected = {};
    ASSERT_EQ(0, ::stat((rootPath + "/inside").c_str(), &expected));
    EXPECT_EQ(expected.st_ino, path.Leaf().AcquiredMetadata().st_ino);
    EXPECT_GT(CountOpenDescriptors(), before);
}

TEST_F(PathAliasTest, RelativeParentIsBoundedByAcceptedRoot)
{
    const std::string rootPath = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(rootPath.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((rootPath + "/sub").c_str(), 0700));
    const std::string file = context.MakeTempfile("contents");
    ASSERT_EQ(0, ::rename(file.c_str(), (rootPath + "/inside").c_str()));
    ASSERT_EQ(0, ::symlink("../inside", (rootPath + "/sub/up").c_str()));
    auto opened = SelectAcceptedPath(context, rootPath, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    ASSERT_TRUE(path.Push("sub", ChildPolicy(SymlinkPolicy::DoNotFollow, MountPolicy::StayOnRootMount)).HasValue());
    auto resolved = path.Push("up", ChildPolicy(SymlinkPolicy::Follow, MountPolicy::StayOnRootMount));
    ASSERT_TRUE(resolved.HasValue()) << resolved.Error().message;
    struct stat expected = {};
    ASSERT_EQ(0, ::stat((rootPath + "/inside").c_str(), &expected));
    EXPECT_EQ(expected.st_ino, path.Leaf().AcquiredMetadata().st_ino);
}

TEST_F(PathAliasTest, LinkExpansionKeepsPhysicalLineageForContinuation)
{
    const std::string rootPath = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(rootPath.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((rootPath + "/first").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((rootPath + "/second").c_str(), 0700));
    const std::string file = context.MakeTempfile("contents");
    ASSERT_EQ(0, ::rename(file.c_str(), (rootPath + "/second/child").c_str()));
    ASSERT_EQ(0, ::symlink("../second", (rootPath + "/first/shortcut").c_str()));
    ASSERT_EQ(0, ::symlink("..", (rootPath + "/second/up").c_str()));
    auto opened = SelectAcceptedPath(context, rootPath, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    ExtensionPolicy strict = ChildPolicy(SymlinkPolicy::DoNotFollow, MountPolicy::StayOnRootMount);
    ExtensionPolicy follow = ChildPolicy(SymlinkPolicy::Follow, MountPolicy::StayOnRootMount);
    ASSERT_TRUE(path.Push("first", strict).HasValue());
    auto shortcut = path.Push("shortcut", follow);
    ASSERT_TRUE(shortcut.HasValue()) << shortcut.Error().message;
    struct stat second = {};
    ASSERT_EQ(0, ::stat((rootPath + "/second").c_str(), &second));
    EXPECT_EQ(second.st_ino, path.Leaf().AcquiredMetadata().st_ino);
    auto child = path.Push("child", follow);
    ASSERT_TRUE(child.HasValue()) << child.Error().message;
    struct stat expected = {};
    ASSERT_EQ(0, ::stat((rootPath + "/second/child").c_str(), &expected));
    EXPECT_EQ(expected.st_ino, path.Leaf().AcquiredMetadata().st_ino);
    ASSERT_TRUE(path.Pop().HasValue());
    auto up = path.Push("up", follow);
    ASSERT_TRUE(up.HasValue()) << up.Error().message;
    EXPECT_EQ(path.Root().AcquiredMetadata().st_ino, path.Leaf().AcquiredMetadata().st_ino);
}

TEST_F(PathAliasTest, ResolverBudgetsFailAtOneBeyondAndLeavePinsAlive)
{
    const std::string rootPath = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(rootPath.c_str(), 0700));
    const std::string file = context.MakeTempfile("contents");
    ASSERT_EQ(0, ::rename(file.c_str(), (rootPath + "/inside").c_str()));
    ASSERT_EQ(0, ::symlink("inside", (rootPath + "/link").c_str()));
    ResolverLimits limits = AmpleLimits();
    limits.linkTargetBytes = 5;
    auto opened = SelectAcceptedPath(context, rootPath, CrossMountPathPolicy(), limits);
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    const std::size_t before = CountOpenDescriptors();
    ExtensionPolicy strict = ChildPolicy(SymlinkPolicy::DoNotFollow, MountPolicy::StayOnRootMount);
    ExtensionPolicy follow = ChildPolicy(SymlinkPolicy::Follow, MountPolicy::StayOnRootMount);
    auto direct = path.Push("inside", strict);
    ASSERT_TRUE(direct.HasValue()) << direct.Error().message;
    ASSERT_TRUE(path.Pop().HasValue());
    auto linkFailed = path.Push("link", follow);
    ASSERT_FALSE(linkFailed.HasValue());
    EXPECT_EQ(E2BIG, linkFailed.Error().code);
    EXPECT_EQ(1U, path.Size());
    EXPECT_EQ(before, CountOpenDescriptors());

    // The public factory and extension share the same caller-supplied work
    // ledger; a failed request does not release its charge or its root pin.
    ASSERT_EQ(0, ::mkdir((rootPath + "/budget-child").c_str(), 0700));
    const std::size_t charge = 128 + 4 * (4096 / 256);
    // Root acquisition charges twice, plus twice per component; the first
    // one-component Push charges three times. The next Push is one beyond.
    const std::size_t rootComponents = static_cast<std::size_t>(std::count(rootPath.begin(), rootPath.end(), '/'));
    ResolverLimits exact = AmpleLimits();
    exact.shared.work = (2 + 2 * rootComponents + 3) * charge;
    auto root = SelectAcceptedPath(context, rootPath, CrossMountPathPolicy(), exact);
    ASSERT_TRUE(root.HasValue());
    Path bounded = std::move(root).Value();
    ASSERT_TRUE(bounded.Push("budget-child", strict).HasValue());
    ASSERT_TRUE(bounded.Pop().HasValue());
    auto noWork = bounded.Push("budget-child", strict);
    ASSERT_FALSE(noWork.HasValue());
    EXPECT_EQ(E2BIG, noWork.Error().code);
}

TEST_F(PathAliasTest, PublicRootAndPushKeepOriginalPinsAndSeparatePolicies)
{
    const std::string rootPath = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(rootPath.c_str(), 0700));
    const std::string file = context.MakeTempfile("contents");
    ASSERT_EQ(0, ::rename(file.c_str(), (rootPath + "/inside").c_str()));
    ASSERT_EQ(0, ::symlink("inside", (rootPath + "/allowed").c_str()));
    ASSERT_EQ(0, ::symlink("/etc/passwd", (rootPath + "/outside").c_str()));
    ResolverLimits limits;
    limits.shared.targetBytes = 4096;
    limits.shared.components = 4096;
    limits.shared.work = 2000000;
    limits.shared.liveDescriptors = 4096;
    limits.shared.retainedBytes = 16U * 1024U * 1024U;
    limits.shared.fdinfoBytes = 4096;
    limits.linkTargetBytes = 4096;
    limits.linkExpansions = 8;
    limits.depth = 4096;
    const Path::Policy rootPolicy = CrossMountPathPolicy();
    ExtensionPolicy strict = ChildPolicy(SymlinkPolicy::DoNotFollow, MountPolicy::StayOnRootMount);
    ExtensionPolicy follow = ChildPolicy(SymlinkPolicy::Follow, MountPolicy::StayOnRootMount);
    const std::size_t before = CountOpenDescriptors();
    {
        auto opened = SelectAcceptedPath(context, rootPath, rootPolicy, limits);
        ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
        Path path = std::move(opened).Value();
        ASSERT_EQ(1U, path.Size());
        const auto rootBorrow = path.Root();
        EXPECT_EQ(rootBorrow.AcquiredMetadata().st_ino, path.Leaf().AcquiredMetadata().st_ino);
        auto denied = path.Push("outside", follow);
        ASSERT_FALSE(denied.HasValue());
        EXPECT_EQ(EXDEV, denied.Error().code);
        EXPECT_EQ(1U, path.Size());
        EXPECT_EQ(rootBorrow.AcquiredMetadata().st_ino, path.Root().AcquiredMetadata().st_ino);
        auto noLinks = path.Push("allowed", strict);
        ASSERT_FALSE(noLinks.HasValue());
        EXPECT_EQ(ELOOP, noLinks.Error().code);
        auto success = path.Push("allowed", follow);
        ASSERT_TRUE(success.HasValue()) << success.Error().message;
        EXPECT_EQ(2U, path.Size());
        EXPECT_EQ(Handle::Type::RegularFile, path.Leaf().AcquiredType());
        EXPECT_EQ(rootBorrow.AcquiredMetadata().st_ino, path.Root().AcquiredMetadata().st_ino);
        auto notDirectory = path.Push("inside", strict);
        ASSERT_FALSE(notDirectory.HasValue());
        EXPECT_EQ(ENOTDIR, notDirectory.Error().code);
    }
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, AbsoluteFactoryNormalizesSeparatorsAndHonorsLinkPolicy)
{
    const std::string file = context.MakeTempfile("contents");
    const std::string link = file + ".link";
    ASSERT_EQ(0, ::symlink(file.c_str(), link.c_str()));
    const Path::Policy strict = CrossMountPathPolicy();
    const Path::Policy follow = CrossMountPathPolicy(SymlinkPolicy::Follow);
    const std::size_t before = CountOpenDescriptors();

    auto invalid = Path::Make(context, file + std::string("\0bad", 4), follow, AmpleLimits());
    ASSERT_FALSE(invalid.HasValue());
    EXPECT_EQ(EINVAL, invalid.Error().code);
    auto relative = Path::Make(context, "relative", follow, AmpleLimits());
    ASSERT_FALSE(relative.HasValue());
    EXPECT_EQ(EINVAL, relative.Error().code);
    auto denied = Path::Make(context, link, strict, AmpleLimits());
    ASSERT_FALSE(denied.HasValue());
    EXPECT_EQ(ELOOP, denied.Error().code);
    auto trailing = Path::Make(context, file + "/", follow, AmpleLimits());
    ASSERT_FALSE(trailing.HasValue());
    EXPECT_EQ(ENOTDIR, trailing.Error().code);
    auto parent = Path::Make(context, context.GetTempdirPath() + "/../", follow, AmpleLimits());
    ASSERT_FALSE(parent.HasValue());
    EXPECT_EQ(EINVAL, parent.Error().code);

    std::string repeated = "/";
    for (const char character : link)
    {
        repeated += character;
        if (character == '/')
        {
            repeated += '/';
        }
    }
    auto opened = Path::Make(context, repeated, follow, AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    ASSERT_TRUE(opened.Value().Is<Path>());
    ASSERT_TRUE(As<Path>(opened.Value()).FreezeRoot().HasValue());
    EXPECT_EQ(Handle::Type::RegularFile, As<Path>(opened.Value()).Leaf().AcquiredType());
    auto processRoot = Path::Make(context, "/", strict, AmpleLimits());
    ASSERT_TRUE(processRoot.HasValue());
    ASSERT_TRUE(processRoot.Value().Is<Path>());
    ASSERT_TRUE(As<Path>(processRoot.Value()).FreezeRoot().HasValue());
    EXPECT_EQ(1U, As<Path>(processRoot.Value()).Size());
    ASSERT_TRUE(As<Path>(processRoot.Value()).Close().HasValue());
    PathOutcome moved(std::move(opened.Value()));
    EXPECT_TRUE(moved.Is<Path>());
    ASSERT_TRUE(As<Path>(moved).Close().HasValue());
    EXPECT_EQ(before, CountOpenDescriptors());
    ASSERT_EQ(0, ::unlink(link.c_str()));
}

TEST_F(PathAliasTest, MakeOutcomesDispatchAndRejectWrongTypedAccess)
{
    auto missing = Path::Make(context, context.GetTempdirPath() + "/directly-absent", CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(missing.HasValue()) << missing.Error().message;
    ASSERT_TRUE(missing.Value().Is<Path::RejectionReason>());
    EXPECT_EQ(Path::RejectionReason::Missing, As<Path::RejectionReason>(missing.Value()));
    EXPECT_THROW((void)As<Path>(missing.Value()), std::logic_error);
    EXPECT_THROW((void)As<Path>(std::move(missing.Value())), std::logic_error);

    const std::string link = context.GetTempdirPath() + "/excluded-link";
    ASSERT_EQ(0, ::symlink("directly-absent", link.c_str()));
    Path::Policy policy = CrossMountPathPolicy();
    policy.nonFollowedLinks = NonFollowedLinkAction::Skip;
    auto excluded = Path::Make(context, link, policy, AmpleLimits());
    ASSERT_TRUE(excluded.HasValue()) << excluded.Error().message;
    ASSERT_TRUE(excluded.Value().Is<Path::RejectionReason>());
    const PathOutcome& constExcluded = excluded.Value();
    EXPECT_EQ(Path::RejectionReason::Excluded, As<Path::RejectionReason>(constExcluded));
    EXPECT_THROW((void)As<Path>(constExcluded), std::logic_error);
    EXPECT_THROW((void)As<Path>(std::move(excluded.Value())), std::logic_error);

    const std::size_t before = CountOpenDescriptors();
    auto opened = Path::Make(context, "/", CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    ASSERT_TRUE(opened.Value().Is<Path>());
    ASSERT_TRUE(As<Path>(opened.Value()).FreezeRoot().HasValue());
    const PathOutcome& constAccepted = opened.Value();
    EXPECT_EQ(1U, As<Path>(constAccepted).Size());
    EXPECT_THROW((void)As<Path::RejectionReason>(constAccepted), std::logic_error);
    ASSERT_TRUE(As<Path>(opened.Value()).Close().HasValue());
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, OutcomeMovesAndExtractionKeepAcceptedPinsUntilDestinationCloses)
{
    const std::size_t before = CountOpenDescriptors();
    std::unique_ptr<Path> retained;
    {
        auto opened = Path::Make(context, "/", CrossMountPathPolicy(), AmpleLimits());
        ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
        ASSERT_TRUE(As<Path>(opened.Value()).FreezeRoot().HasValue());
        PathOutcome destination(std::move(opened.Value()));
        ASSERT_TRUE(destination.Is<Path>());
        retained.reset(new Path(As<Path>(std::move(destination))));
        EXPECT_EQ(1U, retained->Size());
    }
    // Both consumed outcomes have been destroyed; only the extracted Path
    // still owns the pin. Neither moved-from outcome is queried.
    ASSERT_NE(nullptr, retained);
    EXPECT_GT(CountOpenDescriptors(), before);
    EXPECT_EQ(1U, retained->Size());
    ASSERT_TRUE(retained->Close().HasValue());
    retained.reset();
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, OutcomeMoveAssignmentsReplaceAlternativesAndCloseAcceptedPinsOnce)
{
    const std::size_t before = CountOpenDescriptors();
    auto first = Path::Make(context, "/", CrossMountPathPolicy(), AmpleLimits());
    auto second = Path::Make(context, "/", CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(first.HasValue()) << first.Error().message;
    ASSERT_TRUE(second.HasValue()) << second.Error().message;
    ASSERT_TRUE(As<Path>(first.Value()).FreezeRoot().HasValue());
    ASSERT_TRUE(As<Path>(second.Value()).FreezeRoot().HasValue());
    PathOutcome destination(std::move(first.Value()));
    PathOutcome incoming(std::move(second.Value()));
    const std::size_t replacedPins = As<Path>(destination).RetainedDescriptors();
    const std::size_t incomingPins = As<Path>(incoming).RetainedDescriptors();
    const std::size_t held = CountOpenDescriptors();
    ASSERT_GT(replacedPins, 0U);
    ASSERT_GT(incomingPins, 0U);
    EXPECT_CALL(context, CloseFileDescriptor(_)).Times(replacedPins).WillRepeatedly([](int fd) { return ::close(fd); });
    destination = std::move(incoming); // accepted -> accepted
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    EXPECT_EQ(held - replacedPins, CountOpenDescriptors());
    EXPECT_TRUE(destination.Is<Path>());
    EXPECT_EQ(incomingPins, As<Path>(destination).RetainedDescriptors());

    PathOutcome marker(InPlaceType<Path::RejectionReason>{}, Path::RejectionReason::Missing);
    EXPECT_EQ(Path::RejectionReason::Missing, As<Path::RejectionReason>(marker));
    marker = std::move(destination); // missing -> accepted
    EXPECT_TRUE(marker.Is<Path>());
    EXPECT_CALL(context, CloseFileDescriptor(_)).Times(incomingPins).WillRepeatedly([](int fd) { return ::close(fd); });
    marker = PathOutcome(InPlaceType<Path::RejectionReason>{}, Path::RejectionReason::Excluded); // accepted -> excluded
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    EXPECT_EQ(Path::RejectionReason::Excluded, As<Path::RejectionReason>(marker));
    EXPECT_EQ(before, CountOpenDescriptors());

    auto third = Path::Make(context, "/", CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(third.HasValue()) << third.Error().message;
    ASSERT_TRUE(As<Path>(third.Value()).FreezeRoot().HasValue());
    marker = std::move(third.Value()); // excluded -> accepted
    EXPECT_TRUE(marker.Is<Path>());
    const std::size_t finalPins = As<Path>(marker).RetainedDescriptors();
    const std::size_t heldAfterThird = CountOpenDescriptors();
    PathOutcome& same = marker;
    marker = std::move(same); // self-move preserves ownership
    EXPECT_EQ(heldAfterThird, CountOpenDescriptors());
    EXPECT_CALL(context, CloseFileDescriptor(_)).Times(finalPins).WillRepeatedly([](int fd) { return ::close(fd); });
    marker = PathOutcome(InPlaceType<Path::RejectionReason>{}, Path::RejectionReason::Missing); // accepted -> missing
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    EXPECT_EQ(Path::RejectionReason::Missing, As<Path::RejectionReason>(marker));
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, NonFollowedLinksSkipOnlySelectedFinalLinks)
{
    const std::string root = context.GetTempdirPath() + "/link-policy-root";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    const std::string file = context.MakeTempfile("contents");
    ASSERT_EQ(0, ::rename(file.c_str(), (root + "/file").c_str()));
    ASSERT_EQ(0, ::mkdir((root + "/directory").c_str(), 0700));
    ASSERT_EQ(0, ::symlink("file", (root + "/file-link").c_str()));
    ASSERT_EQ(0, ::symlink("directory", (root + "/directory-link").c_str()));

    Path::Policy policy = CrossMountPathPolicy();
    EXPECT_EQ(NonFollowedLinkAction::Reject, policy.nonFollowedLinks);
    auto rejected = Path::Make(context, root + "/file-link", policy, AmpleLimits());
    ASSERT_FALSE(rejected.HasValue());
    EXPECT_EQ(ELOOP, rejected.Error().code);

    policy.nonFollowedLinks = NonFollowedLinkAction::Skip;
    auto excluded = Path::Make(context, root + "/file-link", policy, AmpleLimits());
    ASSERT_TRUE(excluded.HasValue()) << excluded.Error().message;
    ASSERT_TRUE(excluded.Value().Is<Path::RejectionReason>());
    EXPECT_EQ(Path::RejectionReason::Excluded, As<Path::RejectionReason>(excluded.Value()));
    ASSERT_EQ(0, ::symlink("link-policy-root", (context.GetTempdirPath() + "/prefix-link").c_str()));
    auto prefix = Path::Make(context, context.GetTempdirPath() + "/prefix-link/file-link", policy, AmpleLimits());
    ASSERT_FALSE(prefix.HasValue());
    EXPECT_EQ(ELOOP, prefix.Error().code);

    policy.directoryLinks = SymlinkPolicy::Follow;
    auto excludedFile = Path::Make(context, root + "/file-link", policy, AmpleLimits());
    ASSERT_TRUE(excludedFile.HasValue()) << excludedFile.Error().message;
    ASSERT_TRUE(excludedFile.Value().Is<Path::RejectionReason>());
    EXPECT_EQ(Path::RejectionReason::Excluded, As<Path::RejectionReason>(excludedFile.Value()));
    auto followedDirectory = Path::Make(context, root + "/directory-link", policy, AmpleLimits());
    ASSERT_TRUE(followedDirectory.HasValue()) << followedDirectory.Error().message;
    ASSERT_TRUE(followedDirectory.Value().Is<Path>());
    ASSERT_TRUE(As<Path>(followedDirectory.Value()).FreezeRoot().HasValue());
    ASSERT_TRUE(As<Path>(followedDirectory.Value()).Close().HasValue());

    auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    ExtensionPolicy child = ChildPolicy(SymlinkPolicy::DoNotFollow, MountPolicy::AllowCrossing);
    EXPECT_EQ(NonFollowedLinkAction::Reject, child.nonFollowedLinks);
    auto denied = path.Push("file-link", child);
    ASSERT_FALSE(denied.HasValue());
    EXPECT_EQ(ELOOP, denied.Error().code);
    child.nonFollowedLinks = NonFollowedLinkAction::Skip;
    auto skipped = path.Push("file-link", child);
    ASSERT_TRUE(skipped.HasValue()) << skipped.Error().message;
    ASSERT_TRUE(skipped.Value().Is<Path::RejectionReason>());
    EXPECT_EQ(Path::RejectionReason::Excluded, As<Path::RejectionReason>(skipped.Value()));
    EXPECT_EQ(1U, path.Size());
    child.directoryLinks = SymlinkPolicy::Follow;
    auto skippedFile = path.Push("file-link", child);
    ASSERT_TRUE(skippedFile.HasValue()) << skippedFile.Error().message;
    ASSERT_TRUE(skippedFile.Value().Is<Path::RejectionReason>());
    EXPECT_EQ(Path::RejectionReason::Excluded, As<Path::RejectionReason>(skippedFile.Value()));
    auto followed = path.Push("directory-link", child);
    ASSERT_TRUE(followed.HasValue()) << followed.Error().message;
    ASSERT_TRUE(followed.Value().Is<const Path&>());
    EXPECT_EQ(&path, &As<const Path&>(followed.Value()));
    EXPECT_EQ(Handle::Type::Directory, As<const Path&>(followed.Value()).Leaf().AcquiredType());
    EXPECT_EQ(Handle::Type::Directory, path.Leaf().AcquiredType());
    ASSERT_TRUE(path.Close().HasValue());
}

TEST_F(PathAliasTest, RootPolicyDefaultsAreIndependentAndRestrictive)
{
    Path::Policy policy;
    EXPECT_EQ(SymlinkPolicy::DoNotFollow, policy.symlinks);
    EXPECT_EQ(MountPolicy::StayOnRootMount, policy.mounts);
    EXPECT_EQ(SymlinkPolicy::DoNotFollow, policy.fileLinks);
    EXPECT_EQ(SymlinkPolicy::DoNotFollow, policy.directoryLinks);
    EXPECT_EQ(NonFollowedLinkAction::Reject, policy.nonFollowedLinks);
    policy.symlinks = SymlinkPolicy::Follow;
    EXPECT_EQ(SymlinkPolicy::DoNotFollow, policy.fileLinks);
    EXPECT_EQ(SymlinkPolicy::DoNotFollow, policy.directoryLinks);
}

TEST_F(PathAliasTest, ResolverAndExtensionDefaultsAreIndependentAndBounded)
{
    const ResolverLimits limits;
    EXPECT_EQ(4096U, limits.shared.targetBytes);
    EXPECT_EQ(128U, limits.shared.components);
    EXPECT_EQ(100000U, limits.shared.work);
    EXPECT_EQ(256U, limits.shared.liveDescriptors);
    EXPECT_EQ(std::size_t{1024} * 1024, limits.shared.retainedBytes);
    EXPECT_EQ(4096U, limits.shared.fdinfoBytes);
    EXPECT_EQ(4096U, limits.linkTargetBytes);
    EXPECT_EQ(128U, limits.linkExpansions);
    EXPECT_EQ(128U, limits.depth);
    const ExtensionPolicy extension;
    EXPECT_EQ(SymlinkPolicy::DoNotFollow, extension.fileLinks);
    EXPECT_EQ(SymlinkPolicy::DoNotFollow, extension.directoryLinks);
    EXPECT_EQ(MountPolicy::StayOnRootMount, extension.mounts);
    EXPECT_EQ(UnsupportedTypeAction::Reject, extension.unsupported);
    EXPECT_EQ(NonFollowedLinkAction::Reject, extension.nonFollowedLinks);
    EXPECT_FALSE(extension.reportMissingRegularFile);
    ResolverLimits exhausted;
    exhausted.shared.work = 1;
    auto root = Path::Make(context, context.GetTempdirPath(), CrossMountPathPolicy(), exhausted);
    ASSERT_FALSE(root.HasValue());
    EXPECT_EQ(E2BIG, root.Error().code);
    EXPECT_EQ(100000U, limits.shared.work); // overrides cannot mutate other requests
}

TEST_F(PathAliasTest, InitialRootRetainedHeadroomHasExactBoundary)
{
    ResolverLimits limits = AmpleLimits();
    auto baseline = Path::Make(context, "/", CrossMountPathPolicy(), limits);
    ASSERT_TRUE(baseline.HasValue()) << baseline.Error().message;
    ASSERT_TRUE(baseline.Value().Is<Path>());
    // The acquisition ledger includes the root spelling and the full
    // process-root entry footprint; bootstrap must reserve that entire total.
    const std::size_t exactBudget = As<Path>(baseline.Value()).RetainedBytes();
    ASSERT_LE(exactBudget, limits.shared.retainedBytes);
    limits.shared.retainedBytes = exactBudget - 1;
    auto insufficient = Path::Make(context, "/", CrossMountPathPolicy(), limits);
    ASSERT_FALSE(insufficient.HasValue());
    EXPECT_EQ(E2BIG, insufficient.Error().code);
    EXPECT_EQ("Path retained-memory budget exhausted", insufficient.Error().message);

    limits.shared.retainedBytes = exactBudget;
    auto exact = Path::Make(context, "/", CrossMountPathPolicy(), limits);
    ASSERT_TRUE(exact.HasValue()) << exact.Error().message;
    ASSERT_TRUE(exact.Value().Is<Path>());
    EXPECT_EQ(exactBudget, As<Path>(exact.Value()).RetainedBytes());
    EXPECT_LE(As<Path>(exact.Value()).RetainedBytes(), limits.shared.retainedBytes);
}

TEST_F(PathAliasTest, InitialRootWorkChargePrecedesRetainedHeadroomAndFreezeCharge)
{
    const std::size_t charge = 128 + 4 * (4096 / 256);
    ResolverLimits limits = AmpleLimits();
    limits.shared.work = charge - 1;
    limits.shared.retainedBytes = 1;
    auto insufficientWork = Path::Make(context, "/", CrossMountPathPolicy(), limits);
    ASSERT_FALSE(insufficientWork.HasValue());
    EXPECT_EQ(E2BIG, insufficientWork.Error().code);
    EXPECT_EQ("Path work budget exhausted", insufficientWork.Error().message);

    limits.shared.work = charge;
    limits.shared.retainedBytes = AmpleLimits().shared.retainedBytes;
    auto exact = Path::Make(context, "/", CrossMountPathPolicy(), limits);
    ASSERT_TRUE(exact.HasValue()) << exact.Error().message;
    ASSERT_TRUE(exact.Value().Is<Path>());
    auto freeze = As<Path>(exact.Value()).FreezeRoot();
    ASSERT_FALSE(freeze.HasValue());
    EXPECT_EQ(E2BIG, freeze.Error().code);
    EXPECT_EQ("Path work budget exhausted", freeze.Error().message);
}

TEST_F(PathAliasTest, CachedAliasRestoresHeldPhysicalAncestryBeforeDotDot)
{
    const std::string root = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/a").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/a/b").c_str(), 0700));
    ASSERT_EQ(0, ::symlink("a/b", (root + "/alias").c_str()));
    ASSERT_EQ(0, ::symlink((root + "/alias/../victim").c_str(), (root + "/a/b/jump").c_str()));
    const std::string file = context.MakeTempfile("expected");
    ASSERT_EQ(0, ::rename(file.c_str(), (root + "/a/victim").c_str()));
    const std::string other = context.MakeTempfile("wrong");
    ASSERT_EQ(0, ::rename(other.c_str(), (root + "/victim").c_str()));
    struct stat expected = {}, wrong = {};
    ASSERT_EQ(0, ::stat((root + "/a/victim").c_str(), &expected));
    ASSERT_EQ(0, ::stat((root + "/victim").c_str(), &wrong));
    ASSERT_NE(expected.st_ino, wrong.st_ino);
    const auto before = CountOpenDescriptors();
    auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    auto follow = ChildPolicy(SymlinkPolicy::Follow, MountPolicy::AllowCrossing);
    auto alias = path.Push("alias", follow);
    ASSERT_TRUE(alias.HasValue()) << alias.Error().message;
    ASSERT_TRUE(alias.Value().Is<const Path&>());
    auto jump = path.Push("jump", follow);
    ASSERT_TRUE(jump.HasValue()) << jump.Error().message;
    ASSERT_TRUE(jump.Value().Is<const Path&>());
    EXPECT_EQ(expected.st_ino, path.LeafMetadata().accepted.st_ino);
    EXPECT_EQ(root + "/a/victim", path.ToString());
    ASSERT_TRUE(path.Close().HasValue());
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, DotAliasKeepsPhysicalRootAndCopiedOwnersShareOnePin)
{
    const std::string root = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    ASSERT_EQ(0, ::symlink(".", (root + "/self").c_str()));
    const auto before = CountOpenDescriptors();
    auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    auto original = path.Root();
    const auto policy = ChildPolicy(SymlinkPolicy::Follow, MountPolicy::AllowCrossing);
    auto pushed = path.Push("self", policy);
    ASSERT_TRUE(pushed.HasValue()) << pushed.Error().message;
    ASSERT_TRUE(pushed.Value().Is<const Path&>());
    EXPECT_EQ(original.AcquiredMetadata().st_ino, path.Leaf().AcquiredMetadata().st_ino);
    EXPECT_EQ(1U, path.Size());
    auto independent = path.Leaf();
    EXPECT_EQ(before + 1, CountOpenDescriptors()); // copies do not duplicate
    auto detached = path.Pop();
    ASSERT_TRUE(detached.HasValue()) << detached.Error().message;
    EXPECT_EQ(0U, path.Size());
    ASSERT_TRUE(path.Close().HasValue());
    EXPECT_EQ(before + 1, CountOpenDescriptors());
    ASSERT_TRUE(detached.Value().Close().HasValue());
    EXPECT_EQ(before + 1, CountOpenDescriptors());
    ASSERT_TRUE(independent.Close().HasValue());
    ASSERT_TRUE(original.Close().HasValue());
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, FailedPreparedSelfAliasDuplicationKeepsAcceptedRoot)
{
    const std::string root = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    ASSERT_EQ(0, ::symlink(".", (root + "/self").c_str()));
    auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    const auto before = CountOpenDescriptors();
    const auto bytes = path.RetainedBytes();
    const auto inode = path.Root().AcquiredMetadata().st_ino;
    EXPECT_CALL(context, DuplicateDescriptor(_)).WillOnce([](int) {
        errno = EMFILE;
        return -1;
    });
    const auto failed = path.Push("self", ChildPolicy(SymlinkPolicy::Follow, MountPolicy::AllowCrossing));
    ASSERT_FALSE(failed.HasValue());
    EXPECT_EQ(EMFILE, failed.Error().code);
    EXPECT_EQ(1U, path.Size());
    EXPECT_EQ(bytes, path.RetainedBytes());
    EXPECT_EQ(inode, path.Leaf().AcquiredMetadata().st_ino);
    EXPECT_EQ(before, CountOpenDescriptors());
    EXPECT_TRUE(path.Close().HasValue());
}

TEST_F(PathAliasTest, SingleMakeCachedSelfAliasHonorsFinalDirectoryLinkRejectAndSkip)
{
    const std::string root = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    ASSERT_EQ(0, ::symlink(".", (root + "/self").c_str()));
    const auto before = CountOpenDescriptors();
    Path::Policy policy = CrossMountPathPolicy();
    policy.symlinks = SymlinkPolicy::Follow;
    policy.fileLinks = SymlinkPolicy::DoNotFollow;
    policy.directoryLinks = SymlinkPolicy::DoNotFollow;
    auto rejected = Path::Make(context, root + "/self/self", policy, AmpleLimits());
    ASSERT_FALSE(rejected.HasValue());
    EXPECT_EQ(ELOOP, rejected.Error().code);
    policy.nonFollowedLinks = NonFollowedLinkAction::Skip;
    auto skipped = Path::Make(context, root + "/self/self", policy, AmpleLimits());
    ASSERT_TRUE(skipped.HasValue()) << skipped.Error().message;
    ASSERT_TRUE(skipped.Value().Is<Path::RejectionReason>());
    EXPECT_EQ(Path::RejectionReason::Excluded, As<Path::RejectionReason>(skipped.Value()));
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, ReportedMissingChildIsARejectionWithoutAStackMutation)
{
    auto root = SelectAcceptedPath(context, context.GetTempdirPath(), CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(root.HasValue()) << root.Error().message;
    Path path = std::move(root).Value();
    const std::string name = "m71-missing-child";
    struct stat unused = {};
    ASSERT_EQ(-1, ::lstat((context.GetTempdirPath() + "/" + name).c_str(), &unused));
    ASSERT_EQ(ENOENT, errno);
    ExtensionPolicy policy = ChildPolicy(SymlinkPolicy::DoNotFollow, MountPolicy::AllowCrossing);
    policy.reportMissingRegularFile = true;
    auto missing = path.Push(name, policy);
    ASSERT_TRUE(missing.HasValue()) << missing.Error().message;
    ASSERT_TRUE(missing.Value().Is<Path::RejectionReason>());
    EXPECT_EQ(Path::RejectionReason::Missing, As<Path::RejectionReason>(missing.Value()));
    EXPECT_EQ(1U, path.Size());
    EXPECT_TRUE(path.Close().HasValue());
}

TEST_F(PathAliasTest, PushBorrowOutlivesOutcomeWhileOwnerRemainsLive)
{
    const std::string file = context.MakeTempfile("borrowed");
    auto root = SelectAcceptedPath(context, context.GetTempdirPath(), CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(root.HasValue()) << root.Error().message;
    Path path = std::move(root).Value();
    const Path* borrowed = nullptr;
    {
        auto pushed = path.Push(file.substr(file.find_last_of('/') + 1), ChildPolicy(SymlinkPolicy::DoNotFollow, MountPolicy::AllowCrossing));
        ASSERT_TRUE(pushed.HasValue()) << pushed.Error().message;
        ASSERT_TRUE(pushed.Value().Is<const Path&>());
        borrowed = &As<const Path&>(pushed.Value());
        EXPECT_EQ(&path, borrowed);
    }
    EXPECT_EQ(2U, borrowed->Size());
    EXPECT_TRUE(S_ISREG(borrowed->LeafMetadata().accepted.st_mode));
    EXPECT_TRUE(path.Close().HasValue());
    // The pointer is intentionally not used after the owner is closed.
}

TEST_F(PathAliasTest, InvalidChildComponentIsDistinctAndLeavesAcceptedRootOwned)
{
    const std::size_t before = CountOpenDescriptors();
    auto opened = SelectAcceptedPath(context, context.GetTempdirPath(), CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    const std::size_t bytes = path.RetainedBytes();
    const std::size_t pins = path.RetainedDescriptors();
    const std::string root = path.ToString();
    const ExtensionPolicy policy = ChildPolicy(SymlinkPolicy::DoNotFollow, MountPolicy::AllowCrossing);
    const std::string components[] = {"../escape", std::string("x\0y", 3)};
    for (const std::string& component : components)
    {
        auto result = path.Push(component, policy);
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ(EINVAL, result.Error().code);
        EXPECT_EQ("Invalid child component", result.Error().message);
        EXPECT_EQ(root, path.ToString());
        EXPECT_EQ(1U, path.Size());
        EXPECT_EQ(bytes, path.RetainedBytes());
        EXPECT_EQ(pins, path.RetainedDescriptors());
    }
    ASSERT_TRUE(path.Close().HasValue());
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, RejectsInvalidFollowingAndNonFollowedLinkDisposition)
{
    Path::Policy root = CrossMountPathPolicy();
    const char* rootMessages[] = {"Invalid symlink policy", "Invalid file link policy", "Invalid directory link policy"};
    for (int field = 0; field < 3; ++field)
    {
        Path::Policy invalid = root;
        if (field == 0)
            invalid.symlinks = static_cast<SymlinkPolicy>(99);
        else if (field == 1)
            invalid.fileLinks = static_cast<SymlinkPolicy>(99);
        else
            invalid.directoryLinks = static_cast<SymlinkPolicy>(99);
        auto result = Path::Make(context, "/", invalid, AmpleLimits());
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ(EINVAL, result.Error().code);
        EXPECT_EQ(rootMessages[field], result.Error().message);
    }
    root.nonFollowedLinks = static_cast<NonFollowedLinkAction>(99);
    auto invalidRoot = Path::Make(context, "/", root, AmpleLimits());
    ASSERT_FALSE(invalidRoot.HasValue());
    EXPECT_EQ(EINVAL, invalidRoot.Error().code);
    EXPECT_EQ("Invalid non-followed link policy", invalidRoot.Error().message);

    const std::size_t before = CountOpenDescriptors();
    auto opened = SelectAcceptedPath(context, "/", CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    ExtensionPolicy extension = ChildPolicy(SymlinkPolicy::DoNotFollow, MountPolicy::AllowCrossing);
    const std::size_t bytes = path.RetainedBytes();
    const std::size_t pins = path.RetainedDescriptors();
    const char* messages[] = {"Invalid file link policy", "Invalid directory link policy", "Invalid non-followed link policy", "Invalid mount policy",
        "Invalid unsupported type action"};
    for (int field = 0; field < 5; ++field)
    {
        ExtensionPolicy invalid = extension;
        if (field == 0)
            invalid.fileLinks = static_cast<SymlinkPolicy>(99);
        else if (field == 1)
            invalid.directoryLinks = static_cast<SymlinkPolicy>(99);
        else if (field == 2)
            invalid.nonFollowedLinks = static_cast<NonFollowedLinkAction>(99);
        else if (field == 3)
            invalid.mounts = static_cast<MountPolicy>(99);
        else
            invalid.unsupported = static_cast<UnsupportedTypeAction>(99);
        auto result = path.Push("child", invalid);
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ(EINVAL, result.Error().code);
        EXPECT_EQ(messages[field], result.Error().message);
        EXPECT_EQ(1U, path.Size());
        EXPECT_EQ(bytes, path.RetainedBytes());
        EXPECT_EQ(pins, path.RetainedDescriptors());
    }
    ASSERT_TRUE(path.Close().HasValue());
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, MissingFactorySelectionCannotHideCheckedRootCloseFailure)
{
    const std::string missing = context.GetTempdirPath() + "/missing-absolute-child";
    const std::string logPath = context.GetTempdirPath() + "/absolute-close.log";
    OsConfigLogHandle log = OpenLog(logPath.c_str(), nullptr);
    ASSERT_NE(nullptr, log);
    context.SetLogHandle(log);
    struct stat root = {};
    ASSERT_EQ(0, ::stat("/", &root));
    int rootCloses = 0;
    ON_CALL(context, CloseFileDescriptor(_)).WillByDefault([&](int fd) {
        struct stat held = {};
        const int flags = ::fcntl(fd, F_GETFL);
        const bool rootPin = flags >= 0 && (flags & O_PATH) && ::fstat(fd, &held) == 0 && held.st_dev == root.st_dev && held.st_ino == root.st_ino;
        const int result = context.RealCloseFileDescriptor(fd);
        if (rootPin)
        {
            ++rootCloses;
            errno = EACCES;
            return -1;
        }
        return result;
    });

    auto opened = Path::Make(context, missing, CrossMountPathPolicy(SymlinkPolicy::Follow), AmpleLimits());
    EXPECT_FALSE(opened.HasValue());
    if (!opened.HasValue())
    {
        EXPECT_EQ(EACCES, opened.Error().code);
    }
    EXPECT_EQ(1, rootCloses);
    CloseLog(&log);
    context.SetLogHandle(nullptr);
    std::ifstream contents(logPath);
    const std::string text((std::istreambuf_iterator<char>(contents)), std::istreambuf_iterator<char>());
    EXPECT_NE(std::string::npos, text.find("Failed to close internal filesystem descriptor: " + std::to_string(EACCES)));
}

TEST_F(PathAliasTest, FactoryAcquisitionErrorOutranksCloseFailureAndLogsPath)
{
    const std::string requested = context.MakeTempfile("not-a-directory") + "/";
    const std::string logPath = context.GetTempdirPath() + "/factory-acquisition-close.log";
    OsConfigLogHandle log = OpenLog(logPath.c_str(), nullptr);
    ASSERT_NE(nullptr, log);
    context.SetLogHandle(log);
    struct stat root = {};
    ASSERT_EQ(0, ::stat("/", &root));
    int rootCloses = 0;
    EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int fd) {
        struct stat held = {};
        const bool rootPin = ::fstat(fd, &held) == 0 && held.st_dev == root.st_dev && held.st_ino == root.st_ino;
        const int result = context.RealCloseFileDescriptor(fd);
        if (rootPin)
        {
            ++rootCloses;
            errno = EACCES;
            return -1;
        }
        return result;
    });

    auto opened = Path::Make(context, requested, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_FALSE(opened.HasValue());
    EXPECT_EQ(ENOTDIR, opened.Error().code);
    EXPECT_EQ(1, rootCloses);
    CloseLog(&log);
    context.SetLogHandle(nullptr);
    std::ifstream contents(logPath);
    ASSERT_TRUE(contents.is_open());
    const std::string text((std::istreambuf_iterator<char>(contents)), std::istreambuf_iterator<char>());
    EXPECT_NE(std::string::npos, text.find("Failed to close pinned descriptors for " + requested + ": " + std::to_string(EACCES)));
}

TEST_F(PathAliasTest, ExplicitAdministrativeRootLinkAndMovedPath)
{
    const std::string rootPath = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(rootPath.c_str(), 0700));
    const std::string rootLink = context.GetTempdirPath() + "/administrative";
    ASSERT_EQ(0, ::symlink(rootPath.c_str(), rootLink.c_str()));
    ResolverLimits limits;
    limits.shared.targetBytes = 4096;
    limits.shared.components = 4096;
    limits.shared.work = 2000000;
    limits.shared.liveDescriptors = 4096;
    limits.shared.retainedBytes = 16U * 1024U * 1024U;
    limits.shared.fdinfoBytes = 4096;
    limits.linkTargetBytes = 4096;
    limits.linkExpansions = 8;
    limits.depth = 4096;
    auto rejected = SelectAcceptedPath(context, rootLink, CrossMountPathPolicy(), limits);
    ASSERT_FALSE(rejected.HasValue());
    EXPECT_EQ(ELOOP, rejected.Error().code);
    auto approved = SelectAcceptedPath(context, rootLink, CrossMountPathPolicy(SymlinkPolicy::Follow), limits);
    ASSERT_TRUE(approved.HasValue()) << approved.Error().message;
    Path original = std::move(approved).Value();
    const std::size_t inode = original.Root().AcquiredMetadata().st_ino;
    Path moved = std::move(original);
    EXPECT_EQ(1U, moved.Size());
    EXPECT_EQ(inode, moved.Root().AcquiredMetadata().st_ino);
    auto noRoot = original.Push("anything", ChildPolicy(SymlinkPolicy::DoNotFollow, MountPolicy::AllowCrossing));
    ASSERT_FALSE(noRoot.HasValue());
    EXPECT_EQ(EINVAL, noRoot.Error().code);
    const std::string file = context.MakeTempfile("contents");
    ASSERT_EQ(0, ::rename(file.c_str(), (rootPath + "/child").c_str()));
    auto accepted = moved.Push("child", ChildPolicy(SymlinkPolicy::DoNotFollow, MountPolicy::StayOnRootMount));
    ASSERT_TRUE(accepted.HasValue()) << accepted.Error().message;
    EXPECT_EQ(2U, moved.Size());
    ASSERT_TRUE(moved.Pop().HasValue());
    ASSERT_EQ(0, ::symlink("../", (rootPath + "/parent").c_str()));
    auto escaped = moved.Push("parent", ChildPolicy(SymlinkPolicy::Follow, MountPolicy::AllowCrossing));
    ASSERT_FALSE(escaped.HasValue());
    EXPECT_EQ(EXDEV, escaped.Error().code);
    EXPECT_EQ(1U, moved.Size());
    EXPECT_EQ(inode, moved.Leaf().AcquiredMetadata().st_ino);
}

TEST_F(PathAliasTest, EndInsertionKeepsBorrowsStableAndFailedPushDoesNotChangeStack)
{
    const std::string rootPath = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(rootPath.c_str(), 0700));
    ResolverLimits limits;
    limits.shared.targetBytes = 4096;
    limits.shared.components = 4096;
    limits.shared.work = 2000000;
    limits.shared.liveDescriptors = 4096;
    limits.shared.retainedBytes = 16U * 1024U * 1024U;
    limits.shared.fdinfoBytes = 4096;
    limits.linkTargetBytes = 4096;
    limits.linkExpansions = 8;
    limits.depth = 4096;
    auto opened = SelectAcceptedPath(context, rootPath, CrossMountPathPolicy(), limits);
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    auto rootBorrow = path.Root();
    Path::Component first;
    std::string current = rootPath;
    ExtensionPolicy strict = ChildPolicy(SymlinkPolicy::DoNotFollow, MountPolicy::StayOnRootMount);
    for (int index = 0; index < 72; ++index)
    {
        current += "/d";
        ASSERT_EQ(0, ::mkdir(current.c_str(), 0700));
        auto pushed = path.Push("d", strict);
        ASSERT_TRUE(pushed.HasValue()) << "index " << index << ": " << pushed.Error().message;
        if (0 == index)
        {
            first = path.Leaf();
        }
        EXPECT_EQ(rootBorrow.AcquiredMetadata().st_ino, path.Root().AcquiredMetadata().st_ino);
    }
    ASSERT_TRUE(first.HasValue());
    EXPECT_EQ(73U, path.Size());
    EXPECT_EQ(current, path.ToString());
    const std::size_t stableInode = first.AcquiredMetadata().st_ino;
    auto invalid = path.Push("../escape", strict);
    ASSERT_FALSE(invalid.HasValue());
    EXPECT_EQ(EINVAL, invalid.Error().code);
    EXPECT_EQ(73U, path.Size());
    EXPECT_EQ(stableInode, first.AcquiredMetadata().st_ino);
    for (int index = 0; index < 71; ++index)
    {
        ASSERT_TRUE(path.Pop().HasValue());
        EXPECT_EQ(rootBorrow.AcquiredMetadata().st_ino, path.Root().AcquiredMetadata().st_ino);
        EXPECT_EQ(stableInode, first.AcquiredMetadata().st_ino);
    }
    EXPECT_EQ(2U, path.Size());
    EXPECT_EQ(stableInode, path.Leaf().AcquiredMetadata().st_ino);
}

TEST_F(PathAliasTest, FailedPublicPushConsumesWorkWithoutChangingAcceptedRoot)
{
    const std::size_t cost = 128 + 4 * (4096 / 256);
    ResolverLimits limits;
    limits.shared.targetBytes = 4096;
    limits.shared.components = 64;
    limits.shared.work = 5 * cost;
    limits.shared.liveDescriptors = 64;
    limits.shared.retainedBytes = 262144;
    limits.shared.fdinfoBytes = 4096;
    limits.linkTargetBytes = 128;
    limits.linkExpansions = 2;
    limits.depth = 64;
    auto opened = SelectAcceptedPath(context, "/", CrossMountPathPolicy(), limits);
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    const std::string absent = "/m71-nonexistent-fixture-entry";
    struct stat unused = {};
    ASSERT_EQ(-1, ::lstat(absent.c_str(), &unused));
    ASSERT_EQ(ENOENT, errno);
    ExtensionPolicy allow = ChildPolicy(SymlinkPolicy::DoNotFollow, MountPolicy::AllowCrossing);
    const auto missing = path.Push(absent.substr(1), allow);
    ASSERT_FALSE(missing.HasValue());
    EXPECT_EQ(ENOENT, missing.Error().code);
    EXPECT_EQ(1U, path.Size());
    const auto exhausted = path.Push("etc", allow);
    ASSERT_FALSE(exhausted.HasValue());
    EXPECT_EQ(E2BIG, exhausted.Error().code);
    EXPECT_EQ(1U, path.Size());
}

TEST_F(PathAliasTest, RejectedIndependentChildAttemptsCannotResetCumulativeWork)
{
    const std::size_t cost = 128 + 4 * (4096 / 256);
    ResolverLimits limits = AmpleLimits();
    limits.shared.work = 8 * cost;
    auto opened = SelectAcceptedPath(context, "/", CrossMountPathPolicy(), limits);
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path parent = std::move(opened).Value();
    const auto strict = ChildPolicy(SymlinkPolicy::DoNotFollow, MountPolicy::AllowCrossing);
    const std::string missing = "m71-nonexistent-fixture-entry";
    struct stat unused = {};
    ASSERT_EQ(-1, ::lstat(("/" + missing).c_str(), &unused));
    ASSERT_EQ(ENOENT, errno);
    for (int attempt = 0; attempt < 2; ++attempt)
    {
        auto rejected = parent.AcquireChild(missing, strict);
        ASSERT_FALSE(rejected.HasValue());
        EXPECT_EQ(ENOENT, rejected.Error().code);
    }
    auto exhausted = parent.AcquireChild("etc", strict);
    ASSERT_FALSE(exhausted.HasValue());
    EXPECT_EQ(E2BIG, exhausted.Error().code);
    EXPECT_EQ(1U, parent.Size());
    EXPECT_TRUE(parent.Close().HasValue());
}

TEST_F(PathAliasTest, MovedPublicPathRetainsDescriptorCap)
{
    ResolverLimits limits;
    limits.shared.targetBytes = 4096;
    limits.shared.components = 64;
    limits.shared.work = 100000;
    limits.shared.liveDescriptors = 8;
    limits.shared.retainedBytes = 262144;
    limits.shared.fdinfoBytes = 4096;
    limits.linkTargetBytes = 128;
    limits.linkExpansions = 2;
    limits.depth = 64;
    auto opened = SelectAcceptedPath(context, "/", CrossMountPathPolicy(), limits);
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    ExtensionPolicy allow = ChildPolicy(SymlinkPolicy::DoNotFollow, MountPolicy::AllowCrossing);
    ASSERT_TRUE(path.Push("etc", allow).HasValue());
    Path moved = std::move(path);
    EXPECT_EQ(2U, moved.Size());
    auto cap = moved.Push("passwd", allow);
    ASSERT_FALSE(cap.HasValue());
    EXPECT_EQ(EMFILE, cap.Error().code);
    EXPECT_EQ(2U, moved.Size());
}

TEST_F(PathAliasTest, PopTransfersLeafAndPreservesSurvivingOwners)
{
    const std::string rootPath = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(rootPath.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((rootPath + "/one").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((rootPath + "/one/two").c_str(), 0700));
    ResolverLimits limits;
    limits.shared.targetBytes = 4096;
    limits.shared.components = 4096;
    limits.shared.work = 2000000;
    limits.shared.liveDescriptors = 4096;
    limits.shared.retainedBytes = 16U * 1024U * 1024U;
    limits.shared.fdinfoBytes = 4096;
    limits.linkTargetBytes = 4096;
    limits.linkExpansions = 8;
    limits.depth = 4096;
    ExtensionPolicy strict = ChildPolicy(SymlinkPolicy::DoNotFollow, MountPolicy::StayOnRootMount);
    const std::size_t before = CountOpenDescriptors();
    {
        auto opened = SelectAcceptedPath(context, rootPath, CrossMountPathPolicy(), limits);
        ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
        Path path = std::move(opened).Value();
        auto root = path.Root();
        ASSERT_TRUE(path.Push("one", strict).HasValue());
        auto one = path.Leaf();
        ASSERT_TRUE(path.Push("two", strict).HasValue());
        const std::size_t twoInode = path.Leaf().AcquiredMetadata().st_ino;
        auto detached = path.Pop();
        ASSERT_TRUE(detached.HasValue()) << detached.Error().message;
        EXPECT_EQ(2U, path.Size());
        EXPECT_EQ(root.AcquiredMetadata().st_ino, path.Root().AcquiredMetadata().st_ino);
        EXPECT_EQ(one.AcquiredMetadata().st_ino, path.Leaf().AcquiredMetadata().st_ino);
        EXPECT_EQ(rootPath + "/one", path.ToString());
        EXPECT_EQ(twoInode, detached.Value().AcquiredMetadata().st_ino);
        const std::size_t afterPop = CountOpenDescriptors();
        ASSERT_TRUE(path.Push("two", strict).HasValue());
        EXPECT_EQ(twoInode, path.Leaf().AcquiredMetadata().st_ino);
        // The old pin remains independently owned despite a new name lookup.
        EXPECT_GT(CountOpenDescriptors(), afterPop);
        auto again = path.Pop();
        ASSERT_TRUE(again.HasValue());
        auto parent = path.Pop();
        ASSERT_TRUE(parent.HasValue());
        EXPECT_EQ(root.AcquiredMetadata().st_ino, path.Leaf().AcquiredMetadata().st_ino);
    }
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, RelativeLinkParentUsesPinnedPhysicalAncestryNotLogicalPop)
{
    const std::string root = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/a").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/a/b").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/a/other").c_str(), 0700));
    ASSERT_EQ(0, ::symlink("a/b", (root + "/link").c_str()));
    ASSERT_EQ(0, ::symlink("../other", (root + "/a/b/childalias").c_str()));
    struct stat expected = {};
    ASSERT_EQ(0, ::stat((root + "/a/other").c_str(), &expected));
    auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    const auto follow = ChildPolicy(SymlinkPolicy::Follow, MountPolicy::AllowCrossing);
    auto link = path.Push("link", follow);
    ASSERT_TRUE(link.HasValue()) << link.Error().message;
    auto alias = path.Push("childalias", follow);
    ASSERT_TRUE(alias.HasValue()) << alias.Error().message;
    EXPECT_EQ(expected.st_ino, path.Leaf().AcquiredMetadata().st_ino);
    ASSERT_TRUE(path.Pop().HasValue());
    EXPECT_EQ(root + "/a", path.ToString());
    ASSERT_TRUE(path.Pop().HasValue());
    EXPECT_EQ(1U, path.Size());
    EXPECT_EQ(root, path.ToString());
}

TEST_F(PathAliasTest, PhysicalComponentsPopIndividuallyAndFailedExpansionIsAtomic)
{
    const std::string root = context.GetTempdirPath() + "/physical";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/a").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/a/b").c_str(), 0700));
    ASSERT_EQ(0, ::symlink("a/b", (root + "/link").c_str()));
    ASSERT_EQ(0, ::symlink("a/absent", (root + "/broken").c_str()));
    auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    const auto follow = ChildPolicy(SymlinkPolicy::Follow, MountPolicy::AllowCrossing);
    auto broken = path.Push("broken", follow);
    ASSERT_FALSE(broken.HasValue());
    EXPECT_EQ(ENOENT, broken.Error().code);
    EXPECT_EQ(root, path.ToString());
    EXPECT_EQ(1U, path.Size());
    ASSERT_TRUE(path.Push("link", follow).HasValue());
    EXPECT_EQ(3U, path.Size());
    EXPECT_EQ(root + "/a/b", path.ToString());
    ASSERT_TRUE(path.Pop().HasValue());
    EXPECT_EQ(root + "/a", path.ToString());
    ASSERT_TRUE(path.Pop().HasValue());
    EXPECT_EQ(root, path.ToString());
}

TEST_F(PathAliasTest, StagedGrowthAndFailedAliasLeaveOwningCopiesAlive)
{
    const std::string root = context.GetTempdirPath() + "/staged-growth";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    std::string actual = root;
    std::string target;
    for (int index = 0; index < 32; ++index)
    {
        actual += "/d";
        target += (target.empty() ? "" : "/") + std::string("d");
        ASSERT_EQ(0, ::mkdir(actual.c_str(), 0700));
    }
    ASSERT_EQ(0, ::symlink(target.c_str(), (root + "/long").c_str()));
    ASSERT_EQ(0, ::symlink((target + "/absent").c_str(), (root + "/broken").c_str()));
    ResolverLimits limits = AmpleLimits();
    limits.shared.work = 200000;
    limits.shared.liveDescriptors = 256;
    const std::size_t before = CountOpenDescriptors();
    auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(), limits);
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path parent = std::move(opened).Value();
    const auto follow = ChildPolicy(SymlinkPolicy::Follow, MountPolicy::AllowCrossing);
    auto failed = parent.AcquireChild("broken", follow);
    ASSERT_FALSE(failed.HasValue());
    EXPECT_EQ(ENOENT, failed.Error().code);
    auto acquired = parent.AcquireChild("long", follow);
    ASSERT_TRUE(acquired.HasValue()) << acquired.Error().message;
    ASSERT_TRUE(acquired.Value().Is<Path>());
    Path branch = As<Path>(std::move(acquired).Value());
    EXPECT_EQ(actual, branch.ToString());
    const std::size_t pinned = CountOpenDescriptors();
    auto leaf = branch.Leaf();
    auto copy = leaf;
    EXPECT_EQ(pinned, CountOpenDescriptors()); // copies never duplicate native pins
    ASSERT_TRUE(parent.Close().HasValue());
    ASSERT_TRUE(branch.Close().HasValue());
    EXPECT_EQ(leaf.AcquiredMetadata().st_ino, copy.AcquiredMetadata().st_ino);
    EXPECT_TRUE(copy.Stat().HasValue());
    ASSERT_TRUE(leaf.Close().HasValue());
    EXPECT_TRUE(copy.Stat().HasValue());
    ASSERT_TRUE(copy.Close().HasValue());
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, SameDepthAliasLeavesIndependentPreviousBranchWithoutNameLookup)
{
    const std::string root = context.GetTempdirPath() + "/branches";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/first").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/second").c_str(), 0700));
    ASSERT_EQ(0, ::symlink("../second", (root + "/first/shortcut").c_str()));
    auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    const auto follow = ChildPolicy(SymlinkPolicy::Follow, MountPolicy::AllowCrossing);
    ASSERT_TRUE(path.Push("first", follow).HasValue());
    auto first = path.Leaf();
    auto candidate = path.AcquireChild("shortcut", follow);
    ASSERT_TRUE(candidate.HasValue()) << candidate.Error().message;
    ASSERT_TRUE(candidate.Value().Is<Path>());
    Path branch = As<Path>(std::move(candidate).Value());
    EXPECT_EQ(2U, branch.Size());
    EXPECT_EQ(root + "/second", branch.ToString());
    // Historical spelling is not consulted: the held predecessor survives.
    ASSERT_EQ(0, ::rename((root + "/first").c_str(), (root + "/renamed").c_str()));
    EXPECT_EQ(first.AcquiredMetadata().st_ino, path.Leaf().AcquiredMetadata().st_ino);
    EXPECT_EQ(root + "/first", path.ToString());
    EXPECT_EQ(root + "/second", branch.ToString());
    ASSERT_TRUE(branch.Close().HasValue());
    ASSERT_TRUE(path.Close().HasValue());
    EXPECT_TRUE(first.Stat().HasValue());
    EXPECT_TRUE(first.Close().HasValue());
}

TEST_F(PathAliasTest, ComponentsSelectIndependentBranches)
{
    const std::string root = context.GetTempdirPath() + "/component-branches";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/first").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/second").c_str(), 0700));
    ASSERT_EQ(0, ::symlink("../second", (root + "/first/shortcut").c_str()));
    auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    const auto follow = ChildPolicy(SymlinkPolicy::Follow, MountPolicy::AllowCrossing);
    ASSERT_TRUE(path.Push("first", follow).HasValue());
    auto first = path.Leaf();
    auto candidate = path.AcquireChild("shortcut", follow);
    ASSERT_TRUE(candidate.HasValue()) << candidate.Error().message;
    ASSERT_TRUE(candidate.Value().Is<Path>());
    Path branch = As<Path>(std::move(candidate).Value());
    ASSERT_EQ(2U, branch.Size());
    auto active = branch.Components();
    auto item = active.begin();
    EXPECT_EQ(path.Root().AcquiredMetadata().st_ino, item->AcquiredMetadata().st_ino);
    ++item;
    ASSERT_NE(item, active.end());
    EXPECT_EQ(branch.Leaf().AcquiredMetadata().st_ino, item->AcquiredMetadata().st_ino);
    EXPECT_NE(first.AcquiredMetadata().st_ino, item->AcquiredMetadata().st_ino);
    EXPECT_EQ("second", item->effectiveName);
    ++item;
    EXPECT_EQ(active.end(), item);
    // Both branches retain their selected pins without reopening names.
    ASSERT_EQ(0, ::rename((root + "/first").c_str(), (root + "/renamed").c_str()));
    auto previous = path.Components();
    item = previous.begin();
    ++item;
    ASSERT_NE(item, previous.end());
    EXPECT_EQ(first.AcquiredMetadata().st_ino, item->AcquiredMetadata().st_ino);
    EXPECT_EQ("first", item->effectiveName);
    ++item;
    EXPECT_EQ(previous.end(), item);
    EXPECT_EQ(root + "/first", path.ToString());
    EXPECT_EQ(root + "/second", branch.ToString());
}

TEST_F(PathAliasTest, IndependentBranchDoesNotSelectReusedPhysicalSlot)
{
    const std::string root = context.GetTempdirPath() + "/restoration";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/first").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/second").c_str(), 0700));
    auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    const auto strict = ChildPolicy(SymlinkPolicy::DoNotFollow, MountPolicy::AllowCrossing);
    ASSERT_TRUE(path.Push("first", strict).HasValue());
    auto stale = path.Leaf();
    ASSERT_TRUE(path.Pop().HasValue());
    ASSERT_TRUE(path.Push("second", strict).HasValue());
    EXPECT_EQ("first", stale.effectiveName);
    EXPECT_NE(stale.AcquiredMetadata().st_ino, path.Leaf().AcquiredMetadata().st_ino);
    EXPECT_EQ(root + "/second", path.ToString());
    EXPECT_TRUE(stale.Close().HasValue());
}

TEST_F(PathAliasTest, AliasToExistingAncestorUsesItsCanonicalPhysicalParent)
{
    const std::string root = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/a").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/a/sub").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/a/child").c_str(), 0700));
    ASSERT_EQ(0, ::symlink("..", (root + "/a/sub/up").c_str()));
    ASSERT_EQ(0, ::symlink(".", (root + "/self").c_str()));
    ASSERT_EQ(0, ::symlink("..", (root + "/escape").c_str()));
    struct stat expected = {};
    ASSERT_EQ(0, ::stat((root + "/a/child").c_str(), &expected));
    auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    const auto strict = ChildPolicy(SymlinkPolicy::DoNotFollow, MountPolicy::AllowCrossing);
    const auto follow = ChildPolicy(SymlinkPolicy::Follow, MountPolicy::AllowCrossing);
    ASSERT_TRUE(path.Push("a", strict).HasValue());
    ASSERT_TRUE(path.Push("sub", strict).HasValue());
    auto alias = path.Push("up", follow);
    ASSERT_TRUE(alias.HasValue()) << alias.Error().message;
    auto child = path.Push("child", strict);
    ASSERT_TRUE(child.HasValue()) << child.Error().message;
    EXPECT_EQ(expected.st_ino, path.Leaf().AcquiredMetadata().st_ino);
    ASSERT_TRUE(path.Pop().HasValue());
    ASSERT_TRUE(path.Pop().HasValue());
    EXPECT_EQ(1U, path.Size());
    auto self = path.Push("self", follow);
    ASSERT_TRUE(self.HasValue()) << self.Error().message;
    auto escape = path.Push("escape", follow);
    ASSERT_FALSE(escape.HasValue());
    EXPECT_EQ(EXDEV, escape.Error().code);
    EXPECT_EQ(1U, path.Size());
}

TEST_F(PathAliasTest, FailedAuxiliaryPopRestoresParentAndDoesNotRetirePins)
{
    const std::string root = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/first").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/subdir").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/subdir/other").c_str(), 0700));
    ASSERT_EQ(0, ::symlink("../subdir/other", (root + "/first/shortcut").c_str()));
    auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    const std::size_t baseline = path.RetainedDescriptors();
    const auto follow = ChildPolicy(SymlinkPolicy::Follow, MountPolicy::AllowCrossing);
    ASSERT_TRUE(path.Push("first", follow).HasValue());
    ASSERT_TRUE(path.Push("shortcut", follow).HasValue());
    auto other = path.Pop();
    ASSERT_TRUE(other.HasValue());
    ASSERT_TRUE(other.Value().Close().HasValue());
    bool failed = false;
    std::size_t closeAttempts = 0;
    EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int fd) {
        ++closeAttempts;
        const int result = context.RealCloseFileDescriptor(fd);
        if (!failed)
        {
            failed = true;
            errno = EACCES;
            return -1;
        }
        return result;
    });
    auto popped = path.Pop();
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    ASSERT_FALSE(popped.HasValue());
    EXPECT_EQ(EACCES, popped.Error().code);
    EXPECT_EQ(2U, closeAttempts); // selected component and retired branch
    EXPECT_EQ(1U, path.Size());
    EXPECT_EQ(baseline, path.RetainedDescriptors());
    ASSERT_TRUE(path.Push("subdir", follow).HasValue());
    ASSERT_TRUE(path.Pop().HasValue());
    EXPECT_TRUE(path.Close().HasValue());
}

TEST_F(PathAliasTest, ThrowingAuxiliaryPopKeepsPredecessorAndReleasesDetachedPins)
{
    const std::string root = context.GetTempdirPath() + "/pop-exception-root";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/first").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/hidden").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/hidden/leaf").c_str(), 0700));
    ASSERT_EQ(0, ::symlink("../hidden/leaf", (root + "/first/shortcut").c_str()));
    auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    const std::size_t baseline = path.RetainedDescriptors();
    const auto follow = ChildPolicy(SymlinkPolicy::Follow, MountPolicy::AllowCrossing);
    ASSERT_TRUE(path.Push("first", follow).HasValue());
    ASSERT_TRUE(path.Push("shortcut", follow).HasValue());
    auto other = path.Pop();
    ASSERT_TRUE(other.HasValue());
    ASSERT_TRUE(other.Value().Close().HasValue());
    const std::size_t detachedPins = path.RetainedDescriptors() - baseline;
    ASSERT_GT(detachedPins, 1U);
    const auto before = CountOpenDescriptors();
    std::size_t attempts = 0;
    EXPECT_CALL(context, CloseFileDescriptor(_)).Times(detachedPins).WillRepeatedly([&](int fd) {
        ++attempts;
        EXPECT_EQ(0, ::close(fd));
        if (attempts == 1)
            throw std::runtime_error("pop post-close fault");
        return 0;
    });
    try
    {
        (void)path.Pop();
        FAIL() << "Pop must propagate the original exception";
    }
    catch (const std::runtime_error& error)
    {
        EXPECT_STREQ("pop post-close fault", error.what());
    }
    EXPECT_EQ(detachedPins, attempts);
    EXPECT_EQ(1U, path.Size());
    EXPECT_EQ(baseline, path.RetainedDescriptors());
    EXPECT_EQ(root, path.ToString());
    EXPECT_EQ(before - detachedPins, CountOpenDescriptors());
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    ASSERT_TRUE(path.Push("hidden", follow).HasValue());
    ASSERT_TRUE(path.Pop().HasValue());
    EXPECT_TRUE(path.Close().HasValue());
}

TEST_F(PathAliasTest, PopLogAccessorExceptionKeepsUsablePredecessor)
{
    struct FaultyLogContext : NiceMock<MockContext>
    {
        OsConfigLogHandle GetLogHandle() const override
        {
            if (throwOnLog)
                throw std::runtime_error("pop log fault");
            return MockContext::GetLogHandle();
        }
        bool throwOnLog = false;
    } selected;
    const std::string root = selected.GetTempdirPath() + "/pop-log-root";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/first").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/hidden").c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((root + "/hidden/leaf").c_str(), 0700));
    ASSERT_EQ(0, ::symlink("../hidden/leaf", (root + "/first/shortcut").c_str()));
    auto opened = SelectAcceptedPath(selected, root, CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    const std::size_t baseline = path.RetainedDescriptors();
    const auto follow = ChildPolicy(SymlinkPolicy::Follow, MountPolicy::AllowCrossing);
    ASSERT_TRUE(path.Push("first", follow).HasValue());
    ASSERT_TRUE(path.Push("shortcut", follow).HasValue());
    auto other = path.Pop();
    ASSERT_TRUE(other.HasValue());
    ASSERT_TRUE(other.Value().Close().HasValue());
    const std::size_t detachedPins = path.RetainedDescriptors() - baseline;
    ASSERT_GT(detachedPins, 1U);
    const auto before = CountOpenDescriptors();
    std::size_t attempts = 0;
    EXPECT_CALL(selected, CloseFileDescriptor(_)).Times(detachedPins).WillRepeatedly([&](int fd) {
        ++attempts;
        EXPECT_EQ(0, ::close(fd));
        if (attempts == 1)
        {
            errno = EACCES;
            return -1;
        }
        return 0;
    });
    selected.throwOnLog = true;
    try
    {
        (void)path.Pop();
        FAIL() << "Log-accessor exceptions must propagate";
    }
    catch (const std::runtime_error& error)
    {
        EXPECT_STREQ("pop log fault", error.what());
    }
    selected.throwOnLog = false;
    EXPECT_EQ(detachedPins, attempts);
    EXPECT_EQ(1U, path.Size());
    EXPECT_EQ(baseline, path.RetainedDescriptors());
    EXPECT_EQ(root, path.ToString());
    EXPECT_EQ(before - detachedPins, CountOpenDescriptors());
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&selected));
    ASSERT_TRUE(path.Push("hidden", follow).HasValue());
    ASSERT_TRUE(path.Pop().HasValue());
    EXPECT_TRUE(path.Close().HasValue());
}

TEST_F(PathAliasTest, IgnoredPopClosesOnceAndEmptyAccessIsExplicit)
{
    ResolverLimits limits;
    limits.shared.targetBytes = 4096;
    limits.shared.components = 128;
    limits.shared.work = 100000;
    limits.shared.liveDescriptors = 64;
    limits.shared.retainedBytes = 262144;
    limits.shared.fdinfoBytes = 4096;
    limits.linkTargetBytes = 128;
    limits.linkExpansions = 2;
    limits.depth = 128;
    ExtensionPolicy allow = ChildPolicy(SymlinkPolicy::DoNotFollow, MountPolicy::AllowCrossing);
    const std::size_t before = CountOpenDescriptors();
    {
        auto opened = SelectAcceptedPath(context, "/", CrossMountPathPolicy(), limits);
        ASSERT_TRUE(opened.HasValue());
        Path path = std::move(opened).Value();
        ASSERT_TRUE(path.Push("etc", allow).HasValue());
        const std::size_t withLeaf = CountOpenDescriptors();
        ASSERT_TRUE(path.Pop().HasValue()); // The temporary result closes its pin.
        EXPECT_EQ(1U, path.Size());
        EXPECT_LT(CountOpenDescriptors(), withLeaf);
        EXPECT_TRUE(path.Push("etc", allow).HasValue());
        Path moved = std::move(path);
        auto leaf = moved.Pop();
        ASSERT_TRUE(leaf.HasValue());
        auto root = moved.Pop();
        ASSERT_TRUE(root.HasValue());
        EXPECT_EQ(0U, moved.Size());
        auto empty = moved.Pop();
        ASSERT_FALSE(empty.HasValue());
        EXPECT_EQ(EINVAL, empty.Error().code);
        EXPECT_THROW(moved.Root(), std::logic_error);
        EXPECT_THROW(moved.Leaf(), std::logic_error);
        EXPECT_TRUE(moved.Components().empty());
        auto cannotPush = moved.Push("etc", allow);
        ASSERT_FALSE(cannotPush.HasValue());
        EXPECT_EQ(EINVAL, cannotPush.Error().code);
        auto movedFrom = path.Pop();
        ASSERT_FALSE(movedFrom.HasValue());
        EXPECT_EQ(EINVAL, movedFrom.Error().code);
        EXPECT_TRUE(path.Components().empty());
    }
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, DetachedRootAndFileRemainPinnedAfterPathDestruction)
{
    const std::string rootPath = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(rootPath.c_str(), 0700));
    const std::string original = context.MakeTempfile("old contents");
    ASSERT_EQ(0, ::rename(original.c_str(), (rootPath + "/file").c_str()));
    ResolverLimits limits;
    limits.shared.targetBytes = 4096;
    limits.shared.components = 128;
    limits.shared.work = 200000;
    limits.shared.liveDescriptors = 128;
    limits.shared.retainedBytes = 262144;
    limits.shared.fdinfoBytes = 4096;
    limits.linkTargetBytes = 128;
    limits.linkExpansions = 2;
    limits.depth = 128;
    ExtensionPolicy strict = ChildPolicy(SymlinkPolicy::DoNotFollow, MountPolicy::StayOnRootMount);
    const std::size_t before = CountOpenDescriptors();
    {
        auto detached = [&]() -> ComplianceEngine::Result<Path::Component> {
            auto opened = SelectAcceptedPath(context, rootPath, CrossMountPathPolicy(), limits);
            if (!opened.HasValue())
            {
                return std::move(opened).Error();
            }
            Path path = std::move(opened).Value();
            auto pushed = path.Push("file", strict);
            if (!pushed.HasValue())
            {
                return std::move(pushed).Error();
            }
            return path.Pop();
        }();
        ASSERT_TRUE(detached.HasValue());
        EXPECT_EQ(before + 1, CountOpenDescriptors());
        const std::size_t oldInode = detached.Value().AcquiredMetadata().st_ino;
        ASSERT_EQ(0, ::rename((rootPath + "/file").c_str(), (rootPath + "/former").c_str()));
        ASSERT_EQ(0, ::mkfifo((rootPath + "/file").c_str(), 0600));
        auto activated = detached.Value().Stat();
        ASSERT_TRUE(activated.HasValue()) << activated.Error().message;
        EXPECT_EQ(oldInode, activated.Value().st_ino);
        ASSERT_EQ(0, ::unlink((rootPath + "/former").c_str()));
        auto again = detached.Value().Stat();
        ASSERT_TRUE(again.HasValue()) << again.Error().message;
        EXPECT_EQ(oldInode, again.Value().st_ino);
    }
    EXPECT_EQ(before, CountOpenDescriptors());
    {
        auto detachedRoot = [&]() -> ComplianceEngine::Result<Path::Component> {
            auto opened = SelectAcceptedPath(context, rootPath, CrossMountPathPolicy(), limits);
            if (!opened.HasValue())
            {
                return std::move(opened).Error();
            }
            Path path = std::move(opened).Value();
            return path.Pop();
        }();
        ASSERT_TRUE(detachedRoot.HasValue());
        EXPECT_EQ(before + 1, CountOpenDescriptors());
        ASSERT_EQ(0, ::rename(rootPath.c_str(), (rootPath + ".former").c_str()));
        ASSERT_EQ(0, ::mkdir(rootPath.c_str(), 0700));
        auto active = detachedRoot.Value().Stat();
        ASSERT_TRUE(active.HasValue()) << active.Error().message;
        EXPECT_EQ(detachedRoot.Value().AcquiredMetadata().st_ino, active.Value().st_ino);
    }
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, PoppedHandlesLeavePathBudgetAndRemainIndependentlyOwned)
{
    const std::size_t firstStage = sizeof(Handle) + 4 * sizeof(const Handle*) + 1 + sizeof(std::string) + 3 + sizeof(Handle) + 3 + 4 * sizeof(const Handle*);
    // Account for the location's owning entry (component, names and
    // ancestry bookkeeping), not a bare Handle stored in the old stack.
    const std::size_t locationEntry = sizeof(Path::Component) + 2 * sizeof(std::string) + 5 * sizeof(std::size_t);
    ResolverLimits memoryLimits;
    memoryLimits.shared.targetBytes = 4096;
    memoryLimits.shared.components = 128;
    memoryLimits.shared.work = 200000;
    memoryLimits.shared.liveDescriptors = 64;
    memoryLimits.shared.retainedBytes = locationEntry + 1 + firstStage + locationEntry + 2;
    memoryLimits.shared.fdinfoBytes = 4096;
    memoryLimits.linkTargetBytes = 128;
    memoryLimits.linkExpansions = 2;
    memoryLimits.depth = 128;
    ResolverLimits fdLimits;
    fdLimits.shared.targetBytes = 4096;
    fdLimits.shared.components = 128;
    fdLimits.shared.work = 200000;
    fdLimits.shared.liveDescriptors = 8;
    fdLimits.shared.retainedBytes = 262144;
    fdLimits.shared.fdinfoBytes = 4096;
    fdLimits.linkTargetBytes = 128;
    fdLimits.linkExpansions = 2;
    fdLimits.depth = 128;
    ExtensionPolicy allow = ChildPolicy(SymlinkPolicy::DoNotFollow, MountPolicy::AllowCrossing);
    const std::size_t before = CountOpenDescriptors();
    for (const auto& limits : {fdLimits, memoryLimits})
    {
        auto opened = SelectAcceptedPath(context, "/", CrossMountPathPolicy(), limits);
        ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
        Path path = std::move(opened).Value();
        const std::size_t rootBytes = path.RetainedBytes();
        ASSERT_TRUE(path.Push("etc", allow).HasValue());
        const std::size_t charged = path.RetainedBytes();
        const std::size_t pins = path.RetainedDescriptors();
        auto popped = path.Pop();
        ASSERT_TRUE(popped.HasValue());
        Path::Component first = std::move(popped).Value();
        EXPECT_EQ(pins - 1, path.RetainedDescriptors());
        EXPECT_GT(charged, rootBytes);
        EXPECT_EQ(rootBytes, path.RetainedBytes());
        // Even while the consumer retains the first pin, a bounded Path
        // can reacquire another child using its own remaining capacity.
        auto pushed = path.Push("etc", allow);
        ASSERT_TRUE(pushed.HasValue()) << pushed.Error().message;
        auto blocked = path.Push("passwd", allow);
        ASSERT_FALSE(blocked.HasValue());
        EXPECT_EQ(limits.shared.liveDescriptors == 8 ? EMFILE : E2BIG, blocked.Error().code);
        auto second = path.Pop();
        ASSERT_TRUE(second.HasValue());
        Path::Component other = std::move(second).Value();
        const std::size_t ownedPins = path.RetainedDescriptors();
        const std::size_t ownedBytes = path.RetainedBytes();
        Path moved(std::move(path));
        EXPECT_EQ(ownedPins, moved.RetainedDescriptors());
        EXPECT_EQ(ownedBytes, moved.RetainedBytes());
        EXPECT_EQ(0U, path.RetainedDescriptors());
        EXPECT_EQ(0U, path.RetainedBytes());
        EXPECT_TRUE(first.Close().HasValue());
        EXPECT_EQ(ownedPins, moved.RetainedDescriptors());
        EXPECT_EQ(ownedBytes, moved.RetainedBytes());
        EXPECT_TRUE(other.Stat().HasValue());
        EXPECT_TRUE(other.Close().HasValue());
        EXPECT_EQ(ownedPins, moved.RetainedDescriptors());
        EXPECT_EQ(ownedBytes, moved.RetainedBytes());
        EXPECT_TRUE(moved.Close().HasValue());
        EXPECT_EQ(0U, moved.RetainedDescriptors());
        EXPECT_EQ(0U, moved.RetainedBytes());
    }
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, PopRestoresPinnedPhysicalLineageThroughDirectoryLink)
{
    const std::string rootPath = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(rootPath.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir((rootPath + "/actual").c_str(), 0700));
    ASSERT_EQ(0, ::symlink("actual", (rootPath + "/shortcut").c_str()));
    const std::string file = context.MakeTempfile("contents");
    ASSERT_EQ(0, ::rename(file.c_str(), (rootPath + "/actual/child").c_str()));
    ResolverLimits limits;
    limits.shared.targetBytes = 4096;
    limits.shared.components = 4096;
    limits.shared.work = 2000000;
    limits.shared.liveDescriptors = 4096;
    limits.shared.retainedBytes = 16U * 1024U * 1024U;
    limits.shared.fdinfoBytes = 4096;
    limits.linkTargetBytes = 4096;
    limits.linkExpansions = 8;
    limits.depth = 4096;
    ExtensionPolicy follow = ChildPolicy(SymlinkPolicy::Follow, MountPolicy::StayOnRootMount);
    ExtensionPolicy strict = ChildPolicy(SymlinkPolicy::DoNotFollow, MountPolicy::StayOnRootMount);
    const std::size_t before = CountOpenDescriptors();
    {
        auto opened = SelectAcceptedPath(context, rootPath, CrossMountPathPolicy(), limits);
        ASSERT_TRUE(opened.HasValue());
        Path path = std::move(opened).Value();
        ASSERT_TRUE(path.Push("shortcut", follow).HasValue());
        auto directory = path.Leaf();
        ASSERT_TRUE(path.Push("child", strict).HasValue());
        const std::size_t originalInode = path.Leaf().AcquiredMetadata().st_ino;
        auto detached = path.Pop();
        ASSERT_TRUE(detached.HasValue());
        EXPECT_EQ(directory.AcquiredMetadata().st_ino, path.Leaf().AcquiredMetadata().st_ino);
        ASSERT_EQ(0, ::rename((rootPath + "/actual").c_str(), (rootPath + "/former").c_str()));
        ASSERT_EQ(0, ::mkdir((rootPath + "/actual").c_str(), 0700));
        auto next = path.Push("child", strict);
        ASSERT_TRUE(next.HasValue()) << next.Error().message;
        EXPECT_EQ(originalInode, path.Leaf().AcquiredMetadata().st_ino);
        EXPECT_EQ(originalInode, detached.Value().AcquiredMetadata().st_ino);
    }
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, PoppedHandleFailedCloseIsSingleShotEvenAfterMove)
{
    ResolverLimits limits;
    limits.shared.targetBytes = 4096;
    limits.shared.components = 128;
    limits.shared.work = 200000;
    limits.shared.liveDescriptors = 64;
    limits.shared.retainedBytes = 262144;
    limits.shared.fdinfoBytes = 4096;
    limits.linkTargetBytes = 128;
    limits.linkExpansions = 2;
    limits.depth = 128;
    const std::size_t before = CountOpenDescriptors();
    auto popped = [&]() -> ComplianceEngine::Result<Path::Component> {
        auto opened = SelectAcceptedPath(context, "/", CrossMountPathPolicy(), limits);
        if (!opened.HasValue())
        {
            return std::move(opened).Error();
        }
        Path path = std::move(opened).Value();
        return path.Pop();
    }();
    ASSERT_TRUE(popped.HasValue());
    EXPECT_EQ(before + 1, CountOpenDescriptors());
    EXPECT_CALL(context, CloseFileDescriptor(_)).Times(1).WillOnce([](int descriptor) {
        EXPECT_EQ(0, ::close(descriptor));
        errno = EIO;
        return -1;
    });
    {
        Path::Component moved = std::move(popped).Value();
        Path::Component owner = std::move(moved);
    }
    EXPECT_EQ(before, CountOpenDescriptors());
    OwnedTestDescriptor reused(::open("/dev/null", O_RDONLY | O_CLOEXEC));
    ASSERT_GE(reused.Get(), 0);
    EXPECT_NE(-1, ::fcntl(reused.Get(), F_GETFD));
}

TEST_F(PathAliasTest, CheckedPathReleaseVisitsRootLineageHiddenAndLeafPins)
{
    const std::string root = context.GetTempdirPath() + "/accepted";
    const std::string hidden = root + "/hidden";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir(hidden.c_str(), 0700));
    const std::string source = context.MakeTempfile("payload");
    ASSERT_EQ(0, ::rename(source.c_str(), (hidden + "/file").c_str()));
    ASSERT_EQ(0, ::symlink("hidden/file", (root + "/shortcut").c_str()));
    // Global prefix scratch was closed before Make published the root.
    const std::string names[] = {root, hidden, hidden + "/file"};
    ResolverLimits limits;
    limits.shared.targetBytes = 4096;
    limits.shared.components = 128;
    limits.shared.work = 200000;
    limits.shared.liveDescriptors = 128;
    limits.shared.retainedBytes = 262144;
    limits.shared.fdinfoBytes = 4096;
    limits.linkTargetBytes = 4096;
    limits.linkExpansions = 8;
    limits.depth = 128;
    const std::size_t before = CountOpenDescriptors();
    for (const std::string& name : names)
    {
        struct stat target = {};
        ASSERT_EQ(0, ::stat(name.c_str(), &target));
        auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(), limits);
        ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
        Path path = std::move(opened).Value();
        ASSERT_TRUE(path.Push("shortcut", ChildPolicy(SymlinkPolicy::Follow, MountPolicy::AllowCrossing)).HasValue());
        const std::size_t pins = path.RetainedDescriptors();
        ASSERT_EQ(3U, pins); // accepted root, resolved directory, selected leaf
        std::size_t closed = 0, matched = 0;
        EXPECT_CALL(context, CloseFileDescriptor(_)).Times(pins).WillRepeatedly([&](int descriptor) {
            struct stat actual = {};
            EXPECT_EQ(0, ::fstat(descriptor, &actual));
            const bool hit = actual.st_dev == target.st_dev && actual.st_ino == target.st_ino;
            ++closed;
            if (hit)
            {
                ++matched;
            }
            EXPECT_EQ(0, ::close(descriptor));
            if (hit)
            {
                errno = EACCES;
                return -1;
            }
            return 0;
        });
        auto failed = path.Close();
        ASSERT_FALSE(failed.HasValue()) << name;
        EXPECT_EQ(EACCES, failed.Error().code);
        EXPECT_EQ(pins, closed);
        EXPECT_EQ(1U, matched) << name;
        EXPECT_EQ(0U, path.Size());
        EXPECT_EQ(0U, path.RetainedDescriptors());
        EXPECT_EQ(0U, path.RetainedBytes());
        EXPECT_TRUE(path.Close().HasValue());
        ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
        EXPECT_EQ(before, CountOpenDescriptors());
    }
}

TEST_F(PathAliasTest, PoppedFileRootReleasesHiddenPinsImmediately)
{
    const std::string root = context.GetTempdirPath() + "/accepted";
    const std::string hidden = root + "/hidden";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir(hidden.c_str(), 0700));
    const std::string source = context.MakeTempfile("still readable");
    ASSERT_EQ(0, ::rename(source.c_str(), (hidden + "/file").c_str()));
    ASSERT_EQ(0, ::symlink("hidden/file", (root + "/shortcut").c_str()));
    struct stat hiddenStat = {};
    ASSERT_EQ(0, ::stat(hidden.c_str(), &hiddenStat));
    ResolverLimits limits;
    limits.shared.targetBytes = 4096;
    limits.shared.components = 128;
    limits.shared.work = 200000;
    limits.shared.liveDescriptors = 128;
    limits.shared.retainedBytes = 262144;
    limits.shared.fdinfoBytes = 4096;
    limits.linkTargetBytes = 4096;
    limits.linkExpansions = 8;
    limits.depth = 128;
    auto opened = SelectAcceptedPath(context, root + "/shortcut", CrossMountPathPolicy(SymlinkPolicy::Follow), limits);
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    const std::size_t beforePins = path.RetainedDescriptors();
    std::size_t hiddenAttempts = 0;
    EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int fd) {
        struct stat observed = {};
        EXPECT_EQ(0, ::fstat(fd, &observed));
        if (observed.st_dev == hiddenStat.st_dev && observed.st_ino == hiddenStat.st_ino)
            ++hiddenAttempts;
        return context.RealCloseFileDescriptor(fd);
    });
    auto popped = path.Pop();
    ASSERT_TRUE(popped.HasValue());
    Path::Component leaf = std::move(popped).Value();
    ASSERT_EQ(0U, path.Size());
    EXPECT_EQ(1U, beforePins); // scratch prefix pins were closed by Make
    EXPECT_EQ(0U, hiddenAttempts);
    EXPECT_EQ(0U, path.RetainedDescriptors());
    EXPECT_EQ(0U, path.RetainedBytes());
    EXPECT_TRUE(path.Close().HasValue());
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    auto activated = leaf.OpenReadOnly();
    ASSERT_TRUE(activated.HasValue());
    auto chunk = activated.Value().Read(32);
    ASSERT_TRUE(chunk.HasValue());
    ASSERT_TRUE(chunk.Value().HasValue());
    EXPECT_EQ("still readable", chunk.Value().Value());
    EXPECT_TRUE(activated.Value().Close().HasValue());
    EXPECT_TRUE(leaf.Close().HasValue());
    EXPECT_EQ(0U, path.RetainedDescriptors());
    EXPECT_EQ(0U, path.RetainedBytes());
}

TEST_F(PathAliasTest, PhysicalPopRetainsIntermediatePinAndKeepsDetachedLeaf)
{
    const std::string root = context.GetTempdirPath() + "/accepted";
    const std::string hidden = root + "/hidden";
    ASSERT_EQ(0, ::mkdir(root.c_str(), 0700));
    ASSERT_EQ(0, ::mkdir(hidden.c_str(), 0700));
    const std::string source = context.MakeTempfile("descendant");
    ASSERT_EQ(0, ::rename(source.c_str(), (hidden + "/file").c_str()));
    ASSERT_EQ(0, ::symlink("hidden/file", (root + "/shortcut").c_str()));
    struct stat hiddenStat = {};
    ASSERT_EQ(0, ::stat(hidden.c_str(), &hiddenStat));
    ResolverLimits limits;
    limits.shared.targetBytes = 4096;
    limits.shared.components = 128;
    limits.shared.work = 200000;
    limits.shared.liveDescriptors = 128;
    limits.shared.retainedBytes = 262144;
    limits.shared.fdinfoBytes = 4096;
    limits.linkTargetBytes = 4096;
    limits.linkExpansions = 8;
    limits.depth = 128;
    auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(), limits);
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    ASSERT_TRUE(path.Push("shortcut", ChildPolicy(SymlinkPolicy::Follow, MountPolicy::AllowCrossing)).HasValue());
    const std::size_t beforePins = path.RetainedDescriptors();
    std::size_t hiddenAttempts = 0;
    EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int fd) {
        struct stat observed = {};
        EXPECT_EQ(0, ::fstat(fd, &observed));
        if (observed.st_dev == hiddenStat.st_dev && observed.st_ino == hiddenStat.st_ino)
            ++hiddenAttempts;
        return context.RealCloseFileDescriptor(fd);
    });
    auto popped = path.Pop();
    ASSERT_TRUE(popped.HasValue());
    Path::Component leaf = std::move(popped).Value();
    EXPECT_EQ(2U, path.Size());
    const std::size_t retained = path.RetainedDescriptors();
    EXPECT_EQ(beforePins - 1, retained);
    EXPECT_EQ(root + "/hidden", path.ToString());
    EXPECT_EQ(0U, hiddenAttempts); // hidden remains held for physical ..
    auto activated = leaf.OpenReadOnly();
    ASSERT_TRUE(activated.HasValue());
    auto chunk = activated.Value().Read(32);
    ASSERT_TRUE(chunk.HasValue());
    ASSERT_TRUE(chunk.Value().HasValue());
    EXPECT_EQ("descendant", chunk.Value().Value());
    EXPECT_TRUE(activated.Value().Close().HasValue());
    EXPECT_TRUE(leaf.Close().HasValue());
    EXPECT_TRUE(path.Close().HasValue());
    EXPECT_EQ(1U, hiddenAttempts);
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    EXPECT_EQ(0U, path.RetainedDescriptors());
}

TEST_F(PathAliasTest, MultipleCloseFailuresPreserveFirstAndLogSecondary)
{
    const std::string root = context.GetTempdirPath();
    ASSERT_EQ(0, ::mkdir((root + "/pin-child").c_str(), 0700));
    ResolverLimits limits;
    limits.shared.targetBytes = 4096;
    limits.shared.components = 128;
    limits.shared.work = 200000;
    limits.shared.liveDescriptors = 128;
    limits.shared.retainedBytes = 262144;
    limits.shared.fdinfoBytes = 4096;
    limits.linkTargetBytes = 4096;
    limits.linkExpansions = 8;
    limits.depth = 128;
    auto opened = SelectAcceptedPath(context, root, CrossMountPathPolicy(), limits);
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    ASSERT_TRUE(path.Push("pin-child", ChildPolicy(SymlinkPolicy::DoNotFollow, MountPolicy::AllowCrossing)).HasValue());
    const std::size_t pins = path.RetainedDescriptors();
    ASSERT_GT(pins, 1U);
    const std::string logPath = root + "/pin-close.log";
    OsConfigLogHandle log = OpenLog(logPath.c_str(), nullptr);
    ASSERT_NE(nullptr, log);
    context.SetLogHandle(log);
    std::size_t attempts = 0;
    EXPECT_CALL(context, CloseFileDescriptor(_)).Times(pins).WillRepeatedly([&](int descriptor) {
        const std::size_t ordinal = attempts++;
        EXPECT_EQ(0, ::close(descriptor));
        if (ordinal == 0 || ordinal == 1)
        {
            errno = ordinal == 0 ? EACCES : EIO;
            return -1;
        }
        return 0;
    });
    auto closed = path.Close();
    ASSERT_FALSE(closed.HasValue());
    EXPECT_EQ(EACCES, closed.Error().code);
    EXPECT_EQ(pins, attempts);
    Path moved = std::move(path);
    EXPECT_TRUE(path.Close().HasValue());
    EXPECT_TRUE(moved.Close().HasValue()); // Non-caching Close does not retry failed native closes.
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    CloseLog(&log);
    context.SetLogHandle(nullptr);
    std::ifstream stream(logPath);
    ASSERT_TRUE(stream.is_open());
    const std::string text((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
    const std::string secondary = "Secondary filesystem pin close failure: " + std::to_string(EIO);
    const auto at = text.find(secondary);
    ASSERT_NE(std::string::npos, at);
    EXPECT_EQ(std::string::npos, text.find(secondary, at + secondary.size()));
}

TEST_F(PathAliasTest, HandleCloseFailureAfterMoveNeverRetriesReusedDescriptor)
{
    ResolverLimits limits;
    limits.shared.targetBytes = 4096;
    limits.shared.components = 128;
    limits.shared.work = 200000;
    limits.shared.liveDescriptors = 64;
    limits.shared.retainedBytes = 262144;
    limits.shared.fdinfoBytes = 4096;
    limits.linkTargetBytes = 128;
    limits.linkExpansions = 2;
    limits.depth = 128;
    auto opened = SelectAcceptedPath(context, "/", CrossMountPathPolicy(), limits);
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    auto removed = path.Pop();
    ASSERT_TRUE(removed.HasValue());
    Path::Component leaf = std::move(removed).Value();
    EXPECT_EQ(0U, path.RetainedDescriptors());
    EXPECT_EQ(0U, path.RetainedBytes());
    int reused = -1;
    EXPECT_CALL(context, CloseFileDescriptor(_)).Times(1).WillOnce([&](int descriptor) {
        EXPECT_EQ(0, ::close(descriptor));
        const int replacement = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
        EXPECT_GE(replacement, 0);
        if (replacement >= 0)
        {
            reused = descriptor;
            if (replacement != descriptor)
            {
                EXPECT_EQ(descriptor, ::dup2(replacement, descriptor));
                ::close(replacement);
            }
        }
        errno = EIO;
        return -1;
    });
    auto failure = leaf.Close();
    ASSERT_FALSE(failure.HasValue());
    EXPECT_EQ(EIO, failure.Error().code);
    Path::Component moved = std::move(leaf);
    EXPECT_TRUE(moved.Close().HasValue());
    EXPECT_TRUE(leaf.Close().HasValue());
    EXPECT_EQ(0U, path.RetainedDescriptors());
    EXPECT_EQ(0U, path.RetainedBytes());
    EXPECT_TRUE(path.Close().HasValue());
    EXPECT_EQ(0U, path.RetainedDescriptors());
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    ASSERT_GE(reused, 0);
    EXPECT_GE(::fcntl(reused, F_GETFD), 0);
    EXPECT_EQ(0, ::close(reused));
}

TEST_F(PathAliasTest, MovedPathDoesNotRetryFailedCloseOrCloseReusedDescriptor)
{
    ResolverLimits limits;
    limits.shared.targetBytes = 4096;
    limits.shared.components = 128;
    limits.shared.work = 200000;
    limits.shared.liveDescriptors = 64;
    limits.shared.retainedBytes = 262144;
    limits.shared.fdinfoBytes = 4096;
    limits.linkTargetBytes = 128;
    limits.linkExpansions = 2;
    limits.depth = 128;
    auto opened = SelectAcceptedPath(context, "/", CrossMountPathPolicy(), limits);
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    int reused = -1;
    EXPECT_CALL(context, CloseFileDescriptor(_)).Times(1).WillOnce([&](int descriptor) {
        EXPECT_EQ(0, ::close(descriptor));
        const int replacement = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
        EXPECT_GE(replacement, 0);
        if (replacement >= 0)
        {
            reused = descriptor;
            if (replacement != descriptor)
            {
                EXPECT_EQ(descriptor, ::dup2(replacement, descriptor));
                ::close(replacement);
            }
        }
        errno = EACCES;
        return -1;
    });
    auto first = path.Close();
    ASSERT_FALSE(first.HasValue());
    EXPECT_EQ(EACCES, first.Error().code);
    Path moved = std::move(path);
    EXPECT_TRUE(path.Close().HasValue());
    EXPECT_TRUE(moved.Close().HasValue());
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    ASSERT_GE(reused, 0);
    EXPECT_GE(::fcntl(reused, F_GETFD), 0);
    EXPECT_EQ(0, ::close(reused));
}

TEST_F(PathAliasTest, ActivationErrorRemainsPrimaryWhenCheckedCleanupFails)
{
    const std::string source = context.MakeTempfile("contents");
    ResolverLimits limits;
    limits.shared.targetBytes = 4096;
    limits.shared.components = 128;
    limits.shared.work = 200000;
    limits.shared.liveDescriptors = 128;
    limits.shared.retainedBytes = 262144;
    limits.shared.fdinfoBytes = 4096;
    limits.linkTargetBytes = 128;
    limits.linkExpansions = 2;
    limits.depth = 128;
    auto opened = SelectAcceptedPath(context, source, CrossMountPathPolicy(), limits);
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    const std::size_t pins = path.RetainedDescriptors();
    const std::string logPath = context.GetTempdirPath() + "/activation-cleanup.log";
    OsConfigLogHandle log = OpenLog(logPath.c_str(), nullptr);
    ASSERT_NE(nullptr, log);
    context.SetLogHandle(log);
    std::size_t attempts = 0;
    EXPECT_CALL(context, CloseFileDescriptor(_)).Times(pins).WillRepeatedly([&](int fd) {
        const std::size_t index = attempts++;
        EXPECT_EQ(0, ::close(fd));
        if (index == 0)
        {
            errno = EIO;
            return -1;
        }
        return 0;
    });
    // The consumer owns this precedence decision: keep the activation error
    // and record a subsequent release error, not a success-shaped fallback.
    EXPECT_CALL(context, StatFileDescriptor(_, _)).Times(1).WillOnce([](int, struct stat*) {
        errno = EINVAL;
        return -1;
    });
    auto activated = path.Leaf().OpenReadOnly();
    ASSERT_FALSE(activated.HasValue());
    auto primary = std::move(activated).Error();
    EXPECT_EQ(EINVAL, primary.code);
    auto cleanup = path.Close();
    ASSERT_FALSE(cleanup.HasValue());
    OsConfigLogError(context.GetLogHandle(), "Secondary acquisition cleanup failure: %d", cleanup.Error().code);
    EXPECT_EQ(EINVAL, primary.code);
    EXPECT_EQ(pins, attempts);
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    CloseLog(&log);
    context.SetLogHandle(nullptr);
    std::ifstream stream(logPath);
    ASSERT_TRUE(stream.is_open());
    const std::string text((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
    EXPECT_NE(std::string::npos, text.find("Secondary acquisition cleanup failure: " + std::to_string(EIO)));
}

TEST_F(PathAliasTest, MoveAssignmentDoesNotRetryFailedCloseAndReleasesReplacedPins)
{
    ResolverLimits limits;
    limits.shared.targetBytes = 4096;
    limits.shared.components = 128;
    limits.shared.work = 200000;
    limits.shared.liveDescriptors = 64;
    limits.shared.retainedBytes = 262144;
    limits.shared.fdinfoBytes = 4096;
    limits.linkTargetBytes = 128;
    limits.linkExpansions = 2;
    limits.depth = 128;
    auto first = SelectAcceptedPath(context, "/", CrossMountPathPolicy(), limits);
    auto second = SelectAcceptedPath(context, "/", CrossMountPathPolicy(), limits);
    ASSERT_TRUE(first.HasValue());
    ASSERT_TRUE(second.HasValue());
    const std::size_t before = CountOpenDescriptors();
    Path failed = std::move(first).Value();
    Path replaced = std::move(second).Value();
    EXPECT_CALL(context, CloseFileDescriptor(_))
        .Times(2)
        .WillOnce([](int fd) {
            EXPECT_EQ(0, ::close(fd));
            errno = EACCES;
            return -1;
        })
        .WillOnce([](int fd) { return ::close(fd); });
    EXPECT_EQ(EACCES, failed.Close().Error().code);
    replaced = std::move(failed);
    EXPECT_TRUE(failed.Close().HasValue());
    EXPECT_TRUE(replaced.Close().HasValue());
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    EXPECT_EQ(before - 2, CountOpenDescriptors());
}

TEST_F(PathAliasTest, MoveAssignmentReleasesEachPathsPinsWithItsOriginalContext)
{
    NiceMock<MockContext> secondContext;
    auto first = SelectAcceptedPath(context, "/", CrossMountPathPolicy(), AmpleLimits());
    auto second = SelectAcceptedPath(secondContext, "/", CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(first.HasValue());
    ASSERT_TRUE(second.HasValue());
    Path replaced = std::move(first).Value();
    Path incoming = std::move(second).Value();
    EXPECT_EQ(1U, replaced.RetainedDescriptors());
    EXPECT_EQ(1U, incoming.RetainedDescriptors());
    EXPECT_CALL(context, CloseFileDescriptor(_)).Times(1).WillOnce([](int fd) { return ::close(fd); });
    replaced = std::move(incoming);
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    EXPECT_EQ(0U, incoming.Size());
    EXPECT_TRUE(incoming.Close().HasValue());
    EXPECT_CALL(secondContext, CloseFileDescriptor(_)).Times(1).WillOnce([](int fd) { return ::close(fd); });
    EXPECT_TRUE(replaced.Close().HasValue());
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&secondContext));
}

TEST_F(PathAliasTest, ThrowingCloseIsAttemptedOnlyOnceAndOtherPinsStillRelease)
{
    ASSERT_EQ(0, ::mkdir((context.GetTempdirPath() + "/pin-child").c_str(), 0700));
    ResolverLimits limits;
    limits.shared.targetBytes = 4096;
    limits.shared.components = 128;
    limits.shared.work = 200000;
    limits.shared.liveDescriptors = 128;
    limits.shared.retainedBytes = 262144;
    limits.shared.fdinfoBytes = 4096;
    limits.linkTargetBytes = 128;
    limits.linkExpansions = 2;
    limits.depth = 128;
    auto opened = SelectAcceptedPath(context, context.GetTempdirPath(), CrossMountPathPolicy(), limits);
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    ASSERT_TRUE(path.Push("pin-child", ChildPolicy(SymlinkPolicy::DoNotFollow, MountPolicy::AllowCrossing)).HasValue());
    const std::size_t pins = path.RetainedDescriptors();
    ASSERT_GT(pins, 1U);
    const std::size_t before = CountOpenDescriptors();
    std::size_t attempted = 0;
    int reused = -1;
    EXPECT_CALL(context, CloseFileDescriptor(_)).Times(pins).WillRepeatedly([&](int fd) {
        const auto index = attempted++;
        EXPECT_EQ(0, ::close(fd));
        if (index == 0)
        {
            const int replacement = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
            EXPECT_GE(replacement, 0);
            if (replacement >= 0)
            {
                reused = fd;
                if (replacement != fd)
                {
                    EXPECT_EQ(fd, ::dup2(replacement, fd));
                    ::close(replacement);
                }
            }
            throw std::runtime_error("injected post-close failure");
        }
        return 0;
    });
    try
    {
        (void)path.Close();
        FAIL() << "Native close exceptions must propagate";
    }
    catch (const std::runtime_error& error)
    {
        EXPECT_STREQ("injected post-close failure", error.what());
    }
    EXPECT_EQ(0U, path.Size());
    EXPECT_EQ(0U, path.RetainedDescriptors());
    EXPECT_EQ(0U, path.RetainedBytes());
    EXPECT_TRUE(path.Close().HasValue());
    EXPECT_EQ(pins, attempted);
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    ASSERT_GE(reused, 0);
    EXPECT_GE(::fcntl(reused, F_GETFD), 0);
    EXPECT_EQ(before - pins + 1, CountOpenDescriptors());
    EXPECT_EQ(0, ::close(reused));
    EXPECT_EQ(before - pins, CountOpenDescriptors());
}

TEST_F(PathAliasTest, ThrowingCloseLogAccessorLeavesPathEmptyAndReleasesOtherPins)
{
    struct FaultyLogContext : NiceMock<MockContext>
    {
        OsConfigLogHandle GetLogHandle() const override
        {
            if (throwOnLog)
                throw std::runtime_error("path close log fault");
            return MockContext::GetLogHandle();
        }
        bool throwOnLog = false;
    } selected;
    ASSERT_EQ(0, ::mkdir((selected.GetTempdirPath() + "/close-log-child").c_str(), 0700));
    auto opened = SelectAcceptedPath(selected, selected.GetTempdirPath(), CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    ASSERT_TRUE(path.Push("close-log-child", ChildPolicy(SymlinkPolicy::DoNotFollow, MountPolicy::AllowCrossing)).HasValue());
    const auto pins = path.RetainedDescriptors();
    ASSERT_GT(pins, 1U);
    const auto before = CountOpenDescriptors();
    std::size_t attempts = 0;
    EXPECT_CALL(selected, CloseFileDescriptor(_)).Times(pins).WillRepeatedly([&](int fd) {
        ++attempts;
        EXPECT_EQ(0, ::close(fd));
        if (attempts == 1)
        {
            errno = EACCES;
            return -1;
        }
        return 0;
    });
    selected.throwOnLog = true;
    try
    {
        (void)path.Close();
        FAIL() << "The original log-accessor exception must propagate";
    }
    catch (const std::runtime_error& error)
    {
        EXPECT_STREQ("path close log fault", error.what());
    }
    selected.throwOnLog = false;
    EXPECT_EQ(0U, path.Size());
    EXPECT_EQ(0U, path.RetainedDescriptors());
    EXPECT_EQ(0U, path.RetainedBytes());
    EXPECT_EQ(pins, attempts);
    EXPECT_TRUE(path.Close().HasValue());
    EXPECT_EQ(before - pins, CountOpenDescriptors());
}

TEST_F(PathAliasTest, FreshMetadataAndModeStayOnUnlinkedUnreadablePin)
{
    const std::string rootPath = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(rootPath.c_str(), 0700));
    const std::string file = context.MakeTempfile("contents");
    ASSERT_EQ(0, ::rename(file.c_str(), (rootPath + "/target").c_str()));
    ResolverLimits limits;
    limits.shared.targetBytes = 4096;
    limits.shared.components = 128;
    limits.shared.work = 200000;
    limits.shared.liveDescriptors = 128;
    limits.shared.retainedBytes = 262144;
    limits.shared.fdinfoBytes = 4096;
    limits.linkTargetBytes = 128;
    limits.linkExpansions = 2;
    limits.depth = 128;
    ExtensionPolicy strict = ChildPolicy(SymlinkPolicy::DoNotFollow, MountPolicy::StayOnRootMount);
    const std::size_t before = CountOpenDescriptors();
    {
        auto acquired = SelectAcceptedPath(context, rootPath, CrossMountPathPolicy(), limits);
        ASSERT_TRUE(acquired.HasValue()) << acquired.Error().message;
        Path path = std::move(acquired).Value();
        ASSERT_TRUE(path.Push("target", strict).HasValue());
        const std::string extraLink = rootPath + "/other-link";
        ASSERT_EQ(0, ::link((rootPath + "/target").c_str(), extraLink.c_str()));
        auto observed = path.Leaf().Stat();
        ASSERT_TRUE(observed.HasValue()) << observed.Error().message;
        EXPECT_EQ(2U, observed.Value().st_nlink);
        ASSERT_EQ(0, ::unlink(extraLink.c_str()));
        auto changed = path.Leaf().Stat();
        ASSERT_TRUE(changed.HasValue());
        EXPECT_EQ(1U, changed.Value().st_nlink);
        auto removed = path.Pop();
        ASSERT_TRUE(removed.HasValue());
        Path::Component detached = std::move(removed).Value();
        const ino_t originalInode = detached.AcquiredMetadata().st_ino;
        ASSERT_EQ(0, ::chmod((rootPath + "/target").c_str(), 0000));
        ASSERT_EQ(0, ::rename((rootPath + "/target").c_str(), (rootPath + "/former").c_str()));
        ASSERT_EQ(0, ::mkfifo((rootPath + "/target").c_str(), 0600));
        // No content-read activation is required to restore an owned 000 file.
        auto restored = detached.SetMode(0640);
        ASSERT_TRUE(restored.HasValue()) << restored.Error().message;
        auto fresh = detached.Stat();
        ASSERT_TRUE(fresh.HasValue()) << fresh.Error().message;
        EXPECT_EQ(originalInode, fresh.Value().st_ino);
        EXPECT_EQ(0640, fresh.Value().st_mode & 07777);
        struct stat replacement = {};
        ASSERT_EQ(0, ::lstat((rootPath + "/target").c_str(), &replacement));
        EXPECT_TRUE(S_ISFIFO(replacement.st_mode));
        EXPECT_EQ(0600, replacement.st_mode & 07777);
        ASSERT_EQ(0, ::unlink((rootPath + "/former").c_str()));
        ASSERT_TRUE(detached.SetMode(0600).HasValue());
        auto unlinked = detached.Stat();
        ASSERT_TRUE(unlinked.HasValue());
        EXPECT_EQ(0U, unlinked.Value().st_nlink);
        EXPECT_EQ(originalInode, unlinked.Value().st_ino);
        EXPECT_EQ(0600, unlinked.Value().st_mode & 07777);
    }
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, DetachedOwnershipUsesPinWithoutChangingHostAccounts)
{
    const std::string rootPath = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(rootPath.c_str(), 0700));
    const std::string file = context.MakeTempfile("contents");
    ASSERT_EQ(0, ::rename(file.c_str(), (rootPath + "/target").c_str()));
    ResolverLimits limits;
    limits.shared.targetBytes = 4096;
    limits.shared.components = 128;
    limits.shared.work = 200000;
    limits.shared.liveDescriptors = 128;
    limits.shared.retainedBytes = 262144;
    limits.shared.fdinfoBytes = 4096;
    limits.linkTargetBytes = 128;
    limits.linkExpansions = 2;
    limits.depth = 128;
    ExtensionPolicy strict = ChildPolicy(SymlinkPolicy::DoNotFollow, MountPolicy::StayOnRootMount);
    const std::size_t before = CountOpenDescriptors();
    {
        auto detached = [&]() -> ComplianceEngine::Result<Path::Component> {
            auto acquired = SelectAcceptedPath(context, rootPath, CrossMountPathPolicy(), limits);
            if (!acquired.HasValue())
            {
                return std::move(acquired).Error();
            }
            Path path = std::move(acquired).Value();
            auto pushed = path.Push("target", strict);
            if (!pushed.HasValue())
            {
                return std::move(pushed).Error();
            }
            return path.Pop();
        }();
        ASSERT_TRUE(detached.HasValue()) << detached.Error().message;
        EXPECT_EQ(before + 1, CountOpenDescriptors());
        const auto original = detached.Value().Stat();
        ASSERT_TRUE(original.HasValue());
        ASSERT_EQ(0, ::rename((rootPath + "/target").c_str(), (rootPath + "/former").c_str()));
        ASSERT_EQ(0, ::mkfifo((rootPath + "/target").c_str(), 0600));
        // -1/-1 leaves existing owner/group IDs untouched; no foreign ID or
        // host account is changed by this test.
        auto owned = detached.Value().SetOwnership(static_cast<uid_t>(-1), static_cast<gid_t>(-1));
        ASSERT_TRUE(owned.HasValue()) << owned.Error().message;
        auto updated = detached.Value().Stat();
        ASSERT_TRUE(updated.HasValue());
        EXPECT_EQ(original.Value().st_uid, updated.Value().st_uid);
        EXPECT_EQ(original.Value().st_gid, updated.Value().st_gid);
        EXPECT_EQ(original.Value().st_ino, updated.Value().st_ino);
        struct stat replacement = {};
        ASSERT_EQ(0, ::lstat((rootPath + "/target").c_str(), &replacement));
        EXPECT_EQ(0600, replacement.st_mode & 07777);
        EXPECT_TRUE(S_ISFIFO(replacement.st_mode));
    }
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, DetachedDirectoryModeDoesNotChangeReplacementRoot)
{
    const std::string rootPath = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(rootPath.c_str(), 0700));
    ResolverLimits limits;
    limits.shared.targetBytes = 4096;
    limits.shared.components = 128;
    limits.shared.work = 200000;
    limits.shared.liveDescriptors = 128;
    limits.shared.retainedBytes = 262144;
    limits.shared.fdinfoBytes = 4096;
    limits.linkTargetBytes = 128;
    limits.linkExpansions = 2;
    limits.depth = 128;
    const std::size_t before = CountOpenDescriptors();
    {
        auto detached = [&]() -> ComplianceEngine::Result<Path::Component> {
            auto acquired = SelectAcceptedPath(context, rootPath, CrossMountPathPolicy(), limits);
            if (!acquired.HasValue())
            {
                return std::move(acquired).Error();
            }
            Path path = std::move(acquired).Value();
            return path.Pop();
        }();
        ASSERT_TRUE(detached.HasValue());
        ASSERT_EQ(0, ::rename(rootPath.c_str(), (rootPath + ".former").c_str()));
        ASSERT_EQ(0, ::mkdir(rootPath.c_str(), 0700));
        auto changed = detached.Value().SetMode(0750);
        ASSERT_TRUE(changed.HasValue()) << changed.Error().message;
        auto held = detached.Value().Stat();
        ASSERT_TRUE(held.HasValue());
        EXPECT_TRUE(S_ISDIR(held.Value().st_mode));
        EXPECT_EQ(0750, held.Value().st_mode & 07777);
        struct stat replacement = {};
        ASSERT_EQ(0, ::stat(rootPath.c_str(), &replacement));
        EXPECT_EQ(0700, replacement.st_mode & 07777);
        EXPECT_NE(replacement.st_ino, held.Value().st_ino);
    }
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, MetadataPreflightFailureMakesNoChangeAndPostcheckReportsPartialChange)
{
    const std::string file = context.MakeTempfile("contents");
    const std::string component = file.substr(file.find_last_of('/') + 1);
    const std::size_t before = CountOpenDescriptors();
    {
        auto opened = SelectAcceptedPath(context, context.GetTempdirPath(), CrossMountPathPolicy(), AmpleLimits());
        ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
        Path path = std::move(opened).Value();
        ASSERT_TRUE(path.Push(component, ChildPolicy(SymlinkPolicy::DoNotFollow, MountPolicy::AllowCrossing)).HasValue());
        auto pinned = path.Leaf();
        ASSERT_EQ(0, ::chmod(file.c_str(), 0600));
        // The acquired mount no longer needs a second fdinfo read here.
        // Fresh metadata preflight failures still block both mutations.
        struct stat still = {};
        ASSERT_EQ(0, ::stat(file.c_str(), &still));
        EXPECT_EQ(0600, still.st_mode & 07777);
        const uid_t uid = still.st_uid;
        const gid_t gid = still.st_gid;

        bool reject = true;
        ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([&](int descriptor, struct stat* metadata) {
            const int status = context.RealStatFileDescriptor(descriptor, metadata);
            if (reject && (0 == status) && (metadata->st_ino == still.st_ino) && (metadata->st_dev == still.st_dev))
            {
                errno = EIO;
                return -1;
            }
            return status;
        });
        auto invalidMode = pinned.SetMode(0400);
        ASSERT_FALSE(invalidMode.HasValue());
        EXPECT_EQ(EIO, invalidMode.Error().code);
        auto invalidOwner = pinned.SetOwnership(static_cast<uid_t>(-1), static_cast<gid_t>(-1));
        ASSERT_FALSE(invalidOwner.HasValue());
        EXPECT_EQ(EIO, invalidOwner.Error().code);
        ASSERT_EQ(0, ::stat(file.c_str(), &still));
        EXPECT_EQ(0600, still.st_mode & 07777);
        EXPECT_EQ(uid, still.st_uid);
        EXPECT_EQ(gid, still.st_gid);

        reject = false;
        std::size_t matchingStats = 0;
        ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([&](int descriptor, struct stat* metadata) {
            const int status = context.RealStatFileDescriptor(descriptor, metadata);
            if ((0 == status) && (metadata->st_ino == still.st_ino) && (metadata->st_dev == still.st_dev) && (++matchingStats == 6))
            {
                errno = EIO; // First post-chmod pin inspection.
                return -1;
            }
            return status;
        });
        auto partial = pinned.SetMode(0400);
        ASSERT_FALSE(partial.HasValue());
        EXPECT_EQ(EIO, partial.Error().code);
        EXPECT_EQ(6U, matchingStats);
        ASSERT_EQ(0, ::stat(file.c_str(), &still));
        EXPECT_EQ(0400, still.st_mode & 07777);
    }
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, DeniedOwnershipAndModeSyscallsLeaveHeldAndReplacementObjectsUnchanged)
{
    const std::string rootPath = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(rootPath.c_str(), 0700));
    const std::string file = context.MakeTempfile("contents");
    ASSERT_EQ(0, ::rename(file.c_str(), (rootPath + "/target").c_str()));
    ASSERT_EQ(0, ::chmod((rootPath + "/target").c_str(), 0600));
    ResolverLimits limits;
    limits.shared.targetBytes = 4096;
    limits.shared.components = 128;
    limits.shared.work = 200000;
    limits.shared.liveDescriptors = 128;
    limits.shared.retainedBytes = 262144;
    limits.shared.fdinfoBytes = 4096;
    limits.linkTargetBytes = 128;
    limits.linkExpansions = 2;
    limits.depth = 128;
    ExtensionPolicy strict = ChildPolicy(SymlinkPolicy::DoNotFollow, MountPolicy::StayOnRootMount);
    const std::size_t before = CountOpenDescriptors();
    {
        auto acquired = SelectAcceptedPath(context, rootPath, CrossMountPathPolicy(), limits);
        ASSERT_TRUE(acquired.HasValue()) << acquired.Error().message;
        Path path = std::move(acquired).Value();
        ASSERT_TRUE(path.Push("target", strict).HasValue());
        const std::size_t heldDescriptors = CountOpenDescriptors();
        struct stat held = {}, replacement = {};
        ASSERT_EQ(0, ::stat((rootPath + "/target").c_str(), &held));
        ASSERT_EQ(0, ::rename((rootPath + "/target").c_str(), (rootPath + "/former").c_str()));
        ASSERT_EQ(0, ::mkfifo((rootPath + "/target").c_str(), 0600));
        ASSERT_EQ(0, ::lstat((rootPath + "/target").c_str(), &replacement));

        int pinnedDescriptor = -1;
        EXPECT_CALL(context, StatFileDescriptor(_, _)).Times(13); // Includes procfs role re-verification; no postcheck.
        EXPECT_CALL(context, ChownPinnedFileDescriptor(_, static_cast<uid_t>(-1), static_cast<gid_t>(-1))).Times(1).WillOnce([&](int descriptor, uid_t, gid_t) {
            pinnedDescriptor = descriptor;
            struct stat seen = {};
            EXPECT_EQ(0, ::fstat(descriptor, &seen));
            EXPECT_EQ(held.st_ino, seen.st_ino);
            EXPECT_EQ(held.st_dev, seen.st_dev);
            errno = EPERM; // The actual mutation syscall is denied; no host account is changed.
            return -1;
        });
        auto deniedOwner = path.Leaf().SetOwnership(static_cast<uid_t>(-1), static_cast<gid_t>(-1));
        ASSERT_FALSE(deniedOwner.HasValue());
        EXPECT_EQ(EPERM, deniedOwner.Error().code);
        EXPECT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
        EXPECT_EQ(heldDescriptors, CountOpenDescriptors());

        // 11 procfs bootstrap stats, two pin preflights, one alias-role check,
        // one alias-target stat, two retained-pin checks and one chmod-role
        // check. The denied syscall has no postcheck or redundant fdinfo reads.
        EXPECT_CALL(context, StatFileDescriptor(_, _)).Times(18);
        EXPECT_CALL(context, ChmodPinnedAlias(_, _, 0400)).Times(1).WillOnce([&](int procfsDirectory, const char* alias, mode_t) {
            struct stat directory = {}, pin = {};
            EXPECT_EQ(0, ::fstat(procfsDirectory, &directory));
            EXPECT_TRUE(S_ISDIR(directory.st_mode));
            EXPECT_GE(pinnedDescriptor, 0);
            EXPECT_EQ(0, ::fstat(pinnedDescriptor, &pin));
            EXPECT_EQ(held.st_ino, pin.st_ino);
            EXPECT_EQ(std::to_string(pinnedDescriptor), std::string(alias));
            errno = EACCES; // Deny exactly fchmodat, not alias acquisition or inspection.
            return -1;
        });
        auto deniedMode = path.Leaf().SetMode(0400);
        ASSERT_FALSE(deniedMode.HasValue());
        EXPECT_EQ(EACCES, deniedMode.Error().code);
        EXPECT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
        EXPECT_EQ(heldDescriptors, CountOpenDescriptors());

        auto stillPinned = path.Leaf().Stat();
        ASSERT_TRUE(stillPinned.HasValue()) << stillPinned.Error().message;
        EXPECT_EQ(held.st_ino, stillPinned.Value().st_ino);
        EXPECT_EQ(held.st_uid, stillPinned.Value().st_uid);
        EXPECT_EQ(held.st_gid, stillPinned.Value().st_gid);
        EXPECT_EQ(held.st_mode & 07777, stillPinned.Value().st_mode & 07777);
        struct stat stillOriginal = {}, stillReplacement = {};
        ASSERT_EQ(0, ::stat((rootPath + "/former").c_str(), &stillOriginal));
        ASSERT_EQ(0, ::lstat((rootPath + "/target").c_str(), &stillReplacement));
        EXPECT_EQ(held.st_ino, stillOriginal.st_ino);
        EXPECT_EQ(held.st_uid, stillOriginal.st_uid);
        EXPECT_EQ(held.st_gid, stillOriginal.st_gid);
        EXPECT_EQ(held.st_mode & 07777, stillOriginal.st_mode & 07777);
        EXPECT_TRUE(S_ISFIFO(stillReplacement.st_mode));
        EXPECT_EQ(replacement.st_ino, stillReplacement.st_ino);
        EXPECT_EQ(replacement.st_mode & 07777, stillReplacement.st_mode & 07777);
    }
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, InspectionFailureClosesAcquiredDescriptorWithoutHidingPrimaryError)
{
    const std::string source = context.MakeTempfile("contents");
    const std::string component = source.substr(source.find_last_of('/') + 1);
    auto opened = SelectAcceptedPath(context, context.GetTempdirPath(), CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    struct stat target = {};
    ASSERT_EQ(0, ::stat(source.c_str(), &target));
    const std::size_t before = CountOpenDescriptors();
    ON_CALL(context, StatFileDescriptor(_, _)).WillByDefault([&](int descriptor, struct stat* metadata) {
        if ((0 == ::fstat(descriptor, metadata)) && (metadata->st_ino == target.st_ino) && (metadata->st_dev == target.st_dev))
        {
            errno = EIO;
            return -1;
        }
        return context.RealStatFileDescriptor(descriptor, metadata);
    });
    const auto failed = path.Push(component, ChildPolicy(SymlinkPolicy::DoNotFollow, MountPolicy::AllowCrossing));
    ASSERT_FALSE(failed.HasValue());
    EXPECT_EQ(EIO, failed.Error().code);
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, AliasStaysOnPinnedFileAfterNameReplacementAndUnlink)
{
    const std::string source = context.MakeTempfile("original bytes");
    auto opened = context.OpenAbsolutePin(source.c_str(), false);
    ASSERT_TRUE(opened.HasValue());
    Descriptor pinned = std::move(opened).Value();
    struct stat original = {};
    ASSERT_EQ(0, context.StatFile(pinned, &original));
    const std::size_t before = CountOpenDescriptors();
    {
        ASSERT_EQ(0, ::rename(source.c_str(), (source + ".former").c_str()));
        ASSERT_EQ(0, ::mkfifo(source.c_str(), 0600));

        // Opening the original name would block on this substituted FIFO;
        // descriptor-alias activation must instead bind to the prior inode.
        auto active = ComplianceEngine::Filesystem::Detail::ActivateReadOnly(context, pinned, original, false, 4096);
        ASSERT_TRUE(active.HasValue()) << active.Error().message;
        struct stat activated = {};
        ASSERT_EQ(0, context.StatFile(active.Value(), &activated));
        EXPECT_EQ(original.st_ino, activated.st_ino);
        EXPECT_EQ(original.st_dev, activated.st_dev);
        char bytes[15] = {};
        Descriptor reader = std::move(active).Value();
        ASSERT_EQ(14, context.ReadFile(reader, bytes, 14));
        EXPECT_EQ("original bytes", std::string(bytes, 14));

        ASSERT_EQ(0, ::unlink((source + ".former").c_str()));
        auto again = ComplianceEngine::Filesystem::Detail::ActivateReadOnly(context, pinned, original, false, 4096);
        ASSERT_TRUE(again.HasValue()) << again.Error().message;
        struct stat reacquired = {};
        ASSERT_EQ(0, context.StatFile(again.Value(), &reacquired));
        EXPECT_EQ(original.st_ino, reacquired.st_ino);
    }
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, DirectoryAliasAndMovesRetainSingleOwnership)
{
    const std::string directory = context.GetTempdirPath() + "/acquired";
    ASSERT_EQ(0, ::mkdir(directory.c_str(), 0700));
    auto opened = context.OpenAbsolutePin(directory.c_str());
    ASSERT_TRUE(opened.HasValue());
    Descriptor pinned = std::move(opened).Value();
    struct stat original = {};
    ASSERT_EQ(0, context.StatFile(pinned, &original));
    const std::size_t before = CountOpenDescriptors();
    {
        auto active = ComplianceEngine::Filesystem::Detail::ActivateReadOnly(context, pinned, original, true, 4096);
        ASSERT_TRUE(active.HasValue()) << active.Error().message;
        struct stat activated = {};
        ASSERT_EQ(0, context.StatFile(active.Value(), &activated));
        EXPECT_EQ(original.st_ino, activated.st_ino);
        Descriptor transferred = std::move(active).Value();
        ASSERT_EQ(0, context.StatFile(transferred, &activated));
        EXPECT_EQ(original.st_ino, activated.st_ino);
    }
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, ActivationHandsOffOwnerWithoutRetryingFailedClose)
{
    const std::string file = context.MakeTempfile("activation");
    auto opened = context.OpenAbsolutePin(file.c_str(), false);
    ASSERT_TRUE(opened.HasValue());
    Descriptor pin = std::move(opened).Value();
    struct stat snapshot = {};
    ASSERT_EQ(0, context.StatFile(pin, &snapshot));
    const auto before = CountOpenDescriptors();
    {
        auto activated = ComplianceEngine::Filesystem::Detail::ActivateReadOnly(context, pin, snapshot, false, 4096);
        ASSERT_TRUE(activated.HasValue()) << activated.Error().message;
        EXPECT_TRUE(pin.Close().HasValue());
        EXPECT_CALL(context, CloseFileDescriptor(_)).Times(1).WillOnce([](int descriptor) {
            EXPECT_EQ(0, ::close(descriptor));
            errno = EIO;
            return -1;
        });
        Descriptor owner = std::move(activated).Value();
        EXPECT_FALSE(activated.Value().HasValue());
        EXPECT_TRUE(owner.HasValue());
        auto closed = owner.Close();
        ASSERT_FALSE(closed.HasValue());
        EXPECT_EQ(EIO, closed.Error().code);
        EXPECT_TRUE(owner.Close().Value());
    }
    EXPECT_EQ(before - 1, CountOpenDescriptors());
}

TEST_F(PathAliasTest, UnsupportedTypesAndInvalidNamesDoNotActivate)
{
    auto opened = SelectAcceptedPath(context, context.GetTempdirPath(), CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue());
    Path path = std::move(opened).Value();
    ExtensionPolicy strict = ChildPolicy(SymlinkPolicy::DoNotFollow, MountPolicy::AllowCrossing);
    const std::size_t before = CountOpenDescriptors();
    const ino_t root = path.Leaf().AcquiredMetadata().st_ino;
    const std::string special = context.GetTempdirPath() + "/special";
    ASSERT_EQ(0, ::mkfifo(special.c_str(), 0600));
    bool sawSpecial = false, sawLink = false;
    EXPECT_CALL(context, OpenNativeAt(_, _, _)).WillRepeatedly([&](int directory, const char* name, int flags) {
        if (std::string(name) == "special" || std::string(name) == "special.link")
        {
            EXPECT_NE(0, flags & O_PATH);
            EXPECT_NE(0, flags & O_NOFOLLOW);
            sawSpecial |= std::string(name) == "special";
            sawLink |= std::string(name) == "special.link";
        }
        return context.RealOpenNativeAt(directory, name, flags);
    });
    const auto fifo = path.Push("special", strict);
    ASSERT_FALSE(fifo.HasValue());
    EXPECT_EQ(EOPNOTSUPP, fifo.Error().code);
    const auto invalid = path.Push("../special", strict);
    ASSERT_FALSE(invalid.HasValue());
    EXPECT_EQ(EINVAL, invalid.Error().code);
    const auto nul = path.Push(std::string("x\0y", 3), strict);
    ASSERT_FALSE(nul.HasValue());
    EXPECT_EQ(EINVAL, nul.Error().code);
    ASSERT_EQ(0, ::symlink("special", (special + ".link").c_str()));
    const auto link = path.Push("special.link", strict);
    ASSERT_FALSE(link.HasValue());
    EXPECT_EQ(ELOOP, link.Error().code);
    auto followedUnsupported = path.Push("special.link", ChildPolicy(SymlinkPolicy::Follow, MountPolicy::AllowCrossing));
    ASSERT_FALSE(followedUnsupported.HasValue());
    EXPECT_EQ(EOPNOTSUPP, followedUnsupported.Error().code);
    ExtensionPolicy skip = ChildPolicy(SymlinkPolicy::Follow, MountPolicy::AllowCrossing);
    skip.unsupported = UnsupportedTypeAction::Skip;
    auto skippedUnsupported = path.Push("special", skip);
    ASSERT_TRUE(skippedUnsupported.HasValue());
    ASSERT_TRUE(skippedUnsupported.Value().Is<Path::RejectionReason>());
    EXPECT_EQ(Path::RejectionReason::UnsupportedType, As<Path::RejectionReason>(skippedUnsupported.Value()));
    EXPECT_EQ(1U, path.Size());
    EXPECT_EQ(root, path.Leaf().AcquiredMetadata().st_ino);
    auto skippedLinkTarget = path.Push("special.link", skip);
    ASSERT_TRUE(skippedLinkTarget.HasValue()) << skippedLinkTarget.Error().message;
    ASSERT_TRUE(skippedLinkTarget.Value().Is<Path::RejectionReason>());
    EXPECT_EQ(Path::RejectionReason::UnsupportedType, As<Path::RejectionReason>(skippedLinkTarget.Value()));
    EXPECT_EQ(1U, path.Size());
    EXPECT_EQ(root, path.Leaf().AcquiredMetadata().st_ino);
    EXPECT_EQ(Handle::Type::Directory, path.Leaf().AcquiredType());
    EXPECT_TRUE(sawSpecial);
    EXPECT_TRUE(sawLink);
    EXPECT_EQ(before, CountOpenDescriptors());
    auto rootSpecial = Path::Make(context, special, CrossMountPathPolicy(SymlinkPolicy::Follow), AmpleLimits());
    ASSERT_FALSE(rootSpecial.HasValue());
    EXPECT_EQ(EOPNOTSUPP, rootSpecial.Error().code);
    ASSERT_EQ(0, ::symlink("missing-special", (special + ".broken").c_str()));
    auto missing = path.Push("special.broken", skip);
    ASSERT_FALSE(missing.HasValue());
    EXPECT_EQ(ENOENT, missing.Error().code);
    EXPECT_EQ(1U, path.Size());
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, UnsupportedSkipCloseFailureOverridesSkipAndPreservesRoot)
{
    const std::string special = context.GetTempdirPath() + "/special-close";
    ASSERT_EQ(0, ::mkfifo(special.c_str(), 0600));
    auto opened = SelectAcceptedPath(context, context.GetTempdirPath(), CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    const ino_t root = path.Leaf().AcquiredMetadata().st_ino;
    int specialPin = -1;
    EXPECT_CALL(context, OpenNativeAt(_, _, _)).WillRepeatedly([&](int directory, const char* name, int flags) {
        if (std::string(name) == "special-close")
        {
            EXPECT_NE(0, flags & O_PATH);
        }
        const int descriptor = context.RealOpenNativeAt(directory, name, flags);
        if (std::string(name) == "special-close")
            specialPin = descriptor;
        return descriptor;
    });
    bool failed = false;
    EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int descriptor) {
        const int status = ::close(descriptor);
        if (descriptor == specialPin && !failed)
        {
            failed = true;
            errno = EIO;
            return -1;
        }
        return status;
    });
    ExtensionPolicy skip = ChildPolicy(SymlinkPolicy::DoNotFollow, MountPolicy::AllowCrossing);
    skip.unsupported = UnsupportedTypeAction::Skip;
    auto result = path.Push("special-close", skip);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EIO, result.Error().code);
    EXPECT_TRUE(failed);
    EXPECT_EQ(1U, path.Size());
    EXPECT_EQ(root, path.Leaf().AcquiredMetadata().st_ino);
    EXPECT_TRUE(path.Close().HasValue());
}

TEST_F(PathAliasTest, UnsupportedLinkTargetSkipChecksHiddenDirectoryClose)
{
    const std::string directory = context.GetTempdirPath() + "/hidden-special";
    ASSERT_EQ(0, ::mkdir(directory.c_str(), 0700));
    ASSERT_EQ(0, ::mkfifo((directory + "/fifo").c_str(), 0600));
    ASSERT_EQ(0, ::symlink("hidden-special/fifo", (context.GetTempdirPath() + "/shortcut").c_str()));
    struct stat hidden = {};
    ASSERT_EQ(0, ::stat(directory.c_str(), &hidden));
    auto opened = SelectAcceptedPath(context, context.GetTempdirPath(), CrossMountPathPolicy(), AmpleLimits());
    ASSERT_TRUE(opened.HasValue()) << opened.Error().message;
    Path path = std::move(opened).Value();
    const ino_t root = path.Leaf().AcquiredMetadata().st_ino;
    bool failed = false;
    EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int descriptor) {
        struct stat held = {};
        const bool hiddenPin = ::fstat(descriptor, &held) == 0 && held.st_dev == hidden.st_dev && held.st_ino == hidden.st_ino;
        const int status = ::close(descriptor);
        if (hiddenPin && !failed)
        {
            failed = true;
            errno = EACCES;
            return -1;
        }
        return status;
    });
    ExtensionPolicy skip = ChildPolicy(SymlinkPolicy::Follow, MountPolicy::AllowCrossing);
    skip.unsupported = UnsupportedTypeAction::Skip;
    auto result = path.Push("shortcut", skip);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(EACCES, result.Error().code);
    EXPECT_TRUE(failed);
    EXPECT_EQ(1U, path.Size());
    EXPECT_EQ(root, path.Leaf().AcquiredMetadata().st_ino);
    EXPECT_TRUE(path.Close().HasValue());
}

TEST_F(PathAliasTest, FdinfoCapFailsClosedAndCleansUp)
{
    const std::string source = context.MakeTempfile("a");
    auto opened = context.OpenAbsolutePin(source.c_str(), false);
    ASSERT_TRUE(opened.HasValue());
    Descriptor pinned = std::move(opened).Value();
    struct stat snapshot = {};
    ASSERT_EQ(0, context.StatFile(pinned, &snapshot));
    const std::size_t before = CountOpenDescriptors();
    {
        auto tooSmall = ComplianceEngine::Filesystem::Detail::ActivateReadOnly(context, pinned, snapshot, false, 1);
        ASSERT_FALSE(tooSmall.HasValue());
        EXPECT_EQ(E2BIG, tooSmall.Error().code);
        auto invalid = ComplianceEngine::Filesystem::Detail::ActivateReadOnly(context, pinned, snapshot, false, 0);
        ASSERT_FALSE(invalid.HasValue());
        EXPECT_EQ(EINVAL, invalid.Error().code);
    }
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, FdinfoReadOverreportRejectsActualRequestAndClosesHelpers)
{
    const std::size_t before = CountOpenDescriptors();
    {
        const std::string source = context.MakeTempfile("a");
        auto opened = context.OpenAbsolutePin(source.c_str(), false);
        ASSERT_TRUE(opened.HasValue());
        Descriptor pinned = std::move(opened).Value();
        struct stat snapshot = {};
        ASSERT_EQ(0, context.StatFile(pinned, &snapshot));
        const std::size_t withPin = CountOpenDescriptors();
        for (const std::size_t cap : {4096U, 1U})
        {
            const std::size_t requested = (4096U == cap) ? 256U : 2U;
            std::size_t overreports = 0;
            std::set<int> live;
            std::size_t acquired = 0, closed = 0, peak = 0;
            EXPECT_CALL(context, OpenNativePath(_, _)).WillRepeatedly([&](const char* path, int flags) {
                const int descriptor = context.RealOpenNativePath(path, flags);
                if (descriptor >= 0)
                {
                    EXPECT_TRUE(live.insert(descriptor).second);
                    ++acquired;
                    peak = std::max(peak, live.size());
                }
                return descriptor;
            });
            EXPECT_CALL(context, OpenNativeAt(_, _, _)).WillRepeatedly([&](int directory, const char* name, int flags) {
                const int descriptor = context.RealOpenNativeAt(directory, name, flags);
                if (descriptor >= 0)
                {
                    EXPECT_TRUE(live.insert(descriptor).second);
                    ++acquired;
                    peak = std::max(peak, live.size());
                }
                return descriptor;
            });
            EXPECT_CALL(context, ReadFileDescriptor(_, _, _)).WillRepeatedly([&](int descriptor, void* buffer, std::size_t size) -> ssize_t {
                const std::string target = DescriptorTarget(descriptor);
                if ((0 == target.find("/proc/")) && (std::string::npos != target.find("/fdinfo/")))
                {
                    EXPECT_EQ(requested, size);
                    ++overreports;
                    return static_cast<ssize_t>(size + 1); // No write: even an overreported count cannot be read from buffer.
                }
                return context.RealReadFileDescriptor(descriptor, buffer, size);
            });
            EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int descriptor) {
                EXPECT_EQ(1U, live.erase(descriptor));
                ++closed;
                return context.RealCloseFileDescriptor(descriptor);
            });
            auto activated = ComplianceEngine::Filesystem::Detail::ActivateReadOnly(context, pinned, snapshot, false, cap);
            ASSERT_FALSE(activated.HasValue());
            EXPECT_EQ(EIO, activated.Error().code);
            EXPECT_EQ(1U, overreports);
            EXPECT_EQ(8U, acquired); // fdinfo file and seven bootstrap/role directories.
            EXPECT_EQ(acquired, closed);
            EXPECT_TRUE(live.empty());
            EXPECT_LE(peak, 5U); // Four concurrent procfs pins plus one fdinfo reader at most.
            EXPECT_EQ(withPin, CountOpenDescriptors());
            ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
        }
        EXPECT_GE(context.DescriptorFlags(pinned), 0);
    }
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, ActivationPerformsReadPermissionCheck)
{
    if (0 == ::geteuid())
    {
        GTEST_SKIP() << "Privileged processes may open mode-000 files";
    }
    const std::string source = context.MakeTempfile("restricted");
    auto opened = context.OpenAbsolutePin(source.c_str(), false);
    ASSERT_TRUE(opened.HasValue());
    Descriptor pinned = std::move(opened).Value();
    struct stat snapshot = {};
    ASSERT_EQ(0, context.StatFile(pinned, &snapshot));
    ASSERT_EQ(0, ::chmod(source.c_str(), 0000));
    auto denied = ComplianceEngine::Filesystem::Detail::ActivateReadOnly(context, pinned, snapshot, false, 4096);
    ASSERT_FALSE(denied.HasValue());
    EXPECT_EQ(EACCES, denied.Error().code);
    EXPECT_EQ(0, ::chmod(source.c_str(), 0600));
}

TEST_F(PathAliasTest, PinnedRelativeAndAbsoluteLinksIgnoreReplacementNames)
{
    const std::string link = context.GetTempdirPath() + "/relative.link";
    ASSERT_EQ(0, ::symlink("../target", link.c_str()));
    auto relativeResult = context.OpenAbsolutePin(link.c_str(), false);
    ASSERT_TRUE(relativeResult.HasValue());
    Descriptor relative = std::move(relativeResult).Value();
    const std::size_t before = CountOpenDescriptors();
    ASSERT_EQ(0, ::unlink(link.c_str()));
    ASSERT_EQ(0, ::symlink("/etc/passwd", link.c_str()));
    auto target = ReadPinnedLink(relative, 128, 4096);
    ASSERT_TRUE(target.HasValue()) << target.Error().message;
    EXPECT_EQ("../target", target.Value().text);
    EXPECT_GT(target.Value().mountId, 0U);
    auto tooSmall = ReadPinnedLink(relative, 8, 4096);
    ASSERT_FALSE(tooSmall.HasValue());
    EXPECT_EQ(E2BIG, tooSmall.Error().code);
    EXPECT_EQ(before, CountOpenDescriptors());

    auto absoluteResult = context.OpenAbsolutePin(link.c_str(), false);
    ASSERT_TRUE(absoluteResult.HasValue());
    Descriptor absolute = std::move(absoluteResult).Value();
    auto absoluteTarget = ReadPinnedLink(absolute, 128, 4096);
    ASSERT_TRUE(absoluteTarget.HasValue()) << absoluteTarget.Error().message;
    EXPECT_EQ("/etc/passwd", absoluteTarget.Value().text);
}

TEST_F(PathAliasTest, ProcfsMagicLinkCannotEnterManualResolver)
{
    auto opened = context.OpenAbsolutePin("/proc/self/exe", false);
    ASSERT_TRUE(opened.HasValue());
    Descriptor magic = std::move(opened).Value();
    auto denied = ReadPinnedLink(magic, 4096, 4096);
    ASSERT_FALSE(denied.HasValue());
    EXPECT_EQ(ELOOP, denied.Error().code);
}

TEST_F(PathAliasTest, PinnedLinkRejectsEmptyNulAndNonLinkWithoutConsumingPin)
{
    const std::string link = context.GetTempdirPath() + "/bounded.link";
    ASSERT_EQ(0, ::symlink("target", link.c_str()));
    auto opened = context.OpenAbsolutePin(link.c_str(), false);
    ASSERT_TRUE(opened.HasValue());
    Descriptor pin = std::move(opened).Value();
    const std::size_t before = CountOpenDescriptors();
    EXPECT_CALL(context, ReadLinkDescriptor(_, _, _)).WillOnce([](int, char*, std::size_t) -> ssize_t { return 0; }).WillOnce([](int, char* buffer, std::size_t) -> ssize_t {
        std::memcpy(buffer, "a\0b", 3);
        return 3;
    });
    auto empty = ReadPinnedLink(pin, 16, 4096);
    ASSERT_FALSE(empty.HasValue());
    EXPECT_EQ(E2BIG, empty.Error().code);
    auto nul = ReadPinnedLink(pin, 16, 4096);
    ASSERT_FALSE(nul.HasValue());
    EXPECT_EQ(EINVAL, nul.Error().code);
    EXPECT_EQ(before, CountOpenDescriptors());
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));
    auto valid = ReadPinnedLink(pin, 16, 4096);
    ASSERT_TRUE(valid.HasValue()) << valid.Error().message;
    EXPECT_EQ("target", valid.Value().text);

    const std::string file = context.MakeTempfile("ordinary");
    auto regular = context.OpenAbsolutePin(file.c_str(), false);
    ASSERT_TRUE(regular.HasValue());
    auto denied = ReadPinnedLink(regular.Value(), 16, 4096);
    ASSERT_FALSE(denied.HasValue());
    EXPECT_EQ(ELOOP, denied.Error().code);
}

TEST_F(PathAliasTest, PinnedLinkReadRechecksIdentityAndMount)
{
    const std::string link = context.GetTempdirPath() + "/observed.link";
    ASSERT_EQ(0, ::symlink("target", link.c_str()));
    auto opened = context.OpenAbsolutePin(link.c_str(), false);
    ASSERT_TRUE(opened.HasValue());
    Descriptor pin = std::move(opened).Value();
    const std::size_t before = CountOpenDescriptors();

    int observations = 0;
    EXPECT_CALL(context, StatFileDescriptor(_, _)).WillRepeatedly([&](int fd, struct stat* snapshot) {
        const int status = context.RealStatFileDescriptor(fd, snapshot);
        if (status == 0 && S_ISLNK(snapshot->st_mode) && ++observations == 2)
            ++snapshot->st_ino;
        return status;
    });
    auto changed = ReadPinnedLink(pin, 16, 4096);
    ASSERT_FALSE(changed.HasValue());
    EXPECT_EQ(EAGAIN, changed.Error().code);
    EXPECT_EQ(2, observations);
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));

    int records = 0;
    EXPECT_CALL(context, ReadFileDescriptor(_, _, _)).WillRepeatedly([&](int fd, void* buffer, std::size_t size) {
        const ssize_t bytes = context.RealReadFileDescriptor(fd, buffer, size);
        if (bytes > 0 && DescriptorTarget(fd).find("/fdinfo/") != std::string::npos &&
            std::string(static_cast<char*>(buffer), static_cast<std::size_t>(bytes)).find("mnt_id:") != std::string::npos && ++records == 2)
            AlterFdinfoMountId(buffer, bytes);
        return bytes;
    });
    auto mount = ReadPinnedLink(pin, 16, 4096);
    ASSERT_FALSE(mount.HasValue());
    EXPECT_EQ(EAGAIN, mount.Error().code);
    EXPECT_EQ(2, records);
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, PinnedLinkReadFailsClosedOnMountAndStatObservationErrors)
{
    const std::string link = context.GetTempdirPath() + "/fault.link";
    ASSERT_EQ(0, ::symlink("target", link.c_str()));
    auto opened = context.OpenAbsolutePin(link.c_str(), false);
    ASSERT_TRUE(opened.HasValue());
    Descriptor pin = std::move(opened).Value();
    const std::size_t before = CountOpenDescriptors();

    bool failedMount = false;
    EXPECT_CALL(context, ReadLinkDescriptor(_, _, _)).Times(0);
    EXPECT_CALL(context, ReadFileDescriptor(_, _, _)).WillRepeatedly([&](int fd, void* buffer, std::size_t size) {
        if (!failedMount && DescriptorTarget(fd).find("/fdinfo/") != std::string::npos)
        {
            failedMount = true;
            errno = ENOSPC;
            return static_cast<ssize_t>(-1);
        }
        return context.RealReadFileDescriptor(fd, buffer, size);
    });
    auto mount = ReadPinnedLink(pin, 16, 4096);
    ASSERT_FALSE(mount.HasValue());
    EXPECT_EQ(ENOSPC, mount.Error().code);
    EXPECT_TRUE(failedMount);
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(&context));

    int observations = 0;
    EXPECT_CALL(context, StatFileDescriptor(_, _)).WillRepeatedly([&](int fd, struct stat* snapshot) {
        const int status = context.RealStatFileDescriptor(fd, snapshot);
        if (status == 0 && S_ISLNK(snapshot->st_mode) && ++observations == 2)
        {
            errno = EIO;
            return -1;
        }
        return status;
    });
    auto stat = ReadPinnedLink(pin, 16, 4096);
    ASSERT_FALSE(stat.HasValue());
    EXPECT_EQ(EIO, stat.Error().code);
    EXPECT_EQ(2, observations);
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, PinnedLinkReadErrorOutranksHelperCloseFailure)
{
    const std::string link = context.GetTempdirPath() + "/failing.link";
    ASSERT_EQ(0, ::symlink("target", link.c_str()));
    auto opened = context.OpenAbsolutePin(link.c_str(), false);
    ASSERT_TRUE(opened.HasValue());
    Descriptor pin = std::move(opened).Value();
    const std::size_t before = CountOpenDescriptors();
    bool failedRead = false;
    EXPECT_CALL(context, ReadLinkDescriptor(_, _, _)).WillOnce([&](int, char*, std::size_t) -> ssize_t {
        failedRead = true;
        errno = ENOSPC;
        return -1;
    });
    bool failedClose = false;
    EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int fd) {
        const bool helper = IsProcfsHelper(fd);
        const int status = ::close(fd);
        EXPECT_EQ(0, status);
        if (helper && failedRead && !failedClose)
        {
            failedClose = true;
            errno = EIO;
            return -1;
        }
        return status;
    });
    auto failure = ReadPinnedLink(pin, 16, 4096);
    ASSERT_FALSE(failure.HasValue());
    EXPECT_EQ(ENOSPC, failure.Error().code);
    EXPECT_TRUE(failedRead);
    EXPECT_TRUE(failedClose);
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, PinnedLinkSuccessfulReadReportsHelperCloseFailure)
{
    const std::string link = context.GetTempdirPath() + "/close.link";
    ASSERT_EQ(0, ::symlink("target", link.c_str()));
    auto opened = context.OpenAbsolutePin(link.c_str(), false);
    ASSERT_TRUE(opened.HasValue());
    Descriptor pin = std::move(opened).Value();
    const std::size_t before = CountOpenDescriptors();
    bool read = false, failedClose = false;
    EXPECT_CALL(context, ReadLinkDescriptor(_, _, _)).WillOnce([&](int fd, char* buffer, std::size_t size) {
        read = true;
        return ::readlinkat(fd, "", buffer, size);
    });
    EXPECT_CALL(context, CloseFileDescriptor(_)).WillRepeatedly([&](int fd) {
        const bool helper = IsProcfsHelper(fd);
        const int status = ::close(fd);
        EXPECT_EQ(0, status);
        if (helper && read && !failedClose)
        {
            failedClose = true;
            errno = EIO;
            return -1;
        }
        return status;
    });
    auto failure = ReadPinnedLink(pin, 16, 4096);
    ASSERT_FALSE(failure.HasValue());
    EXPECT_EQ(EIO, failure.Error().code);
    EXPECT_TRUE(read);
    EXPECT_TRUE(failedClose);
    EXPECT_EQ(before, CountOpenDescriptors());
}

TEST_F(PathAliasTest, AcceptedRootRecognitionUsesHeldIdentityNotCandidateName)
{
    const std::string rootName = context.GetTempdirPath() + "/accepted";
    ASSERT_EQ(0, ::mkdir(rootName.c_str(), 0700));
    const ResolverLimits limits = AmpleLimits();
    const std::size_t before = CountOpenDescriptors();
    {
        auto accepted = SelectAcceptedPath(context, rootName, CrossMountPathPolicy(), limits);
        auto matching = SelectAcceptedPath(context, rootName, CrossMountPathPolicy(), limits);
        ASSERT_TRUE(accepted.HasValue());
        ASSERT_TRUE(matching.HasValue());
        EXPECT_EQ(accepted.Value().Root().AcquiredMetadata().st_ino, matching.Value().Root().AcquiredMetadata().st_ino);

        ASSERT_EQ(0, ::rename(rootName.c_str(), (rootName + ".former").c_str()));
        ASSERT_EQ(0, ::mkdir(rootName.c_str(), 0700));
        auto replacement = SelectAcceptedPath(context, rootName, CrossMountPathPolicy(), limits);
        ASSERT_TRUE(replacement.HasValue());
        EXPECT_NE(accepted.Value().Root().AcquiredMetadata().st_ino, replacement.Value().Root().AcquiredMetadata().st_ino);
        EXPECT_EQ(accepted.Value().Root().AcquiredMetadata().st_ino, matching.Value().Root().AcquiredMetadata().st_ino);
    }
    EXPECT_EQ(before, CountOpenDescriptors());
}
