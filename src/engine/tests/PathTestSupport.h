// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_TESTS_PATH_TEST_SUPPORT_H
#define COMPLIANCEENGINE_TESTS_PATH_TEST_SUPPORT_H

#include <MockContext.h>
#include <cerrno>
#include <cstdint>
#include <dirent.h>
#include <filesystem/Path.hpp>
#include <fstream>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <iterator>
#include <string>
#include <unistd.h>

// Path layer: fixtures and helpers shared by PathTest.cpp (Path layer) and
// PathTraversalTest.cpp (FTW layer, the FTW-dependent cases moved out of
// PathTest.cpp -- see PathTraversalTest.cpp). Kept here, instead of
// duplicated, so each test file covers one layer; the FTW-layer file may
// include this Path-layer header.

namespace ComplianceEngine
{
namespace Tests
{
inline std::string ReadLog(const std::string& path)
{
    std::ifstream log(path);
    EXPECT_TRUE(log.is_open());
    return {std::istreambuf_iterator<char>(log), std::istreambuf_iterator<char>()};
}

inline void ExpectLoggedOnce(const std::string& text, const std::string& entry)
{
    const auto at = text.find(entry);
    ASSERT_NE(std::string::npos, at);
    EXPECT_EQ(std::string::npos, text.find(entry, at + entry.size()));
}

inline Filesystem::Path::Policy CrossMountPathPolicy(bool following = false)
{
    Filesystem::Path::Policy policy;
    policy.prefixLinks = following ? Filesystem::PrefixLinkPolicy::Follow : Filesystem::PrefixLinkPolicy::Reject;
    policy.mounts = Filesystem::MountPolicy::CrossMounts;
    policy.fileLinks = following ? Filesystem::FileLinkPolicy::Follow : Filesystem::FileLinkPolicy::Reject;
    policy.directoryLinks = following ? Filesystem::DirectoryLinkPolicy::Follow : Filesystem::DirectoryLinkPolicy::Reject;
    return policy;
}

// RAII-closed native descriptor, independent of the production Descriptor
// wrapper: used only to hold an oracle fd (e.g. a kernel-opened "/") for
// comparison against production results, never passed into production code.
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

inline std::size_t CountOpenDescriptors()
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

inline std::string DescriptorTarget(int descriptor)
{
    const std::string alias = "/proc/self/fd/" + std::to_string(descriptor);
    char target[512] = {};
    const ssize_t length = ::readlink(alias.c_str(), target, sizeof(target));
    return (0 < length) ? std::string(target, static_cast<std::size_t>(length)) : std::string();
}

// Independent of ParseMountId: only extracts mnt_id from genuine kernel
// fdinfo text (always well-formed), so it never needs the production
// parser's malformed-input rejection. A hand-computed oracle, not a reuse
// of the formula under test.
inline Result<std::uint64_t> OracleMountId(const std::string& fdinfo)
{
    const std::string key = "mnt_id:";
    std::size_t lineStart = 0;
    while (lineStart < fdinfo.size())
    {
        const std::size_t end = fdinfo.find('\n', lineStart);
        const std::size_t lineEnd = (end == std::string::npos) ? fdinfo.size() : end;
        if ((fdinfo.compare(lineStart, key.size(), key) == 0))
        {
            std::size_t position = lineStart + key.size();
            while ((position < lineEnd) && ((fdinfo[position] == ' ') || (fdinfo[position] == '\t')))
                ++position;
            std::uint64_t value = 0;
            for (; (position < lineEnd) && (fdinfo[position] >= '0') && (fdinfo[position] <= '9'); ++position)
                value = (value * 10) + static_cast<unsigned>(fdinfo[position] - '0');
            return value;
        }
        if (end == std::string::npos)
            break;
        lineStart = end + 1;
    }
    return Error("Oracle fixture fdinfo has no mnt_id", EPROTO);
}

inline Result<std::uint64_t> KernelMountId(int descriptor)
{
    std::ifstream info("/proc/self/fdinfo/" + std::to_string(descriptor));
    if (!info.is_open())
    {
        return Error("Cannot open kernel fdinfo", errno);
    }
    const std::string contents(std::istreambuf_iterator<char>{info}, std::istreambuf_iterator<char>{});
    if (info.bad())
    {
        return Error("Cannot read kernel fdinfo", EIO);
    }
    return OracleMountId(contents);
}

inline Result<Filesystem::Path> SelectAcceptedPath(const ContextInterface& context, const std::string& path, Filesystem::Path::Policy policy,
    Filesystem::ResolverLimits limits)
{
    auto selected = Filesystem::Path::Make(context, path, policy, limits);
    if (!selected.HasValue())
        return std::move(selected).Error();
    if (!selected.Value().Is<Filesystem::Path>())
        return Error("Fixture path unavailable", ENOENT);
    Filesystem::Path accepted = As<Filesystem::Path>(std::move(selected.Value()));
    auto frozen = accepted.Freeze();
    if (!frozen.HasValue())
        return std::move(frozen).Error();
    return accepted;
}

// TM-9: physical root, barrier, and inverse are acquisition properties,
// never a lexical normalization of names or an open-by-name replay.
inline Result<Filesystem::Path::Step> SelectStep(const Filesystem::Path& path, const std::string& name, Filesystem::Path::Policy policy)
{
    auto outcome = path.Resolve(name, policy);
    if (!outcome.HasValue())
        return std::move(outcome).Error();
    if (!outcome.Value().Is<Filesystem::Path::Step>())
        return Error("Fixture child rejected", ENOENT);
    return As<Filesystem::Path::Step>(std::move(outcome.Value()));
}

class PathAliasTest : public testing::Test
{
protected:
    testing::NiceMock<MockContext> context;

    static Filesystem::ResolverLimits AmpleLimits()
    {
        Filesystem::ResolverLimits limits;
        limits.shared.components = 100;
        limits.linkExpansions = 8;
        return limits;
    }
};
} // namespace Tests
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_TESTS_PATH_TEST_SUPPORT_H
