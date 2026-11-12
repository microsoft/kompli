// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_FILESYSTEM_PATH_HPP
#define COMPLIANCEENGINE_FILESYSTEM_PATH_HPP

#include "Handle.hpp"
#include "PathLinkAccess.hpp"
#include "PrefixLimits.hpp"
#include "Variant.hpp"

#include <cstddef>
#include <memory>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>

namespace ComplianceEngine
{
class ContextInterface;
namespace Filesystem
{
enum class MountPolicy
{
    CrossMounts,
    StayOnRootMount
};
struct ResolverLimits
{
    PrefixLimits shared;
    std::size_t linkTargetBytes = 4096;
    std::size_t linkExpansions = 128;
    std::size_t depth = 128;
};
enum class PrefixLinkPolicy
{
    Reject,
    Follow
};
enum class FileLinkPolicy
{
    Reject,
    Follow
};
enum class DirectoryLinkPolicy
{
    Reject,
    Follow
};
enum class RejectedLinkDisposition
{
    Error,
    Skip
};
enum class UnsupportedTypeDisposition
{
    Error,
    Skip
};
enum class MissingFileDisposition
{
    Error,
    Report
};

// A Path always owns the process root and keeps all ancestors of its barrier.
// Context must outlive every Path, Step and copied Component.
class Path
{
public:
    enum class RejectionReason
    {
        Missing,
        Excluded,
        UnsupportedType
    };
    struct Policy
    {
        PrefixLinkPolicy prefixLinks = PrefixLinkPolicy::Reject;
        FileLinkPolicy fileLinks = FileLinkPolicy::Reject;
        DirectoryLinkPolicy directoryLinks = DirectoryLinkPolicy::Reject;
        RejectedLinkDisposition rejectedLinks = RejectedLinkDisposition::Error;
        UnsupportedTypeDisposition unsupportedTypes = UnsupportedTypeDisposition::Error;
        MissingFileDisposition missingFiles = MissingFileDisposition::Error;
        MountPolicy mounts = MountPolicy::StayOnRootMount;
    };

    class Component
    {
    public:
        Component() = delete;
        Component(const Component&) noexcept;
        Component& operator=(const Component&) & noexcept;
        Component(Component&& other) noexcept;
        Component& operator=(Component&& other) & noexcept;
        ~Component() noexcept;
        ::ComplianceEngine::Filesystem::Metadata Metadata() const;
        Result<struct stat> Stat() const;
        Result<bool> SetOwnership(UserId owner, GroupId group) const;
        Result<bool> SetMode(mode_t mode) const;
        Result<ReadableFile> OpenReadOnly() const;
        Result<ReadableFile> OpenReadOnly(ReadableFile::Policy policy) const;

    private:
        friend class Path;
        friend class FTW::Detail::DirectoryCursor;
        explicit Component(Detail::Handle owned);
        // The shared owner is immutable; these read the shared Handle's
        // acquisition directly (no copy), needing Component's private
        // mAcquisition plus the same friend-chain access to Handle/Metadata
        // Path already has -- Component, nested in Path, inherits it.
        static bool SameAcquisition(const Component& first, const Component& second) noexcept;
        static std::size_t LookupNameBytes(const Component& owner) noexcept;
        static std::size_t EffectiveNameBytes(const Component& owner) noexcept;
        static std::string LookupName(const Component& owner);
        static std::string EffectiveName(const Component& owner);
        std::shared_ptr<const Detail::Handle> mAcquisition;
    };

    class Step
    {
    public:
        Step() = delete;
        Step(const Step&) = delete;
        Step& operator=(const Step&) = delete;
        Step(Step&& other) noexcept
            : mData(other.mData)
        {
        }
        Step& operator=(Step&& other) & noexcept
        {
            mData = other.mData;
            return *this;
        }
        ~Step() noexcept = default;
        ::ComplianceEngine::Filesystem::Metadata Metadata() const;
        Component Target() const noexcept;
        std::size_t RetainedDescriptors() const noexcept;
        std::size_t RetainedBytes() const noexcept;

    private:
        struct Data;
        explicit Step(std::shared_ptr<const Data> data) noexcept
            : mData(std::move(data))
        {
        }
        std::shared_ptr<const Data> mData;
        friend class Path;
    };

    Path() = delete;
    Path(const Path&) = delete;
    Path& operator=(const Path&) = delete;
    Path(Path&& other) noexcept
        : mState(other.mState)
    {
    }
    Path& operator=(Path&& other) & noexcept
    {
        mState = other.mState;
        return *this;
    }
    ~Path() noexcept = default;

    static Result<Variant<Path, RejectionReason>> Make(const ContextInterface& context, std::string absolutePath, Policy policy, ResolverLimits limits);
    static Result<Variant<Path, RejectionReason>> Make(const ContextInterface&&, std::string, Policy, ResolverLimits) = delete;
    Result<Variant<Step, RejectionReason>> Resolve(std::string name, Policy policy) const;
    Result<Step> Apply(Step&& step) &;
    Result<bool> Freeze() &;
    // Root is the permanently retained process root, not the current barrier.
    Component Root() const noexcept;
    Component Leaf() const noexcept;
    std::string LookupName() const;
    std::string ToString() const;
    std::size_t Size() const noexcept;
    std::size_t RetainedDescriptors() const noexcept;
    std::size_t RetainedBytes() const noexcept;
    ResolverLimits Limits() const noexcept;
    const ContextInterface& Context() const noexcept;

private:
    struct State;
    enum class InputRole
    {
        Prefix,
        Leaf
    };
    class Resolver;
    // Private Path member (not anonymous-namespace) because it constructs
    // the private nested Resolver and reads limits only through the public
    // Limits() accessor.
    static Result<Variant<Step, RejectionReason>> ResolveInput(const Path& path, std::string name, Policy policy, InputRole role, std::size_t& followed);
    explicit Path(std::shared_ptr<const State> state) noexcept
        : mState(std::move(state))
    {
    }
    // Scopes the allocation-fault guard to exactly this construction so the
    // next heap allocation it covers is the shared root Handle, before it is
    // published into the initial State.
    static Component MakeRootComponent(Detail::Handle root);
    // Checked pinned-link readers: dispatch through ContextInterface's
    // friend-gated native surface (ReadLink/StatFile/StatusFlags/...), so
    // they stay private members of Path, the narrowest existing friend that
    // needs no Handle/Component state -- not anonymous-namespace functions.
    static Result<Detail::LinkTarget> ReadPinnedLink(const Detail::Descriptor& linkPin, std::size_t targetByteCap,
        std::size_t temporaryBudget = PrefixLimits{}.retainedBytes);
    static Result<Detail::LinkTarget> ReadVerifiedLinkText(const Detail::Descriptor& linkPin, const struct stat& before, std::size_t targetByteCap,
        std::size_t temporaryBudget);
    std::shared_ptr<const State> mState;
};
} // namespace Filesystem
} // namespace ComplianceEngine
#endif // COMPLIANCEENGINE_FILESYSTEM_PATH_HPP
