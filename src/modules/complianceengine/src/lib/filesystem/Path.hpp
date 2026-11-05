// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_FILESYSTEM_PATH_HPP
#define COMPLIANCEENGINE_FILESYSTEM_PATH_HPP

#include "FilesystemPolicy.hpp"
#include "Handle.hpp"
#include "PathLinkAccess.hpp"
#include "Variant.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <vector>

namespace ComplianceEngine
{
class ContextInterface;
namespace Filesystem
{
struct PrefixLimits
{
    std::size_t targetBytes = 4096;
    std::size_t components = 128;
    std::size_t work = 100000;
    std::size_t liveDescriptors = 256;
    std::size_t retainedBytes = std::size_t{1024} * 1024;
    std::size_t fdinfoBytes = 4096;
};
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
        Component(const Component&) noexcept = default;
        Component& operator=(const Component&) & noexcept = default;
        Component(Component&& other) noexcept
            : mAcquisition(other.mAcquisition)
        {
        }
        Component& operator=(Component&& other) & noexcept
        {
            mAcquisition = other.mAcquisition;
            return *this;
        }
        ~Component() noexcept = default;
        AcquisitionFacts Acquired() const noexcept
        {
            return mAcquisition->Acquired();
        }
        std::string LookupName() const
        {
            return mAcquisition->LookupName();
        }
        std::string EffectiveName() const
        {
            return mAcquisition->EffectiveName();
        }
        Result<struct stat> Stat() const
        {
            return mAcquisition->Stat();
        }
        Result<bool> SetOwnership(UserId owner, GroupId group) const
        {
            return mAcquisition->SetOwnership(owner, group);
        }
        Result<bool> SetMode(mode_t mode) const
        {
            return mAcquisition->SetMode(mode);
        }
        Result<ReadableFile> OpenReadOnly() const
        {
            return mAcquisition->OpenReadOnly();
        }
        Result<ReadableFile> OpenReadOnly(ReadableFile::Policy policy) const
        {
            return mAcquisition->OpenReadOnly(policy);
        }
        Result<DirectoryCursor> OpenChildren() const
        {
            return mAcquisition->OpenChildren();
        }

    private:
        friend class Path;
        explicit Component(Detail::Handle owned)
            : mAcquisition(std::make_shared<const Detail::Handle>(std::move(owned)))
        {
        }
        bool SameAcquisition(Component other) const noexcept
        {
            return mAcquisition == other.mAcquisition;
        }
        std::size_t LookupNameBytes() const noexcept
        {
            return mAcquisition->mLookupName.value.size();
        }
        std::size_t EffectiveNameBytes() const noexcept
        {
            return mAcquisition->mEffectiveName.value.size();
        }
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
        AcquisitionFacts Acquired() const noexcept;
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
    friend class ::ComplianceEngine::Tests::DescriptorTestAccess;
    struct State;
    struct WorkAllowance
    {
        std::size_t spent = 0;
    };
    enum class InputRole
    {
        Prefix,
        Leaf
    };
    class Resolver;
    explicit Path(std::shared_ptr<const State> state) noexcept
        : mState(std::move(state))
    {
    }
    Result<Variant<Step, RejectionReason>> ResolveInput(std::string name, Policy policy, InputRole role, std::size_t& followed) const;
    static Result<Detail::LinkTarget> ReadPinnedLink(const Detail::Descriptor& linkPin, std::size_t targetByteCap, std::size_t fdinfoByteCap,
        std::size_t temporaryBudget = PrefixLimits{}.retainedBytes);
    static Result<Detail::LinkTarget> ReadVerifiedLinkText(const Detail::Descriptor& linkPin, const struct stat& before,
        const Detail::ProcfsDescriptorAccess& procfs, std::size_t targetByteCap, std::size_t fdinfoByteCap, std::size_t temporaryBudget);
    std::shared_ptr<const State> mState;
};
} // namespace Filesystem
} // namespace ComplianceEngine
#endif // COMPLIANCEENGINE_FILESYSTEM_PATH_HPP
