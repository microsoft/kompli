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
namespace Tests
{
class PathTestAccess; // defined only in the test target
}
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
        Result<ReadableFile> OpenReadOnly(ReadableFile::Policy policy = ReadableFile::Policy()) const;

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
            : mData(std::move(other.mData))
        {
        }
        Step& operator=(Step&& other) & noexcept
        {
            if (this != &other)
                mData = std::move(other.mData);
            return *this;
        }
        ~Step() noexcept = default;
        ::ComplianceEngine::Filesystem::Metadata Metadata() const;
        Component Target() const;
        std::size_t RetainedDescriptors() const;

    private:
        struct Data;
        explicit Step(std::shared_ptr<const Data> data) noexcept
            : mData(std::move(data))
        {
        }
        // Checked moved-from guard, ADR-0048 Decision 2: every state-reading
        // operation calls this first, before any other validation or native
        // dispatch, so a moved-from Step diagnoses deterministically instead
        // of reading retired state.
        void RequireLive() const;
        std::shared_ptr<const Data> mData;
        friend class Path;
    };

    Path() = delete;
    Path(const Path&) = delete;
    Path& operator=(const Path&) = delete;
    Path(Path&& other) noexcept
        : mState(std::move(other.mState))
    {
    }
    Path& operator=(Path&& other) & noexcept
    {
        if (this != &other)
            mState = std::move(other.mState);
        return *this;
    }
    ~Path() noexcept = default;

    static Result<Variant<Path, RejectionReason>> Make(const ContextInterface& context, std::string absolutePath, Policy policy, ResolverLimits limits);
    static Result<Variant<Path, RejectionReason>> Make(const ContextInterface&&, std::string, Policy, ResolverLimits) = delete;
    Result<Variant<Step, RejectionReason>> Resolve(std::string name, Policy policy) const;
    Result<Step> Apply(Step&& step) &;
    Result<bool> Freeze() &;
    // Root is the permanently retained process root, not the current barrier.
    Component Root() const;
    Component Leaf() const;
    std::size_t Size() const;
    std::size_t RetainedDescriptors() const;
    ResolverLimits Limits() const;
    const ContextInterface& Context() const;

private:
    // no production caller (logging included); kept for the
    // bounded-authority test accessor below, not deleted, because leaf
    // metadata is not an equivalent oracle.
    std::string LookupName() const;
    std::string ToString() const;
    friend class ::ComplianceEngine::Tests::PathTestAccess;
    // Checked moved-from guard, ADR-0048 Decision 2: every state-reading
    // operation calls this first, before any other validation or native
    // dispatch, so a moved-from Path diagnoses deterministically instead of
    // reading retired state.
    void RequireLive() const;
    struct State;
    enum class InputRole
    {
        Prefix,
        Leaf
    };
    class Resolver;
    // Private Path member (not anonymous-namespace) because it constructs
    // the private nested Resolver and reads mState directly: both callers
    // (Resolve, already checked; Make's factory loop, never moved) already
    // guarantee a live Path, so this internal read bypasses the checked
    // Limits() accessor rather than duplicating its moved-from check.
    static Result<Variant<Step, RejectionReason>> ResolveInput(const Path& path, std::string name, Policy policy, InputRole role, std::size_t& followed);
    explicit Path(std::shared_ptr<const State> state) noexcept
        : mState(std::move(state))
    {
    }
    // Checked root-component factory: dispatches through Component's
    // private constructor, so it stays a private member of Path, the
    // narrowest existing friend -- not an anonymous-namespace function.
    static Component MakeRootComponent(Detail::Handle root);
    // Checked pinned-link readers: dispatch through ContextInterface's
    // friend-gated native surface (ReadLink/StatFile/StatusFlags/...), so
    // they stay private members of Path, the narrowest existing friend that
    // needs no Handle/Component state -- not anonymous-namespace functions.
    static Result<Detail::LinkTarget> ReadPinnedLink(const Detail::Descriptor& linkPin, std::size_t targetByteCap);
    static Result<Detail::LinkTarget> ReadVerifiedLinkText(const Detail::Descriptor& linkPin, const struct stat& before, std::size_t targetByteCap);
    std::shared_ptr<const State> mState;
};
} // namespace Filesystem
} // namespace ComplianceEngine
#endif // COMPLIANCEENGINE_FILESYSTEM_PATH_HPP
