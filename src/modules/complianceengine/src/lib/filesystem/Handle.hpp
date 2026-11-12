// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#ifndef COMPLIANCEENGINE_FILESYSTEM_HANDLE_HPP
#define COMPLIANCEENGINE_FILESYSTEM_HANDLE_HPP

#include "Descriptor.hpp"
#include "PrefixLimits.hpp"
#include "ReadableFile.hpp"
#include "Result.h"

#include <cstdint>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <type_traits>
#include <utility>

namespace ComplianceEngine
{
class ContextInterface;
namespace Filesystem
{
class Path;
namespace FTW
{
namespace Detail
{
class DirectoryCursor;
}
} // namespace FTW
namespace Detail
{
class Handle;
class ProcfsDescriptorAccess;
} // namespace Detail
enum class Type
{
    Directory,
    RegularFile
};
// Non-const data members: provenance is sealed by the private constructor and
// friendship below, not by const members (which would delete assignment and
// force throwing copies on every move). Rule of zero: copies and moves stay
// implicit and noexcept; the static_asserts below guard it.
class LookupMountId
{
public:
    std::uint64_t Value() const noexcept
    {
        return mValue;
    }

private:
    friend class Path;
    friend class Detail::Handle;
    explicit LookupMountId(std::uint64_t id) noexcept
        : mValue(id)
    {
    }
    std::uint64_t mValue;
};
class TargetMountId
{
public:
    std::uint64_t Value() const noexcept
    {
        return mValue;
    }

private:
    friend class Path;
    friend class Detail::Handle;
    explicit TargetMountId(std::uint64_t id) noexcept
        : mValue(id)
    {
    }
    std::uint64_t mValue;
};
class UserId
{
public:
    explicit UserId(uid_t id) noexcept
        : mValue(id)
    {
    }
    uid_t Value() const noexcept
    {
        return mValue;
    }

private:
    uid_t mValue;
};
class GroupId
{
public:
    explicit GroupId(gid_t id) noexcept
        : mValue(id)
    {
    }
    gid_t Value() const noexcept
    {
        return mValue;
    }

private:
    gid_t mValue;
};
namespace Detail
{
class LookupSpelling
{
public:
    // Allocates: returns a fresh copy so a temporary Metadata/Handle result
    // can be destroyed without dangling a bound const reference.
    std::string Value() const
    {
        return mValue;
    }

private:
    friend class ::ComplianceEngine::Filesystem::Path;
    friend class Handle;
    explicit LookupSpelling(std::string name)
        : mValue(std::move(name))
    {
    }
    std::string mValue;
};
class EffectiveSpelling
{
public:
    std::string Value() const
    {
        return mValue;
    }

private:
    friend class ::ComplianceEngine::Filesystem::Path;
    friend class Handle;
    explicit EffectiveSpelling(std::string name)
        : mValue(std::move(name))
    {
    }
    std::string mValue;
};
} // namespace Detail
class Metadata
{
public:
    // "Type()" would clash with the enum class Type above once declared as a
    // member name in this class; GCC rejects the resulting self-reference.
    Type FileType() const noexcept
    {
        return mType;
    }
    struct stat Stat() const noexcept
    {
        return mStat;
    }
    LookupMountId LookupMount() const noexcept
    {
        return mLookupMount;
    }
    TargetMountId TargetMount() const noexcept
    {
        return mTargetMount;
    }
    // Allocates: a const-ref getter would dangle on a temporary Metadata().
    std::string LookupName() const
    {
        return mLookupName.Value();
    }
    std::string EffectiveName() const
    {
        return mEffectiveName.Value();
    }

private:
    friend class Path;
    friend class Detail::Handle;
    Metadata(Type kind, const struct stat& info, LookupMountId lookup, TargetMountId target, Detail::LookupSpelling source, Detail::EffectiveSpelling effective)
        : mType(kind),
          mStat(info),
          mLookupMount(lookup),
          mTargetMount(target),
          mLookupName(std::move(source)),
          mEffectiveName(std::move(effective))
    {
    }
    Type mType;
    struct stat mStat;
    LookupMountId mLookupMount;
    TargetMountId mTargetMount;
    Detail::LookupSpelling mLookupName;
    Detail::EffectiveSpelling mEffectiveName;
};
static_assert(std::is_nothrow_move_constructible<Metadata>::value,
    "Metadata must be nothrow move constructible (shared Handle allocation relies on it)");
static_assert(std::is_nothrow_move_assignable<Metadata>::value, "Metadata must be nothrow move assignable");
// Rule of zero for the strong value types above: these guard that the
// implicit special members stay noexcept the way the hand-written ones used to.
static_assert(std::is_nothrow_move_constructible<LookupMountId>::value, "LookupMountId must be nothrow move constructible");
static_assert(std::is_nothrow_move_assignable<LookupMountId>::value, "LookupMountId must be nothrow move assignable");
static_assert(std::is_nothrow_copy_constructible<LookupMountId>::value, "LookupMountId must be nothrow copy constructible");
static_assert(std::is_nothrow_copy_assignable<LookupMountId>::value, "LookupMountId must be nothrow copy assignable");
static_assert(std::is_nothrow_move_constructible<TargetMountId>::value, "TargetMountId must be nothrow move constructible");
static_assert(std::is_nothrow_move_assignable<TargetMountId>::value, "TargetMountId must be nothrow move assignable");
static_assert(std::is_nothrow_copy_constructible<TargetMountId>::value, "TargetMountId must be nothrow copy constructible");
static_assert(std::is_nothrow_copy_assignable<TargetMountId>::value, "TargetMountId must be nothrow copy assignable");
static_assert(std::is_nothrow_move_constructible<UserId>::value, "UserId must be nothrow move constructible");
static_assert(std::is_nothrow_move_assignable<UserId>::value, "UserId must be nothrow move assignable");
static_assert(std::is_nothrow_copy_constructible<UserId>::value, "UserId must be nothrow copy constructible");
static_assert(std::is_nothrow_copy_assignable<UserId>::value, "UserId must be nothrow copy assignable");
static_assert(std::is_nothrow_move_constructible<GroupId>::value, "GroupId must be nothrow move constructible");
static_assert(std::is_nothrow_move_assignable<GroupId>::value, "GroupId must be nothrow move assignable");
static_assert(std::is_nothrow_copy_constructible<GroupId>::value, "GroupId must be nothrow copy constructible");
static_assert(std::is_nothrow_copy_assignable<GroupId>::value, "GroupId must be nothrow copy assignable");
static_assert(std::is_nothrow_move_constructible<Detail::LookupSpelling>::value, "LookupSpelling must be nothrow move constructible");
static_assert(std::is_nothrow_move_assignable<Detail::LookupSpelling>::value, "LookupSpelling must be nothrow move assignable");
static_assert(std::is_nothrow_move_constructible<Detail::EffectiveSpelling>::value, "EffectiveSpelling must be nothrow move constructible");
static_assert(std::is_nothrow_move_assignable<Detail::EffectiveSpelling>::value, "EffectiveSpelling must be nothrow move assignable");
namespace Detail
{
class Handle
{
public:
    Handle() = delete;
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& other) noexcept;
    Handle& operator=(Handle&& other) & noexcept;
    ~Handle() noexcept = default;
    ::ComplianceEngine::Filesystem::Metadata Metadata() const;
    Result<struct stat> Stat() const;
    Result<bool> SetOwnership(UserId owner, GroupId group) const;
    Result<bool> SetMode(mode_t mode) const;
    Result<ReadableFile> OpenReadOnly() const;
    Result<ReadableFile> OpenReadOnly(ReadableFile::Policy policy) const;

private:
    friend class ::ComplianceEngine::Filesystem::Path;
    friend class ::ComplianceEngine::Filesystem::FTW::Detail::DirectoryCursor;
    // The live O_PATH pin holds its kernel path (including mount). A verified
    // current-task procfd alias of that pin opens the same path; inode/type
    // checks reject a wrong-object alias. Every helper below dispatches
    // through ContextInterface's friend-gated native surface, so it stays a
    // member of Handle (or a nested type it returns), not a free function.
    static Result<Descriptor> OpenAndVerifyAlias(const ContextInterface& context, const ProcfsDescriptorAccess& procfs, const Descriptor& pin,
        const struct stat& before, Type directory);
    // The returned Descriptor retains the context used to open its alias: a
    // temporary argument here would dangle in the caller.
    static Result<Descriptor> OpenAndVerifyAlias(const ContextInterface&&, const ProcfsDescriptorAccess&, const Descriptor&, const struct stat&, Type) = delete;
    static Result<Descriptor> ActivateReadOnly(const ContextInterface& context, const Descriptor& pin, const struct stat& snapshot, Type directory);
    // Delegates to OpenAndVerifyAlias, so it retains context the same way.
    static Result<Descriptor> ActivateReadOnly(const ContextInterface&&, const Descriptor&, const struct stat&, Type) = delete;
    static Result<struct stat> Inspect(const Handle& owner);
    static Result<bool> SetModeWithProcfs(const Handle& owner, const ProcfsDescriptorAccess& procfs, mode_t mode);
    // Bundles an already-opened pin's identity snapshot with its verified
    // fdinfo mount id, observed together through one scoped procfs session
    // (which retires before this returns). The single acquisition helper
    // used by both the root-pin site (PinProcessRoot) and the resolver's
    // child-pin site, so neither calls ReadMountId directly.
    struct AcquiredPin
    {
        Descriptor pin;
        struct stat snapshot;
        std::uint64_t mount;
    };
    // No deleted rvalue overload: context is used only transiently here
    // (StatFile, a local ProcfsDescriptorAccess::Make/ReadMountId that
    // retires before return); the returned pin keeps whichever context it
    // was already opened with, not a binding created by this function.
    static Result<AcquiredPin> AcquirePinnedObject(const ContextInterface& context, Descriptor pin, std::size_t fdinfoByteCap, const char* statFailureMessage);
    static Result<Handle> PinProcessRoot(const ContextInterface& context, PrefixLimits limits);
    // The returned Handle retains the context used to pin "/" (OpenAbsolutePin):
    // a temporary argument here would dangle in the caller.
    static Result<Handle> PinProcessRoot(const ContextInterface&&, PrefixLimits) = delete;
    Handle(Descriptor descriptor, ::ComplianceEngine::Filesystem::Metadata metadata);
    Descriptor mDescriptor;
    ::ComplianceEngine::Filesystem::Metadata mMetadata;
};
} // namespace Detail
} // namespace Filesystem
} // namespace ComplianceEngine
#endif // COMPLIANCEENGINE_FILESYSTEM_HANDLE_HPP
