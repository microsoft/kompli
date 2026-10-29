// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_FILESYSTEM_PATH_INTERNAL_HPP
#define COMPLIANCEENGINE_FILESYSTEM_PATH_INTERNAL_HPP

// Implementation and focused foundation tests only. Consumers include
// Handle.hpp or Path.hpp.
#include "Descriptor.hpp"
#include "Path.hpp"

namespace ComplianceEngine
{
namespace Filesystem
{
namespace Detail
{
// Implementation-only helpers shared by Path acquisition and Handle
// inspection. Descriptors are never exposed by the public headers.
int SavedError() noexcept;
// Diagnostics only: callers decide whether a failed close is primary.
void LogSecondaryClose(const ContextInterface& context, int error) noexcept;
bool SameIdentity(const struct stat& first, const struct stat& second) noexcept;
struct VerifiedProcfs
{
    explicit VerifiedProcfs(const ContextInterface& context);
    VerifiedProcfs(const ContextInterface&&) = delete;
    Result<bool> Open();
    Result<bool> Close();
    const Descriptor& ProcDirectory() const noexcept
    {
        return proc;
    }
    const Descriptor& FdDirectory() const noexcept
    {
        return fd;
    }
    const Descriptor& FdinfoDirectory() const noexcept
    {
        return fdinfo;
    }

private:
    friend class ::ComplianceEngine::ContextInterface;
    bool VerifyRole(const ContextInterface& context, bool information) const;
    // Only Open() fills the role owners after verifying /proc/self against
    // the current PID. Ordinary callers cannot replace or swap these pins.
    Descriptor proc, self, pid, fd, fdinfo;
    bool mVerified = false;
    struct stat mFdIdentity = {}, mFdinfoIdentity = {};
};
Result<std::uint64_t> MountId(const ContextInterface& context, const VerifiedProcfs& procfs, const Descriptor& descriptor, std::size_t byteCap);

// A strict child component, not a pathname. Root resolution and any
// whole-path parsing belong to the separately authorized acquisition layer.
bool IsSingleChildComponent(const std::string& component) noexcept;
Result<std::uint64_t> ParseMountId(const std::string& fdinfo);

// Inspection only: no kernel-follow of a link, including procfs magic links.
// The caller owns and keeps the O_PATH|O_NOFOLLOW link pin live.
struct LinkTarget
{
    std::string text;
    std::uint64_t mountId = 0;
};
Result<LinkTarget> ReadPinnedLink(const ContextInterface& context, const Descriptor& linkPin, std::size_t targetByteCap, std::size_t fdinfoByteCap);

// Internal read-only activation of an already held O_PATH pin. The returned
// descriptor is independently owned and never exposed through Path.hpp.
Result<Descriptor> ActivateReadOnly(const ContextInterface& context, const Descriptor& pin, const struct stat& snapshot, bool directory, std::size_t fdinfoByteCap);

// Ephemeral resolver staging only. Path commits its pins and checked physical
// indexes into one owning deque; no stage survives a Make/Push operation.
class ResolvedPath
{
public:
    ResolvedPath(ResolvedPath&&) noexcept = default;
    ResolvedPath& operator=(ResolvedPath&&) noexcept = default;
    ResolvedPath(const ResolvedPath&) = delete;
    ResolvedPath& operator=(const ResolvedPath&) = delete;
    const Handle& Leaf() const;
    std::size_t OwnedDescriptors() const noexcept;
    std::size_t AccountedBytes() const noexcept;
    // Checked, attempt-all release of every pin still owned by this stage.
    Result<bool> Close(const ContextInterface& context);

private:
    friend class ::ComplianceEngine::Filesystem::Path;
    friend struct ResolvedPathAllocationProbe; // focused allocator-failure test
    struct Pin
    {
        Pin(Handle&& handle, std::string name)
            : handle(std::move(handle)),
              effective(std::move(name))
        {
        }
        Handle handle;
        std::string effective;
    };
    ResolvedPath()
        : mPins(new std::deque<Pin>())
    {
    }
    Handle TakeOwnedLeaf();
    using Frame = Variant<const Handle*, std::size_t>;
    // The heap-owned deques move by pointer transfer, not by deque move.
    std::unique_ptr<std::deque<Pin>> mPins;
    std::string mEffectiveLeaf;
    std::string mSourceLookup;
    std::vector<Frame> mFrames;
    std::size_t mOwnedLeaf = 0;
    bool mLeafTaken = false;
    std::size_t mAccountedBytes = 0;
    bool mInitialFollowedLink = false;
    std::uint64_t mInitialMountId = 0;
};

} // namespace Detail
} // namespace Filesystem
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_FILESYSTEM_PATH_INTERNAL_HPP
