// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_FILESYSTEM_PATH_INTERNAL_HPP
#define COMPLIANCEENGINE_FILESYSTEM_PATH_INTERNAL_HPP

// Implementation and focused foundation tests only. Consumers include
// Handle.hpp or Path.hpp.
#include "ContextInterface.h"
#include "Path.hpp"

#include <utility>

namespace ComplianceEngine
{
namespace Filesystem
{
namespace Detail
{
// Implementation-only helpers shared by Path acquisition and Handle
// inspection. Descriptors are never exposed by the public headers.
int SavedError() noexcept;
bool SameIdentity(const struct stat& first, const struct stat& second) noexcept;
class ScopedDescriptor
{
public:
    ScopedDescriptor(const ContextInterface& context, int descriptor);
    ScopedDescriptor(const ScopedDescriptor&) = delete;
    ScopedDescriptor& operator=(const ScopedDescriptor&) = delete;
    ~ScopedDescriptor() noexcept;
    int Get() const noexcept;
    void Set(int descriptor) noexcept;
    int Transfer() noexcept;
    const ContextInterface& Context() const noexcept
    {
        return mContext;
    }
    // Relinquish ownership before the syscall. A failed close is never
    // retried, even if the kernel has already recycled its fd number.
    int CloseOnce() noexcept;
    template <typename T>
    Result<T> Finish(Result<T> result);

private:
    const ContextInterface& mContext;
    int mDescriptor;
};
struct VerifiedProcfs
{
    explicit VerifiedProcfs(const ContextInterface& context);
    Result<bool> Open();
    int CloseOnce() noexcept;
    template <typename T>
    Result<T> Finish(Result<T> result);
    ScopedDescriptor proc, self, pid, fd, fdinfo;
};
// Keep the operation error; report a cleanup failure only when no earlier
// error exists. Every Finish attempts all owned descriptors and logs
// secondary failures. Called on normal returns; destructors remain fallback.
template <typename T>
Result<T> FinalizeResult(const ContextInterface& context, Result<T> result, int closeError)
{
    if (0 != closeError)
    {
        if (result.HasValue())
        {
            return Error("Cannot close internal filesystem descriptor", closeError);
        }
        try
        {
            OsConfigLogError(context.GetLogHandle(), "Secondary filesystem helper close failure: %d", closeError);
        }
        catch (...)
        {
        }
    }
    return result;
}
template <typename T>
Result<T> ScopedDescriptor::Finish(Result<T> result)
{
    return FinalizeResult(mContext, std::move(result), CloseOnce());
}
template <typename T>
Result<T> VerifiedProcfs::Finish(Result<T> result)
{
    // The first failing close in release order wins; each later failure is
    // logged, including when the operation itself had already failed.
    return FinalizeResult(proc.Context(), std::move(result), CloseOnce());
}
Result<std::uint64_t> MountId(const ContextInterface& context, int fdinfoDirectory, int descriptor, std::size_t byteCap);

// Keep popped handles charged to their originating Path while any pin lives.
struct DetachedResources
{
    std::size_t descriptors = 0;
    std::size_t bytes = 0;
};

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
Result<LinkTarget> ReadPinnedLink(const ContextInterface& context, int linkPin, std::size_t targetByteCap, std::size_t fdinfoByteCap);

// Internal read-only activation of an already held O_PATH pin. The returned
// descriptor is independently owned and never exposed through Path.hpp.
class ReadOnlyActivation
{
public:
    ReadOnlyActivation(ReadOnlyActivation&& other) noexcept;
    ReadOnlyActivation& operator=(ReadOnlyActivation&& other) noexcept;
    ReadOnlyActivation(const ReadOnlyActivation&) = delete;
    ReadOnlyActivation& operator=(const ReadOnlyActivation&) = delete;
    ~ReadOnlyActivation() noexcept;
    const struct stat& Snapshot() const noexcept;
    int Descriptor() const noexcept;
    // Internal ownership handoff to an opaque public resource.
    int Transfer() noexcept;
    int CloseOnce() noexcept;

private:
    friend Result<ReadOnlyActivation> ActivateReadOnly(const ContextInterface&, int, const struct stat&, bool, std::size_t);
    ReadOnlyActivation(const ContextInterface& context, int descriptor, const struct stat& snapshot) noexcept;
    const ContextInterface* mContext;
    int mDescriptor;
    struct stat mSnapshot;
};
Result<ReadOnlyActivation> ActivateReadOnly(const ContextInterface& context, int pin, const struct stat& snapshot, bool directory, std::size_t fdinfoByteCap);

// Internal result retains all pins acquired during the resolution, including
// hidden directories reached through links. Its borrowed leaf, if any, is
// valid only while the caller's accepted root and parent lineage remain live.
class ResolvedPath
{
public:
    ResolvedPath(ResolvedPath&&) noexcept = default;
    ResolvedPath& operator=(ResolvedPath&&) noexcept = default;
    ResolvedPath(const ResolvedPath&) = delete;
    ResolvedPath& operator=(const ResolvedPath&) = delete;
    const Handle& Leaf() const;
    // Private acquisition lineage for a subsequent internal child resolution.
    // The result and its borrowed root/parent inputs must outlive these refs.
    std::vector<const Handle*> DirectoryLineage() const;
    std::size_t OwnedDescriptors() const noexcept;
    std::size_t AccountedBytes() const noexcept;

private:
    friend class ::ComplianceEngine::Filesystem::Path;
    ResolvedPath() = default;
    Handle TakeOwnedLeaf();
    void ForwardLeaf(const Handle& external);
    struct Frame
    {
        const Handle* borrowed = nullptr;
        std::size_t ownedIndex = 0;
        bool owned = false;
    };
    std::deque<Handle> mPins;
    std::vector<Frame> mFrames;
    const Handle* mBorrowedLeaf = nullptr;
    std::size_t mOwnedLeaf = 0;
    bool mOwnsLeaf = false;
    bool mLeafTaken = false;
    const Handle* mForwardedLeaf = nullptr;
    std::size_t mAccountedBytes = 0;
    Optional<struct stat> mInitialLinkMetadata;
};

} // namespace Detail
} // namespace Filesystem
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_FILESYSTEM_PATH_INTERNAL_HPP
