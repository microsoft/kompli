// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_FILESYSTEM_HANDLE_HPP
#define COMPLIANCEENGINE_FILESYSTEM_HANDLE_HPP

#include "Descriptor.hpp"
#include "Optional.h"
#include "Result.h"

#include <cstddef>
#include <cstdint>
#include <dirent.h>
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
class Path;
struct PrefixLimits;
class Handle;
class ReadableFile;
struct DirectoryChild
{
    std::string name;
    unsigned char type = DT_UNKNOWN; // untrusted readdir type hint, not acquired metadata
};
// Move-only, checked directory stream on a verified descriptor alias. Its
// originating Handle must remain alive through Close/destruction.
class DirectoryCursor
{
public:
    DirectoryCursor(DirectoryCursor&& other) noexcept;
    DirectoryCursor& operator=(DirectoryCursor&& other) noexcept;
    DirectoryCursor(const DirectoryCursor&) = delete;
    DirectoryCursor& operator=(const DirectoryCursor&) = delete;
    ~DirectoryCursor() noexcept;
    Result<Optional<std::string>> Next();
    Result<Optional<DirectoryChild>> NextEntry();
    // Relinquish the stream before closedir; a failed/throwing close is
    // cached and never retried against a possibly reused descriptor.
    Result<bool> Close();

private:
    friend class Handle;
    DirectoryCursor(const ContextInterface& context, DIR* stream);
    const ContextInterface* mContext = nullptr;
    DIR* mStream = nullptr;
    int mCloseError = 0;
};
namespace Detail
{
struct DetachedResources;
} // namespace Detail

// Owns exactly one pinned descriptor. A popped handle needs only its own pin
// for inspection, read-only activation and metadata operations;
// it cannot extend a Path or reacquire its former parent. Construction is
// confined to Path's acquisition implementation; neither the descriptor nor
// ownership escapes through this interface. The context must outlive it.
class Handle
{
public:
    enum class Type
    {
        Directory,
        RegularFile
    };

    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& other) noexcept;
    Handle& operator=(Handle&& other) noexcept;
    ~Handle() noexcept;

    Type AcquiredType() const noexcept;
    const std::string& Component() const noexcept;
    // Cached stat observed during acquisition, not current metadata. The
    // held identity does not freeze content or metadata.
    const struct stat& Stat() const noexcept;
    // Fresh stat of the held object, without resolving its former pathname.
    // It may immediately be stale: neither this observation nor matching
    // before/after stats prove an atomic content snapshot, absence of
    // concurrent writes, race-free authorization or exclusive hardlink
    // membership. Requires a positive, caller-supplied fdinfo byte cap and
    // trusted procfs.
    Result<struct stat> Stat(std::size_t fdinfoByteCap) const;
    // Mount identity of this held descriptor, verified with its inode/type.
    // Unlike st_dev, this distinguishes a same-device bind mount.
    Result<std::uint64_t> MountIdentity(std::size_t fdinfoByteCap) const;
    // One syscall per method; callers retain existing rule mask, ordering and
    // hardlink checks. No ownership/mode transaction or rollback is implied.
    // A post-syscall verification failure can report an error after mutation.
    Result<bool> SetOwnership(uid_t owner, gid_t group, std::size_t fdinfoByteCap) const;
    Result<bool> SetMode(mode_t mode, std::size_t fdinfoByteCap) const;
    // Activates only a held regular file, using verified procfs alias identity
    // and mount checks. The new descriptor survives this Handle's destruction.
    Result<ReadableFile> OpenReadOnly(std::size_t fdinfoByteCap) const;
    // Enumerate through a verified read-only alias; only names escape.
    // Children must still be acquired from the live parent Path.
    Result<DirectoryCursor> OpenChildren(std::size_t fdinfoByteCap) const;
    // Relinquish this pin before attempting its native close, exactly once.
    // A failed close is returned unchanged on later calls, without retrying
    // a descriptor number that may have been reused. Detached Path accounting
    // is released on the first attempt. Existing readable files remain valid.
    // Destruction logs close failure only if no explicit attempt was made.
    Result<bool> Close();

private:
    // Path owns composition and detached-resource accounting. The checked
    // acquisition methods below are private: no consumer can supply an fd.
    friend class Path;
    Handle(Detail::Descriptor&& descriptor, Type type, std::string component, const struct stat& snapshot);
    static Result<Handle> AcquireChild(const ContextInterface& context, int parentDirectory, std::string component, bool directory);
    static Result<Handle> AcquireChild(const Handle& parent, std::string component, bool directory);
    static Result<Handle> PinProcessRoot(const ContextInterface& context);
    static Result<bool> RecognizeAcceptedRoot(const Handle& acceptedRoot, const Handle& candidate, std::size_t fdinfoByteCap);
    static Result<std::string> ValidateAbsolutePrefix(const ContextInterface& context, const std::vector<const Handle*>& heldLineage,
        const std::string& target, const PrefixLimits& limits);
    Result<struct stat> InspectWithProcfs(int fdinfoDirectory, std::size_t fdinfoByteCap, std::uint64_t& mountId) const;
    void Swap(Handle& other) noexcept;
    int CloseOnce() noexcept;

    const ContextInterface* mContext = nullptr;
    Detail::Descriptor mDescriptor;
    Type mType = Type::Directory;
    std::string mComponent;
    struct stat mSnapshot = {};
    bool mPin = true;
    int mCloseError = 0;
    std::shared_ptr<Detail::DetachedResources> mDetachedResources;
    std::size_t mDetachedBytes = 0;
};
} // namespace Filesystem
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_FILESYSTEM_HANDLE_HPP
