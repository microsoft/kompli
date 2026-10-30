// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_FILESYSTEM_HANDLE_HPP
#define COMPLIANCEENGINE_FILESYSTEM_HANDLE_HPP

#include "Descriptor.hpp"
#include "Optional.h"
#include "ReadableFile.hpp"
#include "Result.h"

#include <cstddef>
#include <cstdint>
#include <dirent.h>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>

namespace ComplianceEngine
{
class ContextInterface;

namespace Filesystem
{
namespace Detail
{
class ProcfsDescriptorAccess;
}
class Path;
class Handle;
class ReadableFile;
struct DirectoryChild
{
    std::string name;
    unsigned char type = DT_UNKNOWN; // untrusted readdir type hint, not acquired metadata
};
// Move-only, checked directory stream on a verified descriptor alias. Its
// originating context must remain alive through Close/destruction; the
// originating Handle may be closed or destroyed.
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
    // Relinquish the stream before closedir; return an actual close failure
    // once, never retrying against a possibly reused descriptor.
    Result<bool> Close();

private:
    friend class ::ComplianceEngine::ContextInterface;
    DirectoryCursor(const ContextInterface& context, DIR* stream) noexcept;
    const ContextInterface* mContext = nullptr;
    DIR* mStream = nullptr;
};
// Owns exactly one pinned descriptor. A popped handle needs only its own pin
// for inspection, read-only activation and metadata operations;
// it cannot extend a Path or reacquire its former parent. Construction is
// confined to Path's acquisition implementation; neither the descriptor nor
// ownership escapes through this interface. Popped handles are independently
// owned and no longer count against their former Path's resource limits;
// consumers must bound how many they retain. The context must outlive them.
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
    // Frozen names of this acquisition, not live canonical paths or authority
    // for a new lookup. Available after Close, but not on moved-from owners.
    // References expire when this owner is moved or destroyed.
    const std::string& LookupName() const& noexcept;
    const std::string& LookupName() const&& = delete;
    const std::string& EffectiveName() const& noexcept;
    const std::string& EffectiveName() const&& = delete;
    // Mount of the originally looked-up name, before following a link; it
    // need not be the mount of the held target.
    std::uint64_t OriginalMount() const noexcept;
    // Historical acquisition identity, copied by value; never authority for
    // current permissions. Available even after Close; do not query moved-from owners.
    struct stat AcquiredMetadata() const noexcept;
    // Fresh stat of the held object, without resolving its former pathname.
    // It may immediately be stale: neither this observation nor matching
    // before/after stats prove an atomic content snapshot, absence of
    // concurrent writes, race-free authorization or exclusive hardlink
    // membership. Uses the acquisition-bound inspection budget and trusted procfs.
    Result<struct stat> Stat() const;
    // Mount identity of this held descriptor, verified with its inode/type.
    // Unlike st_dev, this distinguishes a same-device bind mount.
    Result<std::uint64_t> MountIdentity() const;
    // One syscall per method; callers retain existing rule mask, ordering and
    // hardlink checks. No ownership/mode transaction or rollback is implied.
    // A post-syscall verification failure can report an error after mutation.
    Result<bool> SetOwnership(uid_t owner, gid_t group) const;
    Result<bool> SetMode(mode_t mode) const;
    // Activates only a held regular file, using verified procfs alias identity
    // and mount checks. The new descriptor survives this Handle's destruction.
    Result<ReadableFile> OpenReadOnly() const;
    Result<ReadableFile> OpenReadOnly(ReadableFile::Policy policy) const;
    // Enumerate through a verified read-only alias; only names escape.
    // Children must still be acquired from the live parent Path.
    Result<DirectoryCursor> OpenChildren() const;
    // Relinquish this pin before attempting its native close, exactly once.
    // A failed close is returned only on the actual attempt; later calls
    // succeed without retrying a possibly reused number. Existing readable
    // files remain valid. Descriptor logs native close errors.
    Result<bool> Close();

private:
    struct PinObservation
    {
        struct stat metadata;
        std::uint64_t mountId;
    };
    // Path owns composition. The checked acquisition methods below are
    // private: no consumer can supply an fd.
    friend class Path;
    Handle(Detail::Descriptor&& descriptor, Type type, const struct stat& snapshot, std::size_t fdinfoBytes, std::string lookup, std::string effective,
        std::uint64_t originalMount);
    static Result<Handle> PinProcessRoot(const ContextInterface& context, std::size_t fdinfoBytes);
    static Result<bool> RecognizeAcceptedRoot(const Handle& acceptedRoot, const Handle& candidate, std::size_t fdinfoByteCap);
    Result<PinObservation> InspectWithProcfs(const Detail::ProcfsDescriptorAccess& procfs) const;
    Result<bool> SetModeWithProcfs(const Detail::ProcfsDescriptorAccess& procfs, mode_t mode) const;
    void Swap(Handle& other) noexcept;

    Detail::Descriptor mDescriptor;
    Type mType = Type::Directory;
    std::string mLookupName;
    std::string mEffectiveName;
    std::uint64_t mOriginalMount = 0;
    struct stat mAcquiredMetadata = {};
    std::size_t mFdinfoBytes;
};
} // namespace Filesystem
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_FILESYSTEM_HANDLE_HPP
