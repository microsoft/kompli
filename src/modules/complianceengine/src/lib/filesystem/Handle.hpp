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
enum class Type
{
    Directory,
    RegularFile
};
struct LookupMountId
{
    explicit LookupMountId(std::uint64_t id) noexcept
        : value(id)
    {
    }
    std::uint64_t value;
};
struct TargetMountId
{
    explicit TargetMountId(std::uint64_t id) noexcept
        : value(id)
    {
    }
    std::uint64_t value;
};
struct UserId
{
    explicit UserId(uid_t id) noexcept
        : value(id)
    {
    }
    uid_t value;
};
struct GroupId
{
    explicit GroupId(gid_t id) noexcept
        : value(id)
    {
    }
    gid_t value;
};
struct AcquisitionFacts
{
    Type type;
    struct stat metadata;
    LookupMountId lookupMount;
    TargetMountId targetMount;
};
namespace Detail
{
class ProcfsDescriptorAccess;
class Handle;
struct LookupSpelling
{
    std::string value;
};
struct EffectiveSpelling
{
    std::string value;
};
} // namespace Detail
class Path;
class ReadableFile;
struct DirectoryChild
{
    std::string name;
    unsigned char type = DT_UNKNOWN; // untrusted readdir type hint, not acquired metadata
};
// Move-only directory stream on a verified descriptor alias. Its
// originating context must remain alive through Close/destruction; the
// originating Handle may be closed or destroyed.
class DirectoryCursor
{
public:
    DirectoryCursor(DirectoryCursor&& other) noexcept;
    DirectoryCursor& operator=(DirectoryCursor&& other) & noexcept;
    DirectoryCursor(const DirectoryCursor&) = delete;
    DirectoryCursor& operator=(const DirectoryCursor&) = delete;
    ~DirectoryCursor() noexcept;
    Result<Optional<std::string>> Next();
    Result<Optional<DirectoryChild>> NextEntry();
    // Single-attempt diagnostic-only release; never retry a reused descriptor.
    void Close() noexcept;

private:
    friend class ::ComplianceEngine::ContextInterface;
    DirectoryCursor(const ContextInterface& context, DIR* stream) noexcept;
    const ContextInterface* mContext = nullptr;
    DIR* mStream = nullptr;
};
// Internal unique acquisition; ordinary callers retain only Path::Component.
namespace Detail
{
class Handle
{
public:
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& other) noexcept;
    Handle& operator=(Handle&& other) & noexcept;
    ~Handle() noexcept = default;

    AcquisitionFacts Acquired() const noexcept;
    std::string LookupName() const;
    std::string EffectiveName() const;
    Result<struct stat> Stat() const;
    Result<bool> SetOwnership(UserId owner, GroupId group) const;
    Result<bool> SetMode(mode_t mode) const;
    Result<ReadableFile> OpenReadOnly() const;
    Result<ReadableFile> OpenReadOnly(ReadableFile::Policy policy) const;
    Result<DirectoryCursor> OpenChildren() const;

private:
    friend class ::ComplianceEngine::Filesystem::Path;
    friend class ::ComplianceEngine::Tests::DescriptorTestAccess;
    static Result<Descriptor> ActivateReadOnly(const ContextInterface& context, const Descriptor& pin, const struct stat& snapshot, bool directory,
        std::size_t fdinfoByteCap);
    static Result<Descriptor> ActivateReadOnlyImpl(const ContextInterface& context, const Descriptor& pin, const struct stat& snapshot, bool directory,
        std::size_t fdinfoByteCap, const std::uint64_t* heldMount);
    static Result<bool> OpenAndVerifyAlias(const ContextInterface& context, const ProcfsDescriptorAccess& procfs, const Descriptor& pin,
        Descriptor& aliasOwner, const struct stat& before, bool directory, std::size_t fdinfoByteCap, const std::uint64_t* heldMount);
    Handle(Descriptor descriptor, AcquisitionFacts facts, LookupSpelling lookup, EffectiveSpelling effective, std::size_t fdinfoByteCap);
    static Result<Handle> PinProcessRoot(const ContextInterface& context, std::size_t fdinfoBytes);
    static Result<bool> RecognizeAcceptedRoot(const Handle& acceptedRoot, const Handle& candidate, std::size_t fdinfoByteCap);
    Result<struct stat> Inspect() const;
    Result<bool> SetModeWithProcfs(const ProcfsDescriptorAccess& procfs, mode_t mode) const;
    void Swap(Handle& other) noexcept;

    Descriptor mDescriptor;
    AcquisitionFacts mFacts;
    LookupSpelling mLookupName;
    EffectiveSpelling mEffectiveName;
    std::size_t mFdinfoBytes;
};
} // namespace Detail
} // namespace Filesystem
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_FILESYSTEM_HANDLE_HPP
