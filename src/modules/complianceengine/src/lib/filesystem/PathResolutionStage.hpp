// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_FILESYSTEM_PATH_RESOLUTION_STAGE_HPP
#define COMPLIANCEENGINE_FILESYSTEM_PATH_RESOLUTION_STAGE_HPP

// Path implementation and the exact nonallocating Result-transfer test only.
#include "Path.hpp"

#include <utility>

namespace ComplianceEngine
{
namespace Filesystem
{
namespace Detail
{
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
    Result<bool> Close(const ContextInterface& context);

private:
    friend class ::ComplianceEngine::Filesystem::Path;
    friend struct ResolvedPathAllocationProbe; // focused allocator-failure test
    struct Pin
    {
        explicit Pin(Handle&& handle, std::string lookup = {}, std::string effective = {})
            : handle(std::move(handle)),
              lookup(std::move(lookup)),
              effective(std::move(effective))
        {
        }
        Handle handle;
        std::string lookup;
        std::string effective;
    };
    ResolvedPath()
        : mPins(new std::deque<Pin>())
    {
    }
    Handle TakeOwnedLeaf();
    // Indexes below the binding count select the location snapshot; indexes
    // at/above it select mPins. No pointers into either deque survive growth.
    // The heap-owned deques move by pointer transfer, not by deque move.
    std::unique_ptr<std::deque<Pin>> mPins;
    std::string mEffectiveLeaf;
    std::string mSourceLookup;
    std::vector<std::size_t> mFrames;
    std::size_t mOwnedLeaf = 0;
    bool mLeafTaken = false;
    std::size_t mAccountedBytes = 0;
    bool mInitialFollowedLink = false;
    std::uint64_t mInitialMountId = 0;
};
} // namespace Detail
} // namespace Filesystem
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_FILESYSTEM_PATH_RESOLUTION_STAGE_HPP
