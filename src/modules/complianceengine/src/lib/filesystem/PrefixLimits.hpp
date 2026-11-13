// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#ifndef COMPLIANCEENGINE_FILESYSTEM_PREFIX_LIMITS_HPP
#define COMPLIANCEENGINE_FILESYSTEM_PREFIX_LIMITS_HPP
#include <cstddef>
namespace ComplianceEngine
{
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
namespace Detail
{
// Path reserves three temporary procfs descriptors: either the bootstrap
// directories or the published fd/fdinfo pair plus one fdinfo reader.
// Physical pins are charged by Path; the starting cursor needs a separate
// slot. Path.cpp and FilesystemCollection.cpp both charge the same
// acquisition budget against request.limits.openDirectories using this
// shared definition.
constexpr std::size_t PathOperationSlots() noexcept
{
    return 3;
}
constexpr std::size_t StartingCursorSlots() noexcept
{
    return 1;
}
} // namespace Detail
} // namespace Filesystem
} // namespace ComplianceEngine
#endif // COMPLIANCEENGINE_FILESYSTEM_PREFIX_LIMITS_HPP
