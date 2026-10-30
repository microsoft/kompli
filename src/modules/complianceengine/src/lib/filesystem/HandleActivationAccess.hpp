// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_FILESYSTEM_HANDLE_ACTIVATION_ACCESS_HPP
#define COMPLIANCEENGINE_FILESYSTEM_HANDLE_ACTIVATION_ACCESS_HPP

#include "Descriptor.hpp"

#include <cstddef>

namespace ComplianceEngine
{
namespace Filesystem
{
namespace Detail
{
// Handle's read-only activation of a held O_PATH pin; direct-test seam only.
Result<Descriptor> ActivateReadOnly(const ContextInterface& context, const Descriptor& pin, const struct stat& snapshot, bool directory, std::size_t fdinfoByteCap);
} // namespace Detail
} // namespace Filesystem
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_FILESYSTEM_HANDLE_ACTIVATION_ACCESS_HPP
