// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_FILESYSTEM_PATH_LINK_ACCESS_HPP
#define COMPLIANCEENGINE_FILESYSTEM_PATH_LINK_ACCESS_HPP

#include "Descriptor.hpp"

#include <cstddef>
#include <cstdint>
#include <string>

namespace ComplianceEngine
{
namespace Filesystem
{
namespace Detail
{
// Checked pinned-link observation returned by Path's private helper.
// No kernel-follow of link text, including procfs magic links.
struct LinkTarget
{
    std::string text;
    std::uint64_t mountId = 0;
};
} // namespace Detail
} // namespace Filesystem
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_FILESYSTEM_PATH_LINK_ACCESS_HPP
