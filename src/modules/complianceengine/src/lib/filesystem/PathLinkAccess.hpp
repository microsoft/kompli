// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_FILESYSTEM_PATH_LINK_ACCESS_HPP
#define COMPLIANCEENGINE_FILESYSTEM_PATH_LINK_ACCESS_HPP

#include "Descriptor.hpp"

#include <cstddef>
#include <string>

namespace ComplianceEngine
{
namespace Filesystem
{
namespace Detail
{
// Checked pinned-link observation returned by Path's private helper.
// No kernel-follow of link text, including procfs magic links. The pin's
// mount is observed once at acquisition (see the resolver's child-pin site
// and the ProcfsDescriptorAccess-based acquisition helper); a live O_PATH
// pin cannot change mount, so this reader does not re-observe it.
struct LinkTarget
{
    std::string text;
};
} // namespace Detail
} // namespace Filesystem
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_FILESYSTEM_PATH_LINK_ACCESS_HPP
