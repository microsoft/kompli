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
// Path's pinned-link inspection; exposed only to the focused direct tests.
// No kernel-follow of link text, including procfs magic links. The caller
// keeps the O_PATH|O_NOFOLLOW pin live; stat and mount checks bracket the read.
struct LinkTarget
{
    std::string text;
    std::uint64_t mountId = 0;
};
Result<LinkTarget> ReadPinnedLink(const Descriptor& linkPin, std::size_t targetByteCap, std::size_t fdinfoByteCap);
} // namespace Detail
} // namespace Filesystem
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_FILESYSTEM_PATH_LINK_ACCESS_HPP
