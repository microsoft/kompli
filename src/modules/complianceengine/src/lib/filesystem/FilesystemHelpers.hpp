// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_FILESYSTEM_FILESYSTEM_HELPERS_HPP
#define COMPLIANCEENGINE_FILESYSTEM_FILESYSTEM_HELPERS_HPP

#include <string>

struct stat;

namespace ComplianceEngine
{
class ContextInterface;
namespace Filesystem
{
namespace Detail
{
// Shared acquisition/inspection primitives; no Path or Handle dependency.
int SavedError() noexcept;
// Diagnostics only: callers decide whether a failed close is primary.
void LogSecondaryClose(const ContextInterface& context, int error);
bool SameIdentity(const struct stat& first, const struct stat& second) noexcept;
// A strict child component, not a pathname.
bool IsSingleChildComponent(const std::string& component) noexcept;
} // namespace Detail
} // namespace Filesystem
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_FILESYSTEM_FILESYSTEM_HELPERS_HPP
