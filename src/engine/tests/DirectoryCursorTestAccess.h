// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_TESTS_DIRECTORY_CURSOR_TEST_ACCESS_H
#define COMPLIANCEENGINE_TESTS_DIRECTORY_CURSOR_TEST_ACCESS_H

#include <ContextInterface.h>
#include <filesystem/Descriptor.hpp>
#include <filesystem/FTWDirectoryCursor.hpp>
#include <filesystem/Pin.hpp>
#include <utility>

namespace ComplianceEngine
{
namespace Tests
{
// Defined only in tests (the pattern used for DescriptorTestAccess, whose
// cursor adapter this carries -- C4, since it needs the cursor seam).
// Production has no public bridge to typed cursor acquisition.
class DirectoryCursorTestAccess
{
    using Descriptor = Filesystem::Detail::Descriptor;
    using Cursor = Filesystem::FTW::Detail::DirectoryCursor;

public:
    static Result<Cursor> OpenDirectoryCursor(const ContextInterface& context, Descriptor&& owner)
    {
        return context.OpenDirectoryCursor(std::move(owner));
    }
    static Result<Cursor> OpenDirectoryCursor(const ContextInterface&&, Descriptor&&) = delete;
};
} // namespace Tests
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_TESTS_DIRECTORY_CURSOR_TEST_ACCESS_H
