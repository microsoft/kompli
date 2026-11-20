// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_TESTS_PATH_TEST_ACCESS_H
#define COMPLIANCEENGINE_TESTS_PATH_TEST_ACCESS_H

#include <filesystem/Path.hpp>
#include <string>

namespace ComplianceEngine
{
namespace Tests
{
// Defined only in tests (the pattern used for DescriptorTestAccess).
// Bounded authority: exactly the two strings Path::LookupName()/ToString()
// return, nothing else, and no mirrored private definition -- both calls
// dispatch to Path's own private implementation through this sole friend.
class PathTestAccess
{
public:
    static std::string LookupName(const Filesystem::Path& path)
    {
        return path.LookupName();
    }
    static std::string ToString(const Filesystem::Path& path)
    {
        return path.ToString();
    }
};
} // namespace Tests
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_TESTS_PATH_TEST_ACCESS_H
