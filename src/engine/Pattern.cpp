// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <Pattern.h>

namespace Kompli
{
Pattern::Pattern(const std::string& pattern) noexcept(false)
    : mPattern(pattern),
      mRegex(pattern)
{
}
} // namespace Kompli
