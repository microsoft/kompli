// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "Result.h"

#include <ostream>

namespace Kompli
{
std::ostream& operator<<(std::ostream& os, const Kompli::Error& error)
{
    os << "Error: " << error.message << ": code " << error.code;
    return os;
}
} // namespace Kompli
