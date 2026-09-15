// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ContextInterface.h"

namespace ComplianceEngine
{
ContextInterface::ContextInterface()
    : mAccountDatabase(*this)
{
}

// Provide a definition for the virtual destructor
ContextInterface::~ContextInterface() = default;
} // namespace ComplianceEngine
