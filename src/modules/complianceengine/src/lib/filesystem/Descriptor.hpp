// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_FILESYSTEM_DESCRIPTOR_HPP
#define COMPLIANCEENGINE_FILESYSTEM_DESCRIPTOR_HPP

#include "ContextInterface.h"
#include "Optional.h"
#include "Result.h"

#include <cstddef>
#include <cstdint>
#include <utility>

struct stat;

namespace ComplianceEngine
{
namespace Filesystem
{
namespace Detail
{

// Internal, move-only ownership of a native descriptor and the context that
// must close it. Absence of the optional represents no ownership.
class Descriptor
{
public:
    Descriptor(const Descriptor&) = delete;
    Descriptor& operator=(const Descriptor&) = delete;
    Descriptor(Descriptor&& other) noexcept;
    Descriptor& operator=(Descriptor&& other) noexcept;
    ~Descriptor() noexcept;

    // Zero is a valid owned descriptor. Absence means no ownership.
    bool HasValue() const noexcept
    {
        return mDescriptor.HasValue();
    }

    const ContextInterface& Context() const noexcept
    {
        return *mContext;
    }

    // Relinquish ownership before the syscall. A failed close is never
    // retried, even if the kernel has already recycled its fd number.
    Result<bool> Close();

private:
    friend class ::ComplianceEngine::ContextInterface;
    Descriptor(const ContextInterface& context, int descriptor, const char* closeDiagnostic) noexcept;

    const ContextInterface* mContext;
    Optional<int> mDescriptor;
    const char* mCloseDiagnostic;
};

} // namespace Detail
} // namespace Filesystem
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_FILESYSTEM_DESCRIPTOR_HPP
