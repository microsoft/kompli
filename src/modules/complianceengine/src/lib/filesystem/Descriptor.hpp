// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_FILESYSTEM_DESCRIPTOR_HPP
#define COMPLIANCEENGINE_FILESYSTEM_DESCRIPTOR_HPP

#include "ContextInterface.h"
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
// must close it. The -1 sentinel exists only after ownership transfer.
class Descriptor
{
public:
    Descriptor() = delete;
    Descriptor(const Descriptor&) = delete;
    Descriptor& operator=(const Descriptor&) = delete;
    Descriptor(Descriptor&& other) noexcept;
    Descriptor& operator=(Descriptor&& other) & noexcept;
    ~Descriptor() noexcept;

    const ContextInterface& Context() const noexcept
    {
        return *mContext;
    }

    // Relinquish ownership before the syscall. A failed close is never
    // retried, even if the kernel has already recycled its fd number.
    void Close() & noexcept;

private:
    friend class ::ComplianceEngine::ContextInterface;
    friend class ProcfsDescriptorAccess;
    friend class ::ComplianceEngine::Filesystem::ReadableFile;
    friend class ::ComplianceEngine::Tests::DescriptorTestAccess;
    Descriptor(const ContextInterface& context, int descriptor, ContextInterface::CloseDiagnostic closeDiagnostic);
    int RequireOwned() const;
    void ReleaseOwned() noexcept;
    void ReportUseAfterMove() const noexcept;

    const ContextInterface* mContext;
    int mDescriptor;
    ContextInterface::CloseDiagnostic mCloseDiagnostic;
};

} // namespace Detail
} // namespace Filesystem
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_FILESYSTEM_DESCRIPTOR_HPP
