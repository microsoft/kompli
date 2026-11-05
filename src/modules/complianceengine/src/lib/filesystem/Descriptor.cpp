// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "Descriptor.hpp"

#include <cerrno>
#include <stdexcept>

namespace ComplianceEngine
{
namespace Filesystem
{
namespace Detail
{
Descriptor::Descriptor(const ContextInterface& context, int descriptor, ContextInterface::CloseDiagnostic closeDiagnostic)
    : mContext(&context),
      mDescriptor(descriptor),
      mCloseDiagnostic(closeDiagnostic)
{
    if (0 > descriptor)
        throw std::logic_error("Descriptor: construction requires ownership");
}

Descriptor::Descriptor(Descriptor&& other) noexcept
    : mContext(other.mContext),
      mDescriptor(other.mDescriptor),
      mCloseDiagnostic(other.mCloseDiagnostic)
{
    other.mDescriptor = -1;
}

Descriptor& Descriptor::operator=(Descriptor&& other) & noexcept
{
    if (this != &other)
    {
        ReleaseOwned();
        mContext = other.mContext;
        mDescriptor = other.mDescriptor;
        mCloseDiagnostic = other.mCloseDiagnostic;
        other.mDescriptor = -1;
    }
    return *this;
}

Descriptor::~Descriptor() noexcept
{
    ReleaseOwned();
}

int Descriptor::RequireOwned() const
{
    if (0 > mDescriptor)
        throw std::logic_error("Descriptor: use after move (no ownership)");
    return mDescriptor;
}

void Descriptor::ReportUseAfterMove() const noexcept
{
    OsConfigLogError(mContext->GetLogHandle(), "Descriptor: use after move (no ownership) on explicit Close");
}

void Descriptor::Close() & noexcept
{
    if (0 > mDescriptor)
    {
        ReportUseAfterMove();
        return;
    }
    ReleaseOwned();
}

void Descriptor::ReleaseOwned() noexcept
{
    if (0 > mDescriptor)
        return; // Silent on destruction or internal release after consumption.

    const ContextInterface* context = mContext;
    int error = 0;
    errno = 0;
    if (context->CloseOwnedDescriptor(*this) != 0)
        error = errno != 0 ? errno : EIO;
    if (0 == error)
        return;
    const char* diagnostic = mCloseDiagnostic == ContextInterface::CloseDiagnostic::DirectoryActivation ? "Cannot close directory activation" :
                             mCloseDiagnostic == ContextInterface::CloseDiagnostic::ReadableActivation  ? "Cannot close readable-file activation" :
                                                                                                          "Cannot close internal filesystem descriptor";
    OsConfigLogHandle log = context->GetLogHandle();
    if (EBADF == error)
    {
        OsConfigLogError(log, "%s (ownership bug, EBADF): %d", diagnostic, error);
    }
    else
    {
        OsConfigLogError(log, "%s: %d", diagnostic, error);
    }
}

} // namespace Detail
} // namespace Filesystem
} // namespace ComplianceEngine
