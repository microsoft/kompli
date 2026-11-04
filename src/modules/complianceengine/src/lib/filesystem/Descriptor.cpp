// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "Descriptor.hpp"

#include <cerrno>

namespace ComplianceEngine
{
namespace Filesystem
{
namespace Detail
{
Descriptor::Descriptor(const ContextInterface& context, int descriptor, ContextInterface::CloseDiagnostic closeDiagnostic) noexcept
    : mContext(&context),
      mDescriptor(0 > descriptor ? Optional<int>() : Optional<int>(descriptor)),
      mCloseDiagnostic(closeDiagnostic)
{
}

Descriptor::Descriptor(Descriptor&& other) noexcept
    : mContext(other.mContext),
      mDescriptor(std::move(other.mDescriptor)),
      mCloseDiagnostic(other.mCloseDiagnostic)
{
    other.mDescriptor.Reset();
}

Descriptor& Descriptor::operator=(Descriptor&& other) & noexcept
{
    if (this != &other)
    {
        Descriptor replaced(std::move(*this));
        mContext = other.mContext;
        mDescriptor = std::move(other.mDescriptor);
        mCloseDiagnostic = other.mCloseDiagnostic;
        other.mDescriptor.Reset();
    }
    return *this;
}

Descriptor::~Descriptor() noexcept
{
    Close();
}

void Descriptor::Close() noexcept
{
    if (!mDescriptor.HasValue())
        return;

    const ContextInterface* context = mContext;
    int error = 0;
    try
    {
        errno = 0;
        if (context->CloseOwnedDescriptor(*this) != 0)
            error = errno != 0 ? errno : EIO;
    }
    catch (...)
    {
        // The context consumes the owner and budget before the native call.
        // If a trusted override throws before that boundary, detach here.
        if (mDescriptor.HasValue())
        {
            mDescriptor.Reset();
            context->ReleaseManagedDescriptor();
        }
        error = EIO;
    }
    if (error == 0)
        return;
    const char* diagnostic = mCloseDiagnostic == ContextInterface::CloseDiagnostic::DirectoryActivation ? "Cannot close directory activation" :
                             mCloseDiagnostic == ContextInterface::CloseDiagnostic::ReadableActivation  ? "Cannot close readable-file activation" :
                                                                                                          "Cannot close internal filesystem descriptor";
    OsConfigLogHandle log = nullptr;
    try
    {
        log = context->GetLogHandle();
    }
    catch (...)
    {
    }
    try
    {
        if (error == EBADF)
        {
            OsConfigLogError(log, "%s (ownership bug, EBADF): %d", diagnostic, error);
        }
        else
        {
            OsConfigLogError(log, "%s: %d", diagnostic, error);
        }
    }
    catch (...)
    {
    }
}

} // namespace Detail
} // namespace Filesystem
} // namespace ComplianceEngine
