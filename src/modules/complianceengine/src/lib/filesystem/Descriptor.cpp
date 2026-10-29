// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "PathInternal.hpp"

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

Descriptor& Descriptor::operator=(Descriptor&& other) noexcept
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
    try
    {
        (void)Close();
    }
    catch (...)
    {
        OsConfigLogError(nullptr, "Filesystem descriptor close or log failure: %d", EIO);
    }
}

Result<bool> Descriptor::Close()
{
    if (!mDescriptor.HasValue())
    {
        return true;
    }
    const int error = Context().CloseOwnedDescriptor(*this) != 0 ? ((errno != 0) ? errno : EIO) : 0;
    if (error != 0)
    {
        const char* diagnostic = mCloseDiagnostic == ContextInterface::CloseDiagnostic::DirectoryActivation ?
                                     "Failed to close directory activation" :
                                     "Failed to close internal filesystem descriptor";
        OsConfigLogError(Context().GetLogHandle(), "%s: %d", diagnostic, error);
        return Error("Cannot close internal filesystem descriptor", error);
    }
    return true;
}

} // namespace Detail
} // namespace Filesystem
} // namespace ComplianceEngine
