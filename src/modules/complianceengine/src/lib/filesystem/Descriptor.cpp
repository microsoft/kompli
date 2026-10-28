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
Descriptor Descriptor::Take(const ContextInterface& context, int nativeDescriptor, const char* closeDiagnostic) noexcept
{
    return Descriptor(context, nativeDescriptor, closeDiagnostic);
}

Descriptor::Descriptor(const ContextInterface& context, int descriptor, const char* closeDiagnostic) noexcept
    : mContext(context),
      mDescriptor(0 > descriptor ? Optional<int>() : Optional<int>(descriptor)),
      mCloseDiagnostic(closeDiagnostic)
{
}

Descriptor::Descriptor(Descriptor&& other) noexcept
    : mContext(other.mContext),
      mDescriptor(std::move(other.mDescriptor)),
      mCloseDiagnostic(other.mCloseDiagnostic)
{
}

Descriptor& Descriptor::operator=(Descriptor&& other) noexcept
{
    if (this != &other)
    {
        Descriptor replaced(std::move(*this));
        mContext = other.mContext;
        mDescriptor = std::move(other.mDescriptor);
        mCloseDiagnostic = other.mCloseDiagnostic;
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
    const int descriptor = mDescriptor.Value();
    mDescriptor.Reset();
    int error = 0;
    try
    {
        if (Context().CloseFileDescriptor(descriptor) != 0)
        {
            error = (errno != 0) ? errno : EIO;
        }
    }
    catch (...)
    {
        error = EIO;
    }
    if (error != 0)
    {
        try
        {
            OsConfigLogError(Context().GetLogHandle(), "%s: %d", mCloseDiagnostic, error);
        }
        catch (...)
        {
            OsConfigLogError(nullptr, "Filesystem descriptor close or log failure: %d", error);
        }
        return Error("Cannot close internal filesystem descriptor", error);
    }
    return true;
}

Result<int> Descriptor::Get() const
{
    if (!mDescriptor.HasValue())
    {
        return Error("Internal filesystem descriptor is empty", EBADF);
    }
    return mDescriptor.Value();
}

Result<int> Descriptor::Release()
{
    if (!mDescriptor.HasValue())
    {
        return Error("Internal filesystem descriptor is empty", EBADF);
    }
    const int descriptor = mDescriptor.Value();
    mDescriptor.Reset();
    return descriptor;
}
} // namespace Detail
} // namespace Filesystem
} // namespace ComplianceEngine
