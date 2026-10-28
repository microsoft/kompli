// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_FILESYSTEM_DESCRIPTOR_HPP
#define COMPLIANCEENGINE_FILESYSTEM_DESCRIPTOR_HPP

#include "ContextInterface.h"
#include "Optional.h"
#include "Result.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <utility>

struct stat;

namespace ComplianceEngine
{
namespace Filesystem
{
class Handle;
class Path;
namespace Detail
{
class ReadOnlyActivation;
Result<std::uint64_t> MountId(const ContextInterface& context, int fdinfoDirectory, int descriptor, std::size_t byteCap);
Result<ReadOnlyActivation> ActivateReadOnly(const ContextInterface& context, int pin, const struct stat& snapshot, bool directory, std::size_t fdinfoByteCap);

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

    // Borrow the native descriptor; zero is valid, absence is EBADF.
    Result<int> Get() const;
    // Test ownership without constructing an error or touching the native fd.
    bool HasValue() const noexcept
    {
        return mDescriptor.HasValue();
    }

    // Native APIs such as fdopendir take an int and cannot accept a moved
    // C++ owner. Release only after the native API has accepted ownership.
    Result<int> Release();

    const ContextInterface& Context() const noexcept
    {
        return mContext.get();
    }

    // Relinquish ownership before the syscall. A failed close is never
    // retried, even if the kernel has already recycled its fd number.
    Result<bool> Close();

private:
    friend class ::ComplianceEngine::Filesystem::Handle;
    // Path's nested Resolver has its enclosing class's access as well.
    friend class ::ComplianceEngine::Filesystem::Path;
    friend struct VerifiedProcfs;
    friend Result<std::uint64_t> MountId(const ContextInterface&, int, int, std::size_t);
    friend Result<ReadOnlyActivation> ActivateReadOnly(const ContextInterface&, int, const struct stat&, bool, std::size_t);

    // Native adoption is restricted to acquisition owners. This is C++ compile-
    // time encapsulation, not runtime authorization against native syscalls.
    // Nonnegative inputs (including zero) transfer ownership; negative native
    // failures produce an empty owner. No validation, duplicate or open occurs.
    static Descriptor Take(const ContextInterface& context, int nativeDescriptor,
        const char* closeDiagnostic = "Failed to close internal filesystem descriptor") noexcept;
    Descriptor(const ContextInterface& context, int descriptor, const char* closeDiagnostic) noexcept;

    std::reference_wrapper<const ContextInterface> mContext;
    Optional<int> mDescriptor;
    const char* mCloseDiagnostic;
};

} // namespace Detail
} // namespace Filesystem
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_FILESYSTEM_DESCRIPTOR_HPP
