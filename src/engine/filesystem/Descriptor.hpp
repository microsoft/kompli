// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_FILESYSTEM_DESCRIPTOR_HPP
#define COMPLIANCEENGINE_FILESYSTEM_DESCRIPTOR_HPP

#include "ContextInterface.h"

#include <functional>

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
        return mContext.get();
    }

private:
    friend class ::ComplianceEngine::ContextInterface;
    friend class ::ComplianceEngine::Filesystem::ReadableFile;
    friend class ::ComplianceEngine::Tests::DescriptorTestAccess;
    Descriptor(const ContextInterface& context, int descriptor);
    // A temporary context would dangle past construction: this owner retains
    // the context reference for its own lifetime (see mContext below).
    Descriptor(const ContextInterface&&, int) = delete;
    // Disposal: a consumed (moved-from) owner is a silent no-op; otherwise
    // close through the owning context and log any failure. Shared by the
    // destructor and move-assignment so they stay in sync by construction.
    void ReleaseOwned() noexcept;
    // Checked moved-from guard: throws std::logic_error if this owner has
    // already been consumed (see the -1 sentinel above). Private so a
    // native-dispatch friend (ContextInterface) can validate ownership
    // immediately before reading mDescriptor, without a free function that
    // would need the raw native integer passed to it from outside the class.
    void RequireOwnership() const;

    std::reference_wrapper<const ContextInterface> mContext;
    int mDescriptor;
};

} // namespace Detail
} // namespace Filesystem
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_FILESYSTEM_DESCRIPTOR_HPP
