// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_TESTS_PIN_TEST_ACCESS_H
#define COMPLIANCEENGINE_TESTS_PIN_TEST_ACCESS_H

#include <ContextInterface.h>
#include <DescriptorTestAccess.h>
#include <cerrno>
#include <filesystem/Descriptor.hpp>
#include <filesystem/Pin.hpp>
#include <sys/stat.h>
#include <utility>

namespace ComplianceEngine
{
namespace Tests
{
// Defined only in tests (the pattern used for DescriptorTestAccess). The
// Pin layer has no public Pin factory by design: the
// only acquisition routes a caller outside Path/DirectoryCursor can reach
// are PinProcessRoot (root only) and AcquirePinnedObject (an already-open
// Descriptor), both Pin-private. This bridge calls them unmodified -- the
// identical acquisition code Path itself uses -- through the friend
// declarations added to Pin and Metadata in filesystem/Pin.hpp.
class PinTestAccess
{
    using Descriptor = Filesystem::Detail::Descriptor;
    using Pin = Filesystem::Detail::Pin;
    using Metadata = Filesystem::Metadata;

public:
    // Pins whatever OpenAbsolutePin("/") actually opens. Production hardcodes
    // "/" (ContextInterface::OpenAbsolutePin only accepts an absolute path and
    // Pin::PinProcessRoot always passes the literal "/"), so a fixture that
    // wants a temporary directory instead mocks ContextInterface::OpenNativePath
    // (the native seam OpenAbsolutePin itself calls) to redirect that one
    // open to the fixture's own directory; everything downstream (stat,
    // procfs mount verification) then runs unmodified against the real,
    // redirected descriptor. The resulting Pin's Metadata reports type
    // Directory with lookup/effective name "/", regardless of the real path
    // -- every PinTest case below checks type/stat/behavior, never those
    // name strings.
    static Result<Pin> AcquireRoot(const ContextInterface& context, Filesystem::PrefixLimits limits)
    {
        return Pin::PinProcessRoot(context, limits);
    }

    // Builds a sibling Pin around an already-open, already-typed Descriptor
    // (e.g. a regular file opened as a child of the directory AcquireRoot
    // pinned, through the Descriptor-layer descriptor bridge), via Pin's own
    // AcquirePinnedObject -- the identical stat+procfs-mount acquisition
    // Path performs for every non-root component. Metadata's own provenance
    // types are not all reachable here: LookupMountId/TargetMountId are
    // exposed by Metadata's public LookupMount()/TargetMount() getters, but
    // LookupSpelling/EffectiveSpelling are only ever returned as decoded
    // strings (LookupName()/EffectiveName()), never as the object itself,
    // and this class is not friended to those two leaf types (only to Pin
    // and Metadata). So a fresh Metadata reuses an existing
    // sibling's spelling objects by copy (reading Metadata's private fields,
    // which this class's Metadata friendship allows) rather than
    // constructing new ones from a path string. This is sufficient for
    // every PinTest case below, none of which checks the spelling strings.
    static Result<Pin> AcquireSibling(const ContextInterface& context, Descriptor descriptor, Filesystem::Type type, const Pin& provenanceDonor, std::size_t fdinfoByteCap)
    {
        auto acquired = Pin::AcquirePinnedObject(context, std::move(descriptor), fdinfoByteCap, "PinTestAccess: cannot inspect acquired test object");
        if (!acquired.HasValue())
            return std::move(acquired).Error();
        auto object = std::move(acquired).Value();
        const bool matchesType = (type == Filesystem::Type::Directory) ? S_ISDIR(object.snapshot.st_mode) : S_ISREG(object.snapshot.st_mode);
        if (!matchesType)
            return Error("PinTestAccess: acquired test object has an unexpected type", EINVAL);
        const Metadata donor = provenanceDonor.Metadata();
        Metadata facts(type, object.snapshot, donor.LookupMount(), donor.TargetMount(), donor.mLookupName, donor.mEffectiveName);
        return Pin(std::move(object.pin), std::move(facts));
    }

    // The raw fd a Pin holds, read through this class's existing Pin
    // friendship and handed to DescriptorTestAccess (which is itself friended
    // to Descriptor) rather than this class reaching into Descriptor
    // directly. Lets a test pin down a MockContext expectation to the exact
    // native fd a given Pin owns, e.g. to prove a close happens on that fd
    // and no other.
    static int NativeDescriptor(const Pin& pin)
    {
        return DescriptorTestAccess::ConsumedDescriptor(pin.mDescriptor);
    }
};
} // namespace Tests
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_TESTS_PIN_TEST_ACCESS_H
