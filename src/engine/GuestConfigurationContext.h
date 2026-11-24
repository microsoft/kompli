// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef KOMPLI_GUESTCONFIGURATIONCONTEXT_H
#define KOMPLI_GUESTCONFIGURATIONCONTEXT_H

#include "CommonContext.h"
#include "Logging.h"

namespace Kompli
{

class GuestConfigurationContext : public CommonContext
{
public:
    GuestConfigurationContext(OsConfigLogHandle log, const int telemetryFileDescriptor = -1)
        : CommonContext(log, sStatePath, telemetryFileDescriptor)
    {
    }

private:
    static constexpr char sStatePath[] = "/var/lib/GuestConfig";
};

} // namespace Kompli
#endif // KOMPLI_GUESTCONFIGURATIONCONTEXT_H
