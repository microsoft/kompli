// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef KOMPLI_PROCEDURES_APPARMOR_PROFILE_STATE_H
#define KOMPLI_PROCEDURES_APPARMOR_PROFILE_STATE_H

#include <Evaluator.h>

namespace Kompli
{
struct ApparmorProfileStateParams
{
    /// Set for enforce (L2) mode, complain (L1) mode by default
    Optional<bool> enforce = false;
};

Result<Status> AuditApparmorProfileState(const ApparmorProfileStateParams& params, IndicatorsTree& indicators, ContextInterface& context);
} // namespace Kompli
#endif // KOMPLI_PROCEDURES_APPARMOR_PROFILE_STATE_H
