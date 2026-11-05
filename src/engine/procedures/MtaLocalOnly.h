// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_PROCEDURES_MTA_LOCAL_ONLY_H
#define COMPLIANCEENGINE_PROCEDURES_MTA_LOCAL_ONLY_H

#include <Evaluator.h>
#include <Optional.h>

namespace Kompli
{
enum class MtaConfigurationVersion
{
    /// label: none
    None,

    /// label: 1
    Version1,

    /// label: 2
    Version2,

    /// label: 3
    Version3,
};

struct MtaLocalOnlyParams
{
    /// Configuration check version from the source audit; none checks only listening ports
    /// pattern: ^(none|1|2|3)$
    Optional<MtaConfigurationVersion> configurationVersion = MtaConfigurationVersion::None;
};

Result<Status> AuditMtaLocalOnly(const MtaLocalOnlyParams& params, IndicatorsTree& indicators, ContextInterface& context);
} // namespace Kompli
#endif // COMPLIANCEENGINE_PROCEDURES_MTA_LOCAL_ONLY_H
