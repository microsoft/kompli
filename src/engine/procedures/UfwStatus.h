// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef KOMPLI_PROCEDURES_UFW_STATUS_H
#define KOMPLI_PROCEDURES_UFW_STATUS_H

#include <Evaluator.h>
#include <Pattern.h>

namespace Kompli
{
struct UfwStatusParams
{
    /// Regex that the status must match
    Pattern statusRegex;
};

Result<Status> AuditUfwStatus(const UfwStatusParams& params, IndicatorsTree& indicators, ContextInterface& context);
} // namespace Kompli

#endif // KOMPLI_PROCEDURES_UFW_STATUS_H
