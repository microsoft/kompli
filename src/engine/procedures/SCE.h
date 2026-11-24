// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef KOMPLI_PROCEDURES_SCE_H
#define KOMPLI_PROCEDURES_SCE_H

#include <Evaluator.h>

namespace Kompli
{
struct SCEParams
{
    /// Script path
    std::string scriptName;

    /// Environment as passed to the SCE script
    Optional<std::string> environment;
};

Result<Status> AuditSCE(const SCEParams& params, IndicatorsTree& indicators, ContextInterface& context);
Result<Status> RemediateSCE(const SCEParams& params, IndicatorsTree& indicators, ContextInterface& context);
} // namespace Kompli
#endif // KOMPLI_PROCEDURES_SCE_H
