// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef KOMPLI_PROCEDURES_AUDITD_RULES_H
#define KOMPLI_PROCEDURES_AUDITD_RULES_H

#include <Evaluator.h>
#include <Separated.h>

namespace Kompli
{
struct AuditdRulesParams
{
    /// Item being audited
    std::string searchItem;

    /// Option the checked rule line cannot include
    Optional<std::string> excludeOption;

    /// Options that should be included on the rule line, colon separated
    Separated<std::string, ':'> requiredOptions;
};

Result<Status> AuditAuditdRules(const AuditdRulesParams& params, IndicatorsTree& indicators, ContextInterface& context);
} // namespace Kompli
#endif // KOMPLI_PROCEDURES_AUDITD_RULES_H
