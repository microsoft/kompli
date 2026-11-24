// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_PROCEDURES_PASSWORD_POLICY_OPTION_H
#define COMPLIANCEENGINE_PROCEDURES_PASSWORD_POLICY_OPTION_H

#include <Evaluator.h>

namespace ComplianceEngine
{
struct PasswordPolicyOptionParams
{
    /// PAM policy family; managed integration uses effective inline arguments where the module does not read a policy file.
    /// pattern: ^(pwquality|faillock|pwhistory)$
    std::string policy;

    /// Allowlisted numeric or boolean option.
    std::string option;

    /// Explicit integer target, or "true" for a boolean flag; managed integration retains stronger existing settings.
    std::string value;

    /// Opt in to provider-preserving vendor PAM integration and policy database lifecycle.
    /// pattern: ^(true|false)$
    Optional<bool> integratePam = false;
};

Result<Status> AuditPasswordPolicyOption(const PasswordPolicyOptionParams& params, IndicatorsTree& indicators, ContextInterface& context);
Result<Status> RemediatePasswordPolicyOption(const PasswordPolicyOptionParams& params, IndicatorsTree& indicators, ContextInterface& context);
} // namespace ComplianceEngine
#endif // COMPLIANCEENGINE_PROCEDURES_PASSWORD_POLICY_OPTION_H
