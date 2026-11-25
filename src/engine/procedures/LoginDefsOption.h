// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef KOMPLI_PROCEDURES_LOGIN_DEFS_OPTION_H
#define KOMPLI_PROCEDURES_LOGIN_DEFS_OPTION_H

#include <Evaluator.h>
#include <ShadowField.h> // For ComparisonOperation enum

namespace Kompli
{
struct LoginDefsOptionParams
{
    /// The login.defs option name to check (e.g., PASS_MAX_DAYS, PASS_MIN_DAYS, PASS_WARN_AGE, ENCRYPT_METHOD)
    /// pattern: ^(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE|ENCRYPT_METHOD)$
    std::string option;

    /// The expected value to compare against
    std::string value;

    /// The comparison operation to apply
    /// pattern: ^(eq|ne|lt|le|gt|ge)$
    ComparisonOperation comparison = ComparisonOperation::Equal;
};

Result<Status> AuditLoginDefsOption(const LoginDefsOptionParams& params, IndicatorsTree& indicators, ContextInterface& context);
Result<Status> RemediateLoginDefsOption(const LoginDefsOptionParams& params, IndicatorsTree& indicators, ContextInterface& context);
} // namespace Kompli
#endif // KOMPLI_PROCEDURES_LOGIN_DEFS_OPTION_H
