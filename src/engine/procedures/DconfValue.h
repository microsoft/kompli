// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef KOMPLI_PROCEDURES_DCONF_VALUE_H
#define KOMPLI_PROCEDURES_DCONF_VALUE_H

#include <Evaluator.h>

namespace Kompli
{
enum class DconfOperation
{
    /// label: eq
    Eq,

    /// label: ne
    Ne,
};

struct DconfValueParams
{
    /// dconf key name to be checked
    std::string key;

    /// Value to be verified using the operation
    std::string value;

    /// Type of operation, one of eq, ne
    /// pattern: ^(eq|ne)$
    DconfOperation operation = DconfOperation::Eq;
};

Result<Status> AuditDconfValue(const DconfValueParams& params, IndicatorsTree& indicators, ContextInterface& context);
Result<Status> RemediateDconfValue(const DconfValueParams& params, IndicatorsTree& indicators, ContextInterface& context);
} // namespace Kompli
#endif // KOMPLI_PROCEDURES_DCONF_VALUE_H
