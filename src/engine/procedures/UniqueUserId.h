// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef KOMPLI_PROCEDURES_UNIQUE_USER_ID_H
#define KOMPLI_PROCEDURES_UNIQUE_USER_ID_H

#include <Evaluator.h>

namespace Kompli
{
struct UniqueUserIdParams
{
    /// A value to match usernames against
    std::string username;

    /// A value to match the UID against
    /// pattern: \d+
    Optional<int> uid;

    /// A value to match the GID against
    /// pattern: \d+
    Optional<int> gid;
};

Result<Status> AuditUniqueUserId(const UniqueUserIdParams& params, IndicatorsTree& indicators, ContextInterface& context);
} // namespace Kompli
#endif // KOMPLI_PROCEDURES_UNIQUE_USER_ID_H
