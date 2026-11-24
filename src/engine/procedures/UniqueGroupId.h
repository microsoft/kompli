// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef KOMPLI_PROCEDURES_UNIQUE_GROUP_ID_H
#define KOMPLI_PROCEDURES_UNIQUE_GROUP_ID_H

#include <Evaluator.h>

namespace Kompli
{
struct UniqueGroupIdParams
{
    /// A pattern or value to match group names against
    std::string groupName;

    /// A value to match the GID against
    /// pattern: \d+
    Optional<int> gid;
};

Result<Status> AuditUniqueGroupId(const UniqueGroupIdParams& params, IndicatorsTree& indicators, ContextInterface& context);
} // namespace Kompli
#endif // KOMPLI_PROCEDURES_UNIQUE_GROUP_ID_H
