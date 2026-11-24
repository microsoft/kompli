// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef KOMPLI_PROCEDURES_MOUNT_POINT_EXISTS_H
#define KOMPLI_PROCEDURES_MOUNT_POINT_EXISTS_H

#include <Evaluator.h>

namespace Kompli
{
struct MountPointExistsParams
{
    /// Mount point to check
    std::string mountPoint;
};

Result<Status> AuditMountPointExists(const MountPointExistsParams& params, IndicatorsTree& indicators, ContextInterface& context);
} // namespace Kompli
#endif // KOMPLI_PROCEDURES_MOUNT_POINT_EXISTS_H
