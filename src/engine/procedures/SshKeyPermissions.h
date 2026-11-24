// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef KOMPLI_PROCEDURES_SSH_KEY_PERMISSIONS_H
#define KOMPLI_PROCEDURES_SSH_KEY_PERMISSIONS_H

#include <Evaluator.h>
namespace Kompli
{
enum class SshKeyType
{
    /// label: public
    Public,

    /// label: private
    Private,
};

struct SshKeyPermissionsParams
{
    /// Key type - public or private
    /// pattern: ^(public|private)$
    SshKeyType type;
};

Result<Status> AuditSshKeyPermissions(const SshKeyPermissionsParams& params, IndicatorsTree& indicators, ContextInterface& context);
Result<Status> RemediateSshKeyPermissions(const SshKeyPermissionsParams& params, IndicatorsTree& indicators, ContextInterface& context);

} // namespace Kompli
#endif // KOMPLI_PROCEDURES_SSH_KEY_PERMISSIONS_H
