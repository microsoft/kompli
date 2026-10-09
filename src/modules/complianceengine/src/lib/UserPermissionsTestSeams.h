// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_USER_PERMISSIONS_TEST_SEAMS_H
#define COMPLIANCEENGINE_USER_PERMISSIONS_TEST_SEAMS_H

#include <FilePermissions.h>
#include <string>

namespace ComplianceEngine
{
Result<Status> AuditUserDotFilePermissionsWithPasswdFile(IndicatorsTree& indicators, ContextInterface& context, const std::string& passwdPath);
Result<Status> RemediateUserHomeDirectoryPermissionsWithPasswdFile(IndicatorsTree& indicators, ContextInterface& context, const std::string& passwdPath,
    Result<Status> (*remediatePermissions)(const FilePermissionsParams&, IndicatorsTree&, ContextInterface&));
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_USER_PERMISSIONS_TEST_SEAMS_H
