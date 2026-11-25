// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef KOMPLI_PROCEDURES_PACKAGE_INSTALLED_H
#define KOMPLI_PROCEDURES_PACKAGE_INSTALLED_H

#include <Evaluator.h>

namespace Kompli
{
enum class PackageManagerType
{
    /// label: autodetect
    Autodetect,

    /// label: rpm
    RPM,

    /// label: dpkg
    DPKG,
};

struct PackageInstalledParams
{
    /// Package name
    std::string packageName;

    /// Minimum package version to check against (optional)
    Optional<std::string> minPackageVersion;

    /// Package manager, autodetected by default
    /// pattern: ^(rpm|dpkg)$
    Optional<PackageManagerType> packageManager = PackageManagerType::Autodetect;
};

Result<Status> AuditPackageInstalled(const PackageInstalledParams& params, IndicatorsTree& indicators, ContextInterface& context);
} // namespace Kompli
#endif // KOMPLI_PROCEDURES_PACKAGE_INSTALLED_H
