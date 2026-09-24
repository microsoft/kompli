// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "DlTools.h"

#include "ComplianceEngineInterface.h"

#include <cerrno>
#include <dlfcn.h>

namespace ComplianceEngine
{

Result<std::string> GetComplianceEngineDirectory()
{
    Dl_info dlInfo = {};
    if ((0 == dladdr(reinterpret_cast<void*>(ComplianceEngineMmiOpen), &dlInfo)) || (nullptr == dlInfo.dli_fname))
    {
        return Result<std::string>(Error("Dladdr can't find ComplianceEngineMmiOpen Not a so ojbect", EINVAL));
    }

    const std::string modulePath = dlInfo.dli_fname;
    const size_t separator = modulePath.find_last_of('/');
    if (std::string::npos == separator)
    {
        return Result<std::string>(Error("Dlinfo dli_fname invalid path", EINVAL));
    }

    return Result<std::string>(modulePath.substr(0, separator));
}

} // namespace ComplianceEngine
