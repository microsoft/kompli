// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "KernelModuleTools.h"

#include <AtomicFile.h>
#include <Evaluator.h>
#include <KernelModule.h>
#include <cerrno>
#include <sys/stat.h>
#include <unistd.h>

namespace ComplianceEngine
{
namespace
{
const char managedConfigPath[] = "/etc/modprobe.d/60-kompli-disabled-modules.conf";

bool IsValidModuleName(const std::string& moduleName)
{
    if (moduleName.empty())
    {
        return false;
    }
    for (const unsigned char character : moduleName)
    {
        if (!((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9')) &&
            character != '_' && character != '-')
        {
            return false;
        }
    }
    return true;
}

std::string ManagedBlockStart(const std::string& moduleName)
{
    return "# BEGIN KOMPLI DISABLE " + moduleName;
}

std::string ManagedBlockEnd(const std::string& moduleName)
{
    return "# END KOMPLI DISABLE " + moduleName;
}

Result<std::string> UpdateManagedConfig(std::string contents, const std::string& moduleName)
{
    const std::string blockStart = ManagedBlockStart(moduleName);
    const std::string blockEnd = ManagedBlockEnd(moduleName);
    const std::string blockStartLine = blockStart + "\n";
    const std::string blockEndLine = blockEnd + "\n";
    size_t start = contents.find(blockStartLine);
    while (start != std::string::npos)
    {
        size_t endMarker = contents.find(blockEndLine, start + blockStartLine.size());
        size_t blockLength = std::string::npos;
        if (endMarker == std::string::npos)
        {
            endMarker = contents.rfind(blockEnd);
            if (endMarker == std::string::npos || endMarker < start || endMarker + blockEnd.size() != contents.size())
            {
                return Error("Malformed managed modprobe configuration block for '" + moduleName + "'", EINVAL);
            }
            blockLength = contents.size() - start;
        }
        else
        {
            blockLength = endMarker + blockEndLine.size() - start;
        }
        contents.erase(start, blockLength);
        start = contents.find(blockStartLine);
    }

    if (!contents.empty() && contents.back() != '\n')
    {
        contents.push_back('\n');
    }
    contents += blockStart + "\n";
    contents += "blacklist " + moduleName + "\n";
    contents += "install " + moduleName + " /bin/false\n";
    contents += blockEnd + "\n";
    return contents;
}

Optional<Error> RemoveCreatedConfig(const std::string& path, const struct stat& created)
{
    struct stat current;
    if (lstat(path.c_str(), &current) != 0)
    {
        const int status = errno;
        return Error("Failed to inspect created modprobe configuration during rollback: " + std::string(strerror(status)), status);
    }
    if (current.st_dev != created.st_dev || current.st_ino != created.st_ino)
    {
        return Error("Managed modprobe configuration changed before rollback", EAGAIN);
    }
    if (unlink(path.c_str()) != 0)
    {
        const int status = errno;
        return Error("Failed to remove created modprobe configuration during rollback: " + std::string(strerror(status)), status);
    }
    return {};
}
} // namespace

Result<Status> AuditKernelModuleUnavailable(const KernelModuleUnavailableParams& params, IndicatorsTree& indicators, ContextInterface& context)
{
    auto moduleName = params.moduleName;
    auto modulePresent = SearchFilesystemForModuleName(moduleName, context);
    if (!modulePresent.HasValue())
    {
        return Result<Status>(modulePresent.Error());
    }
    else if (modulePresent.Value() == false)
    {
        return indicators.Compliant("Module " + moduleName + " not found");
    }

    auto moduleLoaded = IsKernelModuleLoaded(moduleName, context);
    if (!moduleLoaded.HasValue())
    {
        return Result<Status>(moduleLoaded.Error());
    }
    else if (moduleLoaded.Value() == true)
    {
        return indicators.NonCompliant("Module " + moduleName + " is loaded");
    }

    auto inRunningKernel = IsModuleAvailableInRunningKernel(moduleName, context);
    if (!inRunningKernel.HasValue())
    {
        return Result<Status>(inRunningKernel.Error());
    }

    return IsKernelModuleBlocked(moduleName, inRunningKernel.Value(), indicators, context);
}

Result<Status> RemediateKernelModuleUnavailable(const KernelModuleUnavailableParams& params, IndicatorsTree& indicators, ContextInterface& context)
{
    if (!IsValidModuleName(params.moduleName))
    {
        return Error("Invalid kernel module name", EINVAL);
    }

    auto audit = AuditKernelModuleUnavailable(params, indicators, context);
    if (!audit.HasValue() || audit.Value() == Status::Compliant)
    {
        return audit;
    }

    auto moduleLoaded = IsKernelModuleLoaded(params.moduleName, context);
    if (!moduleLoaded.HasValue())
    {
        return moduleLoaded.Error();
    }
    if (moduleLoaded.Value())
    {
        return Error("Refusing to unload active kernel module '" + params.moduleName + "'", ENOTSUP);
    }

    const std::string configPath = context.GetSpecialFilePath(managedConfigPath);
    struct stat originalMetadata;
    const bool configExists = lstat(configPath.c_str(), &originalMetadata) == 0;
    if (!configExists && errno != ENOENT)
    {
        const int status = errno;
        return Error("Failed to inspect managed modprobe configuration: " + std::string(strerror(status)), status);
    }

    std::string original;
    if (configExists)
    {
        auto contents = context.GetFileContents(configPath);
        if (!contents.HasValue())
        {
            return contents.Error();
        }
        original = contents.Value();
    }
    auto updated = UpdateManagedConfig(original, params.moduleName);
    if (!updated.HasValue())
    {
        return updated.Error();
    }

    struct stat createdMetadata;
    Result<bool> writeResult = configExists ? ReplaceFileContentsAtomic(configPath, updated.Value()) :
                                              CreateFileContentsAtomic(configPath, updated.Value(), S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH, &createdMetadata);
    if (!writeResult.HasValue())
    {
        return writeResult.Error();
    }

    auto postAudit = AuditKernelModuleUnavailable(params, indicators, context);
    if (postAudit.HasValue() && postAudit.Value() == Status::Compliant)
    {
        return postAudit;
    }

    Optional<Error> rollbackError;
    if (configExists)
    {
        auto rollback = ReplaceFileContentsAtomic(configPath, original);
        if (!rollback.HasValue())
        {
            rollbackError = rollback.Error();
        }
    }
    else
    {
        rollbackError = RemoveCreatedConfig(configPath, createdMetadata);
    }
    if (rollbackError.HasValue())
    {
        const std::string reason = postAudit.HasValue() ? "Kernel module remained available" : postAudit.Error().message;
        return Error(reason + "; rollback failed: " + rollbackError->message, rollbackError->code);
    }
    return postAudit;
}

} // namespace ComplianceEngine
