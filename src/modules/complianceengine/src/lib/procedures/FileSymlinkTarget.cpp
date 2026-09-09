#include <FileSymlinkTarget.h>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <sys/stat.h>

namespace ComplianceEngine
{
Result<Status> AuditFileSymlinkTarget(const FileSymlinkTargetParams& params, IndicatorsTree& indicators, ContextInterface&)
{
    struct stat metadata;
    if (lstat(params.filename.c_str(), &metadata) != 0)
    {
        const int status = errno;
        if (status == ENOENT || status == ENOTDIR)
        {
            return indicators.NonCompliant("Symlink does not exist: " + params.filename);
        }
        return Error("Cannot inspect symlink: " + std::string(strerror(status)), status);
    }
    if (!S_ISLNK(metadata.st_mode))
    {
        return indicators.NonCompliant("Path is not a symlink: " + params.filename);
    }
    std::unique_ptr<char, decltype(&free)> canonical(realpath(params.filename.c_str(), nullptr), &free);
    if (!canonical)
    {
        const int status = errno;
        if (status == ENOENT || status == ENOTDIR || status == ELOOP)
        {
            return indicators.NonCompliant("Symlink target cannot be resolved: " + params.filename);
        }
        return Error("Cannot resolve symlink: " + std::string(strerror(status)), status);
    }
    const std::string target(canonical.get());
    if (!regex_search(target, params.targetPattern))
    {
        return indicators.NonCompliant("Unexpected symlink target: " + target);
    }
    return indicators.Compliant("Symlink target matches: " + target);
}
} // namespace ComplianceEngine
