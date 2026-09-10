#ifndef COMPLIANCEENGINE_PROCEDURES_FILE_SYMLINK_TARGET_H
#define COMPLIANCEENGINE_PROCEDURES_FILE_SYMLINK_TARGET_H

#include <Evaluator.h>
#include <Regex.h>

namespace ComplianceEngine
{
struct FileSymlinkTargetParams
{
    /// Path that must be a symbolic link
    std::string filename;
    /// Regular expression searched in the fully resolved canonical target path
    regex targetPattern;
};

Result<Status> AuditFileSymlinkTarget(const FileSymlinkTargetParams& params, IndicatorsTree& indicators, ContextInterface& context);
} // namespace ComplianceEngine

#endif
