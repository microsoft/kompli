#ifndef COMPLIANCEENGINE_PROCEDURES_FILE_SYMLINK_TARGET_H
#define COMPLIANCEENGINE_PROCEDURES_FILE_SYMLINK_TARGET_H

#include <Evaluator.h>
#include <Regex.h>

namespace ComplianceEngine
{
struct FileSymlinkTargetParams
{
    std::string filename;
    regex targetPattern;
};

Result<Status> AuditFileSymlinkTarget(const FileSymlinkTargetParams& params, IndicatorsTree& indicators, ContextInterface& context);
} // namespace ComplianceEngine

#endif
