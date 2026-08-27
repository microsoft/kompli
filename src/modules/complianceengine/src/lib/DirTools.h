#ifndef COMPLIANCEENGINE_DIRTOOLS_H
#define COMPLIANCEENGINE_DIRTOOLS_H

#include <string>
#include <sys/stat.h>

namespace ComplianceEngine
{

bool MkdirRecursive(const std::string& path, mode_t mode = 0755);

} // namespace ComplianceEngine
#endif // COMPLIANCEENGINE_DIRTOOLS_H
