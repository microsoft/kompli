#ifndef KOMPLI_DIRTOOLS_H
#define KOMPLI_DIRTOOLS_H

#include <string>
#include <sys/stat.h>

namespace Kompli
{

bool MkdirRecursive(const std::string& path, mode_t mode = 0700);

} // namespace Kompli
#endif // KOMPLI_DIRTOOLS_H
