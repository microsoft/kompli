// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_TEMPORARYDIRECTORY_H
#define COMPLIANCEENGINE_TEMPORARYDIRECTORY_H

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace ComplianceEngine
{
namespace Detail
{

inline std::string GetTemporaryDirectoryParent()
{
    const char* tmpdir = std::getenv("TMPDIR");
    return ((tmpdir != nullptr) && (tmpdir[0] != '\0')) ? tmpdir : "/tmp";
}

inline std::string CreateTemporaryDirectory(const std::string& prefix)
{
    std::string directoryTemplate = GetTemporaryDirectoryParent();
    if (directoryTemplate.back() != '/')
    {
        directoryTemplate += '/';
    }
    directoryTemplate += prefix + ".XXXXXX";

    std::vector<char> writableTemplate(directoryTemplate.begin(), directoryTemplate.end());
    writableTemplate.push_back('\0');
    char* directory = ::mkdtemp(writableTemplate.data());
    if (directory == nullptr)
    {
        const int error = errno;
        throw std::runtime_error("Failed to create temporary directory from " + directoryTemplate + ": " + std::strerror(error));
    }
    return directory;
}

} // namespace Detail
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_TEMPORARYDIRECTORY_H
