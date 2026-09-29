// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_TEMPORARYDIRECTORY_H
#define COMPLIANCEENGINE_TEMPORARYDIRECTORY_H

#include "Result.h"

#include <string>

namespace ComplianceEngine
{
namespace Detail
{
Result<std::string> GetTemporaryDirectoryParent();
} // namespace Detail

class TemporaryDirectory
{
public:
    static Result<TemporaryDirectory> Make(const std::string& prefix);

    TemporaryDirectory(const TemporaryDirectory&) = delete;
    TemporaryDirectory& operator=(const TemporaryDirectory&) = delete;
    TemporaryDirectory(TemporaryDirectory&& other) noexcept;
    ~TemporaryDirectory();

    const std::string& Path() const;
    Result<bool> Remove();

private:
    TemporaryDirectory(std::string path, std::string name, int parent, int root);

    std::string mPath;
    std::string mName;
    int mParent;
    int mRoot;
    Result<bool> mRemovalResult{true};
};
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_TEMPORARYDIRECTORY_H
