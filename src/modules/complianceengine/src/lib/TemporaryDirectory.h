// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_TEMPORARYDIRECTORY_H
#define COMPLIANCEENGINE_TEMPORARYDIRECTORY_H

#include "Result.h"

#include <string>

namespace ComplianceEngine
{
class TemporaryDirectory;

namespace Detail
{
Result<std::string> GetTemporaryDirectoryParent();

class OpenedTemporaryParent
{
private:
    OpenedTemporaryParent(std::string path, int fd);

    friend class ::ComplianceEngine::TemporaryDirectory;
    friend Result<OpenedTemporaryParent> ValidateTemporaryDirectoryParent(const std::string& parent);

public:
    OpenedTemporaryParent(const OpenedTemporaryParent&) = delete;
    OpenedTemporaryParent& operator=(const OpenedTemporaryParent&) = delete;
    OpenedTemporaryParent(OpenedTemporaryParent&& other) noexcept;
    OpenedTemporaryParent& operator=(OpenedTemporaryParent&& other) noexcept;
    ~OpenedTemporaryParent();

    const std::string& Path() const;

private:
    std::string mPath;
    int mFd;
};

Result<OpenedTemporaryParent> ValidateTemporaryDirectoryParent(const std::string& parent);
} // namespace Detail

class TemporaryDirectory
{
public:
    static Result<TemporaryDirectory> Make(const std::string& prefix);
    static Result<TemporaryDirectory> MakeInParent(Detail::OpenedTemporaryParent openedParent, const std::string& prefix);

    TemporaryDirectory(const TemporaryDirectory&) = delete;
    TemporaryDirectory& operator=(const TemporaryDirectory&) = delete;
    TemporaryDirectory(TemporaryDirectory&& other) noexcept;
    ~TemporaryDirectory();

    const std::string& Path() const;
    bool Remove();

private:
    TemporaryDirectory(Detail::OpenedTemporaryParent parent, std::string name, int root);

    std::string mPath;
    std::string mName;
    Detail::OpenedTemporaryParent mParent;
    int mRoot;
};
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_TEMPORARYDIRECTORY_H
