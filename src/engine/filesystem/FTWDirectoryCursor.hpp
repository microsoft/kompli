// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#ifndef COMPLIANCEENGINE_FILESYSTEM_FTW_DIRECTORY_CURSOR_HPP
#define COMPLIANCEENGINE_FILESYSTEM_FTW_DIRECTORY_CURSOR_HPP
#include "Optional.h"
#include "Path.hpp"
#include "Result.h"

#include <dirent.h>
#include <functional>
#include <string>
namespace ComplianceEngine
{
class ContextInterface;
namespace Filesystem
{
namespace FTW
{
class FileRange;
namespace Detail
{
struct DirectoryChild
{
    std::string name;
    unsigned char type = DT_UNKNOWN; // untrusted readdir hint
};
class DirectoryCursor
{
public:
    DirectoryCursor() = delete;
    DirectoryCursor(const DirectoryCursor&) = delete;
    DirectoryCursor& operator=(const DirectoryCursor&) = delete;
    DirectoryCursor(DirectoryCursor&& other) noexcept;
    DirectoryCursor& operator=(DirectoryCursor&& other) & noexcept;
    ~DirectoryCursor() noexcept;
    Result<Optional<DirectoryChild>> NextEntry();
    void Close() noexcept;

private:
    friend class ::ComplianceEngine::ContextInterface;
    friend class ::ComplianceEngine::Filesystem::FTW::FileRange;
    // Activates a fresh read-only directory pin on the Handle an
    // already-accepted Path::Component owns, then hands it to
    // ContextInterface's friend-gated OpenDirectoryCursor. A private
    // static member of DirectoryCursor (the only wrapper that needs it),
    // not a free function.
    static Result<DirectoryCursor> OpenChildren(Path::Component owner);
    DirectoryCursor(const ContextInterface& context, DIR* stream) noexcept;
    // A temporary context would dangle past construction: this cursor
    // retains the context reference for its own lifetime (see mContext below).
    DirectoryCursor(const ContextInterface&&, DIR*) = delete;
    std::reference_wrapper<const ContextInterface> mContext;
    DIR* mDirectory;
};
} // namespace Detail
} // namespace FTW
} // namespace Filesystem
} // namespace ComplianceEngine
#endif // COMPLIANCEENGINE_FILESYSTEM_FTW_DIRECTORY_CURSOR_HPP
