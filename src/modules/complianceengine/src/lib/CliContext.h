// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_CLICONTEXT_H
#define COMPLIANCEENGINE_CLICONTEXT_H

#include "CommonContext.h"
#include "Logging.h"
#include "TemporaryDirectory.h"

#include <ftw.h>
#include <unistd.h>

namespace ComplianceEngine
{
namespace Cli
{

// Ephemeral, per-invocation Context: state lives in a freshly created temp
// directory that is recursively removed on destruction. Used by short-lived,
// no-platform-daemon consumers of the engine (the `kompli` CLI and the
// lua-evaluator tool today).
class Context : public CommonContext
{
public:
    Context(OsConfigLogHandle log, const int fd = -1)
        : CommonContext(log, CreateTempDir(), fd)
    {
    }
    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;
    Context(Context&&) = delete;
    Context& operator=(Context&&) = delete;

    ~Context() override
    {
        const std::string statePath = GetStatePath();
        nftw(
            statePath.c_str(),
            [](const char* fpath, const struct stat*, int typeflag, struct FTW*) -> int {
                if (typeflag == FTW_DP)
                {
                    (void)rmdir(fpath);
                }
                else
                {
                    (void)unlink(fpath);
                }
                return 0; // best-effort cleanup: keep walking even if a removal fails
            },
            64, FTW_DEPTH | FTW_PHYS);
    }

private:
    static std::string CreateTempDir()
    {
        return Detail::CreateTemporaryDirectory("kompli-cli");
    }
};

} // namespace Cli
} // namespace ComplianceEngine
#endif // COMPLIANCEENGINE_CLICONTEXT_H
