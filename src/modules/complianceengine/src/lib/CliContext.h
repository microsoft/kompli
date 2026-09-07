// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_CLICONTEXT_H
#define COMPLIANCEENGINE_CLICONTEXT_H

#include "CommonContext.h"
#include "Logging.h"

#include <ftw.h>
#include <stdexcept>
#include <unistd.h>

namespace ComplianceEngine
{

// Ephemeral, per-invocation Context: state lives in a freshly created temp
// directory that is recursively removed on destruction. Used by short-lived,
// no-platform-daemon consumers of the engine (the `kompli` CLI and the
// lua-evaluator tool today).
class CliContext : public CommonContext
{
public:
    CliContext(OsConfigLogHandle log)
        : CommonContext(log, CreateTempDir())
    {
    }
    CliContext(const CliContext&) = delete;
    CliContext& operator=(const CliContext&) = delete;
    CliContext(CliContext&&) = delete;
    CliContext& operator=(CliContext&&) = delete;

    ~CliContext() override
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
        char tmpl[] = "/tmp/kompli-cli.XXXXXX";
        if (mkdtemp(tmpl) == nullptr)
        {
            throw std::runtime_error("CliContext: failed to create temporary state directory");
        }
        return std::string(tmpl);
    }
};

} // namespace ComplianceEngine
#endif // COMPLIANCEENGINE_CLICONTEXT_H
