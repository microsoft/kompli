// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_CLICONTEXT_H
#define COMPLIANCEENGINE_CLICONTEXT_H

#include "CommonContext.h"
#include "Logging.h"
#include "TemporaryDirectory.h"

#include <memory>
#include <utility>

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
    static Result<std::unique_ptr<Context>> Make(OsConfigLogHandle log, const int fd = -1)
    {
        auto state = Detail::CreateTemporaryDirectory("kompli-cli");
        if (!state.HasValue())
        {
            return std::move(state).Error();
        }
        return std::unique_ptr<Context>(new Context(log, std::move(state).Value(), fd));
    }
    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;
    Context(Context&&) = delete;
    Context& operator=(Context&&) = delete;

    ~Context() override
    {
        if (!mTemporaryDirectory.Remove())
        {
            OsConfigLogError(GetLogHandle(), "Failed to remove temporary state directory %s", GetStatePath().c_str());
        }
    }

private:
    Context(OsConfigLogHandle log, Detail::TemporaryDirectory state, const int fd)
        : CommonContext(log, state.Path(), fd),
          mTemporaryDirectory(std::move(state))
    {
    }

    Detail::TemporaryDirectory mTemporaryDirectory;
};

} // namespace Cli
} // namespace ComplianceEngine
#endif // COMPLIANCEENGINE_CLICONTEXT_H
