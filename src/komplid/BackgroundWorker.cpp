// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "BackgroundWorker.hpp"

#include "RequestHandler.hpp"
#include "TaskRegistry.hpp"

#include <FileLock.hpp>
#include <unistd.h>

namespace Komplid
{
using ComplianceEngine::FileLock;
using ComplianceEngine::Optional;

pid_t SpawnBackgroundTask(
    RequestHandler& handler, const std::string& registryPath, const std::string& taskId, const Request& request, const std::string& remediationLockPath)
{
    const pid_t pid = ::fork();
    if (pid < 0)
    {
        return -1;
    }
    if (pid > 0)
    {
        // Parent: nothing more to do - Main.cpp's event loop tracks `pid` to
        // know when to reap it and deliver a taskResult push (see
        // README.md "Delivery: push while connected, pull if not").
        return pid;
    }

    // Child: detached from the parent's connection - even if the client (or
    // the parent process itself) goes away, this process keeps running to
    // completion and persists its result, matching
    // FilesystemScanner::BackgroundScan's precedent.
    auto registryResult = TaskRegistry::Open(registryPath);
    if (!registryResult.HasValue())
    {
        // Can't even record failure without a registry connection - nothing
        // more can be done; exit quietly (the task row stays Running).
        ::_exit(1);
    }
    auto registry = std::move(registryResult.Value());

    Optional<FileLock> remediationLock;
    if (RequestMode::Remediate == request.mode && !remediationLockPath.empty())
    {
        // Blocking (unlike the synchronous path): this process has nothing
        // better to do than wait its turn.
        auto lockResult = FileLock::Make(remediationLockPath, /*blocking=*/true);
        if (!lockResult.HasValue())
        {
            registry.FailTask(taskId, "failed to acquire remediation lock: " + lockResult.Error().message);
            ::_exit(1);
        }
        remediationLock = Optional<FileLock>(std::move(lockResult.Value()));
    }

    auto outcome = handler.DispatchCore(request);
    if (outcome.result.HasValue())
    {
        auto serializedResult = SerializeJson(outcome.result.Value());
        if (serializedResult.HasValue())
        {
            registry.CompleteTask(taskId, serializedResult.Value());
        }
        else
        {
            registry.FailTask(taskId, "failed to serialize task result: " + serializedResult.Error().message);
        }
    }
    else
    {
        registry.FailTask(taskId, outcome.errorMessage);
    }

    ::_exit(0);
}

} // namespace Komplid
