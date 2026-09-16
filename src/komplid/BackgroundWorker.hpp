// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef KOMPLID_BACKGROUND_WORKER_HPP
#define KOMPLID_BACKGROUND_WORKER_HPP

#include "Protocol.hpp"

#include <string>
#include <sys/types.h>

namespace Komplid
{
class RequestHandler;

// Forks a child process that runs `request` synchronously via
// `handler.DispatchCore()` and persists the outcome into a *fresh* SQLite
// connection to `registryPath` (opened in the child, after fork - not the
// parent's connection: SQLite connections are not fork-safe and each
// process must have its own, per its documentation). Mirrors
// FilesystemScanner's BackgroundScan fork pattern (see
// src/komplid/README.md "Long-running rules: background tasks" -
// "Precedent, not a new mechanism"). Returns the child's pid on success
// (the caller/Main.cpp tracks it to know when to reap it and deliver a
// taskResult push), or -1 on a fork failure - the task row is left
// `Running` in that case (see README.md "Not yet decided": task expiry).
//
// For RequestMode::Remediate, the child takes an exclusive, *blocking* lock
// on `remediationLockPath` before dispatching and holds it for the task's
// duration, serializing it against every other remediation, foreground or
// background (see README.md "Remediation locking still applies"). Blocking
// rather than failing fast here, unlike the synchronous path: this process
// has nothing better to do than wait its turn.
pid_t SpawnBackgroundTask(
    RequestHandler& handler, const std::string& registryPath, const std::string& taskId, const Request& request, const std::string& remediationLockPath);

} // namespace Komplid

#endif // KOMPLID_BACKGROUND_WORKER_HPP
