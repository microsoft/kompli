// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// komplid - the kompli daemon. Started by systemd via socket activation with
// Accept=yes (see komplid.socket / komplid@.service): one fresh process per
// connection, with the accepted connection wired to this process's
// stdin/stdout (fd 0 is therefore also the connection socket, used below for
// the SO_PEERCRED check). Reads JSONL requests (one JSON object per line),
// executes each one through the same Engine the `kompli` CLI uses, and
// writes one JSONL response per request. Rules listed in kompli.conf's
// backgroundTasks.rules run in a forked child instead of blocking the
// connection - see README.md "Long-running rules: background tasks" - which
// is why this loop uses select()/SIGCHLD instead of a simple blocking read:
// it must keep servicing new requests on this connection while also
// noticing (and delivering) a background task's completion. See README.md
// for the full design and what's still not implemented (`enforce` mode,
// `--passthrough`).

#include "Config.hpp"
#include "PeerAuth.hpp"
#include "Protocol.hpp"
#include "RequestHandler.hpp"
#include "TaskRegistry.hpp"

#include <CliContext.h>
#include <DistributionInfo.h>
#include <Engine.h>
#include <Evaluator.h>
#include <Logging.h>
#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

using ComplianceEngine::Cli::Context;
using ComplianceEngine::Engine;
using ComplianceEngine::JsonFormatter;
using ComplianceEngine::PayloadFormatter;

namespace
{
// Upper bound on a single JSONL request line. Accept=yes means one connection
// is one process, so this only bounds that connection's own memory use, not
// the whole daemon.
constexpr std::size_t kMaxLineBytes = static_cast<std::size_t>(1) * 1024 * 1024;

// Fixed, not configurable: an environment-supplied override would let
// whatever launches this root daemon redirect it at an arbitrary directory,
// which defeats the point of /etc/kompli/definitions/ being a root-owned,
// group-read-only location (see README.md "Privilege model").
const char* const kDefinitionsDir = "/etc/kompli/definitions";
const char* const kConfigPath = "/etc/kompli/kompli.conf";
const char* const kRegistryPath = "/var/lib/komplid/komplid.db";
const char* const kRemediationLockPath = "/var/lib/komplid/remediation.lock";

// Completed/failed task rows older than this are dropped opportunistically
// at startup (see TaskRegistry::CleanupOldTasks). Not yet configurable - see
// README.md "Not yet decided": task expiry/cleanup policy.
constexpr long kTaskCleanupMaxAgeSeconds = 24L * 60 * 60;

// Self-pipe trick: SIGCHLD handlers may only call async-signal-safe
// functions, so the handler just nudges this pipe and the main select()
// loop does the actual (non-signal-safe) waitpid()/registry work once woken.
int gChildSignalPipe[2] = {-1, -1};

void HandleSigChld(int)
{
    const char byte = 0;
    const ssize_t ignored = ::write(gChildSignalPipe[1], &byte, 1);
    (void)ignored; // best-effort wakeup nudge; nothing actionable on failure here
}

void WriteLine(const std::string& line)
{
    std::cout << line << std::endl; // flush: each response should reach the client promptly
}

// Reaps every finished child. For any this connection itself spawned as a
// background task (tracked in `pending`), delivers its outcome as an
// unsolicited taskResult/error push down this same connection - see
// README.md "Delivery: push while connected, pull if not".
void ReapAndDeliver(std::map<pid_t, Komplid::RequestHandler::SpawnedTask>& pending, Komplid::TaskRegistry* registry)
{
    for (;;)
    {
        int status = 0;
        const pid_t pid = ::waitpid(-1, &status, WNOHANG);
        if (pid <= 0)
        {
            break;
        }

        const auto it = pending.find(pid);
        if (pending.end() == it)
        {
            continue; // not a background task this connection started
        }
        const Komplid::RequestHandler::SpawnedTask spawned = it->second;
        pending.erase(it);

        if (nullptr == registry)
        {
            continue;
        }
        auto taskResult = registry->GetTask(spawned.taskId);
        if (!taskResult.HasValue() || !taskResult.Value().HasValue())
        {
            continue;
        }

        const auto& record = taskResult.Value().Value();
        if (Komplid::TaskStatus::Done == record.status)
        {
            auto jsonResult = ComplianceEngine::JsonWrapper::FromString(record.resultJson);
            if (jsonResult.HasValue())
            {
                auto response = Komplid::BuildTaskResultResponse(spawned.requestId, spawned.taskId, std::move(jsonResult.Value()));
                if (response.HasValue())
                {
                    WriteLine(response.Value());
                }
            }
        }
        else if (Komplid::TaskStatus::Failed == record.status)
        {
            auto response = Komplid::BuildErrorResponse(spawned.requestId, Komplid::ErrorCode::InternalError, record.errorMessage);
            if (response.HasValue())
            {
                WriteLine(response.Value());
            }
        }
        // Running (the child already exited - shouldn't happen) is ignored.
    }
}

// Handles one complete request line: writes its response, and if it spawned
// a background task, starts tracking its pid for later delivery.
void ProcessLine(Komplid::RequestHandler& handler, std::map<pid_t, Komplid::RequestHandler::SpawnedTask>& pending, std::string line)
{
    if (!line.empty() && '\r' == line.back())
    {
        line.pop_back(); // tolerate CRLF framing
    }

    if (line.size() > kMaxLineBytes)
    {
        std::cerr << "komplid: refusing oversized request line (" << line.size() << " bytes)" << std::endl;
        WriteLine(Komplid::BuildErrorResponse("", Komplid::ErrorCode::InvalidRequest, "request line exceeds the maximum allowed size").Value());
        return;
    }

    WriteLine(handler.HandleLine(line));

    auto spawned = handler.TakeLastSpawnedTask();
    if (spawned.HasValue())
    {
        pending[spawned.Value().pid] = spawned.Value();
    }
}
} // namespace

int main()
{
    // Ensure file-creation permissions are at least as restrictive as 0077
    // without overriding a stricter inherited mask (same hardening as the
    // kompli CLI). This is also what gives /var/lib/komplid/komplid.db its
    // ADR-0004 root:root 0600 mode: sqlite creates the file with its own
    // open() call, which this umask still governs.
    ::umask(::umask(0) | S_IRWXG | S_IRWXO);

    // Diagnostics here use stderr directly rather than OsConfigLog*: while the
    // shared logging library's console sink now writes stderr unconditionally
    // (the IsDaemon()/getppid()==1 heuristic that used to auto-disable it was
    // removed - see README.md "Logging" and docs/logging.md Decision 2), using
    // std::cerr directly here keeps startup diagnostics independent of the
    // logging library's own init/log-handle plumbing.
    const auto peerAuth = Komplid::CheckPeerAuthorized(STDIN_FILENO);
    if (!peerAuth.authorized)
    {
        std::cerr << "komplid: refusing connection: " << peerAuth.reason << std::endl;
        WriteLine(Komplid::BuildErrorResponse("", Komplid::ErrorCode::Unauthorized, "connection not authorized").Value());
        return 1;
    }

    auto context = std::unique_ptr<Context>(new Context(nullptr));
    // Same as the kompli CLI: the Engine takes ownership of a PayloadFormatter
    // and uses it polymorphically to render each rule's indicators. The JSON
    // one is required here since the indicators become part of the
    // per-request "result" response.
    Engine engine(std::move(context), std::unique_ptr<PayloadFormatter>(new JsonFormatter()));

    auto distributionInfoError = engine.LoadDistributionInfo();
    if (distributionInfoError)
    {
        std::cerr << "komplid: failed to determine system distribution: " << distributionInfoError.Value().message << std::endl;
        return 1;
    }

    auto configResult = Komplid::LoadConfig(kConfigPath);
    if (!configResult.HasValue())
    {
        // Fail-closed on a malformed config file - see
        // kompli/docs/configuration.md "Load semantics".
        std::cerr << "komplid: refusing to start: " << configResult.Error().message << std::endl;
        return 1;
    }
    const Komplid::KompliConfig config = configResult.Value();

    // The task registry/audit cache are an optional layer on top of the
    // synchronous core (see README.md) - a broken /var/lib/komplid/ (e.g.
    // disk full, permissions drift) degrades to always-synchronous,
    // never-cached behavior rather than refusing every connection.
    std::unique_ptr<Komplid::TaskRegistry> registry;
    auto registryResult = Komplid::TaskRegistry::Open(kRegistryPath);
    if (registryResult.HasValue())
    {
        registry.reset(new Komplid::TaskRegistry(std::move(registryResult.Value())));
        registry->CleanupOldTasks(kTaskCleanupMaxAgeSeconds);
    }
    else
    {
        std::cerr << "komplid: task registry unavailable, continuing without background tasks/caching: " << registryResult.Error().message
                  << std::endl;
    }

    Komplid::RequestHandler handler(
        engine, engine.GetDistributionInfo().Value(), kDefinitionsDir, config, registry.get(), kRegistryPath, kRemediationLockPath);

    if (0 != ::pipe(gChildSignalPipe))
    {
        std::cerr << "komplid: failed to create signal pipe: " << std::strerror(errno) << std::endl;
        return 1;
    }
    ::fcntl(gChildSignalPipe[0], F_SETFL, O_NONBLOCK);
    ::fcntl(gChildSignalPipe[1], F_SETFL, O_NONBLOCK);

    struct sigaction sigChldAction;
    std::memset(&sigChldAction, 0, sizeof(sigChldAction));
    sigChldAction.sa_handler = HandleSigChld;
    sigChldAction.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    ::sigaction(SIGCHLD, &sigChldAction, nullptr);

    std::map<pid_t, Komplid::RequestHandler::SpawnedTask> pendingTasks;
    std::string buffer;
    bool eof = false;

    while (!eof)
    {
        std::string::size_type newlinePos;
        while (std::string::npos != (newlinePos = buffer.find('\n')))
        {
            std::string line = buffer.substr(0, newlinePos);
            buffer.erase(0, newlinePos + 1);
            ProcessLine(handler, pendingTasks, std::move(line));
        }

        if (buffer.size() > kMaxLineBytes)
        {
            // A single line, still without a newline, already exceeds the
            // bound - refuse it now rather than waiting indefinitely for the
            // rest, and drop the buffer to resynchronize.
            std::cerr << "komplid: refusing oversized request line (no newline yet, " << buffer.size() << " bytes buffered)" << std::endl;
            WriteLine(Komplid::BuildErrorResponse("", Komplid::ErrorCode::InvalidRequest, "request line exceeds the maximum allowed size").Value());
            buffer.clear();
        }

        fd_set readFds;
        FD_ZERO(&readFds);
        FD_SET(STDIN_FILENO, &readFds);
        FD_SET(gChildSignalPipe[0], &readFds);
        const int maxFd = std::max(STDIN_FILENO, gChildSignalPipe[0]);

        const int selectResult = ::select(maxFd + 1, &readFds, nullptr, nullptr, nullptr);
        if (selectResult < 0)
        {
            if (EINTR == errno)
            {
                continue;
            }
            std::cerr << "komplid: select() failed: " << std::strerror(errno) << std::endl;
            break;
        }

        if (FD_ISSET(gChildSignalPipe[0], &readFds))
        {
            char drain[64];
            while (::read(gChildSignalPipe[0], drain, sizeof(drain)) > 0)
            {
                // Drain fully - level-triggered select() would otherwise spin.
            }
            ReapAndDeliver(pendingTasks, registry.get());
        }

        if (FD_ISSET(STDIN_FILENO, &readFds))
        {
            char readBuf[65536];
            const ssize_t n = ::read(STDIN_FILENO, readBuf, sizeof(readBuf));
            if (n < 0)
            {
                if (EINTR == errno)
                {
                    continue;
                }
                std::cerr << "komplid: read() failed: " << std::strerror(errno) << std::endl;
                break;
            }
            if (0 == n)
            {
                eof = true; // client disconnected
            }
            else
            {
                buffer.append(readBuf, static_cast<size_t>(n));
            }
        }
    }

    // A final line with no trailing newline before EOF is still a real
    // request (matches std::getline's own behavior, which the previous
    // implementation relied on).
    if (!buffer.empty())
    {
        ProcessLine(handler, pendingTasks, std::move(buffer));
    }

    // Any still-`pendingTasks` background children are simply no longer
    // tracked for delivery once this connection process exits - they are
    // already detached (see BackgroundWorker.cpp) and keep running to
    // completion, persisting their result for a later "check task" query.

    return 0;
}
