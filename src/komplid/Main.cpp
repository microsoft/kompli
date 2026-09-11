// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// komplid - the kompli daemon. Started by systemd via socket activation with
// Accept=yes (see komplid.socket / komplid@.service): one fresh process per
// connection, with the accepted connection wired to this process's
// stdin/stdout (fd 0 is therefore also the connection socket, used below for
// the SO_PEERCRED check). Reads JSONL requests (one JSON object per line),
// executes each one synchronously through the same Engine the `kompli` CLI
// uses, and writes one JSONL response per request. See README.md for what is
// and is not decided/implemented yet - notably, background tasks, result
// caching, and a persistent SQLite task registry are NOT part of this first
// implementation; every request runs synchronously and nothing is cached
// across connections.

#include "PeerAuth.hpp"
#include "Protocol.hpp"
#include "RequestHandler.hpp"

#include <CliContext.h>
#include <DistributionInfo.h>
#include <Engine.h>
#include <Evaluator.h>
#include <Logging.h>
#include <cstddef>
#include <iostream>
#include <memory>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

using ComplianceEngine::CliContext;
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

void WriteLine(const std::string& line)
{
    std::cout << line << std::endl; // flush: each response should reach the client promptly
}
} // namespace

int main()
{
    // Ensure file-creation permissions are at least as restrictive as 0077
    // without overriding a stricter inherited mask (same hardening as the
    // kompli CLI).
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

    auto context = std::unique_ptr<CliContext>(new CliContext(nullptr));
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

    Komplid::RequestHandler handler(engine, engine.GetDistributionInfo().Value(), kDefinitionsDir);

    std::string line;
    while (std::getline(std::cin, line))
    {
        if (line.size() > kMaxLineBytes)
        {
            std::cerr << "komplid: refusing oversized request line (" << line.size() << " bytes)" << std::endl;
            WriteLine(Komplid::BuildErrorResponse("", Komplid::ErrorCode::InvalidRequest, "request line exceeds the maximum allowed size").Value());
            continue;
        }

        WriteLine(handler.HandleLine(line));
    }

    return 0;
}
