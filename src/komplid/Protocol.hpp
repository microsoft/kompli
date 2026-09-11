// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef KOMPLID_PROTOCOL_HPP
#define KOMPLID_PROTOCOL_HPP

#include <JsonWrapper.h>
#include <Result.h>
#include <map>
#include <string>

namespace Komplid
{
// The mode requested for one rule. `Enforce` is a reserved placeholder (see
// docs/cli.md and src/komplid/README.md "Wire protocol") - it parses
// successfully but nothing can execute it yet; dispatch reports it as a
// typed "unsupported_mode" error.
enum class RequestMode
{
    Audit,
    Remediate,
    Enforce
};

// One parsed JSONL request line - see src/komplid/README.md "Wire protocol"
// for the draft envelope this mirrors. Provisional: the message schema is
// not finalized upstream.
struct Request
{
    std::string requestId;
    std::string benchmark;
    std::string id;
    RequestMode mode;

    // Parsed but currently unused: parameter overrides aren't implemented
    // anywhere yet (BenchmarkIO::Resource doesn't retain parameterMetadata -
    // see its TODO, and docs/cli.md's "Parametrization" section notes the
    // same prerequisite for `kompli plan`). Every rule runs with its
    // definition's own defaults regardless of this field's contents.
    std::map<std::string, std::string> parameters;
};

// Best-effort extraction of the "requestId" field from a raw JSONL line, so a
// response can still correlate back to the request even when the rest of it
// fails to parse (see ParseRequest). Returns an empty string if the line
// isn't valid JSON, isn't an object, or has no string "requestId".
std::string ExtractRequestId(const std::string& line);

// Parses one JSONL request line. Returns an Error with a client-safe message
// on any malformed input (missing/wrong-typed field, unrecognized `mode`,
// unsafe `benchmark`). Does not resolve or read the benchmark file itself -
// that is RequestHandler's job.
ComplianceEngine::Result<Request> ParseRequest(const std::string& line);

// Provisional error-response codes (see src/komplid/README.md "Response
// envelope" - the taxonomy is explicitly not finalized upstream). Kept as an
// enum + ToString rather than raw strings so call sites can't typo a code.
enum class ErrorCode
{
    // Malformed request line: not JSON, not an object, or a required/typed
    // field is missing or invalid.
    InvalidRequest,
    // `benchmark` does not resolve to a definition file komplid can load.
    UnknownBenchmark,
    // The resolved benchmark has no rule with the requested `id`.
    UnknownRule,
    // `mode` is syntactically valid but not executable yet (only "enforce"
    // today).
    UnsupportedMode,
    // The resolved benchmark's distro/version prefix doesn't match this host.
    BenchmarkNotApplicable,
    // The connecting peer failed the SO_PEERCRED authorization check (see
    // PeerAuth.hpp). Connection-level, not tied to a specific request.
    Unauthorized,
    // Anything else (engine failure, JSON-serialization failure, ...).
    InternalError
};
const char* ToString(ErrorCode code);

// Builds one JSONL response line (no trailing newline; compact, single-line
// serialization - required by the JSONL framing). Takes ownership of
// `result` (a single rule's canonical result object, see
// BenchmarkIO::BuildRuleResultJson) and embeds it verbatim as the "result"
// value.
ComplianceEngine::Result<std::string> BuildResultResponse(const std::string& requestId, ComplianceEngine::JsonWrapper result);

// requestId is empty when the request line couldn't be parsed far enough to
// recover one (see ExtractRequestId), or when the error is connection-level
// (e.g. Unauthorized) rather than tied to one request.
ComplianceEngine::Result<std::string> BuildErrorResponse(const std::string& requestId, ErrorCode code, const std::string& message);

} // namespace Komplid

#endif // KOMPLID_PROTOCOL_HPP
