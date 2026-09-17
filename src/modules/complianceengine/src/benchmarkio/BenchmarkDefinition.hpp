// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCE_ENGINE_BENCHMARKIO_BENCHMARK_DEFINITION_HPP
#define COMPLIANCE_ENGINE_BENCHMARKIO_BENCHMARK_DEFINITION_HPP

#include "Resource.hpp"

#include <Logging.h>
#include <Result.h>
#include <istream>
#include <string>
#include <vector>

namespace ComplianceEngine
{
namespace BenchmarkDefinition
{
// Consumers (the `kompli` CLI today; `komplid` in the future) parse in-repo
// benchmark-definition files (data/definitions/*.benchmark.json) produced by
// the Compliance Augmentation Engine. A definition is a single
// Kubernetes-style resource (apiVersion / kind / metadata / spec) whose
// spec.rules array carries one inline rule payload per rule. It is the
// canonical input format for both.
//
// Each definition rule maps onto a parsed BenchmarkIO::Resource:
//   resourceID   <- rule.title
//   ruleId       <- rule.ruleId
//   ruleName     <- rule.ruleName
//   benchmarkInfo<- CISBenchmarkInfo::Parse(rule.payloadKey) (section '/'->'.'),
//                   cross-checked against the rule's explicit `section` field
//   procedure    <- rule.payload serialized as compact JSON (the ComplianceEngine
//                   parses plain JSON directly; see Engine::SetProcedure)
//   hasInitAudit <- true (every rule carries an init object)
//   payload      <- absent (definitions carry no desired object value)
using BenchmarkIO::Resource;

// Parses a benchmark-definition JSON document into the caller's rule
// resources. Strict about structure: it requires the resource envelope
// (apiVersion / kind == "BenchmarkDefinition" / metadata / spec.rules) and the
// fixed per-rule field set (section, ruleId, ruleName, title, payloadKey,
// payload), rejects a rule whose `section` disagrees with the section encoded
// in its payloadKey, and rejects malformed input. Consistent with the
// definition schema (additionalProperties: true), unknown fields are ignored
// rather than rejected.
//
// TODO(kompli CLI plan/run design, see docs/CLI.md): does NOT currently
// reject a document with a duplicate `payloadKey` across its rules. The
// planned per-rule request/plan model relies on payloadKey being unique
// *within one file* (not globally - user-authored definitions can't be
// guaranteed unique across files); this parser is where that guarantee needs
// to be enforced before anything can rely on it.
Result<std::vector<Resource>> ParseString(const std::string& json, OsConfigLogHandle logHandle);

// Reads the whole document from a stream (stdin / tests), bounding the total
// input size, then parses it.
Result<std::vector<Resource>> ParseStream(std::istream& stream, OsConfigLogHandle logHandle);

// Opens a regular file on disk with the full input-hardening posture
// (path-traversal rejection, root-owned non-writable parent directory,
// O_NOFOLLOW open, regular-file/ownership/mode checks) before the first byte is
// read, then parses it.
Result<std::vector<Resource>> ParseFile(const std::string& path, OsConfigLogHandle logHandle);

} // namespace BenchmarkDefinition
} // namespace ComplianceEngine
#endif // COMPLIANCE_ENGINE_BENCHMARKIO_BENCHMARK_DEFINITION_HPP
