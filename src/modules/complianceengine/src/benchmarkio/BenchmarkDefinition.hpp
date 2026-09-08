// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCE_ENGINE_BENCHMARKIO_BENCHMARK_DEFINITION_HPP
#define COMPLIANCE_ENGINE_BENCHMARKIO_BENCHMARK_DEFINITION_HPP

#include "Resource.hpp"

#include <BenchmarkInfo.h>
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
// Every rule in one file shares the same framework/distribution/
// distributionVersion/benchmarkVersion prefix (see docs/payload-key-format.md
// section 1/3) - hoisted once per file as `benchmarkInfo` below, rather than
// repeated in every rule's payload key as before.
using BenchmarkIO::Resource;

// A fully parsed benchmark-definition file: its stable name, its file-level
// prefix info (shared by every rule), and its rules.
struct BenchmarkDocument
{
    // metadata.name - the benchmark's stable identifier, e.g. "cis_ubuntu24.04".
    std::string name;

    // The file-level prefix (framework/distribution/distributionVersion/
    // benchmarkVersion), built from metadata.labels/annotations
    // (CISBenchmarkInfo::FromMetadata) - shared by every rule in this file.
    // `.section` is left empty here; it's a legacy field of CISBenchmarkInfo
    // used only by the MOF/NRP path's `Parse()` (see BenchmarkInfo.h) - the
    // unified-definition path never populates it.
    CISBenchmarkInfo benchmarkInfo;

    // One entry per rule in spec.rules, in document order. Each rule maps as:
    //   resourceID   <- rule.title
    //   id           <- rule.id (verbatim, opaque, unique within this file -
    //                   kompli's sole per-rule identifier, no separate ruleId
    //                   field - see docs/payload-key-format.md section 2/6/12)
    //   procedure    <- rule.payload serialized as compact JSON (the ComplianceEngine
    //                   parses plain JSON directly; see Engine::SetProcedure)
    //   hasInitAudit <- true (every rule carries an init object)
    //   payload      <- absent (definitions carry no desired object value)
    std::vector<Resource> resources;
};

// Parses a benchmark-definition JSON document. Strict about structure: it
// requires the resource envelope (apiVersion / kind == "BenchmarkDefinition" /
// metadata / spec.rules), the file-level prefix fields (metadata.labels.
// framework/distribution/distributionVersion, metadata.annotations.
// benchmarkVersion), and the fixed per-rule field set (ruleName, title, id,
// payload). Rejects a document with a duplicate `id` across its rules (id
// must be unique within one file - see docs/payload-key-format.md section
// 5/6) and rejects malformed input. Consistent with the definition schema
// (additionalProperties: true), unknown fields are ignored rather than
// rejected.
Result<BenchmarkDocument> ParseString(const std::string& json, OsConfigLogHandle logHandle);

// Reads the whole document from a stream (stdin / tests), bounding the total
// input size, then parses it.
Result<BenchmarkDocument> ParseStream(std::istream& stream, OsConfigLogHandle logHandle);

// Opens a regular file on disk with the full input-hardening posture
// (path-traversal rejection, root-owned non-writable parent directory,
// O_NOFOLLOW open, regular-file/ownership/mode checks) before the first byte is
// read, then parses it.
Result<BenchmarkDocument> ParseFile(const std::string& path, OsConfigLogHandle logHandle);

} // namespace BenchmarkDefinition
} // namespace ComplianceEngine
#endif // COMPLIANCE_ENGINE_BENCHMARKIO_BENCHMARK_DEFINITION_HPP
