// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCE_ENGINE_BENCHMARKIO_BENCHMARK_DEFINITION_HPP
#define COMPLIANCE_ENGINE_BENCHMARKIO_BENCHMARK_DEFINITION_HPP

#include "ContentVersion.hpp"
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
using BenchmarkIO::Resource;

struct BenchmarkDocument
{
    std::string name;
    // spec.version - the definition's content SemVer, independent of apiVersion.
    // Required and parsed for every input (including legacy identity shape).
    ContentVersion version;

    // The file-level prefix (framework/distribution/distributionVersion/
    // benchmarkVersion), built from metadata.labels/annotations for sole-id
    // definitions or derived from consistent payload keys for a legacy
    // definition that predates hoisted identity - shared by every rule.
    // `.section` is left empty here; it's a legacy field of BenchmarkInfo
    // used only by the MOF/NRP path's `Parse()` (see BenchmarkInfo.h) - the
    // unified-definition path never populates it.
    BenchmarkInfo benchmarkInfo;
    std::vector<Resource> resources;
};

// Parses a benchmark-definition JSON document. Strict about structure: it
// requires the resource envelope (apiVersion / kind == "BenchmarkDefinition" /
// metadata / valid spec.version / non-empty spec.rules) and the fixed per-rule fields.
// Rules carry the stable external-correlation `ruleId`. Sole-id definitions
// require the file-level prefix in metadata.labels and metadata.annotations.
// A non-empty, all-legacy document may omit those objects; its prefix is
// derived from the first payload key and every rule must agree. During producer
// migration, each rule must carry either `id` or the complete legacy `section`
// plus `payloadKey` identity; legacy sections are normalized into `id`. Rejects
// a document with a duplicate `id` across its rules (id must be unique within
// one file) and rejects malformed input. Consistent with the definition schema
// (additionalProperties: true), unknown fields are ignored rather than rejected.
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
