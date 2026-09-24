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
using BenchmarkIO::Resource;

struct BenchmarkDocument
{
    std::string name;
    BenchmarkInfo benchmarkInfo;
    std::vector<Resource> resources;
};

// Parses the resource envelope, hoisted benchmark identity, and rules carrying
// a framework-defined `id` plus the stable external-correlation `ruleId`.
// Unknown fields are ignored consistently with the definition schema.
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
