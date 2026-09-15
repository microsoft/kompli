// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//
#ifndef COMPLIANCE_ENGINE_BENCHMARK_FORMATTER_HPP
#define COMPLIANCE_ENGINE_BENCHMARK_FORMATTER_HPP

#include <DistributionInfo.h>
#include <Evaluator.h>
#include <JsonWrapper.h>
#include <Optional.h>
#include <Resource.hpp>
#include <Result.h>
#include <chrono>
#include <map>
#include <string>

namespace ComplianceEngine
{
namespace BenchmarkFormatters
{
// Formats a compliance scan run as a canonical JSON result document. Obtain an
// instance via Begin(), which initialises the result envelope and binds host
// provenance from the supplied DistributionInfo. Call AddEntry() for each
// evaluated rule and Finish() to obtain the serialised JSON.
class BenchmarkFormatter
{
public:
    static Result<BenchmarkFormatter> Begin(DistributionInfo distributionInfo);

    ~BenchmarkFormatter() = default;
    BenchmarkFormatter(const BenchmarkFormatter&) = delete;
    BenchmarkFormatter& operator=(const BenchmarkFormatter&) = delete;
    BenchmarkFormatter(BenchmarkFormatter&&) = default;
    BenchmarkFormatter& operator=(BenchmarkFormatter&&) = default;

    Optional<Error> AddEntry(
        const BenchmarkIO::Resource& entry, Status status, const std::string& payload, const std::map<std::string, std::string>& parameters, Action action) &;
    // A rule present in the benchmark file but never executed (e.g. absent
    // from a `run` plan's rules map) - see RuleResult.hpp's
    // BuildSkippedRuleResultJson.
    Optional<Error> AddSkippedEntry(const BenchmarkIO::Resource& entry, const std::map<std::string, std::string>& parameters) &;
    Result<std::string> Finish(Status status) &&;

private:
    static std::string ToISODatetime(const std::chrono::system_clock::time_point& tp);
    explicit BenchmarkFormatter(DistributionInfo distributionInfo);

    Optional<Error> AppendRuleJson(JsonWrapper rule) &;

    std::chrono::time_point<std::chrono::steady_clock> mBegin;
    DistributionInfo mDistributionInfo;
    JsonWrapper mJson;
};
} // namespace BenchmarkFormatters
} // namespace ComplianceEngine
#endif // COMPLIANCE_ENGINE_BENCHMARK_FORMATTER_HPP
