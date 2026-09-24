// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_BENCHMARK_INFO_H
#define COMPLIANCEENGINE_BENCHMARK_INFO_H

#include <DistributionInfo.h>
#include <Result.h>
#include <string>

namespace ComplianceEngine
{
// Defines the identity and applicability information shared by every rule in a
// benchmark.
struct BenchmarkInfo
{
    // Opaque framework identity, e.g. "cis" or "stig". Framework does not
    // select parsing or execution behavior.
    std::string framework;

    // Defines the Linux distribution, e.g., Ubuntu, CentOS
    LinuxDistribution distribution;

    // Defines the major version of the Linux distribution, e.g., 20, 8, 5
    std::string version;

    // Defines the version of the benchmark, e.g., v1.0.0
    std::string benchmarkVersion;

    // Defines the benchmark section, e.g. 1.1.1. Only populated by Parse()
    // (the full-payload-key path used by the MOF/NRP scenario, where a
    // payload key still carries the section as its trailing segment); empty
    // when built via FromMetadata() (the unified-definition-file path, where
    // the section lives on the rule itself, not this file-level prefix).
    std::string section;

    // Parses a full payload key ("/<framework>/<distribution>/<version>/
    // <benchmarkVersion>/<section>") and converts it to the benchmark
    // information. Used by the MOF/NRP scenario, where every rule's payload
    // key is still fully self-contained - this must keep accepting exactly
    // what it accepts today (including STIG's historical lack of a 'v'
    // prefix on benchmarkVersion), since existing MOFs are not regenerated.
    static Result<BenchmarkInfo> Parse(const std::string& payloadKey);

    // Builds the file-level prefix directly from the unified
    // benchmark-definition file's already-separate metadata fields
    // (metadata.labels.framework/distribution/distributionVersion,
    // metadata.annotations.benchmarkVersion) - no path string to split, since
    // the definition-file schema hoists these once per file rather than
    // repeating them in every rule's payload key.
    // section is left empty; the definition-file schema keeps section on
    // each rule instead.
    static Result<BenchmarkInfo> FromMetadata(const std::string& framework, const std::string& distribution, const std::string& distributionVersion,
        const std::string& benchmarkVersion);

    // Match the benchmark information against detected distribution information.
    // Returns true in case of a match.
    bool Match(const DistributionInfo& distributionInfo) const;

    std::string SanitizedVersion() const
    {
        std::string result;
        for (auto it = version.begin(); it != version.end(); ++it)
        {
            if (*it == '\\')
            {
                // fnmatch treats '\' as an escape: the following character is a
                // literal. Emit that literal (dropping the backslash) so the
                // sanitized version still satisfies the benchmark's fnmatch()
                // check, e.g. the pattern "3\.*" yields "3." rather than "3\.".
                // A trailing lone backslash is dropped.
                if (it + 1 != version.end())
                {
                    ++it;
                    result += *it;
                }
                continue;
            }

            if (*it == '*')
            {
                continue;
            }

            if (*it == '?')
            {
                result += 'x'; // Escape special globbing characters
                continue;
            }

            result += *it;
        }

        return result;
    }
};

} // namespace ComplianceEngine

namespace std
{
std::string to_string(const ComplianceEngine::BenchmarkInfo& benchmarkInfo); // NOLINT(*-identifier-naming)
} // namespace std

#endif // COMPLIANCEENGINE_BENCHMARK_INFO_H
