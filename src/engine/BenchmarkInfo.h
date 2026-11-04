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
    // for the full-payload-key MOF/NRP path.
    std::string section;

    // Parses a full payload key and converts it to benchmark information.
    static Result<BenchmarkInfo> Parse(const std::string& payloadKey);

    // Builds file-level identity from benchmark-definition metadata.
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
