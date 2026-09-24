// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <BenchmarkInfo.h>
#include <Optional.h>
#include <Result.h>
#include <cstring>
#include <fnmatch.h>
#include <fstream>
#include <iterator>
#include <sstream>
#include <string>

namespace ComplianceEngine
{
using std::string;

namespace
{
Optional<Error> ValidateGlobbing(const string& distributionVersion)
{
    for (auto c : distributionVersion)
    {
        if (strchr("[]{}", c) != nullptr)
        {
            return Error("Invalid benchmark version: " + distributionVersion + ". Globbing characters [ ] { } are not allowed.", EINVAL);
        }
    }

    return Optional<Error>();
}
} // namespace

Result<BenchmarkInfo> BenchmarkInfo::Parse(const string& payloadKey)
{
    BenchmarkInfo result;
    string token;
    std::stringstream ss(payloadKey);
    // skip the first token which is expected to be empty due to leading '/'
    if (!std::getline(ss, token, '/') || !token.empty())
    {
        return Error("Invalid payload key format: must start with '/'", EINVAL);
    }

    if (!std::getline(ss, result.framework, '/') || result.framework.empty())
    {
        return Error("Invalid payload key format: missing benchmark framework", EINVAL);
    }

    if (!std::getline(ss, token, '/'))
    {
        return Error("Invalid benchmark payload key format: missing distribution", EINVAL);
    }
    const auto distribution = DistributionInfo::ParseLinuxDistribution(token);
    if (!distribution.HasValue())
    {
        return distribution.Error();
    }
    result.distribution = distribution.Value();

    if (!std::getline(ss, result.version, '/') || result.version.empty())
    {
        return Error("Invalid benchmark payload key format: missing distribution version", EINVAL);
    }
    auto error = ValidateGlobbing(result.version);
    if (error.HasValue())
    {
        return error.Value();
    }

    if (!std::getline(ss, result.benchmarkVersion, '/') || result.benchmarkVersion.empty())
    {
        return Error("Invalid benchmark payload key format: missing benchmark version", EINVAL);
    }

    if (!std::getline(ss, result.section) || result.section.empty())
    {
        return Error("Invalid benchmark payload key format: missing benchmark section", EINVAL);
    }
    return result;
}

Result<BenchmarkInfo> BenchmarkInfo::FromMetadata(const string& framework, const string& distribution, const string& distributionVersion, const string& benchmarkVersion)
{
    BenchmarkInfo result;
    if (framework.empty())
    {
        return Error("Benchmark framework must not be empty", EINVAL);
    }
    result.framework = framework;

    const auto distributionResult = DistributionInfo::ParseLinuxDistribution(distribution);
    if (!distributionResult.HasValue())
    {
        return distributionResult.Error();
    }
    result.distribution = distributionResult.Value();

    if (distributionVersion.empty())
    {
        return Error("Benchmark distribution version must not be empty", EINVAL);
    }
    auto error = ValidateGlobbing(distributionVersion);
    if (error.HasValue())
    {
        return error.Value();
    }
    result.version = distributionVersion;

    if (benchmarkVersion.empty())
    {
        return Error("Benchmark version must not be empty", EINVAL);
    }
    result.benchmarkVersion = benchmarkVersion;
    return result;
}

bool BenchmarkInfo::Match(const DistributionInfo& distributionInfo) const
{
    if (distributionInfo.distribution != distribution)
    {
        return false;
    }

    const int status = fnmatch(version.c_str(), distributionInfo.version.c_str(), 0);
    if (0 != status)
    {
        return false;
    }

    return true;
}
} // namespace ComplianceEngine

namespace std
{
string to_string(const ComplianceEngine::BenchmarkInfo& benchmarkInfo)
{
    ostringstream oss;
    oss << "/" << benchmarkInfo.framework << "/" << to_string(benchmarkInfo.distribution) << "/" << benchmarkInfo.version << "/"
        << benchmarkInfo.benchmarkVersion << "/" << benchmarkInfo.section;
    return oss.str();
}
} // namespace std
