// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef KOMPLID_CONFIG_HPP
#define KOMPLID_CONFIG_HPP

#include <Result.h>
#include <set>
#include <string>

namespace Komplid
{
// Parsed contents of /etc/kompli/kompli.conf - see
// kompli/docs/configuration.md for the schema and load semantics this
// mirrors.
struct KompliConfig
{
    // "Result caching" in README.md: how long a cached audit result is
    // served before re-evaluating. 0 disables caching entirely.
    long auditCacheTtlSeconds = 300;

    // "Long-running rules: background tasks" in README.md: the static
    // opt-in list of rule ids that run in the background instead of
    // synchronously. Empty by default - no rule backgrounds until an
    // operator opts it in here.
    std::set<std::string> backgroundTaskRules;
};

// Parses and validates kompli.conf's JSON content (already read from disk) -
// see kompli/docs/configuration.md for the schema. Split out from LoadConfig
// so it can be unit-tested directly without needing a root-owned file (see
// LoadConfig's use of OpenVerifiedInput). A malformed document (invalid
// JSON, wrong envelope, or a value failing validation) is an Error - see
// "Load semantics" in kompli/docs/configuration.md.
ComplianceEngine::Result<KompliConfig> LoadConfigFromString(const std::string& json);

// Loads and validates /etc/kompli/kompli.conf from `path`. A missing file is
// not an error - returns the defaults. A malformed file (invalid JSON, wrong
// envelope, or a value failing validation) is: see kompli/docs/
// configuration.md "Load semantics" - fail-closed, not a silent fallback.
ComplianceEngine::Result<KompliConfig> LoadConfig(const std::string& path);

} // namespace Komplid

#endif // KOMPLID_CONFIG_HPP
