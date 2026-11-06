// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCE_ENGINE_BENCHMARKIO_CONTENT_VERSION_HPP
#define COMPLIANCE_ENGINE_BENCHMARKIO_CONTENT_VERSION_HPP

#include <Result.h>
#include <string>

namespace ComplianceEngine
{
// A definition's content version, not its apiVersion or upstream
// benchmarkVersion. Decimal components stay strings so comparison does not
// overflow even when a component exceeds the range of integer types.
struct ContentVersion
{
    std::string major;
    std::string minor;
    std::string patch;
};

Result<ContentVersion> ParseContentVersion(const std::string& text);
int CompareContentVersion(const ContentVersion& left, const ContentVersion& right);
std::string ContentVersionToString(const ContentVersion& version);
} // namespace ComplianceEngine

#endif // COMPLIANCE_ENGINE_BENCHMARKIO_CONTENT_VERSION_HPP
