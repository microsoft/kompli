// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_PARSERS_NAMESERVER_SELECTION_H
#define COMPLIANCEENGINE_PARSERS_NAMESERVER_SELECTION_H

#include <Result.h>
#include <cstddef>
#include <string>
#include <vector>

namespace ComplianceEngine
{
namespace NameserverSelection
{
struct Limits
{
    std::size_t occurrences = 16384;
    std::size_t captureBytes = 65536;
    std::size_t capturedBytes = 1024 * 1024;
};

struct Capture
{
    std::size_t anchor;
    std::size_t offset;
    std::size_t length;
};

struct Document
{
    std::string bytes;
    std::string source;
    std::vector<Capture> captures;
};

// Select the source expression ^nameserver\s+(.*)$, not resolv.conf grammar.
// Offsets count bytes; the maximal six-byte ASCII whitespace run may cross LF.
Result<Document> FindNameserverCaptures(std::string bytes, std::string source, const Limits& limits = {});
} // namespace NameserverSelection
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_PARSERS_NAMESERVER_SELECTION_H
