// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "NameserverSelection.h"

#include <StringTools.h>
#include <cerrno>
#include <new>
#include <stdexcept>
#include <utility>

namespace ComplianceEngine
{
namespace NameserverSelection
{
Result<Document> Select(std::string bytes, std::string source, const Limits& limits)
{
    if ((0 == limits.occurrences) || (0 == limits.captureBytes) || (0 == limits.capturedBytes))
    {
        return Error("Nameserver selection limits must be positive: " + source, EINVAL);
    }
    Document document;
    document.bytes = std::move(bytes);
    document.source = std::move(source);
    const auto& content = document.bytes;
    std::size_t capturedBytes = 0;
    static const char prefix[] = "nameserver";
    static const std::size_t prefixLength = sizeof(prefix) - 1;

    try
    {
        for (std::size_t anchor = 0; anchor <= content.size();)
        {
            if (0 == content.compare(anchor, prefixLength, prefix))
            {
                std::size_t cursor = anchor + prefixLength;
                if ((cursor < content.size()) && IsAsciiWhitespace(static_cast<unsigned char>(content[cursor])))
                {
                    do
                    {
                        ++cursor;
                    } while ((cursor < content.size()) && IsAsciiWhitespace(static_cast<unsigned char>(content[cursor])));

                    const std::size_t end = content.find('\n', cursor);
                    const std::size_t captureEnd = (std::string::npos == end) ? content.size() : end;
                    const std::size_t captureLength = captureEnd - cursor;
                    if (document.captures.size() >= limits.occurrences)
                    {
                        return Error("Nameserver selection occurrence limit exceeded: " + document.source, E2BIG);
                    }
                    if (document.captures.size() >= document.captures.max_size())
                    {
                        return Error("Nameserver selection is not representable: " + document.source, EOVERFLOW);
                    }
                    if ((captureLength > limits.captureBytes) || (captureLength > limits.capturedBytes - capturedBytes))
                    {
                        return Error("Nameserver selection capture limit exceeded: " + document.source, E2BIG);
                    }
                    capturedBytes += captureLength;
                    document.captures.push_back({anchor, cursor, captureLength});
                    if (std::string::npos == end)
                    {
                        break;
                    }
                    anchor = end + 1;
                    continue;
                }
            }
            const std::size_t newline = content.find('\n', anchor);
            if (std::string::npos == newline)
            {
                break;
            }
            anchor = newline + 1;
        }
    }
    catch (const std::bad_alloc&)
    {
        return Error("Failed to retain nameserver selection: " + document.source, ENOMEM);
    }
    catch (const std::length_error&)
    {
        return Error("Nameserver selection is not representable: " + document.source, EOVERFLOW);
    }
    return document;
}
} // namespace NameserverSelection
} // namespace ComplianceEngine
