// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_FILESYSTEM_READABLEFILE_HPP
#define COMPLIANCEENGINE_FILESYSTEM_READABLEFILE_HPP

#include "Descriptor.hpp"
#include "Optional.h"
#include "Result.h"

#include <cstddef>
#include <string>
#include <sys/stat.h>

namespace ComplianceEngine
{
class ContextInterface;

namespace Filesystem
{
class Handle;
// Owns a separate read-only descriptor verified against a live regular-file
// Handle. Each bound context must outlive operations and cleanup that use it,
// including cleanup of replaced ownership during a move. No descriptor escapes.
class ReadableFile
{
public:
    ReadableFile(const ReadableFile&) = delete;
    ReadableFile& operator=(const ReadableFile&) = delete;
    ReadableFile(ReadableFile&& other) noexcept = default;
    // Replaces the old descriptor through its original context, then adopts
    // the incoming descriptor and its context (which may be different).
    ReadableFile& operator=(ReadableFile&& other) noexcept = default;
    ~ReadableFile() noexcept = default;

    // Callers supply a positive, representable maxBytes. Fill that many bytes
    // across positive short native reads, or stop at native EOF. Each attempt
    // requests only the unfilled capacity; a full buffer needs no EOF probe.
    // Retry only EINTR while the caller's cumulative remaining interruption
    // budget is positive. Each retry decrements it; positive progress does not
    // reset it. Zero permits a native attempt but no EINTR retry. On exhaustion
    // return native EINTR so the caller can apply its own error policy.
    // A successful disengaged optional means EOF before any bytes; EOF after
    // progress returns an engaged partial string, with NUL and all bytes
    // unchanged. Any error after progress is still an error, not partial data;
    // the descriptor's offset is not rolled back.
    Result<Optional<std::string>> Read(std::size_t maxBytes, std::size_t& remainingInterruptRetries);

    // True only after a native read returned zero, including after partial
    // progress. This sticky observation is not a prediction from a short
    // positive read or stat, and does not guarantee the file cannot later grow.
    // Known EOF avoids further native reads; Close resets it, and moves
    // transfer it with the descriptor. A moved-from source has no observable
    // EOF even if its internal flag remains set. Not an open-validity test:
    // Read on a closed descriptor still reports EBADF.
    bool AtEnd() const noexcept;

    // Fresh stat of this readable descriptor: the held object, not a reopened
    // pathname or the original pin. It may immediately be stale; matching
    // before/after stats do not certify an atomic or consistently unchanged
    // read, nor exclude concurrent writes.
    Result<struct stat> Stat() const;

    // Relinquish ownership before the native close attempt. Return its actual
    // failure on the first call; subsequent calls succeed without touching a
    // possibly reused descriptor number. Destruction closes and logs failures
    // only if the descriptor remains live.
    Result<bool> Close();

private:
    friend class Handle;
    explicit ReadableFile(Detail::Descriptor&& descriptor) noexcept;
    Optional<Detail::Descriptor> mDescriptor;
    // Read advances the native descriptor offset and updates observed EOF.
    bool mAtEnd = false;
};
} // namespace Filesystem
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_FILESYSTEM_READABLEFILE_HPP
