// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_FILE_READER_HPP
#define COMPLIANCEENGINE_FILE_READER_HPP

#include "Result.h"

#include <cstddef>
#include <iterator>
#include <memory>
#include <string>

namespace ComplianceEngine
{
class ContextInterface;
}

namespace FileReader
{
enum class SymlinksPolicy
{
    FollowFinal,
    RejectFinal
};

// The context must outlive the range. Iterators are valid only while their
// range remains alive and unmoved; Close invalidates them. A range is a
// move-only, single-pass resource owner. Only the first begin traverses it.
// Close before EOF (or destruction) releases handles without verifying unread
// input; reaching EOF verifies the entire file but does not close handles.
// maxBytes bounds acquisition (including delimiters); no entire-file buffer
// is retained by the reader. Every yielded string contains the original LF
// when its line was LF-terminated; an unterminated final line has no added LF.
// Empty input yields nothing, and a trailing LF adds no synthetic empty line.
// CR and non-ASCII bytes are preserved; embedded NUL is rejected with EBADMSG
// before the affected line can be yielded.
struct Limits
{
    std::size_t maxBytes = 1024 * 1024;
    std::size_t maxInterruptedReads = 128;
};

struct Policy
{
    SymlinksPolicy symlinks = SymlinksPolicy::FollowFinal;
    Limits limits;
};

class LinesRange
{
public:
    class Iterator
    {
    public:
        using value_type = ComplianceEngine::Result<std::string>;
        using reference = const value_type&;
        using pointer = const value_type*;
        using difference_type = std::ptrdiff_t;
        using iterator_category = std::input_iterator_tag;

        Iterator(); // end sentinel
        Iterator(Iterator&&) noexcept;
        Iterator& operator=(Iterator&&) noexcept;
        Iterator(const Iterator&) = delete;
        Iterator& operator=(const Iterator&) = delete;
        ~Iterator();

        reference operator*() const;
        pointer operator->() const;
        Iterator& operator++();
        bool operator!=(const Iterator& other) const;

    private:
        explicit Iterator(LinesRange* range);
        LinesRange* mRange = nullptr;
        friend class LinesRange;
    };

    LinesRange(LinesRange&&) noexcept;
    LinesRange& operator=(LinesRange&&) noexcept;
    LinesRange(const LinesRange&) = delete;
    LinesRange& operator=(const LinesRange&) = delete;
    ~LinesRange();
    Iterator begin();    // NOLINT(*-identifier-naming)
    Iterator end() const // NOLINT(*-identifier-naming)
    {
        return {};
    }
    // Idempotent, including failures: both descriptors are attempted once.
    // Success means closure succeeded, not that an early-stopped read verified EOF.
    ComplianceEngine::Result<bool> Close();

private:
    struct State;
    explicit LinesRange(std::unique_ptr<State> state);
    std::unique_ptr<State> mState;
    bool mStarted = false;
    friend ComplianceEngine::Result<LinesRange> Lines(const ComplianceEngine::ContextInterface&, std::string, Policy);
};

// Validates, pins, opens and checks identity before returning; reads no bytes.
ComplianceEngine::Result<LinesRange> Lines(const ComplianceEngine::ContextInterface& context, std::string path, Policy policy = Policy{});
} // namespace FileReader

#endif // COMPLIANCEENGINE_FILE_READER_HPP
