// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_LINES_HPP
#define COMPLIANCEENGINE_LINES_HPP

#include "Optional.h"
#include "Result.h"
#include "filesystem/FilesystemPolicy.hpp"

#include <cstddef>
#include <iterator>
#include <memory>
#include <string>

namespace ComplianceEngine
{
class ContextInterface;
namespace Filesystem
{
// The context must outlive the lines. Iterators are valid only while their
// owner remains alive and unmoved; Close invalidates them. Lines is a
// move-only, single-pass resource owner. Only the first begin traverses it.
// Close before EOF (or destruction) releases handles without verifying unread
// input; reaching EOF checks size and before/after descriptor metadata but
// cannot prove an atomic or consistently unchanged read. EOF does not close
// handles.
// maxBytes bounds acquisition (including delimiters); no entire-file buffer
// is retained by the reader. Every yielded string excludes only its
// terminating LF, if present; an unterminated final line is unchanged.
// Empty input yields nothing, and a trailing LF adds no synthetic empty line.
// CR and non-ASCII bytes are preserved; embedded NUL is rejected with EBADMSG
// before the affected line can be yielded. Read and EOF-verification failures
// appear as one error item, followed by end; Close invalidates any held item.
class Lines
{
public:
    struct Limits
    {
        std::size_t maxBytes = std::size_t{1024} * 1024;
        std::size_t maxInterruptedReads = 128;
    };

    struct Policy
    {
        // Applies to every path component; DoNotFollow rejects any link with ELOOP.
        SymlinkFollowing symlinks = SymlinkFollowing::Follow;
        Limits limits;
    };

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
        explicit Iterator(Lines* range);
        void Next();

        Lines* mRange = nullptr;
        ComplianceEngine::Optional<value_type> mCurrent;

        friend class Lines;
    };

    Lines(Lines&&) noexcept;
    Lines& operator=(Lines&&) noexcept;
    Lines(const Lines&) = delete;
    Lines& operator=(const Lines&) = delete;
    ~Lines();

    // Acquires an absolute path from the filesystem root with bounded, checked
    // descriptor-backed resolution. Policy controls every component's links;
    // Follow permits intermediate and final links. Mount crossing remains allowed.
    // Activates a readable file from the final pin, verifies identity, then
    // checks release of all acquisition pins before returning. Reads no content
    // bytes. Lines owns only the independently activated readable file.
    static ComplianceEngine::Result<Lines> Open(const ComplianceEngine::ContextInterface& context, std::string path);
    static ComplianceEngine::Result<Lines> Open(const ComplianceEngine::ContextInterface& context, std::string path, Policy policy);

    Iterator begin();    // NOLINT(*-identifier-naming)
    Iterator end() const // NOLINT(*-identifier-naming)
    {
        return {};
    }

    // The data descriptor is attempted once. The first call returns its native
    // close failure, if any; subsequent calls succeed without another attempt.
    // Failed closes log the source path and descriptor error once.
    // Destruction also closes and logs if needed;
    // the context (and its log handle) must outlive Lines.
    // Success means closure succeeded, not that an early-stopped read verified EOF.
    ComplianceEngine::Result<bool> Close();

private:
    struct State;
    explicit Lines(std::unique_ptr<State> state);

    std::unique_ptr<State> mState;
    bool mStarted = false;
};
} // namespace Filesystem
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_LINES_HPP
