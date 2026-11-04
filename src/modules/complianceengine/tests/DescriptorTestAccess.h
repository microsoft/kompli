// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_TESTS_DESCRIPTOR_TEST_ACCESS_H
#define COMPLIANCEENGINE_TESTS_DESCRIPTOR_TEST_ACCESS_H

#include <ContextInterface.h>
#include <filesystem/Descriptor.hpp>
#include <filesystem/Handle.hpp>
#include <filesystem/Path.hpp>
#include <filesystem/ProcfsDescriptorAccess.hpp>
#include <utility>

namespace ComplianceEngine
{
namespace Tests
{
// Defined only in tests. Production has no public bridge to typed operations.
class DescriptorTestAccess
{
    using Descriptor = Filesystem::Detail::Descriptor;
    using Procfs = Filesystem::Detail::ProcfsDescriptorAccess;
    using Cursor = Filesystem::DirectoryCursor;
    using Profile = ContextInterface::OpenProfile;
    using Diagnostic = ContextInterface::CloseDiagnostic;

public:
    // Keep every context-retaining result tied to a caller-owned lvalue.
    static Descriptor EmptyDescriptor(const ContextInterface& context, Diagnostic diagnostic = Diagnostic::Descriptor) noexcept
    {
        return context.EmptyDescriptor(diagnostic);
    }
    static Descriptor EmptyDescriptor(const ContextInterface&&, Diagnostic = Diagnostic::Descriptor) = delete;
    static Result<Descriptor> OpenAbsolutePin(const ContextInterface& context, const char* path, bool directory = true)
    {
        return context.OpenAbsolutePin(path, directory);
    }
    static Result<Descriptor> OpenAbsolutePin(const ContextInterface&&, const char*, bool = true) = delete;
    static Result<Descriptor> OpenAt(const ContextInterface& context, const Descriptor& directory, const char* name, Profile profile,
        Diagnostic diagnostic = Diagnostic::Descriptor)
    {
        return context.OpenAt(directory, name, profile, diagnostic);
    }
    static Result<Descriptor> OpenAt(const ContextInterface&&, const Descriptor&, const char*, Profile, Diagnostic = Diagnostic::Descriptor) = delete;
    static Result<Descriptor> OpenFdinfo(const ContextInterface& context, const Procfs& procfs, const Descriptor& target)
    {
        return context.OpenFdinfo(procfs, target);
    }
    static Result<Descriptor> OpenFdinfo(const ContextInterface&&, const Procfs&, const Descriptor&) = delete;
    static Result<Descriptor> OpenAlias(const ContextInterface& context, const Procfs& procfs, const Descriptor& target, bool directory,
        Diagnostic diagnostic = Diagnostic::Descriptor)
    {
        return context.OpenAlias(procfs, target, directory, diagnostic);
    }
    static Result<Descriptor> OpenAlias(const ContextInterface&&, const Procfs&, const Descriptor&, bool, Diagnostic = Diagnostic::Descriptor) = delete;
    static Result<Descriptor> OpenPinAlias(const ContextInterface& context, const Procfs& procfs, const Descriptor& target, bool directory)
    {
        return context.OpenPinAlias(procfs, target, directory);
    }
    static Result<Descriptor> OpenPinAlias(const ContextInterface&&, const Procfs&, const Descriptor&, bool) = delete;
    static Result<Descriptor> Duplicate(const ContextInterface& context, const Descriptor& source)
    {
        return context.Duplicate(source);
    }
    static Result<Descriptor> Duplicate(const ContextInterface&&, const Descriptor&) = delete;
    static int StatFile(const ContextInterface& context, const Descriptor& owner, struct stat* metadata)
    {
        return context.StatFile(owner, metadata);
    }
    static int StatFilesystem(const ContextInterface& context, const Descriptor& owner, struct statfs* metadata)
    {
        return context.StatFilesystem(owner, metadata);
    }
    static ssize_t ReadFile(const ContextInterface& context, const Descriptor& owner, void* buffer, std::size_t size)
    {
        return context.ReadFile(owner, buffer, size);
    }
    static ssize_t ReadLink(const ContextInterface& context, const Descriptor& owner, char* buffer, std::size_t size)
    {
        return context.ReadLink(owner, buffer, size);
    }
    static int StatusFlags(const ContextInterface& context, const Descriptor& owner)
    {
        return context.StatusFlags(owner);
    }
    static int DescriptorFlags(const ContextInterface& context, const Descriptor& owner)
    {
        return context.DescriptorFlags(owner);
    }
    static int ChownPinned(const ContextInterface& context, const Descriptor& owner, uid_t user, gid_t group)
    {
        return context.ChownPinned(owner, user, group);
    }
    static int ChmodAlias(const ContextInterface& context, const Procfs& procfs, const Descriptor& owner, mode_t mode)
    {
        return context.ChmodAlias(procfs, owner, mode);
    }
    static Result<Cursor> OpenDirectoryCursor(const ContextInterface& context, Descriptor&& owner)
    {
        return context.OpenDirectoryCursor(std::move(owner));
    }
    static Result<Cursor> OpenDirectoryCursor(const ContextInterface&&, Descriptor&&) = delete;
    static int CloseOwnedDescriptor(const ContextInterface& context, Descriptor& owner)
    {
        return context.CloseOwnedDescriptor(owner);
    }
    static Result<pid_t> CurrentProcessId(const ContextInterface& context)
    {
        return context.CurrentProcessId();
    }
    static Result<pid_t> CurrentThreadId(const ContextInterface& context)
    {
        return context.CurrentThreadId();
    }
    static Result<Descriptor> ActivateReadOnly(const ContextInterface& context, const Descriptor& pin, const struct stat& snapshot, bool directory, std::size_t cap)
    {
        return Filesystem::Detail::Handle::ActivateReadOnly(context, pin, snapshot, directory, cap);
    }
    static Result<Descriptor> ActivateReadOnly(const ContextInterface&&, const Descriptor&, const struct stat&, bool, std::size_t) = delete;
    static Result<Filesystem::Detail::LinkTarget> ReadPinnedLink(const Descriptor& pin, std::size_t targetCap, std::size_t fdinfoCap)
    {
        return Filesystem::Path::ReadPinnedLink(pin, targetCap, fdinfoCap);
    }
    static Procfs ProcfsAccess(const ContextInterface& context)
    {
        return Procfs(context);
    }
    static Procfs ProcfsAccess(const ContextInterface&&) = delete;
};
} // namespace Tests
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_TESTS_DESCRIPTOR_TEST_ACCESS_H
