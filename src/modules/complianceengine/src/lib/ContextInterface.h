// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_CONTEXTINTERFACE_H
#define COMPLIANCEENGINE_CONTEXTINTERFACE_H

#include "FilesystemScanner.h"
#include "Logging.h"
#include "Result.h"
#include "Telemetry.h"

#include <cstddef>
#include <cstdint>
#include <dirent.h>
#include <grp.h>
#include <string>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <vector>

namespace ComplianceEngine
{
class ContextInterface;
namespace Tests
{
class DescriptorTestAccess; // defined only in the test target
}
namespace Filesystem
{
namespace Detail
{
class Descriptor;
class ProcfsDescriptorAccess;
class Handle;
struct LinkTarget;
} // namespace Detail
namespace FTW
{
namespace Detail
{
class DirectoryCursor;
}
} // namespace FTW
class Path;
class ReadableFile;
enum class Type; // Directory or RegularFile; full definition in filesystem/Handle.hpp.
} // namespace Filesystem
// A single network interface as reported by the system: its name and the IFF_* flags
// bitmask (see <net/if.h>). Produced by ContextInterface::GetNetworkInterfaces().
struct InterfaceInfo
{
    std::string name;
    unsigned int flags = 0;
};

class ContextInterface
{
public:
    virtual ~ContextInterface() = 0;
    virtual Result<std::string> ExecuteCommand(const std::string& cmd) const = 0;
    virtual Result<std::string> GetFileContents(const std::string& filePath) const = 0;

    enum class OpenProfile
    {
        PinDirectory,
        PinSelfDirectory,
        PinChild,
        PinChildDirectory,
        ReadFdinfo,
        FollowAliasFile,
        FollowAliasDirectory,
        FollowAliasPin,
        FollowAliasPinDirectory
    };

private:
    // Fail closed when the caller's native process or task identity cannot be read.
    Result<pid_t> CurrentProcessId() const;
    Result<pid_t> CurrentThreadId() const;
    // Only the context syscall boundary extracts native descriptor numbers.
    // Open/duplicate atomically set CLOEXEC. Duplicate shares the open-file
    // description (including offset); it is not an independent reader.
    Result<Filesystem::Detail::Descriptor> OpenAbsolutePin(const char* path) const&;
    Result<Filesystem::Detail::Descriptor> OpenAbsolutePin(const char*) const&& = delete;
    Result<Filesystem::Detail::Descriptor> OpenAt(const Filesystem::Detail::Descriptor& directory, const char* name, OpenProfile profile) const&;
    Result<Filesystem::Detail::Descriptor> OpenAt(const Filesystem::Detail::Descriptor&, const char*, OpenProfile) const&& = delete;
    // The verified helper supplies the fd/fdinfo role; a generic directory
    // owner cannot select a procfs alias or descriptor-information target.
    Result<Filesystem::Detail::Descriptor> OpenFdinfo(const Filesystem::Detail::ProcfsDescriptorAccess& procfs, const Filesystem::Detail::Descriptor& target) const&;
    Result<Filesystem::Detail::Descriptor> OpenFdinfo(const Filesystem::Detail::ProcfsDescriptorAccess&, const Filesystem::Detail::Descriptor&) const&& = delete;
    Result<Filesystem::Detail::Descriptor> OpenAlias(const Filesystem::Detail::ProcfsDescriptorAccess& procfs,
        const Filesystem::Detail::Descriptor& target, Filesystem::Type directoryAlias) const&;
    Result<Filesystem::Detail::Descriptor> OpenAlias(const Filesystem::Detail::ProcfsDescriptorAccess&, const Filesystem::Detail::Descriptor&,
        Filesystem::Type) const&& = delete;
    Result<Filesystem::Detail::Descriptor> OpenPinAlias(const Filesystem::Detail::ProcfsDescriptorAccess& procfs,
        const Filesystem::Detail::Descriptor& target, Filesystem::Type directoryAlias) const&;
    Result<Filesystem::Detail::Descriptor> OpenPinAlias(const Filesystem::Detail::ProcfsDescriptorAccess&, const Filesystem::Detail::Descriptor&,
        Filesystem::Type) const&& = delete;
    Result<Filesystem::Detail::Descriptor> Duplicate(const Filesystem::Detail::Descriptor& source) const&;
    Result<Filesystem::Detail::Descriptor> Duplicate(const Filesystem::Detail::Descriptor&) const&& = delete;
    int StatFile(const Filesystem::Detail::Descriptor& owner, struct stat* metadata) const;
    int StatFilesystem(const Filesystem::Detail::Descriptor& owner, struct statfs* metadata) const;
    ssize_t ReadFile(const Filesystem::Detail::Descriptor& owner, void* buffer, std::size_t size) const;
    ssize_t ReadLink(const Filesystem::Detail::Descriptor& owner, char* buffer, std::size_t size) const;
    int StatusFlags(const Filesystem::Detail::Descriptor& owner) const;
    int DescriptorFlags(const Filesystem::Detail::Descriptor& owner) const;
    int ChownPinned(const Filesystem::Detail::Descriptor& owner, uid_t user, gid_t group) const;
    int ChmodAlias(const Filesystem::Detail::ProcfsDescriptorAccess& procfs, const Filesystem::Detail::Descriptor& pin, mode_t mode) const;
    Result<Filesystem::FTW::Detail::DirectoryCursor> OpenDirectoryCursor(Filesystem::Detail::Descriptor&& owner) const&;
    Result<Filesystem::FTW::Detail::DirectoryCursor> OpenDirectoryCursor(Filesystem::Detail::Descriptor&&) const&& = delete;
    // Internal disposal only: a consumed owner is a silent no-op. Checked native
    // access validates ownership separately, before entering this noexcept path.
    // Relinquish ownership and budget before the single native close attempt.
    Result<void> CloseOwnedDescriptor(Filesystem::Detail::Descriptor& owner) const noexcept;

public:
    // POSIX directory and path operations. A null ReadDirectory result is EOF
    // only when errno is zero; callers clear errno immediately before reading.
    // Overrides must preserve errno on failure, including stat failures.
    virtual DIR* OpenDirectory(const char* path) const noexcept;
    virtual struct dirent* ReadDirectory(DIR* directory) const noexcept;
    virtual Result<void> CloseDirectory(DIR* directory) const noexcept;
    virtual int StatPath(const char* path, struct stat* metadata) const noexcept;
    virtual int LstatPath(const char* path, struct stat* metadata) const noexcept;
    // Native account lookup forward; callers distinguish absent groups from
    // lookup failures using errno immediately after a null result.
    virtual struct group* GetGroupById(gid_t id) const noexcept;

    virtual Telemetry& GetTelemetry() = 0;

    // Enumerates the host's network interfaces with their IFF_* flags. On success returns
    // the list (possibly empty when the system genuinely has no interfaces); on failure
    // returns an Error whose code is the underlying errno. This is the mockable seam that
    // replaces direct /proc/net/dev + /sys/class/net reads.
    virtual Result<std::vector<InterfaceInfo>> GetNetworkInterfaces() const = 0;

    // Returns the currently-running kernel release (equivalent to `uname -r`, i.e. the
    // release field returned by the uname() syscall). On failure returns an Error whose
    // code is the underlying errno. This is the mockable seam for tests that need to
    // control the reported running kernel version.
    virtual Result<std::string> GetRunningKernelRelease() const = 0;

    virtual OsConfigLogHandle GetLogHandle() const noexcept = 0;
    virtual std::string GetSpecialFilePath(const std::string& path) const = 0;

    virtual FilesystemScanner& GetFilesystemScanner() = 0;

    // Returns the path to be used for storing state.
    virtual std::string GetStatePath() const = 0;

protected:
    // The test context may narrow this value; production contexts use 256.
    // Raising a test value cannot exceed the production or kernel ceiling.
    virtual std::size_t ManagedDescriptorAllowance() const noexcept
    {
        return 256;
    }
    ContextInterface();
    // Native-only override seams: subclasses receive integers solely for
    // system-call simulation, never through an owner-access API.
    virtual int OpenNativePath(const char* path, int flags) const noexcept;
    virtual int OpenNativeAt(int directory, const char* path, int flags) const noexcept;
    virtual int StatFileDescriptor(int descriptor, struct stat* metadata) const noexcept;
    virtual int StatFilesystemDescriptor(int descriptor, struct statfs* metadata) const noexcept;
    virtual ssize_t ReadFileDescriptor(int descriptor, void* buffer, std::size_t size) const noexcept;
    virtual ssize_t ReadLinkDescriptor(int descriptor, char* buffer, std::size_t size) const noexcept;
    virtual int StatusFlagsDescriptor(int descriptor) const noexcept;
    virtual int DescriptorFlagsDescriptor(int descriptor) const noexcept;
    virtual int DuplicateDescriptor(int descriptor) const noexcept;
    virtual DIR* FdOpenDirectory(int descriptor) const noexcept;
    virtual Result<void> CloseFileDescriptor(int descriptor) const noexcept;
    virtual int ChownPinnedFileDescriptor(int descriptor, uid_t owner, gid_t group) const noexcept;
    virtual int ChmodPinnedAlias(int procfsDirectory, const char* decimalAlias, mode_t mode) const noexcept;
    virtual pid_t NativeProcessId() const noexcept;
    virtual pid_t NativeThreadId() const noexcept;

private:
    friend class Filesystem::Detail::Descriptor;
    friend class Filesystem::Detail::ProcfsDescriptorAccess;
    friend class Filesystem::Detail::Handle;
    friend class Filesystem::Path;
    friend class Filesystem::ReadableFile;
    friend class Filesystem::FTW::Detail::DirectoryCursor;
    friend class Tests::DescriptorTestAccess;

    // The only followed bootstrap link is /proc/self, reached from the
    // helper's verified procfs pin; generic OpenAt cannot request it.
    Result<Filesystem::Detail::Descriptor> OpenProcfsSelf(const Filesystem::Detail::Descriptor& proc) const&;
    Result<Filesystem::Detail::Descriptor> OpenProcfsSelf(const Filesystem::Detail::Descriptor&) const&& = delete;
    class Reservation;
    struct ManagedDescriptorBudget
    {
        std::size_t owned = 0;
        std::size_t initialCapacity = 0;
        int initializationError = 0;
    };
    Result<bool> ReserveManagedDescriptor() const;
    void ReleaseManagedDescriptor() const noexcept;
    mutable ManagedDescriptorBudget mManagedDescriptors;
    // The fdopendir transfer keeps the charge held by its input Descriptor;
    // closedir releases it exactly once even when the native close fails.
    Result<void> CloseOwnedDirectoryCursor(DIR* stream) const noexcept;
    Result<Filesystem::Detail::Descriptor> OpenVerifiedAt(const Filesystem::Detail::Descriptor& directory, const char* name, OpenProfile profile) const&;
    Result<Filesystem::Detail::Descriptor> OpenVerifiedAt(const Filesystem::Detail::Descriptor&, const char*, OpenProfile) const&& = delete;
};
} // namespace ComplianceEngine
#endif // COMPLIANCEENGINE_CONTEXT_H
