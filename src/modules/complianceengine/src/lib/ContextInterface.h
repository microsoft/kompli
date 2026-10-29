// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_CONTEXTINTERFACE_H
#define COMPLIANCEENGINE_CONTEXTINTERFACE_H

#include "FilesystemScanner.h"
#include "Logging.h"
#include "Result.h"
#include "Telemetry.h"

#include <cstddef>
#include <dirent.h>
#include <grp.h>
#include <string>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <vector>

namespace ComplianceEngine
{
namespace Filesystem
{
namespace Detail
{
class Descriptor;
struct VerifiedProcfs;
} // namespace Detail
class DirectoryCursor;
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
    enum class CloseDiagnostic
    {
        Descriptor,
        DirectoryActivation
    };
    // Only the context syscall boundary extracts native descriptor numbers.
    // Open/duplicate atomically set CLOEXEC. Duplicate shares the open-file
    // description (including offset); it is not an independent reader.
    Filesystem::Detail::Descriptor EmptyDescriptor(CloseDiagnostic diagnostic = CloseDiagnostic::Descriptor) const& noexcept;
    Filesystem::Detail::Descriptor EmptyDescriptor(CloseDiagnostic = CloseDiagnostic::Descriptor) const&& = delete;
    Result<Filesystem::Detail::Descriptor> OpenAbsolutePin(const char* path, bool directory = true) const&;
    Result<Filesystem::Detail::Descriptor> OpenAbsolutePin(const char*, bool = true) const&& = delete;
    Result<Filesystem::Detail::Descriptor> OpenAt(const Filesystem::Detail::Descriptor& directory, const char* name, OpenProfile profile,
        CloseDiagnostic diagnostic = CloseDiagnostic::Descriptor) const&;
    Result<Filesystem::Detail::Descriptor> OpenAt(const Filesystem::Detail::Descriptor&, const char*, OpenProfile,
        CloseDiagnostic = CloseDiagnostic::Descriptor) const&& = delete;
    // The verified helper supplies the fd/fdinfo role; a generic directory
    // owner cannot select a procfs alias or descriptor-information target.
    Result<Filesystem::Detail::Descriptor> OpenFdinfo(const Filesystem::Detail::VerifiedProcfs& procfs, const Filesystem::Detail::Descriptor& target) const&;
    Result<Filesystem::Detail::Descriptor> OpenFdinfo(const Filesystem::Detail::VerifiedProcfs&, const Filesystem::Detail::Descriptor&) const&& = delete;
    Result<Filesystem::Detail::Descriptor> OpenAlias(const Filesystem::Detail::VerifiedProcfs& procfs, const Filesystem::Detail::Descriptor& target,
        bool directoryAlias, CloseDiagnostic diagnostic = CloseDiagnostic::Descriptor) const&;
    Result<Filesystem::Detail::Descriptor> OpenAlias(const Filesystem::Detail::VerifiedProcfs&, const Filesystem::Detail::Descriptor&, bool,
        CloseDiagnostic = CloseDiagnostic::Descriptor) const&& = delete;
    Result<Filesystem::Detail::Descriptor> OpenPinAlias(const Filesystem::Detail::VerifiedProcfs& procfs, const Filesystem::Detail::Descriptor& target,
        bool directoryAlias) const&;
    Result<Filesystem::Detail::Descriptor> OpenPinAlias(const Filesystem::Detail::VerifiedProcfs&, const Filesystem::Detail::Descriptor&, bool) const&& = delete;
    Result<Filesystem::Detail::Descriptor> Duplicate(const Filesystem::Detail::Descriptor& source) const&;
    Result<Filesystem::Detail::Descriptor> Duplicate(const Filesystem::Detail::Descriptor&) const&& = delete;
    int StatFile(const Filesystem::Detail::Descriptor& owner, struct stat* metadata) const;
    int StatFilesystem(const Filesystem::Detail::Descriptor& owner, struct statfs* metadata) const;
    ssize_t ReadFile(const Filesystem::Detail::Descriptor& owner, void* buffer, std::size_t size) const;
    ssize_t ReadLink(const Filesystem::Detail::Descriptor& owner, char* buffer, std::size_t size) const;
    int StatusFlags(const Filesystem::Detail::Descriptor& owner) const;
    int DescriptorFlags(const Filesystem::Detail::Descriptor& owner) const;
    int ChownPinned(const Filesystem::Detail::Descriptor& owner, uid_t user, gid_t group) const;
    int ChmodAlias(const Filesystem::Detail::VerifiedProcfs& procfs, const Filesystem::Detail::Descriptor& pin, mode_t mode) const;
    Result<Filesystem::DirectoryCursor> OpenDirectoryCursor(Filesystem::Detail::Descriptor&& owner) const&;
    Result<Filesystem::DirectoryCursor> OpenDirectoryCursor(Filesystem::Detail::Descriptor&&) const&& = delete;
    // Relinquish before the single native close attempt (even if it throws).
    int CloseOwnedDescriptor(Filesystem::Detail::Descriptor& owner) const;

    // POSIX directory and path operations. A null ReadDirectory result is EOF
    // only when errno is zero; callers clear errno immediately before reading.
    // Overrides must preserve errno on failure, including stat failures.
    virtual DIR* OpenDirectory(const char* path) const;
    virtual struct dirent* ReadDirectory(DIR* directory) const;
    virtual int CloseDirectory(DIR* directory) const;
    virtual int StatPath(const char* path, struct stat* metadata) const;
    virtual int LstatPath(const char* path, struct stat* metadata) const;
    // Native account lookup forward; callers distinguish absent groups from
    // lookup failures using errno immediately after a null result.
    virtual struct group* GetGroupById(gid_t id) const;

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

    virtual OsConfigLogHandle GetLogHandle() const = 0;
    virtual std::string GetSpecialFilePath(const std::string& path) const = 0;

    virtual FilesystemScanner& GetFilesystemScanner() = 0;

    // Returns the path to be used for storing state.
    virtual std::string GetStatePath() const = 0;

protected:
    // Native-only override seams: subclasses receive integers solely for
    // system-call simulation, never through an owner-access API.
    virtual int OpenNativePath(const char* path, int flags) const;
    virtual int OpenNativeAt(int directory, const char* path, int flags) const;
    virtual int StatFileDescriptor(int descriptor, struct stat* metadata) const;
    virtual int StatFilesystemDescriptor(int descriptor, struct statfs* metadata) const;
    virtual ssize_t ReadFileDescriptor(int descriptor, void* buffer, std::size_t size) const;
    virtual ssize_t ReadLinkDescriptor(int descriptor, char* buffer, std::size_t size) const;
    virtual int StatusFlagsDescriptor(int descriptor) const;
    virtual int DescriptorFlagsDescriptor(int descriptor) const;
    virtual int DuplicateDescriptor(int descriptor) const;
    virtual DIR* FdOpenDirectory(int descriptor) const;
    virtual int CloseFileDescriptor(int descriptor) const;
    virtual int ChownPinnedFileDescriptor(int descriptor, uid_t owner, gid_t group) const;
    virtual int ChmodPinnedAlias(int procfsDirectory, const char* decimalAlias, mode_t mode) const;

private:
    Result<Filesystem::Detail::Descriptor> OpenVerifiedAt(const Filesystem::Detail::Descriptor& directory, const char* name, OpenProfile profile,
        CloseDiagnostic diagnostic) const&;
};
} // namespace ComplianceEngine
#endif // COMPLIANCEENGINE_CONTEXT_H
