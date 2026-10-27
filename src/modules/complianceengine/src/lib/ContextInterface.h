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
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <vector>

namespace ComplianceEngine
{
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

    // Syscall results and errno are preserved. Open supports only O_RDONLY (zero),
    // O_PATH, O_CLOEXEC and O_NOFOLLOW; creation and write flags return EINVAL.
    virtual int OpenExistingFile(const char* path, int flags) const;
    // Native acquisition forwards for the filesystem foundation: absolute
    // process-root/procfs opens and dirfd-relative child/procfs-alias opens.
    // These are internal syscall seams, not public Handle fd accessors.
    virtual int OpenNativePath(const char* path, int flags) const;
    virtual int OpenNativeAt(int directory, const char* path, int flags) const;
    virtual int StatFileDescriptor(int descriptor, struct stat* metadata) const;
    virtual ssize_t ReadFileDescriptor(int descriptor, void* buffer, std::size_t size) const;
    virtual int CloseFileDescriptor(int descriptor) const;
    // Internal metadata syscall forwards. The foundation passes only its
    // live O_PATH pin or its verified procfs directory and decimal alias;
    // these are not handle descriptor accessors or alternate path lookups.
    virtual int ChownPinnedFileDescriptor(int descriptor, uid_t owner, gid_t group) const;
    virtual int ChmodPinnedAlias(int procfsDirectory, const char* decimalAlias, mode_t mode) const;

    // POSIX directory and path operations. A null ReadDirectory result is EOF
    // only when errno is zero; callers clear errno immediately before reading.
    // Overrides must preserve errno on failure, including stat failures.
    virtual DIR* OpenDirectory(const char* path) const;
    virtual struct dirent* ReadDirectory(DIR* directory) const;
    virtual int CloseDirectory(DIR* directory) const;
    virtual int StatPath(const char* path, struct stat* metadata) const;
    virtual int LstatPath(const char* path, struct stat* metadata) const;

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
};
} // namespace ComplianceEngine
#endif // COMPLIANCEENGINE_CONTEXT_H
