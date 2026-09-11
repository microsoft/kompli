// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "PeerAuth.hpp"

#include <cerrno>
#include <cstring>
#include <grp.h>
#include <pwd.h>
#include <sys/socket.h>
#include <vector>

namespace Komplid
{
namespace
{
constexpr const char* kKompliGroupName = "kompli";
// Upper bound on group-list buffer growth. Generous for any real account;
// bounds the retry loop for a hostile/misconfigured NSS backend.
constexpr int kMaxGroups = 1024;
} // namespace

PeerAuthResult CheckPeerAuthorized(int fd)
{
    struct ucred cred = {};
    socklen_t credLen = sizeof(cred);
    if (0 != getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &credLen))
    {
        if (ENOTSOCK == errno)
        {
            return PeerAuthResult(true, "not a socket; skipping peer authorization (local invocation)");
        }
        return PeerAuthResult(false, std::string("failed to read peer credentials: ") + std::strerror(errno));
    }

    if (0 == cred.uid)
    {
        return PeerAuthResult(true, "");
    }

    struct group groupBuf = {};
    struct group* groupResult = nullptr;
    std::vector<char> groupStrBuf(4096);
    int rc = 0;
    while (ERANGE == (rc = getgrnam_r(kKompliGroupName, &groupBuf, groupStrBuf.data(), groupStrBuf.size(), &groupResult)))
    {
        groupStrBuf.resize(groupStrBuf.size() * 2);
    }
    if (0 != rc || nullptr == groupResult)
    {
        return PeerAuthResult(false, std::string("'") + kKompliGroupName + "' system group does not exist");
    }
    const gid_t kompliGid = groupResult->gr_gid;

    struct passwd passwdBuf = {};
    struct passwd* passwdResult = nullptr;
    std::vector<char> passwdStrBuf(4096);
    while (ERANGE == (rc = getpwuid_r(cred.uid, &passwdBuf, passwdStrBuf.data(), passwdStrBuf.size(), &passwdResult)))
    {
        passwdStrBuf.resize(passwdStrBuf.size() * 2);
    }
    if (0 != rc || nullptr == passwdResult)
    {
        return PeerAuthResult(false, "peer uid " + std::to_string(cred.uid) + " has no passwd entry");
    }

    int ngroups = 16;
    std::vector<gid_t> groups(static_cast<size_t>(ngroups));
    for (;;)
    {
        const int capacity = ngroups;
        if (-1 != getgrouplist(passwdResult->pw_name, cred.gid, groups.data(), &ngroups))
        {
            break;
        }
        if (ngroups <= capacity || ngroups > kMaxGroups)
        {
            return PeerAuthResult(false, "failed to enumerate groups for peer uid " + std::to_string(cred.uid));
        }
        groups.resize(static_cast<size_t>(ngroups));
    }
    groups.resize(static_cast<size_t>(ngroups));

    for (const gid_t gid : groups)
    {
        if (gid == kompliGid)
        {
            return PeerAuthResult(true, "");
        }
    }

    return PeerAuthResult(
        false, "peer uid " + std::to_string(cred.uid) + " is not root and not a member of the '" + std::string(kKompliGroupName) + "' group");
}

} // namespace Komplid
