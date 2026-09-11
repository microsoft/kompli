// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef KOMPLID_PEER_AUTH_HPP
#define KOMPLID_PEER_AUTH_HPP

#include <string>

namespace Komplid
{
// Outcome of a peer-authorization check on a connected socket.
struct PeerAuthResult
{
    bool authorized;
    // Populated (client-unsafe, log-only detail) when authorized == false.
    std::string reason;

    PeerAuthResult(bool authorized, std::string reason)
        : authorized(authorized),
          reason(std::move(reason))
    {
    }
};

// Verifies the peer connected to `fd` (stdin, under socket activation with
// Accept=yes - see komplid.socket / komplid@.service) is either root or a
// member of the `kompli` system group, via SO_PEERCRED - the kernel-verified
// uid/gid/pid of the actual connected process, independent of and
// unspoofable relative to the socket file's own permissions (see
// src/komplid/README.md "Privilege model"). This is defense-in-depth beyond
// komplid.socket's SocketMode=0660/SocketGroup=kompli.
//
// If `fd` is not a socket (errno ENOTSOCK - e.g. a local `komplid <
// file.jsonl` invocation for manual testing), the check is skipped and the
// result is authorized: komplid already runs as root in that case and there
// is no remote peer to gate.
PeerAuthResult CheckPeerAuthorized(int fd);

} // namespace Komplid

#endif // KOMPLID_PEER_AUTH_HPP
