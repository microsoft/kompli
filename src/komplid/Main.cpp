// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// komplid - the planned kompli daemon.
//
// PLACEHOLDER IMPLEMENTATION. Started by systemd via socket activation with
// Accept=yes (see komplid.socket / komplid@.service): one fresh process per
// connection, with the accepted connection wired to this process's
// stdin/stdout. This version reads JSONL (one JSON value per line) and
// echoes back a pretty-printed copy of each valid line - it does not
// interpret, validate, or act on the input in any way. It exists to validate
// the socket-activation wiring end to end before the real protocol and
// request handling land. See README.md for what is and is not decided yet.

#include <parson.h>

#include <cstddef>
#include <iostream>
#include <string>

namespace
{
// Upper bound on a single JSONL line. Accept=yes means one connection is one
// process, so this only bounds that connection's own memory use, not the
// whole daemon.
constexpr std::size_t kMaxLineBytes = static_cast<std::size_t>(1) * 1024 * 1024;
} // namespace

int main()
{
    std::string line;
    while (std::getline(std::cin, line))
    {
        if (line.size() > kMaxLineBytes)
        {
            std::cerr << "komplid: refusing oversized line (" << line.size() << " bytes)" << std::endl;
            continue;
        }

        JSON_Value* value = json_parse_string(line.c_str());
        if (nullptr == value)
        {
            std::cerr << "komplid: ignoring line that is not valid JSON" << std::endl;
            continue;
        }

        char* pretty = json_serialize_to_string_pretty(value);
        if (nullptr != pretty)
        {
            std::cout << pretty << std::endl;
            json_free_serialized_string(pretty);
        }
        json_value_free(value);
    }

    return 0;
}
