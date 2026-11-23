# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(header "${SDK_SOURCE_DIR}/lib/include/public/ICdsFactory.hpp")
file(READ "${header}" content)

# Older SDK releases rely on transitive includes for uint8_t.
if(NOT content MATCHES "#include[ \t]*[<\"]cstdint[>\"]")
    if(NOT content MATCHES "#include <functional>")
        message(FATAL_ERROR "Cannot patch ${header}: expected include not found")
    endif()
    string(REPLACE "#include <functional>" "#include <cstdint>\n#include <functional>" content "${content}")
    file(WRITE "${header}" "${content}")
endif()
