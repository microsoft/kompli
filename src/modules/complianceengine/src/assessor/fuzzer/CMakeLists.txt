# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
# Benchmark-definition parser fuzzer. Built only when -DBUILD_FUZZER=ON, which
# also requires clang and enables -fsanitize=fuzzer-no-link,address,undefined
# globally (see src/CMakeLists.txt). Run manually:
#
#   ./benchmark-definition-fuzzer -max_total_time=60 seed_corpus/

add_executable(benchmark-definition-fuzzer target.cpp)

# The shared library is built with -fsanitize=fuzzer-no-link (no main); add
# -fsanitize=fuzzer here to pull in libFuzzer's entry point and link it.
target_compile_options(benchmark-definition-fuzzer PRIVATE -fsanitize=fuzzer)
target_link_options(benchmark-definition-fuzzer PRIVATE -fsanitize=fuzzer)

target_link_libraries(benchmark-definition-fuzzer PRIVATE
    compliance-engine-assessor-lib
)
