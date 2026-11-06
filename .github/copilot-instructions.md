# Copilot Coding Agent Instructions for kompli

> Trust these instructions first. Only search the repo if information here is incomplete or found to be incorrect.

## Project Overview

kompli is a Linux security compliance engine derived from Azure OSConfig. The
C++ core lives in `src/engine/`, separate from the local CLI and Machine
Configuration adapter.

The code is written in C11/C++11, uses CMake and vcpkg, and targets Linux only.

## Repository Layout

```
src/
  CMakeLists.txt                  Root CMake file and build options
  adapters/mc/complianceengine/   Machine Configuration adapter for ComplianceEngine
  common/
    commonutils/                  Shared OS utility functions used by ComplianceEngine
    logging/                      Circular file logging
    mpiclient/                    MPI REST API client used by the MC adapter
    parson/                       Vendored JSON parser
  engine/                         Core engine, evaluator, procedures, and Lua integration
    tests/                        Unit tests
  benchmarkio/                    Benchmark-definition parsing + input-file security
  kompli/                         kompli CLI tool
  tools/lua-evaluator/            Lua evaluator tool
  telemetry/                      Telemetry support used by ComplianceEngine
  tests/fuzzer/                   Shared utility libFuzzer targets
external/vcpkg/                   vcpkg package manager submodule
devops/                           Remaining build, package, and container assets
```

## Build Instructions

### Prerequisites

- CMake >= 3.21
- GCC or Clang with C11/C++11 support
- Git submodules initialized with `git submodule update --init --recursive`
- `VCPKG_ROOT` unset, so the project uses `external/vcpkg`

### Clean Build

```bash
cmake -S src -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON -DBUILD_TELEMETRY=OFF
cmake --build build --config Release --parallel $(nproc)
```

Build outputs include `build/adapters/mc/complianceengine/libOsConfigResourceComplianceEngine.so` and `build/modules/bin/complianceengine.so`.

### Running Tests

```bash
ctest --test-dir build --output-on-failure -j$(nproc)
```

Tests are registered from the retained common libraries and `src/engine/tests/`. Some tests requiring root or special filesystem permissions are skipped when run as a normal user.

## CI Checks

Pull requests run the retained build, formatting, static-analysis, sanitizer, and CodeQL workflows. Use `-DBUILD_TELEMETRY=OFF` for local builds unless telemetry credentials are intentionally configured.

## Formatting and Linting

Run pre-commit before submitting changes:

```bash
python3 -m pre_commit run --all-files
```

The clang-format and clang-tidy hooks focus on ComplianceEngine and telemetry C++ sources.

## C++ compliance core

ComplianceEngine evaluates security compliance rules using recursive payloads with logical combinators (`allOf`, `anyOf`, `not`), built-in C++ procedures, and Lua scripts. It supports audit and remediation actions.

Rule payloads are JSON objects, base64-encoded into MOF fields consumed by the MC adapter.

Key directories:

```
src/engine/                      Core engine, evaluator, procedures, and Lua integration
src/engine/tests/                Unit tests
src/benchmarkio/                 Benchmark-definition parsing + input-file security
src/kompli/                      kompli CLI tool
src/tools/lua-evaluator/         Lua evaluator tool
```

When adding or changing built-in procedures, keep the procedure implementation, schema, tests, and generated procedure map in sync.
