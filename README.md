# kompli

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/microsoft/kompli/badge)](https://scorecard.dev/viewer/?uri=github.com/microsoft/kompli)

kompli is a Linux security compliance engine for evaluating and remediating system configuration against industry benchmarks (CIS, STIG, etc.). It is derived from the [Azure OSConfig](https://github.com/Azure/azure-osconfig) project, with its C++ core in [`src/engine/`](src/engine/), a local CLI and a separate Machine Configuration adapter.

## History

This codebase originates from **Azure OSConfig** — a modular security configuration stack for Linux Edge devices developed by Microsoft, supporting multi-authority device management over Azure IoT Hub, GitOps, and local management. OSConfig consisted of a platform daemon, a PnP/MC adapter layer, and a set of management modules (CommandRunner, SecurityBaseline, DeviceInfo, Networking, Firewall, and others).

kompli focuses on the compliance core and its execution entry points rather
than the original platform's full management stack. The MC (Machine
Configuration) adapter, shared utilities, logging, JSON support and optional
telemetry support the core.

## Structure

```
src/
├── adapters/mc/complianceengine/   MC adapter for ComplianceEngine
├── common/
│   ├── commonutils/                Shared C utilities (pruned to CE dependencies)
│   ├── logging/                    Logging library
│   ├── mpiclient/                  MPI client (socket communication)
│   └── parson/                     JSON library
├── engine/                         Core engine, procedures, Lua evaluator
│   └── tests/                      GTest suite
├── benchmarkio/                    Benchmark-definition parsing + input-file security
├── kompli/                         kompli CLI tool
├── tools/lua-evaluator/            Lua evaluator tool
└── telemetry/                      Telemetry library
```

## Getting started

### Prerequisites

```bash
sudo apt -y update && sudo apt-get -y install \
    build-essential cmake git curl pkg-config tar unzip zip \
    libssl-dev python3
pip3 install pre_commit && python3 -m pre_commit install
```

cmake >= 3.21 is required. vcpkg is used for additional dependencies (googletest, parson) and is bootstrapped automatically.

A C++11 compiler and standard library with working `std::regex` support are required; the legacy POSIX regex fallback is no longer provided.

### Build

```bash
cmake -S src -B build \
    -DCMAKE_BUILD_TYPE=Debug \
    -DBUILD_TELEMETRY=OFF \
    -DBUILD_TESTS=ON
cmake --build build
```

To build the release artifact only:

```bash
cmake -S src -B build \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_TELEMETRY=OFF \
    -DBUILD_TESTS=OFF
cmake --build build --target OsConfigResourceComplianceEngine
```

The build produces `build/adapters/mc/complianceengine/libOsConfigResourceComplianceEngine.so`.

### Test

```bash
cd build && ctest
```

## Configuration

ComplianceEngine is configured via `/etc/kompli/kompli.json`:

```json
{
    "LoggingLevel": 6
}
```

`LoggingLevel` values: `6` = informational (default), `7` = debug.

### Distribution override

To override automatic OS detection (useful for testing), create `/etc/kompli/system_id.override`:

```
OS="Linux" ARCH="x86_64" DISTRO="ubuntu" VERSION="24.04"
```

## Contributing

See [CONTRIBUTING](CONTRIBUTING.md) and [SECURITY](SECURITY.md).

## Telemetry

Data Collection. The software may collect information about you and your use of the software and send it to Microsoft. Microsoft may use this information to provide services and improve our products and services. You may turn off the telemetry as described in the repository. There are also some features in the software that may enable you and Microsoft to collect data from users of your applications. If you use these features, you must comply with applicable law, including providing appropriate notices to users of your applications together with a copy of Microsoft’s privacy statement. Our privacy statement is located at https://go.microsoft.com/fwlink/?LinkID=824704. You can learn more about data collection and use in the help documentation and our privacy statement. Your use of the software operates as your consent to these practices.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft
trademarks or logos is subject to and must follow
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft
sponsorship. Any use of third-party trademarks or logos are subject to those third-party's policies.
